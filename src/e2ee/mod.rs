use anyhow::anyhow;
use anyhow::Result;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::{cell::RefMut, collections::HashMap, convert::TryInto};

use std::cell::RefCell;
use std::rc::Rc;

type Poki<T> = Rc<RefCell<T>>;

use crate::api::secret;

use self::aes::HarmonyAes;

mod aes;

pub trait Impure {
    fn store_private_key(&mut self, data: Vec<u8>);
    fn publish_public_key(&mut self, data: &[u8; 32]);
}

pub struct E2EEClient {
    impure: Box<dyn Impure>,
    stream_states: HashMap<(String, String), Poki<StreamState>>,
    message_stream_states: HashMap<String, Poki<StreamState>>,
    state_stream_states: HashMap<String, Poki<StreamState>>,
    keypair: Keypair,
    uid: u64,
}

struct StreamState {
    messages_id: String,
    messages_key: HarmonyAes,

    state_id: String,
    state_key: HarmonyAes,

    known_users: Vec<u64>,
}

pub enum StreamKind {
    Message,
    State,
}

impl E2EEClient {
    pub fn new_with_new_data(mut impure: Box<dyn Impure>, uid: u64, password: String) -> Self {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        let cipher = HarmonyAes::from_pass(password.as_bytes());
        let data = cipher.encrypt((*keypair.secret.as_bytes()).into());

        impure.store_private_key(data);
        impure.publish_public_key(keypair.public.as_bytes());

        E2EEClient {
            impure,
            stream_states: HashMap::new(),
            message_stream_states: HashMap::new(),
            state_stream_states: HashMap::new(),
            keypair,
            uid,
        }
    }
    pub fn new_from_existing_data(
        impure: Box<dyn Impure>,
        uid: u64,
        pubkey: [u8; 32],
        privkey: Vec<u8>,
        password: String,
    ) -> Self {
        let keypair = {
            let cipher = HarmonyAes::from_pass(password.as_bytes());
            let decrypted = cipher.decrypt(privkey);

            let pubkey = ed25519_dalek::PublicKey::from_bytes(&pubkey)
                .expect("Failed to create public key from bytes");
            let privkey = ed25519_dalek::SecretKey::from_bytes(&decrypted)
                .expect("Failed to create private key from bytes");

            Keypair {
                public: pubkey,
                secret: privkey,
            }
        };
        E2EEClient {
            impure,
            stream_states: HashMap::new(),
            message_stream_states: HashMap::new(),
            state_stream_states: HashMap::new(),
            keypair,
            uid,
        }
    }

    pub fn register_channels(
        &mut self,
        messages: (String, [u8; 32]),
        state: (String, [u8; 32]),
        users: Vec<u64>,
    ) {
        let inner_data: RefCell<StreamState> = StreamState {
            messages_id: messages.0.clone(),
            messages_key: HarmonyAes::from_key(messages.1),

            state_id: state.0.clone(),
            state_key: HarmonyAes::from_key(state.1),

            known_users: users,
        }
        .into();
        let data: Poki<StreamState> = inner_data.into();

        self.stream_states
            .insert((messages.0.clone(), state.0.clone()), data.clone());
        self.message_stream_states.insert(messages.0, data.clone());
        self.state_stream_states.insert(state.0, data);
    }

    pub fn prepare_channel_keys(
        &mut self,
        messages: String,
        state: String,
    ) -> ([u8; 32], [u8; 32]) {
        use rand::RngCore;

        let mut csprng = OsRng {};

        let mut messages_key = [0u8; 32];
        let mut state_key = [0u8; 32];

        csprng.fill_bytes(&mut messages_key);
        csprng.fill_bytes(&mut state_key);

        let inner_data: RefCell<StreamState> = StreamState {
            messages_id: messages.clone(),
            messages_key: HarmonyAes::from_key(messages_key),

            state_id: state.clone(),
            state_key: HarmonyAes::from_key(state_key),

            known_users: Vec::new(),
        }
        .into();
        let data: Poki<StreamState> = inner_data.into();

        self.stream_states
            .insert((messages.clone(), state.clone()), data.clone());
        self.message_stream_states.insert(messages, data.clone());
        self.state_stream_states.insert(state, data);

        (messages_key, state_key)
    }

    fn decrypt_using_privkey(&self, data: Vec<u8>) -> Vec<u8> {
        let key: [u8; 32] = self.keypair.secret.to_bytes();
        let aes = HarmonyAes::from_key(key);

        aes.decrypt(data)
    }

    /// message should always be a Flow in serialised form
    pub fn encrypt_message(
        &self,
        for_channel: (StreamKind, String),
        message: Vec<u8>
    ) -> Result<Vec<u8>> {
        use prost::Message;

        // let's fetch us some state keys
        let mut state: RefMut<StreamState>;
        match for_channel.0 {
            StreamKind::Message => state = self.message_stream_states[&for_channel.1].borrow_mut(),
            StreamKind::State => state = self.state_stream_states[&for_channel.1].borrow_mut(),
        };
        let state_key = match for_channel.0 {
            StreamKind::Message => &mut state.messages_key,
            StreamKind::State => &mut state.state_key,
        };

        // generate the new key...
        // TODO
        // let new_key = {
        //     use rand::RngCore;

        //     let mut csprng = OsRng {};
        //     let mut key = [0u8; 32];
        //     csprng.fill_bytes(&mut key);

        //     key
        // };
        // state_key.set_key(new_key);

        // create the fanout...
        // TODO

        let mut signed: secret::SignedMessage = Default::default();
        signed.message = message;
        signed.from_user = self.uid;

        // TODO: sign message

        let mut signed_bytes = Vec::<u8>::new();
        signed.encode(&mut signed_bytes)?;
        let encrypted = state_key.encrypt(signed_bytes);

        let mut encrypted_message: secret::EncryptedMessage = Default::default();
        encrypted_message.message = encrypted;

        let mut out = Vec::<u8>::new();
        encrypted_message.encode(&mut out)?;

        Ok(out)
    }

    /// handle_message takes in the type of stream the message came from, the stream's ID, and
    // the raw bytedata of the EncryptedMessage, and returns a tuple containing the message's author ID
    // and its inner Flow.
    pub fn handle_message(
        &mut self,
        kind: StreamKind,
        stream_id: String,
        data: Vec<u8>,
    ) -> Result<(u64, Vec<u8>)> {
        use prost::Message;

        let mut msg: secret::EncryptedMessage = Default::default();
        msg.merge(data.as_slice())?;

        let mut state: RefMut<StreamState>;
        match kind {
            StreamKind::Message => state = self.message_stream_states[&stream_id].borrow_mut(),
            StreamKind::State => state = self.state_stream_states[&stream_id].borrow_mut(),
        };
        let state_key = match kind {
            StreamKind::Message => &mut state.messages_key,
            StreamKind::State => &mut state.state_key,
        };

        let decrypted = state_key.decrypt(msg.message);

        let mut signed_msg: secret::SignedMessage = Default::default();
        signed_msg.merge(decrypted.as_slice())?;

        // TODO: validate signature
        let mut flow: secret::Flow = Default::default();
        flow.merge(signed_msg.message.as_slice())?;

        match signed_msg.fanout {
            Some(fanout) => {
                let keys: &HashMap<u64, secret::Key> = &fanout.keys;
                if keys.len() != (state.known_users.len() + 1) {
                    return Err(anyhow!("Bad message fanout; length of keys is not equivalent to known trusted users"));
                }
                for key in &state.known_users {
                    if !keys.contains_key(&key) {
                        return Err(anyhow!(
                            "Bad message fanout; user ID {} is missing from keys",
                            key
                        ));
                    }
                }
                if !keys.contains_key(&self.uid) {
                    return Err(anyhow!("Bad message fanout; no key for self"));
                }
                let key = &keys[&self.uid];
                let data: [u8; 32] = key.key_data.as_slice().try_into()?;
                let unenc = self.decrypt_using_privkey(data.into());
                let unenc_arr: [u8; 32] = unenc.as_slice().try_into()?;

                match kind {
                    StreamKind::Message => {
                        state.messages_key.set_key(unenc_arr);
                    }
                    StreamKind::State => {
                        state.state_key.set_key(unenc_arr);
                    }
                }
            }
            None => (),
        };

        // TODO:
        // add "ensure has key" method which looks up public keys in a cache, falls back to impure, and then finally errors if it can't find any
        // verify byte data of signed_msg.message using signed_msg.signature and signed_msg.from_user

        Ok((signed_msg.from_user, signed_msg.message))
    }
}

#[cfg(test)]
mod tests;
