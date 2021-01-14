use self::aes::HarmonyAes;
use crate::api::secret;

use std::{
    cell::{RefCell, RefMut},
    collections::HashMap,
    convert::TryInto,
    rc::Rc,
};

use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PrivateKeyPemEncoding, PublicKey, PublicKeyPemEncoding, RSAPrivateKey};

type Poki<T> = Rc<RefCell<T>>;

mod aes;

pub trait Impure {
    fn store_private_key(&mut self, data: Vec<u8>);

    fn publish_public_key(&mut self, data: String);
    fn get_public_key_for_user(&mut self, uid: u64) -> String;
}

pub struct E2EEClient {
    impure: Box<dyn Impure>,
    stream_states: HashMap<(String, String), Poki<StreamState>>,
    message_stream_states: HashMap<String, Poki<StreamState>>,
    state_stream_states: HashMap<String, Poki<StreamState>>,
    key: RSAPrivateKey,
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
        let bits = 4098;

        let priv_key = RSAPrivateKey::new(&mut csprng, bits).expect("failed to generate key");
        let data: String = priv_key.to_pem_pkcs8().expect("failed to pem key");

        let cipher = HarmonyAes::from_pass(password.as_bytes());
        let data = cipher.encrypt((data.as_bytes()).into());

        impure.store_private_key(data);
        impure.publish_public_key(
            priv_key
                .to_public_key()
                .to_pem_pkcs8()
                .expect("failed to pem key"),
        );

        E2EEClient {
            impure,
            stream_states: HashMap::new(),
            message_stream_states: HashMap::new(),
            state_stream_states: HashMap::new(),
            key: priv_key,
            uid,
        }
    }
    pub fn new_from_existing_data(
        impure: Box<dyn Impure>,
        uid: u64,
        priv_key: String,
        password: String,
    ) -> Result<Self> {
        let keypair = {
            let cipher = HarmonyAes::from_pass(password.as_bytes());
            let bytes = priv_key.as_bytes();
            let decrypted = cipher.decrypt(bytes.into());

            RSAPrivateKey::from_pkcs8(&decrypted)?
        };
        Ok(E2EEClient {
            impure,
            stream_states: HashMap::new(),
            message_stream_states: HashMap::new(),
            state_stream_states: HashMap::new(),
            key: keypair,
            uid,
        })
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

    fn decrypt_using_privkey(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self
            .key
            .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &data)?)
    }

    /// message should always be a Flow in serialised form
    pub fn encrypt_message(
        &mut self,
        for_channel: (StreamKind, String),
        message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut csprng = OsRng {};

        use prost::Message;

        // let's fetch us some state keys
        let mut state: RefMut<StreamState>;
        match for_channel.0 {
            StreamKind::Message => state = self.message_stream_states[&for_channel.1].borrow_mut(),
            StreamKind::State => state = self.state_stream_states[&for_channel.1].borrow_mut(),
        };
        let state_users = state.known_users.clone();
        let state_key = match for_channel.0 {
            StreamKind::Message => &mut state.messages_key,
            StreamKind::State => &mut state.state_key,
        };

        // generate the new key
        let new_key = {
            use rand::RngCore;

            let mut csprng = OsRng {};
            let mut key = [0u8; 32];
            csprng.fill_bytes(&mut key);

            key
        };

        // create the message
        let mut signed = secret::SignedMessage {
            message,
            from_user: self.uid,
            ..Default::default()
        };

        // create the fanout...
        signed.fanout = Some(secret::Fanout {
            keys: {
                let mut map = HashMap::new();

                for user in state_users {
                    let pubkey = self.impure.get_public_key_for_user(user);
                    let k = rsa::RSAPublicKey::from_pkcs8(pubkey.as_bytes())?;
                    let keydata =
                        k.encrypt(&mut csprng, PaddingScheme::new_pkcs1v15_encrypt(), &new_key)?;

                    map.insert(user, secret::Key { key_data: keydata });
                }

                map
            },
        });

        // TODO: sign message

        let mut signed_bytes = Vec::<u8>::new();
        signed.encode(&mut signed_bytes)?;
        let encrypted = state_key.encrypt(signed_bytes);

        let encrypted_message = secret::EncryptedMessage {
            message: encrypted,
            ..Default::default()
        };

        let mut out = Vec::<u8>::new();
        encrypted_message.encode(&mut out)?;

        state_key.set_key(new_key);
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
        let state_key = match kind {
            StreamKind::Message => {
                state = self.message_stream_states[&stream_id].borrow_mut();
                &mut state.messages_key
            }
            StreamKind::State => {
                state = self.state_stream_states[&stream_id].borrow_mut();
                &mut state.state_key
            }
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
                let unenc = self.decrypt_using_privkey(data.into())?;
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
