use std::{collections::HashMap};
use prost::DecodeError;
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;

use std::rc::Rc;

mod aes;
use self::aes::HarmonyAes;

use crate::api::secret;

pub trait Impure {
    fn store_private_key(&mut self, data: &[u8; 32]);
    fn publish_public_key(&mut self, data: &[u8; 32]);
}

pub struct E2EEClient {
    impure: Box<dyn Impure>,
    stream_states: HashMap<(String,String),Rc<StreamState>>,
    message_stream_states: HashMap<String,Rc<StreamState>>,
    state_stream_states: HashMap<String,Rc<StreamState>>,
    keypair: Keypair,
}

struct StreamState {
    messages_id: String,
    messages_key: HarmonyAes,

    state_id: String,
    state_key: HarmonyAes,

    known_users: Vec<u64>
}

pub enum StreamKind {
    Message,
    State,
}

impl E2EEClient {
    pub fn new_with_new_data(mut impure: Box<dyn Impure>, password: String) -> Self {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);

        let cipher = HarmonyAes::new_from_pass(password);
        let data = cipher.encrypt_fixed(*keypair.secret.as_bytes());

        impure.store_private_key(&data);
        impure.publish_public_key(keypair.public.as_bytes());

        E2EEClient {
            impure,
            stream_states: HashMap::new(),
            message_stream_states: HashMap::new(),
            state_stream_states: HashMap::new(),
            keypair,
        }
    }
    pub fn new_from_existing_data(impure: Box<dyn Impure>, pubkey: [u8; 32], privkey: [u8; 32], password: String) -> Self {
        let keypair = {
            let cipher = HarmonyAes::new_from_pass(password);
            let decrypted = cipher.decrypt_fixed(privkey);

            let pubkey = ed25519_dalek::PublicKey::from_bytes(&pubkey).expect("");
            let privkey = ed25519_dalek::SecretKey::from_bytes(&decrypted).expect("");

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
        }
    }

    pub fn prepare_channel_keys(&mut self, messages: String, state: String) -> ([u8; 32], [u8; 32]) {
        use rand::RngCore;

        let mut csprng = OsRng{};

        let mut messages_key = [0u8; 32];
        let mut state_key = [0u8; 32];

        csprng.fill_bytes(&mut messages_key);
        csprng.fill_bytes(&mut state_key);

        let data: Rc<StreamState> = StreamState {
            messages_id: messages.clone(),
            messages_key: HarmonyAes::new_from_key(messages_key),

            state_id: state.clone(),
            state_key: HarmonyAes::new_from_key(state_key),

            known_users: Vec::new(),
        }.into();

        self.stream_states.insert(
            (messages.clone(), state.clone()),
            data.clone(),
        );
        self.message_stream_states.insert(messages.clone(), data.clone());
        self.state_stream_states.insert(state.clone(), data.clone());

        (messages_key, state_key)
    }

    pub fn handle_message(&mut self, kind: StreamKind, stream_id: String, data: Vec<u8>) -> Result<(u64, u64, Vec<u8>), DecodeError> {
        use prost::Message;

        let mut msg: secret::EncryptedMessage = Default::default();
        msg.merge(data.as_slice())?;

        let state = match kind {
            StreamKind::Message => {
                &self.message_stream_states[&stream_id].messages_key
            },
            StreamKind::State => {
                &self.state_stream_states[&stream_id].state_key
            }
        };

        let decrypted = state.decrypt(msg.message);

        let mut signed_msg: secret::SignedMessage = Default::default();
        signed_msg.merge(decrypted.as_slice())?;

        // TODO:
        // add "ensure has key" method which looks up public keys in a cache, falls back to impure, and then finally errors if it can't find any
        // verify byte data of signed_msg.message using signed_msg.signature and signed_msg.from_user

        unimplemented!("see above todo");
    }
}

#[cfg(test)]
mod tests;
