use std::{collections::HashMap};
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;

mod aes;
use self::aes::HarmonyAes;

use crate::api::secret;

pub trait Impure {
    fn store_private_key(&mut self, data: &[u8; 32]);
    fn publish_public_key(&mut self, data: &[u8; 32]);
}

pub struct E2EEClient {
    impure: Box<dyn Impure>,
    stream_states: HashMap<String,StreamState>,
    keypair: Keypair,
}

struct StreamState {
    stream_id: String,
    key: HarmonyAes,
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

        self.stream_states.insert(
            messages.clone(),
            StreamState {
                stream_id: messages,
                key: HarmonyAes::new_from_key(messages_key)
            }
        );
        self.stream_states.insert(
            state.clone(),
            StreamState {
                stream_id: state,
                key: HarmonyAes::new_from_key(messages_key)
            }
        );

        (messages_key, state_key)
    }
}

#[cfg(test)]
mod tests;
