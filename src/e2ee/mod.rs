use self::aes::HarmonyAes;
use crate::api::secret;

use std::{collections::HashMap, convert::TryInto};

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use rand::rngs::OsRng;
use rsa::{
    PaddingScheme, PrivateKeyPemEncoding, PublicKey, PublicKeyPemEncoding, RSAPrivateKey,
    RSAPublicKey,
};

mod aes;

const ENCRYPT_PADDING_SCHEME: PaddingScheme = PaddingScheme::PKCS1v15Encrypt;

#[async_trait]
pub trait Impure: std::fmt::Debug {
    async fn store_private_key(&mut self, data: Vec<u8>);
    async fn publish_public_key(&mut self, data: String);
    async fn get_public_key_for_user(&mut self, uid: u64) -> Option<String>;
}

#[derive(Debug)]
pub struct E2EEClient {
    impure: Box<dyn Impure>,
    stream_states: StreamStates,
    key: RSAPrivateKey,
    uid: u64,
}

#[derive(Default, Debug)]
struct StreamStates {
    inner: HashMap<StreamId, StreamState>,
}

impl StreamStates {
    fn insert(&mut self, stream_id: StreamId, stream_state: StreamState) -> Option<StreamState> {
        self.inner.insert(stream_id, stream_state)
    }

    fn get_mut(
        &mut self,
        stream_kind: StreamKind,
        stream_id: &str,
    ) -> Option<(&StreamId, &mut StreamState)> {
        self.inner
            .iter_mut()
            .find(|(id, _)| match stream_kind { StreamKind::Message => &id.message_id, StreamKind::State => &id.state_id, } == stream_id)
    }

    fn get(&self, stream_kind: StreamKind, stream_id: &str) -> Option<(&StreamId, &StreamState)> {
        self.inner
            .iter()
            .find(|(id, _)| match stream_kind { StreamKind::Message => &id.message_id, StreamKind::State => &id.state_id, } == stream_id)
    }

    fn get_mut_key(&mut self, stream_kind: StreamKind, stream_id: &str) -> Option<&mut HarmonyAes> {
        self.get_mut(stream_kind, stream_id)
            .map(|(_, state)| match stream_kind {
                StreamKind::Message => &mut state.messages_key,
                StreamKind::State => &mut state.state_key,
            })
    }

    fn get_key(&mut self, stream_kind: StreamKind, stream_id: &str) -> Option<&HarmonyAes> {
        self.get(stream_kind, stream_id)
            .map(|(_, state)| match stream_kind {
                StreamKind::Message => &state.messages_key,
                StreamKind::State => &state.state_key,
            })
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct StreamId {
    message_id: String,
    state_id: String,
}

#[derive(Debug)]
struct StreamState {
    messages_key: HarmonyAes,
    state_key: HarmonyAes,

    known_users: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Message,
    State,
}

impl E2EEClient {
    pub async fn new_with_new_data(
        mut impure: Box<dyn Impure>,
        uid: u64,
        password: String,
    ) -> Self {
        const BITS: usize = 4096;

        let priv_key = RSAPrivateKey::new(&mut OsRng, BITS).expect("failed to generate key");
        let data: String = priv_key.to_pem_pkcs8().expect("failed to pem key");

        let cipher = HarmonyAes::from_pass(password.as_bytes());
        let data = cipher.encrypt((data.as_bytes()).into());

        impure.store_private_key(data).await;
        impure
            .publish_public_key(
                priv_key
                    .to_public_key()
                    .to_pem_pkcs8()
                    .expect("failed to pem key"),
            )
            .await;

        E2EEClient {
            impure,
            stream_states: StreamStates::default(),
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
            stream_states: StreamStates::default(),
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
        let (message_id, messages_key) = messages;
        let (state_id, state_key) = state;

        let id = StreamId {
            message_id,
            state_id,
        };
        let state = StreamState {
            messages_key: HarmonyAes::from_key(messages_key),
            state_key: HarmonyAes::from_key(state_key),

            known_users: users,
        };

        log::trace!(
            "Registering channels: Stream states before:\n{:?}",
            self.stream_states
        );
        self.stream_states.insert(id, state);
        log::trace!(
            "Registering channels: Stream states after:\n{:?}",
            self.stream_states
        );
    }

    pub fn prepare_channel_keys(
        &mut self,
        message_id: String,
        state_id: String,
    ) -> ([u8; 32], [u8; 32]) {
        use rand::RngCore;

        let mut csprng = OsRng {};

        let mut messages_key = [0u8; 32];
        let mut state_key = [0u8; 32];

        csprng.fill_bytes(&mut messages_key);
        csprng.fill_bytes(&mut state_key);

        let id = StreamId {
            message_id,
            state_id,
        };
        let state = StreamState {
            messages_key: HarmonyAes::from_key(messages_key),
            state_key: HarmonyAes::from_key(state_key),

            known_users: Vec::new(),
        };

        log::trace!(
            "Preparing channel keys: Stream states before:\n{:?}",
            self.stream_states
        );
        self.stream_states.insert(id, state);
        log::trace!(
            "Preparing channel keys: Stream states after:\n{:?}",
            self.stream_states
        );

        (messages_key, state_key)
    }

    fn decrypt_using_privkey(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.key
            .decrypt(ENCRYPT_PADDING_SCHEME, &data)
            .map_err(Into::into)
    }

    /// message should always be a Flow in serialised form
    pub async fn encrypt_message(
        &mut self,
        for_channel: (StreamKind, String),
        message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut csprng = OsRng;

        let (kind, stream_id) = for_channel;
        // let's fetch us some state keys
        let (_, state) = self.stream_states.get_mut(kind, &stream_id).unwrap();
        let state_key = match kind {
            StreamKind::Message => &mut state.messages_key,
            StreamKind::State => &mut state.state_key,
        };

        // generate the new key
        let new_key = {
            use rand::RngCore;

            let mut csprng = OsRng;
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

                for user in &state.known_users {
                    let pubkey = pubkey_from_pem(
                        self.impure
                            .get_public_key_for_user(*user)
                            .await
                            .expect("user key"),
                    )?;
                    let key_data = pubkey.encrypt(&mut csprng, ENCRYPT_PADDING_SCHEME, &new_key)?;

                    map.insert(*user, secret::Key { key_data });
                }

                map
            },
        });

        // TODO: sign message

        let signed_bytes = serialize_message(signed)?;
        let encrypted = state_key.encrypt(signed_bytes);

        let encrypted_message = secret::EncryptedMessage {
            message: encrypted,
            ..Default::default()
        };

        state_key.set_key(new_key);
        Ok(serialize_message(encrypted_message)?)
    }

    pub async fn create_invite(&mut self, messages_id: String, for_client: u64) -> Result<Vec<u8>> {
        log::trace!(
            "Creating invite: Stream states before:\n{:?}",
            self.stream_states
        );
        let (id, state) = self
            .stream_states
            .get_mut(StreamKind::Message, &messages_id)
            .unwrap();

        let pubkey = pubkey_from_pem(
            self.impure
                .get_public_key_for_user(for_client)
                .await
                .expect("user key"),
        )?;

        let mut rng = OsRng;
        let mut encrypt_with_pubkey =
            |data: &[u8]| pubkey.encrypt(&mut rng, ENCRYPT_PADDING_SCHEME, data);

        let enc_message_key = encrypt_with_pubkey(&state.messages_key.get_key())?;
        let enc_state_key = encrypt_with_pubkey(&state.state_key.get_key())?;

        let invite = secret::Invite {
            message_id: id.message_id.clone(),
            state_id: id.state_id.clone(),
            message_key: enc_message_key,
            state_key: enc_state_key,
            known_users: {
                let mut users = state.known_users.clone();
                // Invite receiver will need to know sender's known users + sender
                users.push(self.uid);
                users
            },
        };

        state.known_users.push(for_client);
        Ok(serialize_message(invite)?)
    }

    pub fn handle_invite(&mut self, invite: Vec<u8>) -> Result<()> {
        let secret::Invite {
            message_id,
            state_id,
            message_key: enc_message_key,
            state_key: enc_state_key,
            known_users,
        } = deser_message(invite.as_slice())?;

        let message_key = self.decrypt_using_privkey(enc_message_key)?;
        let state_key = self.decrypt_using_privkey(enc_state_key)?;

        let id = StreamId {
            message_id,
            state_id,
        };
        let state = StreamState {
            state_key: HarmonyAes::from_key(
                state_key
                    .try_into()
                    .map_err(|_| anyhow!("State key not expected length"))?,
            ),
            messages_key: HarmonyAes::from_key(
                message_key
                    .try_into()
                    .map_err(|_| anyhow!("Message key not expected length"))?,
            ),
            known_users,
        };

        log::trace!(
            "Handling invite: Stream states before:\n{:?}",
            self.stream_states
        );
        self.stream_states.insert(id, state);
        log::trace!(
            "Handling invite: Stream states after:\n{:?}",
            self.stream_states
        );

        Ok(())
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

        log::trace!(
            "Handling message: stream_kind: {:?} stream_id: {:?}\n {:?}",
            kind,
            stream_id,
            self.stream_states
        );
        let (_, state) = self.stream_states.get(kind, &stream_id).unwrap();
        let decrypted = match kind {
            StreamKind::Message => state.messages_key.decrypt(msg.message),
            StreamKind::State => state.state_key.decrypt(msg.message),
        };

        let signed_msg: secret::SignedMessage = deser_message(decrypted.as_slice())?;

        // TODO: validate signature
        let flow: secret::Flow = deser_message(signed_msg.message.as_slice())?;

        if let Some(fanout) = signed_msg.fanout {
            let keys: &HashMap<u64, secret::Key> = &fanout.keys;

            if keys.len() != state.known_users.len() {
                bail!(
                    "Bad message fanout; length of keys is not equivalent to known trusted users"
                );
            }

            for key in &state.known_users {
                // Don't check for senders key, since we trust them already
                if key != &signed_msg.from_user && !keys.contains_key(key) {
                    bail!("Bad message fanout; user ID {} is missing from keys", key);
                }
            }

            if !keys.contains_key(&self.uid) {
                bail!("Bad message fanout; no key for self");
            }

            let key = &keys[&self.uid];
            let unenc = self.decrypt_using_privkey(key.key_data.clone())?;
            let unenc_arr: [u8; 32] = unenc.as_slice().try_into()?;

            self.stream_states
                .get_mut_key(kind, &stream_id)
                .unwrap()
                .set_key(unenc_arr);
        };

        // TODO:
        // add "ensure has key" method which looks up public keys in a cache, falls back to impure, and then finally errors if it can't find any
        // verify byte data of signed_msg.message using signed_msg.signature and signed_msg.from_user

        Ok((signed_msg.from_user, signed_msg.message))
    }
}

pub(crate) fn serialize_message(msg: impl prost::Message) -> Result<Vec<u8>> {
    let len = msg.encoded_len();
    let mut buf = Vec::with_capacity(len);
    msg.encode(&mut buf)?;
    Ok(buf)
}

pub(crate) fn deser_message<Msg: prost::Message + Default>(data: &[u8]) -> Result<Msg> {
    Msg::decode(data).map_err(Into::into)
}

pub(crate) fn pubkey_from_pem(pem_pcks8: String) -> Result<RSAPublicKey> {
    rsa::pem::parse(pem_pcks8)?.try_into().map_err(Into::into)
}

#[cfg(test)]
mod tests;
