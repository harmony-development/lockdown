use self::aes::{HarmonyAes, KeySize};
use crate::{api::secret, bail};
use error::{E2EEError, E2EEResult, FanoutError, ImpureError};

use std::{collections::HashMap, convert::TryInto};

use async_trait::async_trait;
use hmac::{Hmac, Mac, NewMac};
use rand::rngs::OsRng;
use rsa::{
    Hash, PaddingScheme, PrivateKeyPemEncoding, PublicKey, PublicKeyPemEncoding, RSAPrivateKey,
    RSAPublicKey,
};
use sha3::Sha3_512;

pub mod aes;
/// Error types used in this library.
pub mod error;

pub mod megolm;

type HmacSha512 = Hmac<Sha3_512>;

const ENCRYPT_PADDING_SCHEME: PaddingScheme = PaddingScheme::PKCS1v15Encrypt;
const SIGN_PADDING_SCHEME: PaddingScheme = PaddingScheme::PKCS1v15Sign {
    hash: Some(Hash::SHA3_512),
};

/// Trait used for operations that need networking, which is not handled by this library.
#[async_trait]
pub trait Impure<Error: ImpureError>: std::fmt::Debug {
    /// Stores a private key in the server.
    async fn store_private_key(&mut self, data: Vec<u8>) -> Result<(), Error>;
    /// Publishes a public key to the server.
    async fn publish_public_key(&mut self, data: String) -> Result<(), Error>;
    /// Gets the public key for a user. It is recommended to implement a cache mechanism for keys.
    async fn get_public_key_for_user(&mut self, uid: u64) -> Result<String, Error>;
}

/// E2EE client implementation.
#[derive(Debug)]
pub struct E2EEClient<ImpErr: ImpureError> {
    impure: Box<dyn Impure<ImpErr>>,
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

    #[allow(dead_code)]
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

/// Kind of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Message,
    State,
}

impl<ImpErr: ImpureError> E2EEClient<ImpErr> {
    pub async fn new_with_new_data(
        mut impure: Box<dyn Impure<ImpErr>>,
        uid: u64,
        password: String,
    ) -> E2EEResult<Self, ImpErr> {
        const BITS: usize = 4096;

        let priv_key = RSAPrivateKey::new(&mut OsRng, BITS).expect("failed to generate key");
        let data: String = priv_key.to_pem_pkcs8().expect("failed to pem key");

        let cipher = HarmonyAes::from_pass(password.as_bytes());
        let data = cipher.encrypt((data.as_bytes()).into());

        impure.store_private_key(data).await?;
        impure
            .publish_public_key(
                priv_key
                    .to_public_key()
                    .to_pem_pkcs8()
                    .expect("failed to pem key"),
            )
            .await?;

        Ok(E2EEClient {
            impure,
            stream_states: StreamStates::default(),
            key: priv_key,
            uid,
        })
    }

    pub fn new_from_existing_data(
        impure: Box<dyn Impure<ImpErr>>,
        uid: u64,
        priv_key: String,
        password: String,
    ) -> E2EEResult<Self, ImpErr> {
        let keypair = {
            let cipher = HarmonyAes::from_pass(password.as_bytes());
            let bytes = priv_key.as_bytes();
            let decrypted = cipher.decrypt(bytes.into());

            RSAPrivateKey::from_pkcs8(&decrypted).map_err(E2EEError::ConvertToKey)?
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
        messages: (String, KeySize),
        state: (String, KeySize),
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
    ) -> (KeySize, KeySize) {
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

    /// Creates a (serialized) encrpyted invite for other clients to consume.
    pub async fn create_invite(
        &mut self,
        messages_id: impl AsRef<str>,
        for_client: u64,
    ) -> E2EEResult<Vec<u8>, ImpErr> {
        log::trace!(
            "Creating invite: Stream states before:\n{:?}",
            self.stream_states
        );
        let (id, state) = self
            .stream_states
            .get_mut(StreamKind::Message, messages_id.as_ref())
            .unwrap();

        let pubkey = pubkey_from_pem(self.impure.get_public_key_for_user(for_client).await?)?;

        let serialized_invite = serialize_message(secret::Invite {
            message_id: id.message_id.clone(),
            state_id: id.state_id.clone(),
            message_key: state.messages_key.get_key().to_vec(),
            state_key: state.state_key.get_key().to_vec(),
            known_users: {
                let mut users = state.known_users.clone();
                // Invite receiver will need to know sender's known users + sender
                users.push(self.uid);
                users
            },
        })?;

        let encrypted_invite = secret::EncryptedInvite {
            invite: pubkey
                .encrypt(&mut OsRng, ENCRYPT_PADDING_SCHEME, &serialized_invite)
                .map_err(E2EEError::Encrypt)?,
        };

        state.known_users.push(for_client);
        Ok(serialize_message(encrypted_invite)?)
    }

    /// Consumes a (serialized) encrypted invite.
    pub fn handle_invite(&mut self, encrypted_invite: impl AsRef<[u8]>) -> E2EEResult<(), ImpErr> {
        let secret::EncryptedInvite { invite: enc_invite } =
            deser_message(encrypted_invite.as_ref())?;

        let decrypted_invite = self.decrypt_using_privkey(enc_invite)?;

        let secret::Invite {
            message_id,
            state_id,
            message_key,
            state_key,
            known_users,
        } = deser_message(&decrypted_invite)?;

        let id = StreamId {
            message_id,
            state_id,
        };
        let state = StreamState {
            state_key: HarmonyAes::from_key(
                state_key
                    .try_into()
                    .map_err(|_| E2EEError::UnexpectedArraySize)?,
            ),
            messages_key: HarmonyAes::from_key(
                message_key
                    .try_into()
                    .map_err(|_| E2EEError::UnexpectedArraySize)?,
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

    /// Encrypts and signs a message. `message` should always be a Flow in serialised form.
    pub async fn encrypt_message(
        &mut self,
        stream_kind: StreamKind,
        stream_id: impl AsRef<str>,
        message: impl AsRef<[u8]>,
    ) -> E2EEResult<Vec<u8>, ImpErr> {
        let mut csprng = OsRng;

        let known_users = self
            .stream_states
            .get(stream_kind, stream_id.as_ref())
            .ok_or_else(|| E2EEError::NoSuchStream {
                kind: stream_kind,
                id: stream_id.as_ref().to_string(),
            })?
            .1
            .known_users
            .clone();

        // generate the new key
        let new_key = {
            use rand::RngCore;

            let mut csprng = OsRng;
            let mut key = [0u8; 32];
            csprng.fill_bytes(&mut key);

            key
        };

        let hasher = HmacSha512::new_varkey(message.as_ref()).expect("key was invalid size");
        let hashed_message = hasher.finalize().into_bytes();
        // sign the message data
        let signature = self
            .key
            .sign(SIGN_PADDING_SCHEME, hashed_message.as_slice())
            .map_err(E2EEError::Sign)?;

        // create the message
        let signed = secret::SignedMessage {
            message: message.as_ref().to_vec(),
            signature,
            // create the fanout...
            fanout: Some(secret::Fanout {
                keys: {
                    let mut map = HashMap::new();

                    for user in known_users {
                        let pubkey =
                            pubkey_from_pem(self.impure.get_public_key_for_user(user).await?)?;
                        let key_data = pubkey
                            .encrypt(&mut csprng, ENCRYPT_PADDING_SCHEME, &new_key)
                            .map_err(E2EEError::Encrypt)?;

                        map.insert(user, secret::Key { key_data });
                    }

                    map
                },
            }),
            from_user: self.uid,
        };

        let state_key = self
            .stream_states
            .get_mut_key(stream_kind, stream_id.as_ref())
            .ok_or_else(|| E2EEError::NoSuchStream {
                kind: stream_kind,
                id: stream_id.as_ref().to_string(),
            })?;

        let signed_bytes = serialize_message(signed)?;
        let encrypted = state_key.encrypt(signed_bytes);

        let encrypted_message = secret::EncryptedMessage {
            message: encrypted,
            ..Default::default()
        };

        state_key.set_key(new_key);
        Ok(serialize_message(encrypted_message)?)
    }

    /// Verifies signature and decrypts an encrypted message.
    ///
    /// Takes the type of stream the message came from, the stream's ID, and
    /// the raw bytedata of the EncryptedMessage, and returns a tuple containing the message's author ID
    /// and its inner Flow.
    pub async fn handle_message(
        &mut self,
        stream_kind: StreamKind,
        stream_id: impl AsRef<str>,
        data: impl AsRef<[u8]>,
    ) -> E2EEResult<(u64, Vec<u8>), ImpErr> {
        let msg: secret::EncryptedMessage = deser_message(data.as_ref())?;

        log::trace!(
            "Client id: {}\n\nHandling message: stream_kind: {:?} stream_id: {:?}\n {:?}",
            self.uid,
            stream_kind,
            stream_id.as_ref(),
            self.stream_states
        );
        let (_, state) = self
            .stream_states
            .get(stream_kind, stream_id.as_ref())
            .ok_or_else(|| E2EEError::NoSuchStream {
                kind: stream_kind,
                id: stream_id.as_ref().to_string(),
            })?;
        let decrypted = match stream_kind {
            StreamKind::Message => state.messages_key.decrypt(msg.message),
            StreamKind::State => state.state_key.decrypt(msg.message),
        };
        let known_users = state.known_users.clone();

        let signed_msg: secret::SignedMessage = deser_message(decrypted.as_slice())?;

        let sender_pubkey = pubkey_from_pem(
            self.impure
                .get_public_key_for_user(signed_msg.from_user)
                .await?,
        )?;

        // Verify signature
        let hasher =
            HmacSha512::new_varkey(signed_msg.message.as_slice()).expect("invalid key size");
        let hashed_message = hasher.finalize().into_bytes();
        if let Err(err) = sender_pubkey.verify(
            SIGN_PADDING_SCHEME,
            hashed_message.as_slice(),
            signed_msg.signature.as_slice(),
        ) {
            bail!(E2EEError::InvalidSignature(err));
        }

        if let Some(fanout) = signed_msg.fanout {
            let keys: &HashMap<u64, secret::Key> = &fanout.keys;

            if keys.len() != known_users.len() {
                bail!(FanoutError::LengthNotEqual {
                    known_users: known_users.len(),
                    key_count: keys.len(),
                })
            }

            for key in &known_users {
                // Don't check for senders key, since we trust them already
                if key != &signed_msg.from_user && !keys.contains_key(key) {
                    bail!(FanoutError::UserIdMissing(*key));
                }
            }

            if !keys.contains_key(&self.uid) {
                bail!(FanoutError::NoSelfKey);
            }

            let key = &keys[&self.uid];
            let unenc = self.decrypt_using_privkey(key.key_data.clone())?;
            let unenc_arr: KeySize = unenc
                .try_into()
                .map_err(|_| E2EEError::UnexpectedArraySize)?;

            self.stream_states
                .get_mut_key(stream_kind, stream_id.as_ref())
                .ok_or_else(|| E2EEError::NoSuchStream {
                    kind: stream_kind,
                    id: stream_id.as_ref().to_string(),
                })?
                .set_key(unenc_arr);
        };

        Ok((signed_msg.from_user, signed_msg.message))
    }

    fn decrypt_using_privkey(&self, data: impl AsRef<[u8]>) -> E2EEResult<Vec<u8>, ImpErr> {
        self.key
            .decrypt(ENCRYPT_PADDING_SCHEME, data.as_ref())
            .map_err(E2EEError::Decrypt)
    }
}

pub(crate) fn serialize_message<Msg: prost::Message, ImpErr: ImpureError>(
    msg: Msg,
) -> E2EEResult<Vec<u8>, ImpErr> {
    let len = msg.encoded_len();
    let mut buf = Vec::with_capacity(len);
    msg.encode(&mut buf)?;
    Ok(buf)
}

pub(crate) fn deser_message<Msg: prost::Message + Default, ImpErr: ImpureError>(
    data: &[u8],
) -> E2EEResult<Msg, ImpErr> {
    Msg::decode(data).map_err(Into::into)
}

pub(crate) fn pubkey_from_pem<ImpErr: ImpureError>(
    pem_pcks8: String,
) -> E2EEResult<RSAPublicKey, ImpErr> {
    rsa::pem::parse(pem_pcks8)?
        .try_into()
        .map_err(E2EEError::ConvertToKey)
}

#[cfg(test)]
mod tests;
