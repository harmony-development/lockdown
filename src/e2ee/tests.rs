use super::{error::ImpureError, E2EEClient, Impure, StreamKind};
use crate::api::secret;

use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use prost::EncodeError;
use rand::Rng;

#[derive(Debug)]
struct TestImpureServer {
    private_keys: Mutex<HashMap<u64, Vec<u8>>>,
    public_keys: Mutex<HashMap<u64, String>>,
    channels: Mutex<HashMap<String, Vec<Vec<u8>>>>,
}

impl TestImpureServer {
    fn new() -> Self {
        TestImpureServer {
            private_keys: Mutex::new(HashMap::new()),
            public_keys: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
        }
    }

    fn store_private_key(&self, id: u64, key: Vec<u8>) {
        self.private_keys.lock().expect("aaa").insert(id, key);
    }

    fn publish_public_key(&self, id: u64, key: String) {
        self.public_keys.lock().expect("aaa").insert(id, key);
    }

    fn get_public_key_for_user(&self, id: &u64) -> Option<String> {
        self.public_keys.lock().expect("aaa").get(id).cloned()
    }

    fn new_channels(&self) -> (String, String) {
        let rng = rand::thread_rng();
        let mid: String = rng
            .sample_iter(rand::distributions::Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        let sid: String = rng
            .sample_iter(rand::distributions::Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();

        self.channels
            .lock()
            .expect("aaa")
            .insert(mid.clone(), Vec::new());
        self.channels
            .lock()
            .expect("aaa")
            .insert(sid.clone(), Vec::new());

        (mid, sid)
    }
}

#[derive(Debug)]
struct TestImpure {
    server: Arc<TestImpureServer>,
    uid: u64,
}

impl TestImpure {
    fn new(server: Arc<TestImpureServer>) -> (Self, u64) {
        let mut rng = rand::thread_rng();
        let data = rng.gen::<u64>();

        (TestImpure { server, uid: data }, data)
    }
}

#[async_trait::async_trait]
impl Impure<Infallible> for TestImpure {
    async fn store_private_key(&mut self, data: Vec<u8>) -> Result<(), Infallible> {
        self.server.store_private_key(self.uid, data);
        Ok(())
    }

    async fn publish_public_key(&mut self, data: String) -> Result<(), Infallible> {
        self.server.publish_public_key(self.uid, data);
        Ok(())
    }

    async fn get_public_key_for_user(&mut self, uid: u64) -> Result<String, Infallible> {
        Ok(self
            .server
            .get_public_key_for_user(&uid)
            .expect("cant happen"))
    }
}

impl ImpureError for Infallible {}

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn serialize_message<Msg: prost::Message>(msg: Msg) -> Result<Vec<u8>, EncodeError> {
    let len = msg.encoded_len();
    let mut buf = Vec::with_capacity(len);
    msg.encode(&mut buf)?;
    Ok(buf)
}

#[tokio::test]
async fn client_creation() {
    init();

    const PASSWORD: &str = "very strong password";

    let server = Arc::new(TestImpureServer::new());
    let (impure, client_id) = TestImpure::new(server);
    E2EEClient::new_with_new_data(Box::new(impure), client_id, PASSWORD.into())
        .await
        .unwrap();
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn many_clients() {
    const CLIENTS_SIZE: usize = 10;

    init();

    let server = Arc::new(TestImpureServer::new());
    let (msg_chan, stt_chan) = server.new_channels();

    let mut impures = Vec::with_capacity(CLIENTS_SIZE);
    for _ in 0..CLIENTS_SIZE {
        impures.push(TestImpure::new(server.clone()));
    }

    let rng = rand::thread_rng();
    let mut clients = Vec::with_capacity(CLIENTS_SIZE);
    for (impure, id) in impures {
        let new_client = E2EEClient::new_with_new_data(
            Box::new(impure),
            id,
            rng.sample_iter(rand::distributions::Alphanumeric)
                .take(30)
                .map(char::from)
                .collect(),
        )
        .await
        .expect("failed");

        clients.push((new_client, id));
    }

    clients[0]
        .0
        .prepare_channel_keys(msg_chan.clone(), stt_chan.clone());
    for i in 1..CLIENTS_SIZE {
        let for_user = clients[i].1;
        let trust_key = clients[0].0.create_trust_key(for_user).await.expect("err");
        // put trust key event into state stream
        server
            .channels
            .lock()
            .expect("mutex poisoned")
            .get_mut(&stt_chan)
            .expect("no state chan")
            .push(trust_key);
        let invite = clients[0]
            .0
            .create_invite(msg_chan.clone(), for_user)
            .await
            .expect("err");
        clients[i].0.handle_invite(invite).expect("err");
    }

    let chans = server.channels.lock().expect("aaa");
    let trust_keys = chans.get(&stt_chan).expect("no state chan");
    for (client, _) in clients.iter_mut().skip(1) {
        for trust_key in trust_keys {
            client.handle_trust_key(&stt_chan, trust_key).expect("err");
        }
    }

    let test_data = serialize_message(secret::Flow {
        content: Some(secret::flow::Content::Message(secret::Message {
            kind: Some(secret::message::Kind::Sent(secret::SentMessage {
                contents: "hi!".into(),
            })),
        })),
        ..Default::default()
    })
    .expect("failure serializing message");
    let test_data_enc = clients[0]
        .0
        .encrypt_message(StreamKind::Message, &msg_chan, &test_data)
        .await
        .expect("err");

    for i in 1..CLIENTS_SIZE {
        let (id, msg) = clients[i]
            .0
            .handle_message(StreamKind::Message, &msg_chan, &test_data_enc)
            .await
            .expect("err");
        assert_eq!(id, clients[0].1);
        assert_eq!(msg, test_data);

        /*let reply_data = serialize_message(secret::Flow {
            content: Some(secret::flow::Content::Message(secret::Message {
                kind: Some(secret::message::Kind::Sent(secret::SentMessage {
                    contents: rng
                        .sample_iter(rand::distributions::Alphanumeric)
                        .take(30)
                        .map(char::from)
                        .collect::<String>(),
                })),
            })),
            ..Default::default()
        })
        .expect("failure serializing message");
        let reply_data_enc = clients[i]
            .0
            .encrypt_message(StreamKind::Message, &msg_chan, reply_data.as_slice())
            .await
            .expect("err");

        let (rid, rmsg) = clients[0]
            .0
            .handle_message(StreamKind::Message, &msg_chan, &reply_data_enc)
            .await
            .expect("aaa");
        assert_eq!(rid, clients[i].1);
        assert_eq!(rmsg, reply_data);*/
    }
}

#[tokio::test]
#[should_panic(expected = "NoSuchStream")]
async fn invalid_stream() {
    init();

    const PASSWORD: &str = "very strong password";

    let server = Arc::new(TestImpureServer::new());
    let (_, stt_chan) = server.new_channels();

    let (impure, client_id) = TestImpure::new(server);
    let mut client = E2EEClient::new_with_new_data(Box::new(impure), client_id, PASSWORD.into())
        .await
        .unwrap();

    client
        .encrypt_message(StreamKind::Message, &stt_chan, &[0])
        .await
        .unwrap();
}

#[tokio::test]
async fn exchange_messages() {
    init();

    let server = Arc::new(TestImpureServer::new());
    log::info!("server");

    let (impure_one, client_one_id) = TestImpure::new(server.clone());
    log::info!("impure one: {}", client_one_id);
    let (impure_two, client_two_id) = TestImpure::new(server.clone());
    log::info!("impure two: {}", client_two_id);

    let mut client_one =
        E2EEClient::new_with_new_data(Box::new(impure_one), client_one_id, "hi".into())
            .await
            .unwrap();
    log::info!("client one");
    let mut client_two =
        E2EEClient::new_with_new_data(Box::new(impure_two), client_two_id, "oh".into())
            .await
            .unwrap();
    log::info!("client two");

    let (messages_chan, state_chan) = server.new_channels();
    log::info!("channenls");
    client_one.prepare_channel_keys(messages_chan.clone(), state_chan);
    log::info!("keys");

    let invite = client_one
        .create_invite(messages_chan.clone(), client_two_id)
        .await
        .unwrap();
    log::info!("client one created invite");
    client_two.handle_invite(invite).unwrap();
    log::info!("client two accepted invite");

    let test_data = serialize_message(secret::Flow {
        content: Some(secret::flow::Content::Message(secret::Message {
            kind: Some(secret::message::Kind::Sent(secret::SentMessage {
                contents: "hi!".into(),
            })),
        })),
        ..Default::default()
    })
    .expect("failure serializing message");
    log::info!("test data");

    let encrypted = client_one
        .encrypt_message(StreamKind::Message, &messages_chan, test_data.as_slice())
        .await
        .expect("failure encrypting");
    log::info!("client one enctrpy test data");

    let (user_id, data) = client_two
        .handle_message(StreamKind::Message, &messages_chan, &encrypted)
        .await
        .expect("failure decrypting");
    log::info!("client two decrtpye encrypted test data");

    assert_eq!(user_id, client_one_id);
    assert_eq!(test_data, data);

    let test_data_two = serialize_message(secret::Flow {
        content: Some(secret::flow::Content::Message(secret::Message {
            kind: Some(secret::message::Kind::Sent(secret::SentMessage {
                contents: "hoi!".into(),
            })),
        })),
        ..Default::default()
    })
    .expect("failure serializing message");
    log::info!("test data two");

    let encrypted_two = client_two
        .encrypt_message(
            StreamKind::Message,
            &messages_chan,
            test_data_two.as_slice(),
        )
        .await
        .expect("failure encrypting");
    log::info!("client two encrypt test data two");

    let (user_id_two, data_two) = client_one
        .handle_message(StreamKind::Message, &messages_chan, &encrypted_two)
        .await
        .expect("failure decrypting");
    log::info!("client one decsrypt encryprted test data two");

    assert_eq!(user_id_two, client_two_id);
    assert_eq!(test_data_two, data_two);
}
