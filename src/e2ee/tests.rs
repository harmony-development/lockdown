use rand::Rng;
use rsa::{RSAPrivateKey, RSAPublicKey};

use crate::api::secret;

use super::{E2EEClient, Impure, StreamKind};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

type Poki<T> = Rc<RefCell<T>>;

#[derive(Debug)]
struct TestImpureServer {
    private_keys: HashMap<u64, Vec<u8>>,
    public_keys: HashMap<u64, String>,
    channels: HashMap<String, Vec<Vec<u8>>>,
}

impl TestImpureServer {
    fn new() -> Self {
        TestImpureServer {
            private_keys: HashMap::new(),
            public_keys: HashMap::new(),
            channels: HashMap::new(),
        }
    }

    fn store_private_key(&mut self, id: u64, key: Vec<u8>) {
        self.private_keys.insert(id, key);
    }

    fn publish_public_key(&mut self, id: u64, key: String) {
        self.public_keys.insert(id, key);
    }

    fn get_public_key_for_user(&self, id: &u64) -> Option<String> {
        self.public_keys.get(id).cloned()
    }

    fn new_channels(&mut self) -> (String, String) {
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

        self.channels.insert(mid.clone(), Vec::new());
        self.channels.insert(sid.clone(), Vec::new());

        (mid, sid)
    }
}

#[derive(Debug)]
struct TestImpure {
    server: Poki<TestImpureServer>,
    uid: u64,
}

impl TestImpure {
    fn new(server: Poki<TestImpureServer>) -> (Self, u64) {
        let mut rng = rand::thread_rng();
        let data = rng.gen::<u64>();

        (TestImpure { server, uid: data }, data)
    }
}

impl Impure for TestImpure {
    fn store_private_key(&mut self, data: Vec<u8>) {
        self.server.borrow_mut().store_private_key(self.uid, data);
    }

    fn publish_public_key(&mut self, data: String) {
        self.server.borrow_mut().publish_public_key(self.uid, data);
    }

    fn get_public_key_for_user(&mut self, uid: u64) -> Option<String> {
        self.server.borrow().get_public_key_for_user(&uid)
    }
}

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn client_creation() {
    init();

    const PASSWORD: &str = "very strong password";

    let server = Poki::new(RefCell::new(TestImpureServer::new()));
    let (impure, client_id) = TestImpure::new(server);
    E2EEClient::new_with_new_data(Box::new(impure), client_id, PASSWORD.into());
}

#[test]
fn exchange_messages() {
    init();

    let server = Poki::new(RefCell::new(TestImpureServer::new()));
    log::info!("server");

    let (impure_one, client_one_id) = TestImpure::new(server.clone());
    log::info!("impure one: {}", client_one_id);
    let (impure_two, client_two_id) = TestImpure::new(server.clone());
    log::info!("impure two: {}", client_two_id);

    let mut client_one =
        E2EEClient::new_with_new_data(Box::new(impure_one), client_one_id, "hi".into());
    log::info!("client one");
    let mut client_two =
        E2EEClient::new_with_new_data(Box::new(impure_two), client_two_id, "oh".into());
    log::info!("client two");

    let (messages_chan, state_chan) = server.borrow_mut().new_channels();
    log::info!("channenls");
    client_one.prepare_channel_keys(messages_chan.clone(), state_chan);
    log::info!("keys");

    let invite = client_one
        .create_invite(messages_chan.clone(), client_two_id)
        .unwrap();

    client_two.handle_invite(invite).unwrap();
    log::info!("client two register channels");

    let test_data = {
        use prost::Message;

        let pb = secret::Flow {
            content: Some(secret::flow::Content::Message(secret::Message {
                kind: Some(secret::message::Kind::Sent(secret::SentMessage {
                    contents: "hi!".into(),
                })),
            })),
            ..Default::default()
        };

        let mut out = Vec::<u8>::new();
        pb.encode(&mut out).expect("eep");

        out
    };
    log::info!("test data");

    let encrypted = client_one
        .encrypt_message(
            (StreamKind::Message, messages_chan.clone()),
            test_data.clone(),
        )
        .expect("failure encrypting");
    log::info!("client one enctrpy test data");

    let (user_id, data) = client_two
        .handle_message(StreamKind::Message, messages_chan.clone(), encrypted)
        .expect("failure decrypting");
    log::info!("client two decrtpye encrypted test data");

    assert_eq!(user_id, client_one_id);
    assert_eq!(test_data, data);

    let test_data_two = {
        use prost::Message;

        let pb = secret::Flow {
            content: Some(secret::flow::Content::Message(secret::Message {
                kind: Some(secret::message::Kind::Sent(secret::SentMessage {
                    contents: "hoi!".into(),
                })),
            })),
            ..Default::default()
        };

        let mut out = Vec::<u8>::new();
        pb.encode(&mut out).expect("eep");

        out
    };
    log::info!("test data two");

    let encrypted_two = client_two
        .encrypt_message(
            (StreamKind::Message, messages_chan.clone()),
            test_data_two.clone(),
        )
        .expect("failure encrypting");
    log::info!("client two encrypt test data two");

    let (user_id_two, data_two) = client_one
        .handle_message(StreamKind::Message, messages_chan, encrypted_two)
        .expect("failure decrypting");
    log::info!("client one decsrypt encryprted test data two");

    assert_eq!(user_id_two, client_two_id);
    assert_eq!(test_data_two, data_two);
}
