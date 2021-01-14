use rand::Rng;

use crate::api::secret;

use super::{E2EEClient, Impure, StreamKind};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

type Poki<T> = Rc<RefCell<T>>;

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

    fn get_public_key_for_user(&mut self, uid: u64) -> String {
        todo!()
    }
}

#[test]
fn client_creation() {
    const PASSWORD: &str = "very strong password";

    let server = Poki::new(RefCell::new(TestImpureServer::new()));
    let (impure, client_id) = TestImpure::new(server);
    E2EEClient::new_with_new_data(Box::new(impure), client_id, PASSWORD.into());
}

#[test]
fn exchange_messages() {
    let server = Poki::new(RefCell::new(TestImpureServer::new()));
    println!("server");

    let (impure_one, client_one_id) = TestImpure::new(server.clone());
    println!("impure one");
    let (impure_two, client_two_id) = TestImpure::new(server.clone());
    println!("impure two");

    let mut client_one =
        E2EEClient::new_with_new_data(Box::new(impure_one), client_one_id, "hi".into());
    println!("client one");
    let mut client_two =
        E2EEClient::new_with_new_data(Box::new(impure_two), client_two_id, "oh".into());
    println!("client two");

    let (messages_chan, state_chan) = server.borrow_mut().new_channels();
    println!("channenls");
    let (messages_key, state_key) =
        client_one.prepare_channel_keys(messages_chan.clone(), state_chan.clone());
    println!("keys");

    client_two.register_channels(
        (messages_chan.clone(), messages_key),
        (state_chan, state_key),
        vec![client_one_id],
    );
    println!("client two register channels");

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
    println!("test data");

    let encrypted = client_one
        .encrypt_message(
            (StreamKind::Message, messages_chan.clone()),
            test_data.clone(),
        )
        .expect("failure encrypting");
    println!("client one enctrpy test data");

    let (user_id, data) = client_two
        .handle_message(StreamKind::Message, messages_chan.clone(), encrypted)
        .expect("failure decrypting");
    println!("client two decrtpye encrypted test data");

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
    println!("test data two");

    let encrypted_two = client_two
        .encrypt_message(
            (StreamKind::Message, messages_chan.clone()),
            test_data_two.clone(),
        )
        .expect("failure encrypting");
    println!("client two encrypt test data two");

    let (user_id_two, data_two) = client_one
        .handle_message(StreamKind::Message, messages_chan, encrypted_two)
        .expect("failure decrypting");
    println!("client one decsrypt encryprted test data two");

    assert_eq!(user_id_two, client_two_id);
    assert_eq!(test_data_two, data_two);
}
