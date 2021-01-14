use rand::Rng;

use crate::api::secret;

use super::{E2EEClient, Impure, Poki, StreamKind};
use std::{cell::{RefCell}, collections::HashMap};

struct TestImpureServer {
    private_keys: HashMap<u64, Vec<u8>>,
    public_keys: HashMap<u64, [u8; 32]>,
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
    fn publish_public_key(&mut self, id: u64, key: [u8; 32]) {
        self.public_keys.insert(id, key);
    }

    fn new_channels(&mut self) -> (String, String) {
        let rng = rand::thread_rng();
        let mid: String = rng.sample_iter(rand::distributions::Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        let sid: String = rng.sample_iter(rand::distributions::Alphanumeric)
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

        (TestImpure{
            server: server,
            uid: data,
        }, data)
    }
}

impl Impure for TestImpure {
    fn store_private_key(&mut self, data: Vec<u8>) {
        self.server.borrow_mut().store_private_key(self.uid, data);
    }
    fn publish_public_key(&mut self, data: &[u8; 32]) {
        self.server.borrow_mut().publish_public_key(self.uid, *data);
    }
}

#[test]
fn exchange_messages() {
    let server = Poki::new(RefCell::new(TestImpureServer::new()));

    let (impure_one, client_one_id) = TestImpure::new(server.clone());
    let (impure_two, client_two_id) = TestImpure::new(server.clone());

    let mut client_one = E2EEClient::new_with_new_data(Box::new(impure_one), client_one_id, "hi".into());
    let mut client_two = E2EEClient::new_with_new_data(Box::new(impure_two), client_two_id, "oh".into());

    let (messages_chan, state_chan) = server.borrow_mut().new_channels();
    let (messages_key, state_key) = client_one.prepare_channel_keys(messages_chan.clone(), state_chan.clone());

    client_two.register_channels(
        (messages_chan.clone(), messages_key),
        (state_chan.clone(), state_key),
        vec![client_one_id],
    );

    let test_data = {
        use prost::Message;

        let mut pb: secret::Flow = Default::default();
        pb.content = Some(secret::flow::Content::Message(secret::Message {
            kind: Some(secret::message::Kind::Sent(secret::SentMessage {
                contents: "hi!".into()
            }))
        }));

        let mut out = Vec::<u8>::new();
        pb.encode(&mut out).expect("eep");

        out
    };

    let encrypted = client_one.encrypt_message(
        (StreamKind::Message, messages_chan.clone()),
        test_data.clone(),
    ).expect("failure encrypting");

    let (user_id, data) = client_two.handle_message(
        StreamKind::Message,
        messages_chan.clone(),
        encrypted,
    ).expect("failure decrypting");

    assert_eq!(user_id, client_one_id);
    assert_eq!(test_data, data);

    let test_data_two = {
        use prost::Message;

        let mut pb: secret::Flow = Default::default();
        pb.content = Some(secret::flow::Content::Message(secret::Message {
            kind: Some(secret::message::Kind::Sent(secret::SentMessage {
                contents: "hoi!".into()
            }))
        }));

        let mut out = Vec::<u8>::new();
        pb.encode(&mut out).expect("eep");

        out
    };
    let encrypted_two = client_two.encrypt_message(
        (StreamKind::Message, messages_chan.clone()),
        test_data_two.clone(),
    ).expect("failure encrypting");
    let (user_id_two, data_two) = client_one.handle_message(
        StreamKind::Message,
        messages_chan.clone(),
        encrypted_two,
    ).expect("failure decrypting");

    assert_eq!(user_id_two, client_two_id);
    assert_eq!(test_data_two, data_two);
}
