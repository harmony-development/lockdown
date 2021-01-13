pub mod secret {
    include!(concat!(env!("OUT_DIR"), "/protocol.secret.v1.rs"));
}

pub mod harmonytypes {
    include!(concat!(env!("OUT_DIR"), "/protocol.harmonytypes.v1.rs"));
}
