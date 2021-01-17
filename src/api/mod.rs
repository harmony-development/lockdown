/// E2EE secret service.
pub mod secret {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/protocol.secret.v1.rs"));
    }
    pub use v1::*;
}

/// Common types used by other services.
pub mod harmonytypes {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/protocol.harmonytypes.v1.rs"));
    }
    pub use v1::*;
}
