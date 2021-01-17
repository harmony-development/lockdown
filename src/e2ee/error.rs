use std::fmt::{self, Display, Formatter};

pub use prost::{DecodeError, EncodeError};
pub use rsa::errors::Error as RsaError;
pub use rsa::pem::PemError;

/// Shorthand for `Result<R, E2EEError>`.
pub type E2EEResult<R, ImpureError> = Result<R, E2EEError<ImpureError>>;

/// Superset trait that `Impure` trait error needs to implement.
pub trait ImpureError: std::fmt::Debug + std::fmt::Display {}

/// Errors that this library can produce.
#[derive(Debug)]
pub enum E2EEError<Error: ImpureError> {
    /// Occurs if there was an error while processing the message fanout.
    Fanout(FanoutError),
    /// Occurs if a message has invalid signature.
    InvalidSignature(RsaError),
    /// Occurs if protobuf message decoding fails.
    ProtobufDecode(DecodeError),
    /// Occurs if protobuf message encoding fails.
    ProtobufEncode(EncodeError),
    /// Occurs if parsing a PEM fails.
    PemParse(PemError),
    /// Occurs if conversion to an RSA key fails.
    ConvertToKey(RsaError),
    /// Occurs if encrypting some data fails.
    Encrypt(RsaError),
    /// Occurs if decrypting some data fails.
    Decrypt(RsaError),
    /// Occurs if signing some data fails.
    Sign(RsaError),
    /// May (but should not) occur when converting a variable-length list to a fixed-size array.
    UnexpectedArraySize,
    /// Error produced by an [`Impure`].
    Impure(Error),
    /// A custom error.
    Custom(String),
}

impl<Error: ImpureError> Display for E2EEError<Error> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            E2EEError::Fanout(err) => write!(f, "Bad message fanout: {}", err),
            E2EEError::InvalidSignature(err) => {
                write!(f, "Failed to verify signature: {}", err)
            }
            E2EEError::ConvertToKey(err) => {
                write!(f, "Failed to convert to key: {}", err)
            }
            E2EEError::ProtobufDecode(err) => {
                write!(f, "Failed to decode a protobuf message: {}", err)
            }
            E2EEError::ProtobufEncode(err) => {
                write!(f, "Failed to encode a protobuf message: {}", err)
            }
            E2EEError::Decrypt(err) => {
                write!(f, "Failed to decrypt data: {}", err)
            }
            E2EEError::Encrypt(err) => {
                write!(f, "Failed to encrypt data: {}", err)
            }
            E2EEError::Sign(err) => {
                write!(f, "Failed to sign data: {}", err)
            }
            E2EEError::PemParse(err) => write!(f, "Failed to parse PEM: {}", err),
            E2EEError::UnexpectedArraySize => {
                write!(f, "Variable-length list does not have expected length")
            }
            E2EEError::Impure(err) => {
                write!(f, "An error occured in the impure: {}", err)
            }
            E2EEError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

impl<Error: ImpureError> From<Error> for E2EEError<Error> {
    fn from(err: Error) -> Self {
        E2EEError::Impure(err)
    }
}

impl<Error: ImpureError> From<FanoutError> for E2EEError<Error> {
    fn from(err: FanoutError) -> Self {
        E2EEError::Fanout(err)
    }
}

impl<Error: ImpureError> From<DecodeError> for E2EEError<Error> {
    fn from(err: DecodeError) -> Self {
        E2EEError::ProtobufDecode(err)
    }
}

impl<Error: ImpureError> From<EncodeError> for E2EEError<Error> {
    fn from(err: EncodeError) -> Self {
        E2EEError::ProtobufEncode(err)
    }
}

impl<Error: ImpureError> From<PemError> for E2EEError<Error> {
    fn from(err: PemError) -> Self {
        E2EEError::PemParse(err)
    }
}

/// Errors that can occur while processing a message fanout.
#[derive(Debug)]
pub enum FanoutError {
    /// Occurs if known user count and fanout key count are not equal.
    LengthNotEqual {
        known_users: usize,
        key_count: usize,
    },
    /// Occurs if a known user's ID is missing from fanout keys.
    UserIdMissing(u64),
    /// Occurs if client's own ID is missing from fanout keys.
    NoSelfKey,
}

impl Display for FanoutError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            FanoutError::LengthNotEqual {
                known_users,
                key_count,
            } => write!(
                f,
                "length of keys ({}) is not equivalent to known trusted users ({})",
                key_count, known_users
            ),
            FanoutError::UserIdMissing(id) => write!(f, "user ID {} is missing from keys", id),
            FanoutError::NoSelfKey => write!(f, "no key for self"),
        }
    }
}

// Not part of the public API
#[doc(hidden)]
#[macro_export]
macro_rules! bail {
    ($err:expr) => {
        return Err($err.into())
    };
    ($($arg:tt)*) => {
        return Err($crate::custom_err!($($arg)*))
    }
}

// Not part of the public API
#[doc(hidden)]
#[macro_export]
macro_rules! custom_err {
    ($($arg:tt)*) => {
        $crate::e2ee::error::E2EEError::Custom(format!($($arg)*))
    };
}
