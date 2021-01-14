use std::convert::TryInto;
use std::fmt::{self, Debug, Formatter};

use aes::{
    cipher::{
        generic_array::{typenum::UTerm, GenericArray},
        NewBlockCipher,
    },
    Aes256,
};
use block_modes::{block_padding::Pkcs7, BlockMode, Ecb};
use hmac::{Hmac, Mac, NewMac};
use sha3::Sha3_256;

type U8Array<Size> = GenericArray<u8, Size>;

type HmacSha256 = Hmac<Sha3_256>;
type Aes256Ecb = Ecb<Aes256, Pkcs7>;

pub struct HarmonyAes {
    aes: Aes256,
    aes_varlen: Aes256Ecb,
    key: [u8; 32],
}

impl Debug for HarmonyAes {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("HarmonyAes")
            .field("key", &self.key)
            .finish()
    }
}

impl HarmonyAes {
    /// Creates a new [`HarmonyAes`] from a key.
    pub fn from_key(key: [u8; 32]) -> Self {
        let arr = GenericArray::from_slice(&key);
        let blank = U8Array::<UTerm>::default();

        let cipher = Aes256::new(&arr);
        let varlen = Aes256Ecb::new(cipher.clone(), &blank);

        HarmonyAes {
            aes: cipher,
            aes_varlen: varlen,
            key,
        }
    }

    /// Creates a new [`HarmonyAes`] from a password.
    pub fn from_pass(password: &[u8]) -> Self {
        let mac = HmacSha256::new_varkey(password).expect("somehow the key was invalid length");
        let password_hash = mac.finalize().into_bytes();

        Self::from_key(password_hash.try_into().unwrap())
    }

    pub fn set_key(&mut self, key: [u8; 32]) {
        let arr = GenericArray::from_slice(&key);

        let blank: aes::cipher::generic_array::GenericArray<
            u8,
            aes::cipher::generic_array::typenum::UTerm,
        > = Default::default();

        let cipher = Aes256::new(&arr);
        let varlen = Aes256Ecb::new(cipher.clone(), &blank);

        self.aes = cipher;
        self.aes_varlen = varlen;
    }

    pub fn get_key(&self) -> [u8; 32] {
        self.key
    }

    pub fn encrypt(&self, data: Vec<u8>) -> Vec<u8> {
        let cipher = self.aes_varlen.clone();
        cipher.encrypt_vec(&data)
    }

    /// Decrypt some data.
    pub fn decrypt(&self, data: Vec<u8>) -> Vec<u8> {
        let cipher = self.aes_varlen.clone();
        cipher.decrypt_vec(&data).expect("Block mode error?")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0; 32];
    const PASS: &str = "strong password";

    const UNENCRYPTED: [u8; 32] = [0; 32];
    const ENCRYPTED: [u8; 48] = [
        220, 149, 192, 120, 162, 64, 137, 137, 173, 72, 162, 20, 146, 132, 32, 135, 220, 149, 192,
        120, 162, 64, 137, 137, 173, 72, 162, 20, 146, 132, 32, 135, 31, 120, 143, 230, 216, 108,
        49, 117, 73, 105, 127, 191, 12, 7, 250, 67,
    ];

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn from_key() {
        init();
        HarmonyAes::from_key(KEY);
    }

    #[test]
    fn from_pass() {
        init();
        HarmonyAes::from_pass(PASS.as_bytes());
    }

    #[test]
    fn encrypt() {
        init();
        let aes = HarmonyAes::from_key(KEY);
        let encrypted = aes.encrypt(UNENCRYPTED.to_vec());
        assert_eq!(ENCRYPTED.to_vec(), encrypted)
    }

    #[test]
    fn decrypt() {
        init();
        let aes = HarmonyAes::from_key(KEY);
        let decrypted = aes.decrypt(ENCRYPTED.to_vec());
        assert_eq!(UNENCRYPTED.to_vec(), decrypted)
    }

    #[test]
    fn encrypt_decrypt() {
        init();
        let aes = HarmonyAes::from_key(KEY);
        let encrypted = aes.encrypt(UNENCRYPTED.to_vec());
        let unencrypted = aes.decrypt(encrypted);
        assert_eq!(UNENCRYPTED.to_vec(), unencrypted)
    }

    #[test]
    fn decrypt_encrypt() {
        init();
        let aes = HarmonyAes::from_key(KEY);
        let unencrypted = aes.decrypt(ENCRYPTED.to_vec());
        let encrypted = aes.encrypt(unencrypted);
        assert_eq!(ENCRYPTED.to_vec(), encrypted)
    }
}
