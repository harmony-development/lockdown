use std::convert::TryInto;

use aes::{
    cipher::{
        generic_array::{
            typenum::{
                bit::{B0, B1},
                UInt, UTerm,
            },
            GenericArray,
        },
        BlockCipher, NewBlockCipher,
    },
    Aes256,
};
use block_modes::{block_padding::Pkcs7, BlockMode, Ecb};
use hmac::{Hmac, Mac, NewMac};
use sha3::Sha3_256;

type U8Array<Size> = GenericArray<u8, Size>;
type BlockSize = UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>;

type HmacSha256 = Hmac<Sha3_256>;
type Aes256Ecb = Ecb<Aes256, Pkcs7>;

pub struct HarmonyAes {
    aes: Aes256,
    aes_varlen: Aes256Ecb,
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

        let blank: aes::cipher::generic_array::GenericArray::<u8, aes::cipher::generic_array::typenum::UTerm> = Default::default();

        let cipher = Aes256::new(&arr);
        let varlen = Aes256Ecb::new(cipher.clone(), &blank);

        self.aes = cipher;
        self.aes_varlen = varlen;
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

    #[test]
    fn from_key() {
        HarmonyAes::from_key(KEY);
    }

    #[test]
    fn from_pass() {
        HarmonyAes::from_pass(PASS.as_bytes());
    }

    #[test]
    fn encrypt() {
        let aes = HarmonyAes::from_key(KEY);
        let encrypted = aes.encrypt(UNENCRYPTED.to_vec());
        assert_eq!(ENCRYPTED.to_vec(), encrypted)
    }

    #[test]
    fn decrypt() {
        let aes = HarmonyAes::from_key(KEY);
        let decrypted = aes.decrypt(ENCRYPTED.to_vec());
        assert_eq!(UNENCRYPTED.to_vec(), decrypted)
    }

    #[test]
    fn encrypt_decrypt() {
        let aes = HarmonyAes::from_key(KEY);
        let encrypted = aes.encrypt(UNENCRYPTED.to_vec());
        let unencrypted = aes.decrypt(encrypted);
        assert_eq!(UNENCRYPTED.to_vec(), unencrypted)
    }

    #[test]
    fn decrypt_encrypt() {
        let aes = HarmonyAes::from_key(KEY);
        let unencrypted = aes.decrypt(ENCRYPTED.to_vec());
        let encrypted = aes.encrypt(unencrypted);
        assert_eq!(ENCRYPTED.to_vec(), encrypted)
    }
}
