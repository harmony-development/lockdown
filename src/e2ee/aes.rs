use aes::cipher::{generic_array::GenericArray, BlockCipher, NewBlockCipher};
use aes::Aes256;
use std::convert::TryInto;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;

use aes::cipher::generic_array::typenum::bit::B0;
use aes::cipher::generic_array::typenum::bit::B1;
use aes::cipher::generic_array::typenum::UInt;
use aes::cipher::generic_array::typenum::UTerm;

type BlockSize = UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>;
use hmac::{Hmac, Mac, NewMac};

use sha3::Sha3_256;
type HmacSha256 = Hmac<Sha3_256>;

type Aes256Ecb = Ecb<Aes256, Pkcs7>;

pub struct HarmonyAes {
    aes: Aes256,
    aes_varlen: Aes256Ecb,
}

impl HarmonyAes {
    pub fn new_from_key(key: [u8; 32]) -> Self {
        let arr = GenericArray::from_slice(&key);

        let blank: aes::cipher::generic_array::GenericArray::<u8, aes::cipher::generic_array::typenum::UTerm> = Default::default();

        let cipher = Aes256::new(&arr);
        let varlen = Aes256Ecb::new(cipher.clone(), &blank);

        HarmonyAes {
            aes: cipher,
            aes_varlen: varlen,
        }
    }
    pub fn new_from_pass(password: String) -> Self {
        let mac = HmacSha256::new_varkey(password.as_bytes())
            .expect("somehow the key was invalid length");
        let password_hash: &[u8] = &mac.finalize().into_bytes();
        let arr = GenericArray::from_slice(password_hash);

        let blank: aes::cipher::generic_array::GenericArray::<u8, aes::cipher::generic_array::typenum::UTerm> = Default::default();

        let cipher = Aes256::new(&arr);
        let varlen = Aes256Ecb::new(cipher.clone(), &blank);

        HarmonyAes {
            aes: cipher,
            aes_varlen: varlen,
        }
    }

    pub fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        let cipher = self.aes_varlen.clone();
        cipher.encrypt_vec(&data)
    }
    
    pub fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        let cipher = self.aes_varlen.clone();
        cipher.encrypt_vec(&data)
    }

    pub fn encrypt_fixed(&self, data: [u8; 32]) -> [u8; 32] {
        let mut block = GenericArray::<u8, BlockSize>::clone_from_slice(&data);
        self.aes.encrypt_block(&mut block);

        block.as_slice().try_into().expect("")
    }

    pub fn decrypt_fixed(&self, data: [u8; 32]) -> [u8; 32] {
        let mut block = GenericArray::<u8, BlockSize>::clone_from_slice(&data);
        self.aes.decrypt_block(&mut block);

        block.as_slice().try_into().expect("")
    }
}
