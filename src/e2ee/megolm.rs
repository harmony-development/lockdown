// this is taken mostly from https://gitlab.matrix.org/matrix-org/olm/-/blob/master/src/megolm.c
// which is licensed under the apache license

const PART_LENGTH: usize = 32;
const PART_COUNT: usize = 4;

use std::convert::TryInto;

use hmac::{Hmac, Mac, NewMac};
use sha3::Sha3_256;
type HmacSha256 = Hmac<Sha3_256>;

#[derive(Debug, Clone, Copy)]
pub struct MegOlm {
    data: [[u8; PART_LENGTH]; PART_COUNT],
    counter: u32
}


fn rehash_part(data: &mut [[u8; PART_LENGTH]; PART_COUNT], rehash_from: usize, rehash_to: usize) {
    let mac = HmacSha256::new_varkey(&data[rehash_from]).expect("somehow the key was invalid length");
    let done = mac.finalize().into_bytes();

    data[rehash_to] = done.as_slice().try_into().expect("bad output length")
}

impl MegOlm {
    pub fn new(random_data: [u8; PART_LENGTH * PART_COUNT], counter: u32) -> MegOlm {
        MegOlm {
            data: unsafe {
                std::mem::transmute(random_data)
            },
            counter: counter
        }
    }
    pub fn advance(&mut self) {
        let mut mask: u32 = 0x00FFFFFF;
        let mut h = 0;

        self.counter += 1;

        while h < PART_COUNT {
            if self.counter & mask == 0 {
                break
            }

            h += 1;
            mask >>= 8;
        }

        for i in (PART_COUNT-1)..h {
            rehash_part(&mut self.data, h, i);
        }
    }
    pub fn advance_to(&mut self, to: u32) {
        while self.counter != to {
            self.advance()
        }
    }
    pub fn key(&self) -> [u8; 128] {
        unsafe { std::mem::transmute_copy(&self.data) }
    }
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

#[derive(Debug, Clone)]
pub struct Keyinator {
    from: MegOlm,
    now: MegOlm
}

impl Keyinator {
    pub fn new(olm: MegOlm) -> Self {
        Keyinator {
            from: olm,
            now: olm
        }
    }
    pub fn key_at(&mut self, i: u32) -> [u8; 128] {
        if i < self.now.counter() {
            let cpy = self.from;
            cpy.advance_to(i);
            cpy.key()
        } else {
            self.now.advance_to(i);

            self.now.key()
        }
    }
    pub fn counter(&mut self) -> u32 {
        self.now.counter()
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn basic_ratchet() {
        let mut csprng = OsRng {};
        let mut random_data = [0u8; PART_LENGTH * PART_COUNT];
        csprng.fill_bytes(&mut random_data);

        let mut olm = MegOlm::new(random_data, 0);
        olm.advance();
        olm.advance();

        let mut other_olm = MegOlm::new(olm.key(), 0);

        olm.advance();
        other_olm.advance();

        assert_eq!(olm.key(), other_olm.key());
    }

    #[test]
    fn advance_to_ratchet() {
        let mut csprng = OsRng {};
        let mut random_data = [0u8; PART_LENGTH * PART_COUNT];
        csprng.fill_bytes(&mut random_data);

        let mut olm_one = MegOlm::new(random_data, 0);
        let mut olm_two = MegOlm::new(random_data, 0);

        olm_one.advance();
        olm_one.advance();
        olm_one.advance();

        olm_two.advance_to(3);

        assert_eq!(olm_one.counter(), olm_two.counter());
        assert_eq!(olm_one.key(), olm_two.key());
    }
}
