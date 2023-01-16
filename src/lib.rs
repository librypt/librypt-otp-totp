#![no_std]
#![forbid(unsafe_code)]

use librypt_hash::HashFn;
use librypt_hotp::Hotp;

pub struct Totp<const BLOCK_SIZE: usize, const HASH_SIZE: usize, H: HashFn<BLOCK_SIZE, HASH_SIZE>> {
    hotp: Hotp<BLOCK_SIZE, HASH_SIZE, H>,
}

impl<const BLOCK_SIZE: usize, const HASH_SIZE: usize, H: HashFn<BLOCK_SIZE, HASH_SIZE>>
    Totp<BLOCK_SIZE, HASH_SIZE, H>
{
    pub fn new(secret: &[u8]) -> Self {
        Self {
            hotp: Hotp::new(secret),
        }
    }

    pub fn generate(&mut self, time: u64, duration: u64, digits: u32) -> u32 {
        self.hotp.generate(time / duration, digits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use librypt_hash_sha1::Sha1;

    #[test]
    fn test_totp() {
        let mut otp = Totp::<64, 20, Sha1>::new(b"12345678901234567890");

        assert_eq!(otp.generate(59, 30, 8), 94287082);
    }
}
