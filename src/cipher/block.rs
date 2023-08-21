use crate::{Ciphertext, Plaintext};

mod modes;
mod padding;

pub use {
    modes::{Cbc, Ecb},
    padding::{Padding, Pkcs7},
};

pub trait BlockCipher {
    const BLOCK_SIZE: usize;

    fn encrypt(p: Plaintext<&[u8]>) -> Ciphertext<Vec<u8>>;
    fn decrypt(c: Ciphertext<&[u8]>) -> Plaintext<Vec<u8>>;
}
