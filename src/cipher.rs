use crate::{Ciphertext, Plaintext};

mod block;

pub use block::{BlockCipher, Cbc, Ecb, Padding, Pkcs7};

pub trait Cipher {
    fn encrypt(&self, p: Plaintext<&[u8]>) -> Ciphertext<Vec<u8>>;
    fn decrypt(&self, c: Ciphertext<&[u8]>) -> Plaintext<Vec<u8>>;
}
