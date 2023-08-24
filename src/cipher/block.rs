use crate::{Bytes, Ciphertext, Key, Plaintext};

mod aes;
mod modes;
mod padding;

pub use {
    aes::{Aes128, Aes192, Aes256},
    modes::{BlockMode, Cbc, Ecb},
    padding::{Padding, Pkcs7},
};

pub trait BlockCipher {
    type Block: Bytes;
    type Key: Bytes;

    fn encrypt(data: Plaintext<Self::Block>, key: Key<Self::Key>) -> Ciphertext<Self::Block>;
    fn decrypt(data: Ciphertext<Self::Block>, key: Key<Self::Key>) -> Plaintext<Self::Block>;
}
