use crate::{Ciphertext, Plaintext};

mod modes;
mod padding;

pub use {
    modes::{Cbc, Ecb},
    padding::{Padding, Pkcs7},
};

pub trait BlockCipher {
    type Block;

    fn encrypt(p: Plaintext<Self::Block>) -> Ciphertext<Self::Block>;
    fn decrypt(c: Ciphertext<Self::Block>) -> Plaintext<Self::Block>;
}
