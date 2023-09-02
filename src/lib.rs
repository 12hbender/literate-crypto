#[cfg(test)]
mod test;

#[cfg(doc)]
pub mod doc;

mod bytes;
mod cipher;
mod key;
mod random;
mod text;

pub use {
    bytes::Bytes,
    cipher::{
        aes,
        Aes128,
        Aes192,
        Aes256,
        BlockCipher,
        BlockMode,
        Cbc,
        Cipher,
        Ecb,
        Padding,
        Pkcs7,
    },
    key::Key,
    text::{Ciphertext, Plaintext},
};
