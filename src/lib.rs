mod cipher;

pub use cipher::{BlockCipher, Cbc, Cipher, Ecb, Padding, Pkcs7};

#[derive(Debug, Clone)]
pub struct Plaintext<T>(T);

#[derive(Debug, Clone)]
pub struct Ciphertext<T>(T);

#[cfg(test)]
mod test;
