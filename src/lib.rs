mod cipher;

pub use cipher::{BlockCipher, Cbc, Cipher, Ecb, Padding, Pkcs7};

#[derive(Debug, Clone)]
pub struct Plaintext<T>(T);

#[derive(Debug, Clone)]
pub struct Ciphertext<T>(T);

impl Plaintext<Vec<u8>> {
    pub fn as_ref(&self) -> Plaintext<&[u8]> {
        Plaintext(self.0.as_ref())
    }
}

impl Plaintext<&[u8]> {
    pub fn to_vec(&self) -> Plaintext<Vec<u8>> {
        Plaintext(self.0.to_vec())
    }
}

#[cfg(test)]
mod test;
