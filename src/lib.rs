#[cfg(test)]
mod test;

mod cipher;

pub use cipher::{BlockCipher, BlockMode, Cbc, Cipher, Ecb, Padding, Pkcs7};

/// Unencrypted data.
#[derive(Debug, Clone)]
pub struct Plaintext<T>(T);

/// Encrypted data.
#[derive(Debug, Clone)]
pub struct Ciphertext<T>(T);

impl<T> Plaintext<T>
where
    T: AsRef<[u8]>,
{
    pub fn as_ref(&self) -> Plaintext<&[u8]> {
        Plaintext(self.0.as_ref())
    }
}

impl Plaintext<&[u8]> {
    pub fn to_vec(&self) -> Plaintext<Vec<u8>> {
        Plaintext(self.0.to_vec())
    }
}
