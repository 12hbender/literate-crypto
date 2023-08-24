#[cfg(test)]
mod test;

mod cipher;

pub use cipher::{
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
};

/// Unencrypted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plaintext<T>(T);

/// Encrypted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext<T>(T);

/// Encryption/decryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key<T>(T);

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

pub trait Bytes:
    'static
    + for<'a> TryFrom<&'a [u8], Error = std::array::TryFromSliceError>
    + AsRef<[u8]>
    + Clone
    + Copy
    + Sized
{
}

impl<const N: usize> Bytes for [u8; N] {}
