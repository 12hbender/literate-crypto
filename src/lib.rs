#[cfg(test)]
mod test;

#[cfg(doc)]
pub mod doc;

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

impl<T> Ciphertext<T>
where
    T: AsRef<[u8]>,
{
    pub fn as_ref(&self) -> Ciphertext<&[u8]> {
        Ciphertext(self.0.as_ref())
    }
}

/// A fixed-size byte array.
pub trait Bytes:
    'static
    + for<'a> TryFrom<&'a [u8], Error = std::array::TryFromSliceError>
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Clone
    + Copy
    + Sized
    + IntoIterator<Item = u8>
    + std::fmt::Debug
{
}

impl<const N: usize> Bytes for [u8; N] {}
