use crate::{Bytes, Ciphertext, Key, Plaintext};

pub mod aes;
mod modes;
mod padding;

pub use {
    aes::{Aes128, Aes192, Aes256},
    modes::{BlockMode, Cbc, Ecb},
    padding::{Padding, Pkcs7},
};

/// A block cipher encrypts and decrypts data in blocks of fixed size.
///
/// Note that a block cipher alone does not fulfill the definition of a
/// [cipher](crate::Cipher), because it can't handle inputs of arbitrary length.
/// To be a cipher, a block cipher must be used with a
/// [block mode](crate::BlockMode).
///
/// The encrypt and decrypt methods must fulfill the same contract as those in
/// the [`crate::Cipher`] trait.
pub trait BlockCipher {
    type Block: Bytes;
    type Key: Bytes;

    /// Encrypt the plaintext.
    fn encrypt(&self, data: Plaintext<Self::Block>, key: Key<Self::Key>)
        -> Ciphertext<Self::Block>;

    /// Decrypt the ciphertext.
    fn decrypt(&self, data: Ciphertext<Self::Block>, key: Key<Self::Key>)
        -> Plaintext<Self::Block>;
}
