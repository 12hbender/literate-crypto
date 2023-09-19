use crate::{Ciphertext, Key, Plaintext};

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
pub trait BlockCipher:
    BlockEncrypt<EncryptionBlock = Self::Block, EncryptionKey = Self::Key>
    + BlockDecrypt<DecryptionBlock = Self::Block, DecryptionKey = Self::Key>
{
    type Block;
    type Key;
}

pub trait BlockEncrypt {
    type EncryptionBlock;
    type EncryptionKey;

    /// Encrypt the plaintext.
    fn encrypt(
        &self,
        data: Plaintext<Self::EncryptionBlock>,
        key: Key<Self::EncryptionKey>,
    ) -> Ciphertext<Self::EncryptionBlock>;
}

pub trait BlockDecrypt {
    type DecryptionBlock;
    type DecryptionKey;

    /// Decrypt the ciphertext.
    fn decrypt(
        &self,
        data: Ciphertext<Self::DecryptionBlock>,
        key: Key<Self::DecryptionKey>,
    ) -> Plaintext<Self::DecryptionBlock>;
}
