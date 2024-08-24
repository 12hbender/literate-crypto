pub mod aes;
mod modes;
mod padding;

pub use {
    aes::{Aes128, Aes192, Aes256},
    modes::{BlockMode, BlockSizeTooSmall, Cbc, Ctr, Ecb},
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

/// The encryption half of a [block cipher](BlockCipher).
pub trait BlockEncrypt {
    type EncryptionBlock;
    type EncryptionKey;

    /// Encrypt the plaintext.
    fn encrypt(
        &self,
        data: Self::EncryptionBlock,
        key: Self::EncryptionKey,
    ) -> Self::EncryptionBlock;
}

/// The decryption half of a [block cipher](BlockCipher).
pub trait BlockDecrypt {
    type DecryptionBlock;
    type DecryptionKey;

    /// Decrypt the ciphertext.
    fn decrypt(
        &self,
        data: Self::DecryptionBlock,
        key: Self::DecryptionKey,
    ) -> Self::DecryptionBlock;
}
