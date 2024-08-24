use docext::docext;

mod block;
mod onetimepad;

pub use {
    block::{
        aes,
        Aes128,
        Aes192,
        Aes256,
        BlockCipher,
        BlockDecrypt,
        BlockEncrypt,
        BlockMode,
        BlockSizeTooSmall,
        Cbc,
        Ctr,
        Ecb,
        Padding,
        Pkcs7,
    },
    onetimepad::OneTimePad,
};

/// A cipher encrypts and decrypts data of arbitrary length using a symmetric
/// key.
///
/// The encrypted data is called ciphertext, and the unencrypted data is called
/// plaintext. Ciphertext should be statistically indistinguishable from random
/// data.
///
/// The following relation must hold between the encrypt and decrypt methods:
/// $$
/// decrypt(encrypt(p, k), k) = p \quad \forall p \in \mathbf{P}, k \in
/// \mathbf{K}
/// $$
///
/// where $\mathbf{P}$ is the set of all possible plaintexts (plaintext space)
/// and $\mathbf{K}$ is the set of all possible keys (key space). Note that the
/// key space usually has a fixed size, while the plaintext space is infinite.
#[docext]
pub trait Cipher:
    CipherEncrypt<EncryptionKey = Self::Key> + CipherDecrypt<DecryptionKey = Self::Key>
{
    type Key;
}

/// The encryption half of a [cipher](Cipher).
pub trait CipherEncrypt {
    type EncryptionErr;
    type EncryptionKey;

    /// Encrypt the plaintext.
    fn encrypt(
        &self,
        data: Vec<u8>,
        key: Self::EncryptionKey,
    ) -> Result<Vec<u8>, Self::EncryptionErr>;
}

/// The decryption half of a [cipher](Cipher).
pub trait CipherDecrypt {
    type DecryptionErr;
    type DecryptionKey;

    /// Decrypt the ciphertext. This operation can fail, for example, if the
    /// ciphertext was not created by this cipher.
    fn decrypt(
        &self,
        data: Vec<u8>,
        key: Self::DecryptionKey,
    ) -> Result<Vec<u8>, Self::DecryptionErr>;
}
