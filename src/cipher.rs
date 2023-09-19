use {
    crate::{Ciphertext, Key, Plaintext},
    docext::docext,
};

mod block;

pub use block::{
    aes,
    Aes128,
    Aes192,
    Aes256,
    BlockCipher,
    BlockDecrypt,
    BlockEncrypt,
    BlockMode,
    Cbc,
    Ecb,
    Padding,
    Pkcs7,
};

/// A cipher encrypts and decrypts data of arbitrary length using a symmetric
/// key.
///
/// The encrypted data is called [ciphertext](crate::Ciphertext), and the
/// unencrypted data is called [plaintext](crate::Plaintext). Ciphertext should
/// be statistically indistinguishable from random data.
///
/// The following relation must hold between the encrypt and decrypt methods:
/// $$
/// decrypt(encrypt(p, k), k) = p \quad \forall p \in \mathbf{P}, k \in
/// \mathbf{K}
/// $$
/// where $\mathbf{P}$ is the set of all possible plaintexts (plaintext space)
/// and $\mathbf{K}$ is the set of all possible keys (key space). Note that the
/// key space usually has a fixed size, while the plaintext space is infinite.
#[docext]
pub trait Cipher {
    type Err;
    type Key;

    /// Encrypt the plaintext.
    fn encrypt(&self, data: Plaintext<Vec<u8>>, key: Key<Self::Key>) -> Ciphertext<Vec<u8>>;

    /// Decrypt the ciphertext. This operation can fail, for example, if the
    /// ciphertext was not created by this cipher.
    fn decrypt(
        &self,
        data: Ciphertext<Vec<u8>>,
        key: Key<Self::Key>,
    ) -> Result<Plaintext<Vec<u8>>, Self::Err>;
}
