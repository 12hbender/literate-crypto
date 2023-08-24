use crate::{Bytes, Ciphertext, Key, Plaintext};

mod block;

pub use block::{Aes128, Aes192, Aes256, BlockCipher, BlockMode, Cbc, Ecb, Padding, Pkcs7};

// TODO Doc comment
// TODO Note that Cipher here is defined over data of any length, so a
// BlockCipher alone does not fulfill the definition of a Cipher
pub trait Cipher {
    type Err;
    type Key: Bytes;

    /// Encrypt the plaintext.
    fn encrypt(data: Plaintext<&[u8]>, key: Key<Self::Key>) -> Ciphertext<Vec<u8>>;

    /// Decrypt the ciphertext. This operation can fail, for example, if the
    /// ciphertext was not created by this cipher.
    fn decrypt(
        data: Ciphertext<&[u8]>,
        key: Key<Self::Key>,
    ) -> Result<Plaintext<Vec<u8>>, Self::Err>;
}
