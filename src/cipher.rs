use crate::{Ciphertext, Plaintext};

mod block;

pub use block::{BlockCipher, BlockMode, Cbc, Ecb, Padding, Pkcs7};

// TODO Doc comment
// TODO Note that Cipher here is defined over data of any length, so a
// BlockCipher alone does not fulfill the definition of a Cipher
pub trait Cipher {
    type Err;

    /// Encrypt the plaintext.
    fn encrypt(data: Plaintext<&[u8]>) -> Ciphertext<Vec<u8>>;

    /// Decrypt the ciphertext. This operation can fail, for example, if the
    /// ciphertext was not created by this cipher.
    fn decrypt(data: Ciphertext<&[u8]>) -> Result<Plaintext<Vec<u8>>, Self::Err>;
}
