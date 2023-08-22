use crate::{Ciphertext, Plaintext};

mod block;

pub use block::{BlockCipher, Cbc, Ecb, Padding, Pkcs7};

// TODO Doc comment
pub trait Cipher {
    type Err;

    /// Encrypt the plaintext.
    fn encrypt(&mut self, p: Plaintext<&[u8]>) -> Ciphertext<Vec<u8>>;

    /// Decrypt the ciphertext. This operation can fail, for example, if the
    /// ciphertext was not created by this cipher.
    fn decrypt(&mut self, c: Ciphertext<&[u8]>) -> Result<Plaintext<Vec<u8>>, Self::Err>;
}
