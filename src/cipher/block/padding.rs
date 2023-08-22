mod pkcs7;

pub use pkcs7::Pkcs7;

use crate::Plaintext;

// TODO Explain the padding oracle attack

/// [`crate::BlockCipher`]s expect the input data to be a multiple of
/// the block size. However, messages are rarely an exact multiple of the block
/// size, so a padding scheme is needed as a way to ensure that message lengths
/// are a multiple of the block size.
pub trait Padding {
    type Err;

    /// Pad the input data to a multiple of `n`. The length of the returned data
    /// must be a multiple of `n`.
    fn pad(data: Plaintext<&[u8]>, n: usize) -> Plaintext<Vec<u8>>;

    /// Remove the padding from the input data. Return an error if the padding
    /// is invalid.
    fn unpad(data: Plaintext<&[u8]>, n: usize) -> Result<Plaintext<Vec<u8>>, Self::Err>;
}
