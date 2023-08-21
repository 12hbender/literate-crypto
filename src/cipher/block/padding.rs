mod pkcs7;

pub use pkcs7::Pkcs7;

/// [`crate::cipher::BlockCipher`]s expect the input data to be a multiple of
/// the block size. However, messages are rarely an exact multiple of the block
/// size, so a padding scheme is needed as a way to ensure that message lengths
/// are a multiple of the block size.
///
/// The `N` parameter is typically the block size in bytes.
pub trait Padding<const N: usize> {
    /// Pad the input data to a multiple of the block size.
    fn pad(data: &[u8]) -> Vec<u8>;
    /// Remove the padding from the input data.
    fn unpad(data: &[u8]) -> Option<Vec<u8>>;
}
