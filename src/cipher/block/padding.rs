mod pkcs7;

pub use pkcs7::Pkcs7;

// TODO I've realized that my approach of doing things "in-place" only saves a
// single heap allocation. This is not worth it. Instead, pad should split into
// blocks I think, and Encrypt/Decrypt can take references instead
// TODO No, the real mistake is that I'm shoehorning the message schedule into
// the padding function. How about making the encrypt call mutable, and updating
// the schedule there?

/// A scheme to pad messages to be a multiple of some block size.
///
/// [Block ciphers](`crate::BlockCipher`) expect the input data to be a multiple
/// of the block size. However, messages are rarely an exact multiple of the
/// block size, so a padding scheme is needed as a way to extend the length of
/// the data.
///
/// Exposing information about the validity of padding can be dangerous. Imagine
/// a server which accepts encrypted messages from clients. An adversary can
/// send arbitrary ciphertexts to such a server. This attack model is called a
/// chosen ciphertext attack. Now imagine that the server has a design flaw, and
/// it will return a specific type of error if the padding is invalid. This
/// allows the attacker to send arbitrary ciphertexts to the server and learn
/// whether the padding is valid or not. The attacker can use this information
/// to decrypt the ciphertext faster than a simple bruteforce attack, since he
/// can learn whether the last bytes of the plaintext constitute valid padding.
///
/// This is called a padding oracle attack. To defend against this attack,
/// ensure that no information about the validity of the padding is exposed.
pub trait Padding {
    type Err;

    /// Pad the input data to a multiple of `n`. The length of the returned data
    /// must be a multiple of `n`.
    fn pad(&self, data: Vec<u8>, n: usize) -> Vec<u8>;

    /// Remove the padding from the input data. Return an error if the padding
    /// is invalid.
    fn unpad(&self, data: Vec<u8>, n: usize) -> Result<Vec<u8>, Self::Err>;
}
