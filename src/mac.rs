mod hmac;

pub use hmac::Hmac;

/// A message authentication code algorithm is a method for computing a keyed
/// [hash](crate::Hash).
///
/// A MAC algorithm takes a message and a key, and produces a fixed-size _tag_,
/// which is essentially a hash specific to the given message and key. The tag
/// can be used to prove that a message was encrypted with the given pre-shared
/// key. The tag should be checked before decrypting the message to make sure
/// that it is authentic and hasn't been tampered.
///
/// A message authentication code does not prevent man-in-the-middle attacks or
/// replay attacks.
pub trait Mac {
    type Tag;

    fn mac(&mut self, msg: &[u8], key: &[u8]) -> Self::Tag;
}
