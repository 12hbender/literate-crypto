mod hmac;

pub use hmac::Hmac;

/// A message authentication code algorithm is a method for computing a keyed
/// [hash](crate::Hash).
///
/// A MAC algorithm takes a message and a key, and produces a fixed-size _tag_,
/// which is essentially a hash specific to the given message and key. The tag
/// can be used to prove, for example, that a (possibly encrypted) message was
/// not modified in transit. It can also prove that the message corresponding to
/// the given tag was signed with a specific pre-shared key.
///
/// A message authentication code does not prevent man-in-the-middle attacks or
/// replay attacks.
pub trait Mac {
    type Tag;

    fn mac(&mut self, msg: &[u8], key: &[u8]) -> Self::Tag;
}
