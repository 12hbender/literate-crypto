/// Symmetric key used for encryption and decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key<T>(pub T);
