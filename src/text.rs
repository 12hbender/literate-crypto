/// Unencrypted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plaintext<T>(pub T);

/// Encrypted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext<T>(pub T);
