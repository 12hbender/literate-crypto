/// Unencrypted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plaintext<T>(pub T);

/// Encrypted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext<T>(pub T);

impl<T> Plaintext<T>
where
    T: AsRef<[u8]>,
{
    pub fn as_ref(&self) -> Plaintext<&[u8]> {
        Plaintext(self.0.as_ref())
    }
}

impl<T> Ciphertext<T>
where
    T: AsRef<[u8]>,
{
    pub fn as_ref(&self) -> Ciphertext<&[u8]> {
        Ciphertext(self.0.as_ref())
    }
}
