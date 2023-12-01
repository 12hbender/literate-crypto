use {
    crate::{BlockMode, Cipher, CipherDecrypt, CipherEncrypt},
    docext::docext,
    std::{fmt, marker::PhantomData},
};

/// The one-time pad is a simple cipher which XORs the input plaintext with the
/// key.
///
/// This means that the key must be at least as long as the plaintext. The
/// key determines which bits of the plaintext will be flipped: if a bit in the
/// key is 1, then the corresponding bit of plaintext will be flipped when
/// generating the plaintext. For this reason, the key should be uniformly
/// random and free of any patterns that can be analyzed.
///
/// Because the XOR operation cancels itself ($X \oplus Y \oplus Y = X$ for any
/// $X, Y$), the decryption process is exactly the same as encryption.
///
/// If the key is kept secret and uniformly random, the one-time pad can be
/// mathematically proven to be a perfect cipher, meaning that the ciphertext
/// reveals absolutely nothing about the plaintext.
#[docext]
#[derive(Debug)]
pub struct OneTimePad<K>(PhantomData<K>);

impl<K> Default for OneTimePad<K> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<K: Iterator<Item = u8>> Cipher for OneTimePad<K> {
    type Key = K;
}

impl<K: Iterator<Item = u8>> BlockMode for OneTimePad<K> {}

impl<K: Iterator<Item = u8>> CipherEncrypt for OneTimePad<K> {
    type EncryptionErr = KeyTooShort;
    type EncryptionKey = K;

    fn encrypt(
        &self,
        data: Vec<u8>,
        key: Self::EncryptionKey,
    ) -> Result<Vec<u8>, Self::EncryptionErr> {
        cipher(data, key)
    }
}

impl<K: Iterator<Item = u8>> CipherDecrypt for OneTimePad<K> {
    type DecryptionErr = KeyTooShort;
    type DecryptionKey = K;

    fn decrypt(
        &self,
        data: Vec<u8>,
        key: Self::DecryptionKey,
    ) -> Result<Vec<u8>, Self::DecryptionErr> {
        // Because XOR is symmetric, the decryption process is equivalent to
        // encryption.
        cipher(data, key)
    }
}

fn cipher(mut data: Vec<u8>, mut key: impl Iterator<Item = u8>) -> Result<Vec<u8>, KeyTooShort> {
    for x in data.iter_mut() {
        *x ^= key.next().ok_or(KeyTooShort)?;
    }
    Ok(data)
}

#[derive(Debug)]
pub struct KeyTooShort;

impl fmt::Display for KeyTooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("key is too short for one-time pad input")
    }
}
