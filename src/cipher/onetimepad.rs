use {
    crate::{BlockMode, Cipher, CipherDecrypt, CipherEncrypt, Ciphertext, Key, Plaintext},
    std::{fmt, marker::PhantomData},
};

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
        data: Plaintext<Vec<u8>>,
        key: Key<Self::EncryptionKey>,
    ) -> Result<Ciphertext<Vec<u8>>, Self::EncryptionErr> {
        cipher(data.0, key.0).map(Ciphertext)
    }
}

impl<K: Iterator<Item = u8>> CipherDecrypt for OneTimePad<K> {
    type DecryptionErr = KeyTooShort;
    type DecryptionKey = K;

    fn decrypt(
        &self,
        data: Ciphertext<Vec<u8>>,
        key: Key<Self::DecryptionKey>,
    ) -> Result<Plaintext<Vec<u8>>, Self::DecryptionErr> {
        // Because XOR is symmetric, the decryption process is equivalent to
        // encryption.
        cipher(data.0, key.0).map(Plaintext)
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
