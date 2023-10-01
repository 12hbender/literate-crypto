use {
    crate::{
        BlockCipher,
        BlockDecrypt,
        BlockEncrypt,
        BlockMode,
        Cipher,
        CipherDecrypt,
        CipherEncrypt,
        Ciphertext,
        Key,
        Padding,
        Plaintext,
    },
    std::{convert::Infallible, fmt},
};

/// Electronic codebook mode, a simple and insecure [mode of
/// operation](crate::BlockMode).
///
/// ECB is the simplest mode of operation for block ciphers: it simply splits
/// the input data into blocks, and encrypts each block independently.
///
/// # Security
///
/// ECB is insecure because the same block in the plaintext will always encrypt
/// to the same block in the ciphertext. Imagine a server accepting encrypted
/// YES/NO messages from a client. If an attacker can see the encrypted
/// messages, he will know when the client is sending two identical messages. If
/// the attacker can perform some context-dependent analysis of the messages, he
/// might even be able to guess which messages are being sent (YES or NO).
#[derive(Debug)]
pub struct Ecb<Cip, Pad> {
    cip: Cip,
    pad: Pad,
}

impl<Cip: BlockCipher, Pad: Padding> Ecb<Cip, Pad> {
    pub fn new(cip: Cip, pad: Pad) -> Self {
        Self { cip, pad }
    }
}

impl<Cip: BlockCipher, Pad: Padding> Cipher for Ecb<Cip, Pad>
where
    Cip::Block: for<'a> TryFrom<&'a mut [u8], Error: fmt::Debug> + AsRef<[u8]>,
    Cip::Key: Clone,
{
    type Key = Cip::Key;
}

impl<Cip: BlockCipher, Pad: Padding> BlockMode for Ecb<Cip, Pad>
where
    Cip::Block: for<'a> TryFrom<&'a mut [u8], Error: fmt::Debug> + AsRef<[u8]>,
    Cip::Key: Clone,
{
}

impl<Enc: BlockEncrypt, Pad: Padding> CipherEncrypt for Ecb<Enc, Pad>
where
    Enc::EncryptionBlock: for<'a> TryFrom<&'a mut [u8], Error: fmt::Debug> + AsRef<[u8]>,
    Enc::EncryptionKey: Clone,
{
    type EncryptionErr = Infallible;
    type EncryptionKey = Enc::EncryptionKey;

    fn encrypt(
        &self,
        data: Plaintext<Vec<u8>>,
        key: Key<Self::EncryptionKey>,
    ) -> Result<Ciphertext<Vec<u8>>, Self::EncryptionErr> {
        // Encrypt the blocks in-place, using the input vector.
        let block_size = std::mem::size_of::<Enc::EncryptionBlock>();
        let mut data = self.pad.pad(data, block_size);
        for chunk in data.0.chunks_mut(block_size) {
            let block = Plaintext(chunk.try_into().unwrap());
            chunk.copy_from_slice(self.cip.encrypt(block, key.clone()).0.as_ref());
        }
        Ok(Ciphertext(data.0))
    }
}

impl<Dec: BlockDecrypt, Pad: Padding> CipherDecrypt for Ecb<Dec, Pad>
where
    Dec::DecryptionBlock: for<'a> TryFrom<&'a mut [u8], Error: fmt::Debug> + AsRef<[u8]>,
    Dec::DecryptionKey: Clone,
{
    type DecryptionErr = Pad::Err;
    type DecryptionKey = Dec::DecryptionKey;

    fn decrypt(
        &self,
        mut data: Ciphertext<Vec<u8>>,
        key: Key<Self::DecryptionKey>,
    ) -> Result<Plaintext<Vec<u8>>, Self::DecryptionErr> {
        // Decrypt the blocks in-place, using the input vector.
        let block_size = std::mem::size_of::<Dec::DecryptionBlock>();
        for chunk in data.0.chunks_mut(block_size) {
            let block = Ciphertext(chunk.try_into().unwrap());
            chunk.copy_from_slice(self.cip.decrypt(block, key.clone()).0.as_ref());
        }
        self.pad.unpad(Plaintext(data.0), block_size)
    }
}
