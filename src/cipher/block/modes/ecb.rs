use crate::{BlockCipher, BlockMode, Cipher, Ciphertext, Key, Padding, Plaintext};

/// Electronic codebook mode, a simple and insecure [mode of
/// operation](crate::BlockMode).
///
/// ECB is the simplest mode of operation for block ciphers: it simply splits
/// the input data into blocks, and encrypts each block independently.
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

// TODO Do the encryption and decryption in place. This is the best design.
impl<Cip: BlockCipher, Pad: Padding> Cipher for Ecb<Cip, Pad> {
    type Err = Pad::Err;
    type Key = Cip::Key;

    fn encrypt(&self, data: Plaintext<Vec<u8>>, key: Key<Self::Key>) -> Ciphertext<Vec<u8>> {
        // Encrypt the blocks in-place, using the input vector.
        let block_size = std::mem::size_of::<Cip::Block>();
        let mut data = self.pad.pad(data, block_size);
        for chunk in data.0.chunks_mut(block_size) {
            let block = Plaintext(chunk.try_into().unwrap());
            chunk.copy_from_slice(self.cip.encrypt(block, key).0.as_ref());
        }
        Ciphertext(data.0)
    }

    fn decrypt(
        &self,
        mut data: Ciphertext<Vec<u8>>,
        key: Key<Self::Key>,
    ) -> Result<Plaintext<Vec<u8>>, Self::Err> {
        // Decrypt the blocks in-place, using the input vector.
        let block_size = std::mem::size_of::<Cip::Block>();
        for chunk in data.0.chunks_mut(block_size) {
            let block = Ciphertext(chunk.try_into().unwrap());
            chunk.copy_from_slice(self.cip.decrypt(block, key).0.as_ref());
        }
        self.pad.unpad(Plaintext(data.0), block_size)
    }
}

impl<Cip: BlockCipher, Pad: Padding> BlockMode for Ecb<Cip, Pad> {}
