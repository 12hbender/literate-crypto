use crate::{BlockCipher, BlockMode, Cipher, Ciphertext, Key, Padding, Plaintext};

/// Electronic codebook mode, a simple and insecure mode of operation.
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

impl<Cip: BlockCipher, Pad: Padding> Cipher for Ecb<Cip, Pad> {
    type Err = Pad::Err;
    type Key = Cip::Key;

    fn encrypt(&self, data: Plaintext<Vec<u8>>, key: Key<Self::Key>) -> Ciphertext<Vec<u8>> {
        let mut result = Vec::new();
        let block_size = std::mem::size_of::<Cip::Block>();
        let data = self.pad.pad(data, block_size);
        let data = data.as_ref();
        for block in data.0.chunks(block_size) {
            let block = self.cip.encrypt(Plaintext(block.try_into().unwrap()), key);
            result.extend_from_slice(block.0.as_ref());
        }
        Ciphertext(result)
    }

    fn decrypt(
        &self,
        data: Ciphertext<Vec<u8>>,
        key: Key<Self::Key>,
    ) -> Result<Plaintext<Vec<u8>>, Self::Err> {
        let mut result = Plaintext(Vec::new());
        let block_size = std::mem::size_of::<Cip::Block>();
        for block in data.0.chunks(block_size) {
            let block = self.cip.decrypt(Ciphertext(block.try_into().unwrap()), key);
            result.0.extend_from_slice(block.0.as_ref());
        }
        self.pad.unpad(result, block_size)
    }
}

impl<Cip: BlockCipher, Pad: Padding> BlockMode for Ecb<Cip, Pad> {}
