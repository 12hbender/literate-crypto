use {
    crate::{BlockCipher, Cipher, Ciphertext, Key, Padding, Plaintext},
    std::mem::size_of,
};

/// Cipher block chaining mode, the most common mode of operation for block
/// ciphers.
///
/// CBC XORs the plaintext of each block with the ciphertext of the previous
/// block before encrypting it. This means that each block depends on all blocks
/// before it, and changing a single bit in the plaintext will cause the entire
/// ciphertext to change.
///
/// The first block of plaintext is XORed with an initialization vector (IV),
/// which is a block of random data. The IV does not need to be secret, but it
/// must be unique for each message encrypted with the same key.
///
/// Because the same plaintext with a different IV will encrypt to a different
/// ciphertext, CBC solves the issues of [ECB mode](crate::Ecb).
pub struct Cbc<Cip: BlockCipher, Pad> {
    cip: Cip,
    pad: Pad,
    iv: Cip::Block,
}

impl<Cip: BlockCipher, Pad: Padding> Cbc<Cip, Pad> {
    pub fn new(cip: Cip, pad: Pad, iv: Cip::Block) -> Self {
        Self { cip, pad, iv }
    }
}

impl<Cip: BlockCipher, Pad: Padding> Cipher for Cbc<Cip, Pad> {
    type Err = Pad::Err;
    type Key = Cip::Key;

    fn encrypt(&self, data: Plaintext<Vec<u8>>, key: Key<Self::Key>) -> Ciphertext<Vec<u8>> {
        let block_size = size_of::<Cip::Block>();
        let mut prev = Ciphertext(self.iv);
        let mut result = Vec::new();
        let mut data = self.pad.pad(data, block_size);
        for block in data.0.chunks_mut(block_size) {
            block
                .iter_mut()
                .zip(prev.0.into_iter())
                .for_each(|(a, b)| *a ^= b);
            let block = &*block;
            let ciphertext = self.cip.encrypt(Plaintext(block.try_into().unwrap()), key);
            result.extend_from_slice(ciphertext.0.as_ref());
            prev = ciphertext;
        }
        Ciphertext(result)
    }

    fn decrypt(
        &self,
        data: Ciphertext<Vec<u8>>,
        key: Key<Self::Key>,
    ) -> Result<Plaintext<Vec<u8>>, Self::Err> {
        let block_size = size_of::<Cip::Block>();
        let mut prev = Ciphertext(self.iv);
        let mut result = Vec::new();
        for block in data.0.chunks(block_size) {
            let block = Ciphertext(Cip::Block::try_from(block).unwrap());
            let mut plaintext = self.cip.decrypt(block, key);
            plaintext
                .0
                .as_mut()
                .iter_mut()
                .zip(prev.0.into_iter())
                .for_each(|(a, b): (&mut u8, _)| *a ^= b);
            result.extend_from_slice(plaintext.0.as_ref());
            prev = block;
        }
        self.pad.unpad(Plaintext(result), block_size)
    }
}
