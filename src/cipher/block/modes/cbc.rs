use {
    crate::{BlockCipher, BlockMode, Bytes, Cipher, Ciphertext, Key, Padding, Plaintext},
    docext::docext,
    std::mem::size_of,
};

/// Cipher block chaining mode, the most common [mode of
/// operation](crate::BlockMode) for block ciphers.
///
/// Given a block cipher $E_k$ with key $k$ and some plaintext $P = P_1 || P_2
/// || \dots || P_n$, where $P_i$ are the plaintext blocks, CBC mode encrypts $P$ as
/// follows:
///
/// $$
/// C_i = E(P_i \oplus C_{i-1}),\newline
/// C = C_1 || C_2 || \dots || C_n
/// $$
///
/// $C_0$ is a special value called the _initialization vector (IV)_.
///
/// In other words, CBC XORs the plaintext of each block with the ciphertext of
/// the previous block before encrypting it. This means that each block depends
/// on all blocks before it, and changing a single bit in the plaintext will
/// cause every next block of ciphertext to change in an unpredictable way.
///
/// The first block of plaintext is XORed with an initialization vector (IV),
/// referred to as $C_0$ above. The IV is a block of random data which does not
/// need to be secret, but it must be unique for each message encrypted with the
/// same key. The IV is necessary in order to decrypt the ciphertext, and must
/// be sent to the recipient along with the ciphertext.
///
/// Because the same plaintext with a different IV will encrypt to a different
/// ciphertext, CBC solves the issues of [ECB mode](crate::Ecb).
#[docext]
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
        let mut data = self.pad.pad(data, block_size);
        // Encrypt the blocks in-place, using the input vector.
        for chunk in data.0.chunks_mut(block_size) {
            let mut block: Cip::Block = chunk.try_into().unwrap();
            block
                .iter_mut()
                .zip(prev.0.into_iter())
                .for_each(|(a, b)| *a ^= b);
            let ciphertext = self.cip.encrypt(Plaintext(block), key);
            chunk.copy_from_slice(ciphertext.0.as_ref());
            prev = ciphertext;
        }
        Ciphertext(data.0)
    }

    fn decrypt(
        &self,
        mut data: Ciphertext<Vec<u8>>,
        key: Key<Self::Key>,
    ) -> Result<Plaintext<Vec<u8>>, Self::Err> {
        let block_size = size_of::<Cip::Block>();
        let mut prev = Ciphertext(self.iv);
        // Decrypt the blocks in-place, using the input vector.
        for chunk in data.0.chunks_mut(block_size) {
            let block = Ciphertext(chunk.try_into().unwrap());
            let mut plaintext = self.cip.decrypt(block, key);
            plaintext
                .0
                .as_mut()
                .iter_mut()
                .zip(prev.0.into_iter())
                .for_each(|(a, b): (&mut u8, _)| *a ^= b);
            chunk.copy_from_slice(plaintext.0.as_ref());
            prev = block;
        }
        self.pad.unpad(Plaintext(data.0), block_size)
    }
}

impl<Cip: BlockCipher, Pad: Padding> BlockMode for Cbc<Cip, Pad> {}
