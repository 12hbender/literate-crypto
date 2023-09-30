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
    docext::docext,
    std::{convert::Infallible, fmt, mem::size_of},
};

/// Cipher block chaining mode, the most common [mode of
/// operation](crate::BlockMode) for block ciphers.
///
/// Given a block cipher $E_k$ with key $k$ and some plaintext $P = P_1
/// \parallel P_2 \parallel \dots \parallel P_n$, where $P_i$ are the plaintext
/// blocks, CBC mode encrypts $P$ as follows:
///
/// $$
/// C_i = E(P_i \oplus C_{i-1}),\\
/// C = C_1 \parallel C_2 \parallel \dots \parallel C_n
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
pub struct Cbc<Cip, Pad, Block> {
    cip: Cip,
    pad: Pad,
    iv: Block,
}

impl<Cip, Pad, Block> Cbc<Cip, Pad, Block> {
    pub fn new(cip: Cip, pad: Pad, iv: Block) -> Self {
        Self { cip, pad, iv }
    }
}

impl<Cip: BlockCipher, Pad: Padding> Cipher for Cbc<Cip, Pad, Cip::Block>
where
    Cip::Block: for<'a> TryFrom<&'a mut [u8], Error: fmt::Debug>
        + AsRef<[u8]>
        + AsMut<[u8]>
        + IntoIterator<Item = u8>
        + Clone,
    Cip::Key: Clone,
{
    type Key = Cip::Key;
}

impl<Cip: BlockCipher, Pad: Padding> BlockMode for Cbc<Cip, Pad, Cip::Block>
where
    Cip::Block: for<'a> TryFrom<&'a mut [u8], Error: fmt::Debug>
        + AsRef<[u8]>
        + AsMut<[u8]>
        + IntoIterator<Item = u8>
        + Clone,
    Cip::Key: Clone,
{
}

impl<Enc: BlockEncrypt, Pad: Padding> CipherEncrypt for Cbc<Enc, Pad, Enc::EncryptionBlock>
where
    Enc::EncryptionBlock: for<'a> TryFrom<&'a mut [u8], Error: fmt::Debug>
        + AsRef<[u8]>
        + AsMut<[u8]>
        + IntoIterator<Item = u8>
        + Clone,
    Enc::EncryptionKey: Clone,
{
    type EncryptionErr = Infallible;
    type EncryptionKey = Enc::EncryptionKey;

    fn encrypt(
        &self,
        data: Plaintext<Vec<u8>>,
        key: Key<Self::EncryptionKey>,
    ) -> Result<Ciphertext<Vec<u8>>, Self::EncryptionErr> {
        let block_size = size_of::<Enc::EncryptionBlock>();
        let mut prev = Ciphertext(self.iv.clone());
        let mut data = self.pad.pad(data, block_size);
        // Encrypt the blocks in-place, using the input vector.
        for chunk in data.0.chunks_mut(block_size) {
            let mut block: Enc::EncryptionBlock = chunk.try_into().unwrap();
            block
                .as_mut()
                .iter_mut()
                .zip(prev.0.into_iter())
                .for_each(|(a, b)| *a ^= b);
            let ciphertext = self.cip.encrypt(Plaintext(block), key.clone());
            chunk.copy_from_slice(ciphertext.0.as_ref());
            prev = ciphertext;
        }
        Ok(Ciphertext(data.0))
    }
}

impl<Dec: BlockDecrypt, Pad: Padding> CipherDecrypt for Cbc<Dec, Pad, Dec::DecryptionBlock>
where
    Dec::DecryptionBlock: for<'a> TryFrom<&'a mut [u8], Error: fmt::Debug>
        + AsRef<[u8]>
        + AsMut<[u8]>
        + IntoIterator<Item = u8>
        + Clone,
    Dec::DecryptionKey: Clone,
{
    type DecryptionErr = Pad::Err;
    type DecryptionKey = Dec::DecryptionKey;

    fn decrypt(
        &self,
        mut data: Ciphertext<Vec<u8>>,
        key: Key<Self::DecryptionKey>,
    ) -> Result<Plaintext<Vec<u8>>, Self::DecryptionErr> {
        let block_size = size_of::<Dec::DecryptionBlock>();
        let mut prev = Ciphertext(self.iv.clone());
        // Decrypt the blocks in-place, using the input vector.
        for chunk in data.0.chunks_mut(block_size) {
            let block = Ciphertext(chunk.try_into().unwrap());
            let mut plaintext = self.cip.decrypt(block.clone(), key.clone());
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
