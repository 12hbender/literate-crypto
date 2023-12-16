use {
    crate::{BlockEncrypt, BlockMode, Cipher, CipherDecrypt, CipherEncrypt, OneTimePad},
    docext::docext,
    std::{convert::Infallible, fmt, iter, mem},
};

/// Block counter [mode](crate::BlockMode) is a block chaining mode which turns
/// a block cipher into a stream cipher, and hence does not require a [padding
/// scheme](crate::Padding).
///
/// The algorithm keeps a monotonically incrementing counter. The
/// plaintext is split into blocks. Each block of plaintext is encrypted by
/// converting the counter into bytes, converting the bytes into a block (by
/// appending as many zero bytes as needed to reach the block size),
/// encrypting that block with the underlying block cipher, and XORing the
/// ciphertext block with the appropriate block of plaintext. Afterwards, the
/// block counter is incremented, and the process is repeated until there are no
/// blocks left.
///
/// If the last block of plaintext is shorter than the block size, the last
/// block of ciphertext is simply truncated to the length of the remaining
/// plaintext.
///
/// The block counter is first set to some initial value, called the nonce. Like
/// the [IV](crate::Cbc#iv) for [CBC mode](crate::Cbc), the nonce does not need
/// to be secret, but it needs to be unique.
///
/// Because the XOR operation cancels itself ($X \oplus Y \oplus Y = X$ for any
/// $X, Y$), the decryption is exactly the same as encryption. Notably, it only
/// relies on the [encryption function](crate::BlockEncrypt) of the underlying
/// block cipher. The [decryption function](crate::BlockDecrypt) is never used.
///
/// The operation of counter mode essentially represents a [one-time
/// pad](crate::OneTimePad), where the keystream is generated using the
/// underlying block cipher and the block counter.
#[docext]
#[derive(Debug, Clone)]
pub struct Ctr<Enc> {
    enc: Enc,
    nonce: u64,
}

impl<Enc> Cipher for Ctr<Enc>
where
    Enc: BlockEncrypt,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + Clone,
{
    type Key = Enc::EncryptionKey;
}

impl<Enc> BlockMode for Ctr<Enc>
where
    Enc: BlockEncrypt,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + Clone,
{
}

impl<Enc: BlockEncrypt> Ctr<Enc> {
    pub fn new(enc: Enc, nonce: u64) -> Result<Self, BlockSizeTooSmall> {
        // Check that the counter bytes can be packed into the plaintext block.
        // TODO Remove this with a proper BlockSize trait
        let block_size = mem::size_of::<Enc::EncryptionBlock>();
        if block_size < mem::size_of_val(&nonce) {
            Err(BlockSizeTooSmall)
        } else {
            Ok(Self { enc, nonce })
        }
    }
}

impl<Enc> CipherEncrypt for Ctr<Enc>
where
    Enc: BlockEncrypt,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + Clone,
{
    type EncryptionErr = Infallible;
    type EncryptionKey = Enc::EncryptionKey;

    fn encrypt(
        &self,
        data: Vec<u8>,
        key: Self::EncryptionKey,
    ) -> Result<Vec<u8>, Self::EncryptionErr> {
        Ok(OneTimePad::default()
            .encrypt(data, keystream(&self.enc, key, self.nonce))
            .expect("infinite keystream"))
    }
}

impl<Enc> CipherDecrypt for Ctr<Enc>
where
    Enc: BlockEncrypt,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + Clone,
{
    type DecryptionErr = Infallible;
    type DecryptionKey = Enc::EncryptionKey;

    fn decrypt(
        &self,
        data: Vec<u8>,
        key: Self::DecryptionKey,
    ) -> Result<Vec<u8>, Self::DecryptionErr> {
        Ok(OneTimePad::default()
            .decrypt(data, keystream(&self.enc, key, self.nonce))
            .expect("infinite keystream"))
    }
}

fn keystream<Enc>(enc: &Enc, key: Enc::EncryptionKey, nonce: u64) -> impl Iterator<Item = u8> + '_
where
    Enc: BlockEncrypt,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + Clone,
{
    iter::successors(Some(nonce), |ctr| Some(ctr.wrapping_add(1))).flat_map(move |ctr| {
        // Copy the counter bytes into a block and encrypt it.
        let mut ctr_block = Enc::EncryptionBlock::default();
        ctr_block
            .as_mut()
            .iter_mut()
            .zip(ctr.to_le_bytes())
            .for_each(|(b, n)| *b = n);
        enc.encrypt(ctr_block, key.clone()).into_iter()
    })
}

#[derive(Debug)]
pub struct BlockSizeTooSmall;

impl fmt::Display for BlockSizeTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("block size too small to fit counter")
    }
}
