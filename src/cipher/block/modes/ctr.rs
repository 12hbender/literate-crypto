use {
    crate::{
        BlockEncrypt,
        BlockMode,
        Cipher,
        CipherDecrypt,
        CipherEncrypt,
        Ciphertext,
        Key,
        OneTimePad,
        Plaintext,
    },
    std::{fmt, iter, mem},
};

pub struct Ctr<Enc: BlockEncrypt> {
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
    pub fn new(enc: Enc, nonce: u64) -> Self {
        Self { enc, nonce }
    }
}

impl<Enc> CipherEncrypt for Ctr<Enc>
where
    Enc: BlockEncrypt,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + Clone,
{
    type EncryptionErr = BlockSizeTooSmall;
    type EncryptionKey = Enc::EncryptionKey;

    fn encrypt(
        &self,
        data: Plaintext<Vec<u8>>,
        key: Key<Self::EncryptionKey>,
    ) -> Result<Ciphertext<Vec<u8>>, Self::EncryptionErr> {
        Ok(OneTimePad::default()
            .encrypt(data, keystream(&self.enc, key, self.nonce)?)
            .expect("infinite keystream"))
    }
}

impl<Enc> CipherDecrypt for Ctr<Enc>
where
    Enc: BlockEncrypt,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + Clone,
{
    type DecryptionErr = BlockSizeTooSmall;
    type DecryptionKey = Enc::EncryptionKey;

    fn decrypt(
        &self,
        data: Ciphertext<Vec<u8>>,
        key: Key<Self::DecryptionKey>,
    ) -> Result<Plaintext<Vec<u8>>, Self::DecryptionErr> {
        Ok(OneTimePad::default()
            .decrypt(data, keystream(&self.enc, key, self.nonce)?)
            .expect("infinite keystream"))
    }
}

fn keystream<Enc>(
    enc: &Enc,
    key: Key<Enc::EncryptionKey>,
    nonce: u64,
) -> Result<Key<impl Iterator<Item = u8> + '_>, BlockSizeTooSmall>
where
    Enc: BlockEncrypt,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + Clone,
{
    // Check that the counter bytes can be packed into the plaintext block.
    let block_size = mem::size_of::<Enc::EncryptionBlock>();
    if block_size < mem::size_of_val(&nonce) {
        return Err(BlockSizeTooSmall);
    }

    let keystream = iter::successors(Some(nonce), |ctr| Some(ctr.wrapping_add(1)))
        .map(move |ctr| {
            // Copy the counter bytes into a block and encrypt it.
            let mut ctr_block = Enc::EncryptionBlock::default();
            ctr_block
                .as_mut()
                .iter_mut()
                .zip(dbg!(ctr).to_le_bytes().into_iter())
                .for_each(|(b, n)| *b = n);
            enc.encrypt(Plaintext(ctr_block), key.clone()).0.into_iter()
        })
        .flatten();
    Ok(Key(keystream))
}

#[derive(Debug)]
pub struct BlockSizeTooSmall;

impl fmt::Display for BlockSizeTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("block size too small to fit counter")
    }
}
