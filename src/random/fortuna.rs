use {
    crate::{Aes256, BlockEncrypt, Csprng, Entropy, Hash, Sha256},
    std::iter,
};

// TODO I'll need CTR mode first
pub struct Fortuna<Ent, Enc: BlockEncrypt = Aes256, H = Sha256>
where
    Enc::EncryptionBlock: IntoIterator<Item = u8>,
{
    entropy: Ent,
    enc: Enc,
    hash: H,
    key: Option<Enc::EncryptionKey>,
    block: Option<iter::Peekable<<Enc::EncryptionBlock as IntoIterator>::IntoIter>>,
    // TODO Missing byte counter, or maybe just use the counter from CTR mode?
}

impl<Ent, Enc: BlockEncrypt, H> Fortuna<Ent, Enc, H>
where
    Enc::EncryptionBlock: IntoIterator<Item = u8>,
{
    pub fn new(entropy: Ent, enc: Enc, hash: H) -> Self {
        Self {
            entropy,
            enc,
            hash,
            key: None,
            block: None,
        }
    }
}

impl<Ent: Default, Enc: BlockEncrypt + Default, H: Default> Default for Fortuna<Ent, Enc, H>
where
    Enc::EncryptionBlock: IntoIterator<Item = u8>,
{
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

impl<Ent: Entropy, Enc: BlockEncrypt, H: Hash<Output = Enc::EncryptionKey>> Csprng
    for Fortuna<Ent, Enc, H>
where
    Enc::EncryptionBlock: IntoIterator<Item = u8>,
{
    fn next(&mut self) -> u8 {
        // TODO This code can probably be expressed better if I add the constraints that
        // block and key implement Default? The take()s are ugly. Rekeying should happen
        // whenever bytes % 2048 == 0.
        let key = self
            .key
            .take()
            .unwrap_or_else(f /* TODO Get key from entropy */);
        let mut block = self.block.take().unwrap_or_else(
            f, /* TODO Encrypt Default::default() block in counter mode - needs additional
               * constraint */
        );
        let res = match block.next() {
            Some(res) => res,
            None => {
                /* TODO Encrypt Default::default() block in counter mode -
                 * needs additional constraint, set block to that value */
                0
            }
        };
        self.key = Some(key);
        self.block = Some(block);
        res
    }
}

fn f<T>() -> T {
    todo!()
}
