use {
    crate::{
        Aes256,
        BlockEncrypt,
        BlockSizeTooSmall,
        CipherEncrypt,
        Csprng,
        Ctr,
        Entropy,
        Hash,
        Sha256,
    },
    std::iter,
};

/// Size of the seed in bytes.
const SEED_SIZE: usize = 32;

/// Number of bytes generated by Fortuna before it gets reseeded.
const RESEED_SIZE: usize = 2048;

/// Fortuna is a [CSPRNG](crate::Csprng) built from a [block
/// cipher](crate::BlockEncrypt) and a [hash function](crate::Hash).
///
/// There are variations on the design of Fortuna, but generally it works as
/// follows: the [source of entropy](crate::Entropy) is polled and the random
/// bytes are hashed to generate a key. The block cipher runs in [CTR
/// mode](crate::Ctr), encrypting a monotonically incrementing counter. The
/// output of the block cipher represents a stream of random numbers. The key is
/// periodically reseeded, in which case the random bytes of entropy are
/// appended to the current key and the resulting sequence of bytes is hashed
/// to generate the new key. This helps avoid attackers from predicting future
/// output, especially in the case that the internal state is compromised.
///
/// One variation is to also update the key more frequently by using the output
/// of the block cipher. This helps prevent attackers from knowing future
/// outputs in the case where only the key has been compromised (but not the
/// internal counter), so the usefulness of this method is somewhat limited.
#[derive(Debug, Clone)]
pub struct Fortuna<Ent, Enc = Aes256, H = Sha256> {
    entropy: Ent,
    ctr: Ctr<Enc>,
    hash: H,
}

impl<Ent, Enc, H, const BLOCK_SIZE: usize> Fortuna<Ent, Enc, H>
where
    Enc: BlockEncrypt<EncryptionBlock = [u8; BLOCK_SIZE]>,
{
    pub fn new(entropy: Ent, enc: Enc, hash: H) -> Result<Self, BlockSizeTooSmall> {
        Ok(Self {
            entropy,
            ctr: Ctr::new(enc, 0)?,
            hash,
        })
    }
}

impl<Ent, Enc, H> Csprng for Fortuna<Ent, Enc, H>
where
    Ent: Entropy,
    Enc: BlockEncrypt,
    H: Hash<Digest = Enc::EncryptionKey>,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + AsRef<[u8]> + Clone + Default,
{
}

impl<Ent, Enc, H> IntoIterator for Fortuna<Ent, Enc, H>
where
    Ent: Entropy,
    Enc: BlockEncrypt,
    H: Hash<Digest = Enc::EncryptionKey>,
    Enc::EncryptionBlock: IntoIterator<Item = u8> + AsMut<[u8]> + Default,
    Enc::EncryptionKey: 'static + AsRef<[u8]> + Clone + Default,
{
    type Item = u8;

    type IntoIter = impl Iterator<Item = u8>;

    fn into_iter(mut self) -> Self::IntoIter {
        let mut key = Enc::EncryptionKey::default();
        iter::repeat_with(move || {
            // Fetch random bytes from the source of entropy to use for reseeding.
            let mut seed = [0; SEED_SIZE];
            self.entropy.get(&mut seed);
            // As part of the reseed, the cipher key is updated by hashing the old key and
            // the entropy bytes.
            let mut key_and_seed = Vec::new();
            key_and_seed.extend(key.as_ref());
            key_and_seed.extend(seed);
            key = self.hash.hash(&key_and_seed);

            // Generate RESEED_SIZE pseudorandom bytes via the block cipher.
            self.ctr.encrypt(vec![0; RESEED_SIZE], key.clone()).unwrap()
        })
        .flatten()
    }
}
