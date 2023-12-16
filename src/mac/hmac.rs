use {
    crate::{Hash, Mac},
    docext::docext,
};

const OPAD: u8 = 0x5C;
const IPAD: u8 = 0x36;

/// A hash-based message authentication code is a method for creating a
/// [MAC](crate::Mac) from a [hash function](crate::Hash).
///
/// It works by first padding the key with zeros if it is smaller than the
/// [internal block size of the hash function](crate::Hash::Block). If the key
/// is larger than the internal block size, it is first hashed and then either
/// truncated or padded with zeros to exactly the block size. The resulting
/// value is $K'$.
///
/// The HMAC tag is computed as
///
/// $$
/// H\Big((K' \oplus opad) \parallel H\big((K' \oplus ipad) \parallel m
/// \big) \Big)
/// $$
///
/// where $m$ is the message, $H$ is the hash function, $opad$ is a sequence of
/// $\mathrm{5C}_{16}$ bytes equal in size to the internal block of the hash
/// function, and $ipad$ is a sequence of $\mathrm{36}_{16}$ bytes.
///
/// This method was chosen as the standard because it's theoretically more
/// secure than simply prepending or appending the key to the message, and is
/// resistant to [length-extension
/// attacks](crate::MerkleDamgard#length-extension-attacks) even if the
/// underlying hash function isn't.
#[docext]
pub struct Hmac<H>(H);

impl<H> Hmac<H> {
    pub fn new(h: H) -> Self {
        Self(h)
    }
}

impl<H, const BLOCK_SIZE: usize, const DIGEST_SIZE: usize> Mac for Hmac<H>
where
    H: Hash<Block = [u8; BLOCK_SIZE], Digest = [u8; DIGEST_SIZE]>,
{
    type Tag = H::Digest;

    fn mac(&mut self, msg: &[u8], key: &[u8]) -> Self::Tag {
        // Derive K' from the key.
        let mut k = [0; BLOCK_SIZE];
        if key.len() <= BLOCK_SIZE {
            k[..key.len()].copy_from_slice(key);
        } else {
            k[..DIGEST_SIZE].copy_from_slice(&self.0.hash(key));
        };

        // Compute the inner hash.
        let mut inner_preimage = Vec::new();
        // Apply the inner padding to k.
        inner_preimage.extend(k.iter().map(|n| n ^ IPAD));
        inner_preimage.extend(msg);
        let inner_hash = self.0.hash(&inner_preimage);

        // Compute the outer hash, which is the result of the MAC function.
        let mut outer_preimage = Vec::new();
        // Apply the outer padding to k.
        outer_preimage.extend(k.iter().map(|n| n ^ OPAD));
        outer_preimage.extend(inner_hash);
        self.0.hash(&outer_preimage)
    }
}
