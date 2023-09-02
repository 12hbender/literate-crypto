use crate::Bytes;

/// Cryptographically secure pseudorandom number generator.
///
/// TODO Explain what this means and how it's different from a regular PRNG.
pub trait Csprng {
    // TODO Explain why this (mostly performance)
    type Output: Bytes;

    fn next(&mut self) -> Self::Output;
}

// TODO The main Csprng implementation would be Fortuna. Unlike the spec, I
// should make it use a stream cipher instead of a block cipher. Then it can be
// implemented with both ChaCha20 and CTR AES.
// TODO Fortuna needs SHA256, so I should implement hashing first.

/// Iterator over a PRNG.
pub struct CsprngIter<T>(T);

impl<Rng> Iterator for CsprngIter<Rng>
where
    Rng: Csprng,
{
    type Item = Rng::Output;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0.next())
    }
}
