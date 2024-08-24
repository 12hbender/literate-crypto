use crate::{CommitmentScheme, Hash, InvalidReveal};

#[derive(Debug)]
pub struct HashCommitmentScheme<H>(H);

#[derive(Debug)]
pub struct HashCommitment<H: Hash>(H::Digest);

impl<H> HashCommitmentScheme<H> {
    pub fn new(hash: H) -> Self {
        Self(hash)
    }
}

impl<H> CommitmentScheme for HashCommitmentScheme<H>
where
    H: Hash,
    H::Digest: PartialEq,
{
    type Value = Vec<u8>;
    type Commitment = HashCommitment<H>;
    type Reveal = Vec<u8>;

    fn commit(&self, a: &Self::Value) -> Self::Commitment {
        HashCommitment(self.0.hash(a))
    }

    fn reveal(
        &self,
        commitment: &Self::Commitment,
        reveal: &Self::Reveal,
    ) -> Result<(), InvalidReveal> {
        if self.0.hash(reveal) == commitment.0 {
            Ok(())
        } else {
            Err(InvalidReveal)
        }
    }
}
