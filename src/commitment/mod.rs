use std::fmt;

mod hash;

pub use hash::{HashCommitment, HashCommitmentScheme};

pub trait CommitmentScheme {
    type Value;
    type Commitment;
    type Reveal;

    fn commit(&self, a: &Self::Value) -> Self::Commitment;
    fn reveal(
        &self,
        commitment: &Self::Commitment,
        reveal: &Self::Reveal,
    ) -> Result<(), InvalidReveal>;
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidReveal;

impl fmt::Display for InvalidReveal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid reveal")
    }
}

impl std::error::Error for InvalidReveal {}
