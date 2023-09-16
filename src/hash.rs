use crate::Bytes;

mod merkledamgard;
pub mod sha3;

pub use {
    merkledamgard::{CompressionFn, DaviesMeyer, DaviesMeyerStep, MerkleDamgard, MerkleDamgardPad},
    sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512},
};

/// A cryptographic hash function.
///
/// TODO Explain what this actually means
pub trait Hash {
    type Output: Bytes;

    fn hash(&self, input: &[u8]) -> Self::Output;
}
