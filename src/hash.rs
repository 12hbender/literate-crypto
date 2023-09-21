use docext::docext;

mod merkledamgard;
pub mod sha2;
pub mod sha3;

pub use {
    merkledamgard::{CompressionFn, DaviesMeyer, DaviesMeyerStep, MerkleDamgard, MerkleDamgardPad},
    sha2::{Sha1, Sha224, Sha256},
    sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512},
};

/// A cryptographic hash function maps a [preimage](Preimage) of arbitrary
/// length into a fixed-size [hash digest](Digest).
///
/// To be cryptographically secure, this function must be one-way and collision
/// resistant. One-way means that given a hash digest, there is no better way to
/// get the preimage than by brute force.
///
/// A _hash collision_ occurs when two preimages $M_1$ and $M_2$, $M_1
/// \neq M_2$, generate the same hash digest, $Hash(M_1) = Hash(M_2)$. The hash
/// function is _collision resistant_ if the best way to find such $(M_1, M_2)$
/// is by brute force.
#[docext]
pub trait Hash {
    type Output;

    fn hash(&self, preimage: Preimage<&[u8]>) -> Digest<Self::Output>;
}

/// The preimage is an input to a [hash function](Hash).
#[derive(Debug, Clone, Copy)]
pub struct Preimage<T>(pub T);

/// The hash digest is the fixed-size output of a [hash function](Hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digest<T>(pub T);
