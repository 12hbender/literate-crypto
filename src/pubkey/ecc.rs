//! Elliptic curve cryptography.

use {crate::InvalidPrivateKey, std::marker::PhantomData};

mod curve;
mod ecdsa;
mod num;
mod schnorr;
mod secp256k1;

pub use {
    curve::{Coordinates, Curve, InvalidPoint, Point},
    ecdsa::{Ecdsa, EcdsaSignature},
    num::Num,
    schnorr::{Schnorr, SchnorrSignature},
    secp256k1::Secp256k1,
};

#[derive(Debug)]
pub struct PrivateKey<C>(num::Num, PhantomData<C>);

impl<C> Clone for PrivateKey<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for PrivateKey<C> {}

impl<C: Curve> PrivateKey<C> {
    pub fn new(n: num::Num) -> Result<Self, InvalidPrivateKey> {
        // Verify that the private key is reduced modulo N.
        if n < C::N {
            Ok(Self(n, Default::default()))
        } else {
            Err(InvalidPrivateKey)
        }
    }
}

#[derive(Debug)]
pub struct PublicKey<C>(Point<C>);

impl<C> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for PublicKey<C> {}

impl<C: Curve> PublicKey<C> {
    pub fn new(p: Point<C>) -> Self {
        Self(p)
    }

    /// Derive the public key from a [private key](PrivateKey).
    ///
    /// This is done by simply multiplying the private key with the [generator
    /// point](crate::ecc::Curve::g).
    pub fn derive(key: PrivateKey<C>) -> Self {
        Self(key.0 * C::g())
    }
}
