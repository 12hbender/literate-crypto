//! Elliptic curve cryptography.

use std::{fmt, marker::PhantomData};

mod curve;
mod ecdsa;
mod num;
mod schnorr;
mod secp256k1;

pub use {
    curve::{Coordinates, Curve, InvalidPoint, Point},
    ecdsa::{Ecdsa, EcdsaSignature},
    num::Num,
    schnorr::{
        MultiSchnorr,
        Schnorr,
        SchnorrRandomness,
        SchnorrSag,
        SchnorrSagSignature,
        SchnorrSignature,
    },
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
        if n < C::N && n != Num::ZERO {
            Ok(Self(n, Default::default()))
        } else {
            Err(InvalidPrivateKey)
        }
    }

    /// Derive the [public key](PublicKey) from a private key.
    ///
    /// This is done by simply multiplying the private key with the [generator
    /// point](crate::ecc::Curve::g).
    pub fn derive(&self) -> PublicKey<C> {
        PublicKey::new(self.0 * C::g()).unwrap()
    }
}

#[derive(Debug)]
pub struct PublicKey<C> {
    x: Num,
    y: Num,
    _curve: PhantomData<C>,
}

impl<C> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for PublicKey<C> {}

impl<C: Curve> PublicKey<C> {
    pub fn new(p: Point<C>) -> Result<Self, InvalidPublicKey> {
        match p.coordinates() {
            Coordinates::Infinity => Err(InvalidPublicKey),
            Coordinates::Finite(x, y) => Ok(Self {
                x,
                y,
                _curve: Default::default(),
            }),
        }
    }

    pub fn point(&self) -> Point<C> {
        Point::new(self.x, self.y).unwrap()
    }

    pub fn x(&self) -> Num {
        self.x
    }

    pub fn y(&self) -> Num {
        self.y
    }
}

/// Error indicating that a private key is invalid.
#[derive(Debug, Clone, Copy)]
pub struct InvalidPrivateKey;

impl fmt::Display for InvalidPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid private key")
    }
}

impl std::error::Error for InvalidPrivateKey {}

/// Error indicating that a public key is invalid.
#[derive(Debug, Clone, Copy)]
pub struct InvalidPublicKey;

impl fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid public key")
    }
}

impl std::error::Error for InvalidPublicKey {}
