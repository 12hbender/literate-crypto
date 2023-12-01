use std::fmt;

pub mod ecc;

pub use ecc::{ecdsa, Ecdsa, Secp256k1};

pub trait SignatureScheme {
    type PublicKey;
    type PrivateKey;
    type Signature;

    fn sign(&self, key: Self::PrivateKey, data: &[u8]) -> Self::Signature;
    fn verify(
        &self,
        key: Self::PublicKey,
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), InvalidSignature>;
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidSignature;

impl fmt::Display for InvalidSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid signature")
    }
}

impl std::error::Error for InvalidSignature {}

#[derive(Debug, Clone, Copy)]
pub struct InvalidPrivateKey;

impl fmt::Display for InvalidPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid private key")
    }
}

impl std::error::Error for InvalidPrivateKey {}
