//! - [Cipher]
//!     - [One Time Pad](OneTimePad)
//!     - [Block Cipher](BlockCipher)
//!         - [Padding]
//!         - [Block Mode](BlockMode)
//!             - [ECB](Ecb)
//!             - [CBC](Cbc)
//!             - [CTR](Ctr)
//! - [Hashing](Hash)
//!     - [SHA-2](sha2)
//!     - [SHA-3](sha3)
//! - [CSPRNG](Csprng)
//!     - [Fortuna]
//! - [MAC](Mac)
//!     - [HMAC](Hmac)
//! - [Signature Scheme (Public Key Cryptography)](SignatureScheme)
//!     - [Elliptic Curve Math](ecc::Curve)
//!         - [ECDSA](Ecdsa)

#![forbid(unsafe_code)]
#![feature(return_position_impl_trait_in_trait)]
#![feature(array_chunks)]
#![feature(associated_type_bounds)]
#![feature(custom_inner_attributes)]
#![feature(impl_trait_in_assoc_type)]

#[cfg(test)]
mod test;

#[cfg(doc)]
pub mod doc;

mod cipher;
mod hash;
mod mac;
mod pubkey;
mod random;
mod util;

pub use {
    cipher::{
        aes,
        Aes128,
        Aes192,
        Aes256,
        BlockCipher,
        BlockDecrypt,
        BlockEncrypt,
        BlockMode,
        BlockSizeTooSmall,
        Cbc,
        Cipher,
        CipherDecrypt,
        CipherEncrypt,
        Ctr,
        Ecb,
        OneTimePad,
        Padding,
        Pkcs7,
    },
    hash::{
        sha2,
        sha3,
        CompressionFn,
        DaviesMeyer,
        DaviesMeyerStep,
        Hash,
        MerkleDamgard,
        MerkleDamgardPad,
        Sha1,
        Sha224,
        Sha256,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
    },
    mac::{Hmac, Mac},
    pubkey::{
        ecc,
        Ecdsa,
        EcdsaSignature,
        InvalidPrivateKey,
        InvalidSignature,
        MultiSchnorr,
        MultisigScheme,
        Schnorr,
        SchnorrRandomness,
        SchnorrSignature,
        Secp256k1,
        SignatureScheme,
    },
    random::{uniform_random, Csprng, Entropy, Fortuna},
};
