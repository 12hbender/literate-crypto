#![feature(return_position_impl_trait_in_trait)]
#![feature(array_chunks)]
#![feature(associated_type_bounds)]
#![feature(proc_macro_hygiene)]
#![feature(custom_inner_attributes)]
#![forbid(unsafe_code)]
#![feature(impl_trait_in_assoc_type)]

#[cfg(test)]
mod test;

#[cfg(doc)]
pub mod doc;

mod cipher;
mod hash;
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
        Digest,
        Hash,
        MerkleDamgard,
        MerkleDamgardPad,
        Preimage,
        Sha1,
        Sha224,
        Sha256,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
    },
    pubkey::{ecc, ecdsa, Ecdsa, InvalidPrivateKey, InvalidSignature, Secp256k1, SignatureScheme},
    random::{Csprng, Entropy, Fortuna},
};
