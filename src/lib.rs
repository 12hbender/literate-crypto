#![feature(return_position_impl_trait_in_trait)]
#![feature(array_chunks)]
#![feature(associated_type_bounds)]
#![forbid(unsafe_code)]

#[cfg(test)]
mod test;

#[cfg(doc)]
pub mod doc;

mod cipher;
mod hash;
mod random;
mod text;
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
        Cbc,
        Cipher,
        Ecb,
        Key,
        Padding,
        Pkcs7,
    },
    hash::{
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
    text::{Ciphertext, Plaintext},
};
