#![feature(return_position_impl_trait_in_trait)]
#![feature(array_chunks)]
#![forbid(unsafe_code)]

#[cfg(test)]
mod test;

#[cfg(doc)]
pub mod doc;

mod bytes;
mod cipher;
mod hash;
mod key;
mod random;
mod text;
mod util;

pub use {
    bytes::Bytes,
    cipher::{
        aes,
        Aes128,
        Aes192,
        Aes256,
        BlockCipher,
        BlockMode,
        Cbc,
        Cipher,
        Ecb,
        Padding,
        Pkcs7,
    },
    hash::{
        sha3,
        CompressionFn,
        DaviesMeyer,
        DaviesMeyerCipher,
        DaviesMeyerStep,
        Hash,
        MerkleDamgard,
        MerkleDamgardPad,
        Sha1,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
    },
    key::Key,
    text::{Ciphertext, Plaintext},
};
