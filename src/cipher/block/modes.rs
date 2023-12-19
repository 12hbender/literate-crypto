use crate::Cipher;

mod cbc;
mod ctr;
mod ecb;

// TODO Implement GCM, start from mathematical foundations for polynomials,
// those MIGHT also be useful for ZKP or something else, or maybe not.

/// A way to execute a [block cipher](crate::BlockCipher) on data of arbitrary
/// length.
///
/// A block cipher can only encrypt or decrypt one block at a time. In order to
/// encrypt arbitrary amounts of data, there needs to be a way to ensure that
/// the data is a multiple of the block size ([padding](crate::Padding)) and a
/// way to map input blocks of plaintext to output blocks of ciphertext. The
/// "mode of operation" usually refers to the combination of these two
/// requirements.
pub trait BlockMode: Cipher {}

pub use {
    cbc::Cbc,
    ctr::{BlockSizeTooSmall, Ctr},
    ecb::Ecb,
};
