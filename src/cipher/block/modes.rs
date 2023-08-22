use crate::Cipher;

mod cbc;
mod ecb;

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

pub use {cbc::Cbc, ecb::Ecb};
