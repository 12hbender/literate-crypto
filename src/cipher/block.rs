use crate::{Ciphertext, Plaintext};

mod modes;
mod padding;

pub use {
    modes::{BlockMode, Cbc, Ecb},
    padding::{Padding, Pkcs7},
};

pub trait BlockCipher {
    // TODO Document the requirements for this type
    type Block: 'static
        + for<'a> TryFrom<&'a [u8], Error = std::array::TryFromSliceError>
        + AsRef<[u8]>
        + Clone
        + Copy;

    fn encrypt(data: Plaintext<Self::Block>) -> Ciphertext<Self::Block>;
    fn decrypt(data: Ciphertext<Self::Block>) -> Plaintext<Self::Block>;
}
