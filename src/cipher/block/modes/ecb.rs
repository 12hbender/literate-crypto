use crate::{
    cipher::{block::BlockCipher, Cipher},
    Ciphertext,
    Plaintext,
};

pub struct Ecb<C>(C);

impl<C: BlockCipher> Cipher for Ecb<C> {
    fn encrypt(&self, p: Plaintext<&[u8]>) -> Ciphertext<Vec<u8>> {
        todo!()
    }

    fn decrypt(&self, c: Ciphertext<&[u8]>) -> Plaintext<Vec<u8>> {
        todo!()
    }
}
