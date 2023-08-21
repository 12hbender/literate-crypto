use crate::{
    cipher::{block::BlockCipher, Cipher},
    Ciphertext,
    Plaintext,
};

pub struct Cbc<C>(C);

impl<C: BlockCipher> Cipher for Cbc<C> {
    fn encrypt(&self, p: Plaintext<&[u8]>) -> Ciphertext<Vec<u8>> {
        todo!()
    }

    fn decrypt(&self, c: Ciphertext<&[u8]>) -> Plaintext<Vec<u8>> {
        todo!()
    }
}
