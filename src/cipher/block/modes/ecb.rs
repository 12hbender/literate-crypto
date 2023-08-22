use {
    crate::{BlockCipher, Cipher, Ciphertext, Padding, Plaintext},
    std::marker::PhantomData,
};

#[derive(Debug, Default)]
pub struct Ecb<Cip, Pad> {
    _cipher: PhantomData<Cip>,
    _padding: PhantomData<Pad>,
}

impl<Cip: BlockCipher, Pad: Padding> Cipher for Ecb<Cip, Pad> {
    type Err = Pad::Err;

    fn encrypt(&mut self, p: Plaintext<&[u8]>) -> Ciphertext<Vec<u8>> {
        todo!()
    }

    fn decrypt(&mut self, c: Ciphertext<&[u8]>) -> Result<Plaintext<Vec<u8>>, Self::Err> {
        todo!()
    }
}
