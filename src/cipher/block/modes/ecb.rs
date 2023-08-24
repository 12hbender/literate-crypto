use {
    crate::{BlockCipher, BlockMode, Cipher, Ciphertext, Key, Padding, Plaintext},
    std::marker::PhantomData,
};

/// Electronic codebook mode, a simple and insecure mode of operation.
///
/// ECB is the simplest mode of operation for block ciphers: it simply splits
/// the input data into blocks, and encrypts each block independently.
///
/// ECB is insecure because the same block in the plaintext will always encrypt
/// to the same block in the ciphertext. Imagine a server accepting encrypted
/// YES/NO messages from a client. If an attacker can see the encrypted
/// messages, he will know when the client is sending two identical messages. If
/// the attacker can perform some context-dependent analysis of the messages, he
/// might even be able to guess which messages are being sent (YES or NO).
#[derive(Debug, Default)]
pub struct Ecb<Cip, Pad>(PhantomData<Cip>, PhantomData<Pad>);

impl<Cip: BlockCipher, Pad: Padding> Cipher for Ecb<Cip, Pad> {
    type Err = Pad::Err;
    type Key = Cip::Key;

    fn encrypt(data: Plaintext<&[u8]>, key: Key<Self::Key>) -> Ciphertext<Vec<u8>> {
        let mut result = Vec::new();
        let n = std::mem::size_of::<Cip::Block>();
        let data = Pad::pad(data, n);
        let data = data.as_ref();
        for block in data.0.chunks(n) {
            let block = Cip::encrypt(Plaintext(block.try_into().unwrap()), key);
            result.extend_from_slice(block.0.as_ref());
        }
        Ciphertext(result)
    }

    fn decrypt(
        data: Ciphertext<&[u8]>,
        key: Key<Self::Key>,
    ) -> Result<Plaintext<Vec<u8>>, Self::Err> {
        let mut result = Vec::new();
        let n = std::mem::size_of::<Cip::Block>();
        for block in data.0.chunks(n) {
            let block = Cip::decrypt(Ciphertext(block.try_into().unwrap()), key);
            result.extend_from_slice(block.0.as_ref());
        }
        Pad::unpad(Plaintext(&result), n)
    }
}

impl<Cip: BlockCipher, Pad: Padding> BlockMode for Ecb<Cip, Pad> {}
