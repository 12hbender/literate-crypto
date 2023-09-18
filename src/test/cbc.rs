use {
    crate::{BlockCipher, Cbc, Cipher, Ciphertext, Key, Padding, Plaintext},
    std::convert::Infallible,
};

#[test]
fn cbc() {
    let iv = [1, 2];
    let cip = Cbc::new(TestCipher, NoPadding, iv);
    let data = Plaintext([1, 2, 3, 4, 5, 6].to_vec());
    let key = Key([7, 8]);

    let ciphertext = cip.encrypt(data.clone(), key);
    #[allow(clippy::identity_op)]
    let expected = Ciphertext([
        1 ^ 1 ^ 7,
        2 ^ 2 ^ 8,
        1 ^ 1 ^ 7 ^ 3 ^ 7,
        2 ^ 2 ^ 8 ^ 4 ^ 8,
        1 ^ 1 ^ 7 ^ 3 ^ 7 ^ 5 ^ 7,
        2 ^ 2 ^ 8 ^ 4 ^ 8 ^ 6 ^ 8,
    ]);
    assert_eq!(
        ciphertext.0, expected.0,
        "invalid cbc encryption\nexpected: {expected:?}\nciphertext: {ciphertext:?}"
    );

    let plaintext = cip.decrypt(ciphertext, key).unwrap();
    assert_eq!(
        plaintext, data,
        "invalid cbc decryption\nexpected: {data:?}\nplaintext: {plaintext:?}"
    );
}

/// Test block cipher which XORs the data with the key.
struct TestCipher;

impl BlockCipher for TestCipher {
    type Block = [u8; 2];
    type Key = [u8; 2];

    fn encrypt(
        &self,
        data: Plaintext<Self::Block>,
        key: Key<Self::Key>,
    ) -> Ciphertext<Self::Block> {
        Ciphertext([data.0[0] ^ key.0[0], data.0[1] ^ key.0[1]])
    }

    fn decrypt(
        &self,
        data: Ciphertext<Self::Block>,
        key: Key<Self::Key>,
    ) -> Plaintext<Self::Block> {
        Plaintext([data.0[0] ^ key.0[0], data.0[1] ^ key.0[1]])
    }
}

/// Test padding which does nothing.
struct NoPadding;

impl Padding for NoPadding {
    type Err = Infallible;

    fn pad(&self, data: Plaintext<Vec<u8>>, n: usize) -> Plaintext<Vec<u8>> {
        if data.0.len() % n != 0 {
            panic!("invalid test setup: data length not a multiple of block size");
        }

        data
    }

    fn unpad(&self, data: Plaintext<Vec<u8>>, n: usize) -> Result<Plaintext<Vec<u8>>, Self::Err> {
        if data.0.len() % n != 0 {
            panic!("invalid test setup: data length not a multiple of block size");
        }

        Ok(data)
    }
}
