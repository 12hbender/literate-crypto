//! Tests for ciphers. The tests ensure that
//! ```
//! decrypt(encrypt(plaintext, key)) == plaintext
//! ```
//! for a random plaintext and key.

use {
    crate::{Aes128, Aes192, Aes256, Cipher, Ecb, Key, Pkcs7, Plaintext},
    rand::Rng,
};

#[test]
fn aes_128_ecb_pkcs7() {
    test::<Ecb<Aes128, Pkcs7>>(10);
    test::<Ecb<Aes128, Pkcs7>>(20);
    test::<Ecb<Aes128, Pkcs7>>(30);
    test::<Ecb<Aes128, Pkcs7>>(16);
}

#[test]
fn aes_192_ecb_pkcs7() {
    test::<Ecb<Aes192, Pkcs7>>(10);
    test::<Ecb<Aes192, Pkcs7>>(20);
    test::<Ecb<Aes192, Pkcs7>>(30);
    test::<Ecb<Aes192, Pkcs7>>(16);
}

#[test]
fn aes_256_ecb_pkcs7() {
    test::<Ecb<Aes256, Pkcs7>>(10);
    test::<Ecb<Aes256, Pkcs7>>(20);
    test::<Ecb<Aes256, Pkcs7>>(30);
    test::<Ecb<Aes256, Pkcs7>>(16);
}

fn test<Cip: Cipher>(data_size: usize)
where
    Cip::Err: std::fmt::Debug,
{
    let data: Plaintext<Vec<u8>> =
        Plaintext((0..data_size).map(|_| rand::thread_rng().gen()).collect());
    let key_size = std::mem::size_of::<Cip::Key>();
    let key: Vec<u8> = (0..key_size).map(|_| rand::thread_rng().gen()).collect();
    let key = Key(Cip::Key::try_from(&key).unwrap());

    let ciphertext = Cip::encrypt(data.as_ref(), key);
    let plaintext = Cip::decrypt(ciphertext.as_ref(), key).unwrap();

    assert_eq!(
        data.as_ref(),
        plaintext.as_ref(),
        "decrypted plaintext did not match for cipher\ndata: {data:?}\nkey: {key:?}\nciphertext: \
         {ciphertext:?}\nplaintext: {plaintext:?}"
    );
}
