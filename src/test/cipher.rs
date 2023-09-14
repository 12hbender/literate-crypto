//! Tests for ciphers. The tests ensure that
//! ```
//! decrypt(encrypt(plaintext, key)) == plaintext
//! ```
//! for a random plaintext and key.

use {
    crate::{Aes128, Aes192, Aes256, Cbc, Cipher, Ecb, Key, Pkcs7, Plaintext},
    rand::Rng,
};

#[test]
fn aes_128_ecb_pkcs7() {
    test(Ecb::new(Aes128::default(), Pkcs7::default()), 10);
    test(Ecb::new(Aes128::default(), Pkcs7::default()), 20);
    test(Ecb::new(Aes128::default(), Pkcs7::default()), 30);
    test(Ecb::new(Aes128::default(), Pkcs7::default()), 16);
}

#[test]
fn aes_192_ecb_pkcs7() {
    test(Ecb::new(Aes192::default(), Pkcs7::default()), 10);
    test(Ecb::new(Aes192::default(), Pkcs7::default()), 20);
    test(Ecb::new(Aes192::default(), Pkcs7::default()), 30);
    test(Ecb::new(Aes192::default(), Pkcs7::default()), 16);
}

#[test]
fn aes_256_ecb_pkcs7() {
    test(Ecb::new(Aes256::default(), Pkcs7::default()), 10);
    test(Ecb::new(Aes256::default(), Pkcs7::default()), 20);
    test(Ecb::new(Aes256::default(), Pkcs7::default()), 30);
    test(Ecb::new(Aes256::default(), Pkcs7::default()), 16);
}

#[test]
fn aes_128_cbc_pkcs7() {
    let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    test(Cbc::new(Aes128::default(), Pkcs7::default(), iv), 10);
    test(Cbc::new(Aes128::default(), Pkcs7::default(), iv), 20);
    test(Cbc::new(Aes128::default(), Pkcs7::default(), iv), 30);
    test(Cbc::new(Aes128::default(), Pkcs7::default(), iv), 16);
}

#[test]
fn aes_192_cbc_pkcs7() {
    let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    test(Cbc::new(Aes192::default(), Pkcs7::default(), iv), 10);
    test(Cbc::new(Aes192::default(), Pkcs7::default(), iv), 20);
    test(Cbc::new(Aes192::default(), Pkcs7::default(), iv), 30);
    test(Cbc::new(Aes192::default(), Pkcs7::default(), iv), 16);
}

#[test]
fn aes_256_cbc_pkcs7() {
    let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    test(Cbc::new(Aes256::default(), Pkcs7::default(), iv), 10);
    test(Cbc::new(Aes256::default(), Pkcs7::default(), iv), 20);
    test(Cbc::new(Aes256::default(), Pkcs7::default(), iv), 30);
    test(Cbc::new(Aes256::default(), Pkcs7::default(), iv), 16);
}

/// Test that a cipher is valid by making sure that
/// ```
/// decrypt(encrypt(plaintext, key)) == plaintext
/// ```
fn test<Cip: Cipher>(cip: Cip, data_size: usize)
where
    Cip::Err: std::fmt::Debug,
{
    let data: Plaintext<Vec<u8>> =
        Plaintext((0..data_size).map(|_| rand::thread_rng().gen()).collect());
    let key_size = std::mem::size_of::<Cip::Key>();
    let key: Vec<u8> = (0..key_size).map(|_| rand::thread_rng().gen()).collect();
    let key = Key(Cip::Key::try_from(key.as_slice()).unwrap());

    let ciphertext = cip.encrypt(data.clone(), key);
    let plaintext = cip.decrypt(ciphertext.clone(), key).unwrap();

    assert_eq!(
        data, plaintext,
        "decrypted plaintext did not match for cipher\ndata: {data:?}\nkey: {key:?}\nciphertext: \
         {ciphertext:?}\nplaintext: {plaintext:?}"
    );
}
