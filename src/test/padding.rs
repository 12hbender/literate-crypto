//! Tests for padding schemes. The tests ensure that
//! ```
//! len(pad(data)) % N == 0 && unpad(pad(data)) == data
//! ```
//! for any random data.

use {
    crate::{Padding, Pkcs7, Plaintext},
    rand::Rng,
};

#[test]
fn pkcs7() {
    test(Pkcs7::default(), 16, 13);
    test(Pkcs7::default(), 16, 16);
    test(Pkcs7::default(), 16, 17);
    test(Pkcs7::default(), 16, 18);
}

/// Ensure that
/// ```
/// len(pad(data)) % N == 0 && unpad(pad(data)) == data
/// ```
/// for any random data of length `data_len`.
fn test<Pad: Padding>(pad: Pad, n: usize, data_len: usize)
where
    Pad::Err: std::fmt::Debug,
{
    let data: Vec<u8> = (0..data_len).map(|_| rand::thread_rng().gen()).collect();

    let padded = pad.pad(Plaintext(data.clone()), n);
    assert!(
        padded.0.len() % n == 0,
        "padding does not align to block size\ndata: {data:?}\npadded: {padded:?}\nblock size: {n}",
    );

    let unpadded = pad.unpad(padded.clone(), n).unwrap();
    assert_eq!(
        unpadded.0, data,
        "unpadded data does not match original\ndata: {data:?}\npadded: {padded:?}\nunpadded: \
         {unpadded:?}"
    );
}
