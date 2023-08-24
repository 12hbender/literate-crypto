use {
    crate::{Padding, Pkcs7, Plaintext},
    rand::Rng,
};

#[test]
fn pkcs7() {
    test::<Pkcs7>(16, 13);
    test::<Pkcs7>(16, 16);
    test::<Pkcs7>(16, 17);
    test::<Pkcs7>(16, 18);
}

// TODO The error messages have to be good
fn test<Pad: Padding>(n: usize, data: usize)
where
    Pad::Err: std::fmt::Debug,
{
    let data: Vec<u8> = (0..data).map(|_| rand::thread_rng().gen()).collect();
    let padded = Pad::pad(Plaintext(&data), n);
    dbg!(&padded);
    assert!(padded.0.len() % n == 0);
    let unpadded = Pad::unpad(padded.as_ref(), n).unwrap();
    assert_eq!(unpadded.0, data);
}
