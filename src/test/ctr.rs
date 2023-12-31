use crate::{Aes128, CipherEncrypt, Ctr};

/// Test the [CTR block mode](Ctr) with hand-checked test vectors. The nonce is
/// set to 1 and never incremented.
#[test]
fn ctr_no_increments() {
    let ctr = Ctr::new(Aes128::default(), 1).unwrap();
    let ciphertext = ctr
        .encrypt(
            vec![0x01, 0x10, 0x20],
            [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ],
        )
        .unwrap();
    assert_eq!(ciphertext, vec![0x7f, 0x49, 0x17]);
}

/// Test the [CTR block mode](Ctr) with hand-checked test vectors. The nonce is
/// set to 256 and incremented once.
#[test]
fn ctr_with_increment() {
    let ctr = Ctr::new(Aes128::default(), 256).unwrap();
    let ciphertext = ctr
        .encrypt(
            vec![
                0x01, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x30, 0x40, 0x50,
            ],
            [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ],
        )
        .unwrap();
    assert_eq!(
        ciphertext,
        vec![
            0xfc, 0xe3, 0xf9, 0xdf, 0xcd, 0x52, 0x35, 0x0d, 0x21, 0xd5, 0xdc, 0xda, 0x57, 0x8f,
            0x32, 0x28, 0x0b, 0x87, 0x73
        ]
    );
}
