use {super::test, crate::Sha1};

/// SHA-1 test vectors.
#[test]
fn sha1() {
    let hash = Sha1::default();

    test(
        &hash,
        b"abc",
        &[
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ],
    );

    test(
        &hash,
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        &[
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
            0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
        ],
    );

    test(
        &hash,
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop",
        &[
            0x47, 0xb1, 0x72, 0x81, 0x07, 0x95, 0x69, 0x9f, 0xe7, 0x39, 0x19, 0x7d, 0x1a, 0x1f,
            0x59, 0x60, 0x70, 0x02, 0x42, 0xf1,
        ],
    );
}