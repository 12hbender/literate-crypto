use {
    super::test,
    crate::{Sha224, Sha256},
};

/// SHA-256 test vectors.
#[test]
fn sha256() {
    let hash = Sha256::default();

    test(
        &hash,
        b"abc",
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ],
    );

    test(
        &hash,
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        &[
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ],
    );

    test(
        &hash,
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop",
        &[
            0xaa, 0x35, 0x3e, 0x00, 0x9e, 0xdb, 0xae, 0xbf, 0xc6, 0xe4, 0x94, 0xc8, 0xd8, 0x47,
            0x69, 0x68, 0x96, 0xcb, 0x8b, 0x39, 0x8e, 0x01, 0x73, 0xa4, 0xb5, 0xc1, 0xb6, 0x36,
            0x29, 0x2d, 0x87, 0xc7,
        ],
    );
}

/// SHA-224 test vectors.
#[test]
fn sha224() {
    let hash = Sha224::default();

    test(
        &hash,
        b"abc",
        &[
            0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
            0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
        ],
    );

    test(
        &hash,
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        &[
            0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89,
            0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25,
        ],
    );

    test(
        &hash,
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop",
        &[
            0x7a, 0x02, 0x7d, 0x88, 0xe3, 0x94, 0xd2, 0x89, 0xed, 0x7a, 0x10, 0xa9, 0x18, 0xb9,
            0x3d, 0x1f, 0x21, 0x0b, 0x47, 0x41, 0xd4, 0x45, 0x34, 0xce, 0x64, 0x27, 0x5a, 0xb9,
        ],
    );
}