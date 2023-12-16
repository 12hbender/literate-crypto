use crate::{Hmac, Mac, Sha1};

#[test]
fn hmac_sha1() {
    let mut hmac = Hmac::new(Sha1::default());
    let tag = hmac.mac(b"The quick brown fox jumps over the lazy dog", b"key");
    assert_eq!(
        tag,
        [
            0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7, 0x0a,
            0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9,
        ],
    );
}
