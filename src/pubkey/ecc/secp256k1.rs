use crate::ecc::{modular, Curve, Point};

#[derive(Debug, Default)]
pub struct Secp256k1(());

impl Curve for Secp256k1 {
    const SIZE: usize = 32;

    const P: modular::Num = modular::Num::from_le_words([
        0xFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ]);

    const N: modular::Num = modular::Num::from_le_words([
        0xBFD25E8CD0364141,
        0xBAAEDCE6AF48A03B,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
    ]);

    const A: modular::Num = modular::ZERO;
    const B: modular::Num = modular::SEVEN;

    fn g() -> Point<Self> {
        Point::new(
            modular::Num::from_le_words([
                0x59F2815B16F81798,
                0x029BFCDB2DCE28D9,
                0x55A06295CE870B07,
                0x79BE667EF9DCBBAC,
            ]),
            modular::Num::from_le_words([
                0x9C47D08FFB10D4B8,
                0xFD17B448A6855419,
                0x5DA4FBFC0E1108A8,
                0x483ADA7726A3C465,
            ]),
        )
        .unwrap()
    }
}
