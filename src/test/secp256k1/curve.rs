use crate::ecc::{modular, Curve, Point, Secp256k1};

#[test]
fn doubling() {
    assert_eq!(
        Secp256k1::g() + Secp256k1::g(),
        Point::new(
            modular::Num::from_le_words([
                12370272968204394213,
                6662950628856118439,
                3478257130916576472,
                14268669794154544493
            ]),
            modular::Num::from_le_words([
                2550217892273579306,
                17867523981857706209,
                11800983642684844782,
                1936944757666071353
            ]),
        )
        .unwrap()
    );
}

#[test]
fn addition() {
    let p = Point::new(
        modular::Num::from_le_words([
            12370272968204394213,
            6662950628856118439,
            3478257130916576472,
            14268669794154544493,
        ]),
        modular::Num::from_le_words([
            2550217892273579306,
            17867523981857706209,
            11800983642684844782,
            1936944757666071353,
        ]),
    )
    .unwrap();
    assert_eq!(
        Secp256k1::g() + p,
        Point::new(
            modular::Num::from_le_words([
                9656264143134537465,
                13056436995607206320,
                5274928500377997865,
                17956003453681058576
            ]),
            modular::Num::from_le_words([
                7834571707967399538,
                7278003473310950171,
                1144820191972553558,
                4075611493812267028
            ]),
        )
        .unwrap()
    );
}

#[test]
fn multiplication() {
    assert_eq!(
        modular::SEVEN * Secp256k1::g(),
        Point::new(
            modular::Num::from_le_words([
                16801766848214661564,
                4413980075321516956,
                11788439643834972686,
                6682761736226714858
            ]),
            modular::Num::from_le_words([
                11891796769454056666,
                12111253311957362613,
                11752017254187422939,
                7704473966897092960
            ]),
        )
        .unwrap()
    );
}
