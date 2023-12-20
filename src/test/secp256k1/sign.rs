use crate::{
    ecc::{self, Curve, Num},
    test::fortuna::NoEntropy,
    util::CollectVec,
    Aes256,
    Ecdsa,
    EcdsaSignature,
    Fortuna,
    Schnorr,
    SchnorrSignature,
    Secp256k1,
    Sha256,
    Sha3_256,
    SignatureScheme,
};

/// Assert that valid ECDSA signatures verify successfully, and invalid
/// signatures fail to verify.
#[test]
fn ecdsa() {
    let mut ecdsa = Ecdsa::new(Secp256k1::default(), Sha3_256::default());
    let data = (0u8..100).collect_vec();
    let privkey = rand_privkey();
    let pubkey = privkey.derive();

    let sig = ecdsa.sign(privkey, &data);
    // A valid signature should verify successfully.
    assert!(ecdsa.verify(pubkey, &data, &sig).is_ok());

    // Invalidate the signature by adding random numbers to r and s.
    let sig = EcdsaSignature::new(
        sig.r().add(rand_num(), Secp256k1::N),
        sig.s().add(rand_num(), Secp256k1::N),
    )
    .unwrap();
    // An invalid signature should fail to verify.
    assert!(ecdsa.verify(pubkey, &data, &sig).is_err());
}

/// Assert that valid Schnorr signatures verify successfully, and invalid
/// signatures fail to verify.
#[test]
fn schnorr() {
    let mut schnorr = Schnorr::new(
        Secp256k1::default(),
        Sha3_256::default(),
        Fortuna::new(NoEntropy, Aes256::default(), Sha256::default()).unwrap(),
    );
    let data = (0u8..100).collect_vec();
    let privkey = rand_privkey();
    let pubkey = privkey.derive();

    let sig = schnorr.sign(privkey, &data);
    // A valid signature should verify successfully.
    assert!(schnorr.verify(pubkey, &data, &sig).is_ok());

    // Invalidate the signature by adding random numbers to r and s.
    let sig = SchnorrSignature::new(
        sig.s().add(rand_num(), Secp256k1::N),
        sig.e().add(rand_num(), Secp256k1::N),
    )
    .unwrap();
    // An invalid signature should fail to verify.
    assert!(schnorr.verify(pubkey, &data, &sig).is_err());
}

fn rand_privkey() -> ecc::PrivateKey<Secp256k1> {
    loop {
        if let Ok(key) = ecc::PrivateKey::new(rand_num()) {
            return key;
        }
    }
}

fn rand_num() -> Num {
    Num::from_le_words([
        rand::random(),
        rand::random(),
        rand::random(),
        rand::random(),
    ])
}
