use crate::{
    ecc::{ecdsa, modular, Curve},
    Ecdsa,
    Secp256k1,
    Sha3_256,
    SignatureScheme,
};

/// Assert that valid signatures verify successfully, and invalid signatures
/// fail to verify.
#[test]
fn sign() {
    let ecdsa = Ecdsa::new(Secp256k1::default(), Sha3_256::default());
    let data: Vec<_> = (0u8..100).collect();
    let privkey = rand_privkey();
    let pubkey = ecdsa::PublicKey::derive(privkey);
    let sig = ecdsa.sign(privkey, &data);
    // A valid signature should verify successfully.
    assert!(ecdsa.verify(pubkey, &data, &sig).is_ok());
    // Invalidate the signature by adding random numbers to r and s.
    let sig = ecdsa::Signature::new(
        sig.r().add(rand_num(), Secp256k1::N),
        sig.s().add(rand_num(), Secp256k1::N),
    )
    .unwrap();
    // An invalid signature should fail to verify.
    assert!(ecdsa.verify(pubkey, &data, &sig).is_err());
}

fn rand_privkey() -> ecdsa::PrivateKey<Secp256k1> {
    loop {
        if let Ok(key) = ecdsa::PrivateKey::new(rand_num()) {
            return key;
        }
    }
}

fn rand_num() -> modular::Num {
    modular::Num::from_le_words([
        rand::random(),
        rand::random(),
        rand::random(),
        rand::random(),
    ])
}
