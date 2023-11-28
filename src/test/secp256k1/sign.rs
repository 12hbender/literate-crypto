use crate::{
    secp256k1::{Num, PrivateKey, PublicKey, Signature, N},
    Secp256k1Ecdsa,
    Sha3_256,
    SignatureScheme,
};

/// Assert that valid signatures verify successfully, and invalid signatures
/// fail to verify.
#[test]
fn sign() {
    let cases = [
        (
            PrivateKey::new(Num::from_le_words([
                13150183333990655493,
                925367387008091836,
                1945566746406471217,
                1723435623737461351,
            ]))
            .unwrap(),
            Num::ONE,
            Num::ZERO,
        ),
        (
            PrivateKey::new(Num::from_le_words([
                12264584818125349599,
                11925430807002198587,
                9927884302678645491,
                16838034688021697606,
            ]))
            .unwrap(),
            Num::TWO,
            Num::ONE,
        ),
    ];

    let ecdsa = Secp256k1Ecdsa::new(Sha3_256::default());
    let data: Vec<_> = (0u8..100).collect();
    for (privkey, i, j) in cases {
        let pubkey = PublicKey::derive(privkey);
        let sig = ecdsa.sign(privkey, &data);
        // A valid signature should verify successfully.
        assert!(ecdsa.verify(pubkey, &data, &sig).is_ok());
        // Invalidate the signature by adding arbitrary numbers to r and s.
        let sig = Signature::new(sig.r().add(i, N), sig.s().add(j, N)).unwrap();
        // An invalid signature should fail to verify.
        assert!(ecdsa.verify(pubkey, &data, &sig).is_err());
    }
}
