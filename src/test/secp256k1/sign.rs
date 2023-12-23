use {
    crate::{
        ecc::{self, Curve, Num, PublicKey},
        test::fortuna::NoEntropy,
        util::CollectVec,
        Aes256,
        Ecdsa,
        EcdsaSignature,
        Fortuna,
        MultiSchnorr,
        MultisigScheme,
        Schnorr,
        SchnorrRandomness,
        SchnorrSignature,
        Secp256k1,
        Sha256,
        Sha3_256,
        SignatureScheme,
    },
    rand::Rng,
};

/// Assert that valid ECDSA signatures verify successfully.
#[test]
fn ecdsa_valid() {
    let EcdsaSetup {
        pubkey,
        sig,
        data,
        mut ecdsa,
    } = ecdsa_setup();

    assert!(ecdsa.verify(pubkey, &data, &sig).is_ok());
}

/// Assert that invalid ECDSA signatures fail to verify.
#[test]
fn ecdsa_invalid_signature() {
    let EcdsaSetup {
        pubkey,
        sig,
        data,
        mut ecdsa,
    } = ecdsa_setup();

    // Invalidate the signature by adding random numbers to r and s.
    let sig = EcdsaSignature::new(
        sig.r().add(rand_num(), Secp256k1::N),
        sig.s().add(rand_num(), Secp256k1::N),
    )
    .unwrap();

    assert!(ecdsa.verify(pubkey, &data, &sig).is_err());
}

/// Assert that valid ECDSA signatures fail to verify with an incorrect pubkey.
#[test]
fn ecdsa_invalid_pubkey() {
    let EcdsaSetup {
        sig,
        data,
        mut ecdsa,
        ..
    } = ecdsa_setup();

    assert!(ecdsa.verify(rand_pubkey(), &data, &sig).is_err());
}

/// Assert that valid Schnorr signatures verify successfully.
#[test]
fn schnorr_valid() {
    let SchnorrSetup {
        pubkey,
        sig,
        data,
        mut schnorr,
    } = schnorr_setup();

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

/// Assert that valid Schnorr signatures fail to verify with an incorrect
/// pubkey.
#[test]
fn schnorr_invalid_pubkey() {
    let SchnorrSetup {
        sig,
        data,
        mut schnorr,
        ..
    } = schnorr_setup();

    assert!(schnorr.verify(rand_pubkey(), &data, &sig).is_err());
}

/// Assert that invalid Schnorr signatures fail to verify.
#[test]
fn schnorr_invalid_signature() {
    let SchnorrSetup {
        pubkey,
        sig,
        data,
        mut schnorr,
    } = schnorr_setup();

    // Invalidate the signature by adding random numbers to r and s.
    let sig = SchnorrSignature::new(
        sig.s().add(rand_num(), Secp256k1::N),
        sig.e().add(rand_num(), Secp256k1::N),
    )
    .unwrap();

    assert!(schnorr.verify(pubkey, &data, &sig).is_err());
}

/// Assert that valid Schnorr multisigs verify successfully.
#[test]
fn multi_schnorr_valid() {
    let MultiSchnorrSetup {
        pubkey1,
        pubkey2,
        sig,
        data,
        mut schnorr,
        ..
    } = multi_schnorr_setup();

    assert!(schnorr.verify(&[pubkey1, pubkey2], &data, &sig).is_ok());
}

/// Assert that valid Schnorr multisigs fail to verify if the pubkeys used for
/// verification are incorrect.
#[test]
fn multi_schnorr_invalid_pubkeys() {
    let MultiSchnorrSetup {
        pubkey1,
        sig,
        data,
        mut schnorr,
        ..
    } = multi_schnorr_setup();

    assert!(schnorr.verify(&[pubkey1], &data, &sig).is_err());
    assert!(schnorr
        .verify(&[pubkey1, rand_pubkey()], &data, &sig)
        .is_err());
}

/// Assert that invalid Schnorr multisigs fail to verify.
#[test]
fn multi_schnorr_invalid_sig() {
    let MultiSchnorrSetup {
        pubkey1,
        pubkey2,
        sig,
        data,
        mut schnorr,
        ..
    } = multi_schnorr_setup();

    // Invalidate the signature by adding random numbers to r and s.
    let sig = SchnorrSignature::new(
        sig.s().add(rand_num(), Secp256k1::N),
        sig.e().add(rand_num(), Secp256k1::N),
    )
    .unwrap();

    assert!(schnorr.verify(&[pubkey1, pubkey2], &data, &sig).is_err());
}

fn ecdsa_setup() -> EcdsaSetup {
    let mut ecdsa = Ecdsa::new(Secp256k1::default(), Sha3_256::default());
    let data = (0u8..100).collect_vec();
    let privkey = rand_privkey();
    let pubkey = privkey.derive();
    let sig = ecdsa.sign(privkey, &data);
    EcdsaSetup {
        pubkey,
        sig,
        data,
        ecdsa,
    }
}

#[derive(Debug)]
struct EcdsaSetup {
    pubkey: PublicKey<Secp256k1>,
    sig: EcdsaSignature<Secp256k1, Sha3_256>,
    data: Vec<u8>,
    ecdsa: Ecdsa<Secp256k1, Sha3_256>,
}

/// Create a Schnorr signature.
fn schnorr_setup() -> SchnorrSetup {
    let mut schnorr = Schnorr::new(
        Secp256k1::default(),
        Sha256::default(),
        Fortuna::new(NoEntropy, Aes256::default(), Sha256::default()).unwrap(),
    );
    let data = (0u8..100).collect_vec();
    let privkey = rand_privkey();
    let pubkey = privkey.derive();
    let sig = schnorr.sign(privkey, &data);
    SchnorrSetup {
        pubkey,
        sig,
        data,
        schnorr,
    }
}

#[derive(Debug)]
struct SchnorrSetup {
    pubkey: PublicKey<Secp256k1>,
    sig: SchnorrSignature<Secp256k1, Sha256>,
    data: Vec<u8>,
    schnorr: Schnorr<Secp256k1, Sha256, Fortuna<NoEntropy, Aes256, Sha256>>,
}

/// Create a multisig of two keys.
fn multi_schnorr_setup() -> MultiSchnorrSetup {
    let mut schnorr = MultiSchnorr::new(
        Secp256k1::default(),
        Sha256::default(),
        Fortuna::new(NoEntropy, Aes256::default(), Sha256::default()).unwrap(),
    );

    let r1 = rand_num();
    let r2 = rand_num();

    let privkey1 = rand_privkey();
    let pubkey1 = privkey1.derive();

    let privkey2 = rand_privkey();
    let pubkey2 = privkey2.derive();

    let data = (0..100u8).collect_vec();

    // Sign by 1st signer.
    let sig = schnorr.sign(
        (
            privkey1,
            vec![pubkey1, pubkey2],
            SchnorrRandomness::new(r1, &[r2 * Secp256k1::g()]).unwrap(),
        ),
        &data,
        Default::default(),
    );

    // Sign by 2nd signer.
    let sig = schnorr.sign(
        (
            privkey2,
            vec![pubkey1, pubkey2],
            SchnorrRandomness::new(r2, &[r1 * Secp256k1::g()]).unwrap(),
        ),
        &data,
        sig,
    );

    MultiSchnorrSetup {
        pubkey1,
        pubkey2,
        sig,
        data,
        schnorr,
    }
}

#[derive(Debug)]
struct MultiSchnorrSetup {
    pubkey1: PublicKey<Secp256k1>,
    pubkey2: PublicKey<Secp256k1>,
    sig: SchnorrSignature<Secp256k1, Sha256>,
    data: Vec<u8>,
    schnorr: MultiSchnorr<Secp256k1, Sha256, Fortuna<NoEntropy, Aes256, Sha256>>,
}

fn rand_privkey() -> ecc::PrivateKey<Secp256k1> {
    'retry: loop {
        match ecc::PrivateKey::new(rand_num()) {
            Ok(key) => return key,
            Err(_) => continue 'retry,
        }
    }
}

/// Generate a random pubkey quickly.
fn rand_pubkey() -> ecc::PublicKey<Secp256k1> {
    let n = rand::thread_rng().gen_range(1..100);
    let n = Num::from_le_words([n, 0, 0, 0]);
    ecc::PublicKey::new(n * Secp256k1::g()).unwrap()
}

fn rand_num() -> Num {
    Num::from_le_words([
        rand::random(),
        rand::random(),
        rand::random(),
        rand::random(),
    ])
}
