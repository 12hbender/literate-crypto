use crate::{CommitmentScheme, HashCommitmentScheme, Sha256, Sha3_384, Sha3_512};

#[test]
fn test_hash_commitment() {
    test(
        HashCommitmentScheme::new(Sha256::default()),
        vec![1, 2, 3],
        vec![1, 2, 3],
    );
    test(
        HashCommitmentScheme::new(Sha3_384::default()),
        vec![],
        vec![],
    );
    test(
        HashCommitmentScheme::new(Sha3_512::default()),
        vec![4; 1024],
        vec![4; 1024],
    );
}

fn test<C: CommitmentScheme>(scheme: C, value: C::Value, reveal: C::Reveal) {
    let commitment = scheme.commit(&value);
    let result = scheme.reveal(&commitment, &reveal);
    assert!(result.is_ok());
}
