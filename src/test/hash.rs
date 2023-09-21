use {
    crate::{Hash, Preimage},
    std::fmt,
};

mod sha1;
mod sha2;
mod sha3;

fn test<H: Hash>(hash: &H, preimage: &[u8], output: &[u8])
where
    H::Output: AsRef<[u8]> + fmt::Debug,
{
    let hash = hash.hash(Preimage(preimage));
    assert_eq!(
        hash.0.as_ref(),
        output,
        "invalid hash for:\n{preimage:#?}\n\nexpected:\n{output:#?}\n\ngot:\n{hash:#?}"
    );
}
