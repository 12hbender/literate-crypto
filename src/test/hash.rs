use {crate::Hash, std::fmt};

mod sha1;
mod sha3;

fn test<H: Hash>(hash: &H, input: &[u8], output: &[u8])
where
    H::Output: AsRef<[u8]> + fmt::Debug,
{
    let hash = hash.hash(input);
    assert_eq!(
        hash.as_ref(),
        output,
        "invalid hash for:\n{input:#?}\n\nexpected:\n{output:#?}\n\ngot:\n{hash:#?}"
    );
}
