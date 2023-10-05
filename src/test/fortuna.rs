use crate::{Aes256, Entropy, Fortuna, Sha256};

/// Test that fortuna generates bytes. Don't test the values of those bytes, as
/// they are pseudo-random.
#[test]
fn fortuna_generates_bytes() {
    let fortuna = Fortuna::new(NoEntropy, Aes256::default(), Sha256::default()).unwrap();
    let bytes: Vec<_> = fortuna.into_iter().take(4086).collect();
    assert!((0..=u8::MAX).all(|x| bytes.contains(&x)));
}

struct NoEntropy;

impl Entropy for NoEntropy {
    fn get(&mut self, buf: &mut [u8]) {
        buf.iter_mut().for_each(|x| *x = 0);
    }
}
