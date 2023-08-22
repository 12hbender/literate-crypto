use {
    crate::{Padding, Plaintext},
    docext::docext,
};

// TODO Include some examples for what this would look like?
/// PKCS #7 is a simple approach to padding.
///
/// If the message needs to be padded with $n$ bytes and the block size is $B$,
/// this padding scheme will append $n$ bytes with the value $n$. If $n = 0$,
/// then an entire block of padding is appended, i.e. $B$ bytes with the value
/// $B$.
///
/// Note that this scheme does not work for $B \ge 256$, since $255$ is the
/// maximum value for a single byte.
#[docext]
pub struct Pkcs7;

impl Padding for Pkcs7 {
    type Err = InvalidPadding;

    fn pad(data: Plaintext<&[u8]>, n: usize) -> Plaintext<Vec<u8>> {
        if n >= 256 {
            panic!("Pkcs7 does not work for block sizes >= 256");
        }

        let mut data = data.to_vec();
        // Calculate the amount of padding needed.
        let m = n - data.0.len() % n;
        // If the data is already a multiple of the block size, an entire block of
        // padding is needed.
        let m = if m == 0 { n } else { m };
        // Add the padding.
        data.0.resize(data.0.len() + m, m.try_into().unwrap());
        data
    }

    fn unpad(data: Plaintext<&[u8]>, n: usize) -> Result<Plaintext<Vec<u8>>, Self::Err> {
        if n >= 256 {
            panic!("Pkcs7 does not work for block sizes >= 256");
        }

        let m: usize = data
            .0
            .last()
            .ok_or(InvalidPadding)?
            .to_owned()
            .try_into()
            .unwrap();
        if m == 0 || m > n {
            return Err(InvalidPadding);
        }
        let padding = &data.0[data.0.len() - m..];
        if !padding.iter().all(|&b| usize::try_from(b).unwrap() == m) {
            return Err(InvalidPadding);
        }
        Ok(Plaintext(&data.0[..data.0.len() - m]).to_vec())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid padding")]
pub struct InvalidPadding;
