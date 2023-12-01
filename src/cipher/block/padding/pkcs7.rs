use {crate::Padding, docext::docext, std::fmt};

// TODO Include some examples for what this would look like?
/// PKCS #7, a simple approach to padding.
///
/// If the message needs to be padded with $n$ bytes and the block size is $B$,
/// this padding scheme will append $n$ bytes with the value $n$. If $n = 0$,
/// then an entire block of padding is appended, i.e. $B$ bytes with the value
/// $B$.
///
/// Note that this scheme does not work for $B \ge 256$, since $255$ is the
/// maximum value for a single byte.
#[docext]
#[derive(Debug, Default)]
pub struct Pkcs7(());

impl Padding for Pkcs7 {
    type Err = InvalidPadding;

    fn pad(&self, mut data: Vec<u8>, n: usize) -> Vec<u8> {
        if n >= 256 {
            panic!("Pkcs7 does not work for block sizes >= 256");
        }

        // Calculate the amount of padding needed.
        let m = n - data.len() % n;
        // If the data is already a multiple of the block size, an entire block of
        // padding is needed.
        let m = if m == 0 { n } else { m };
        // Add the padding.
        data.resize(data.len() + m, m.try_into().unwrap());
        data
    }

    fn unpad(&self, mut data: Vec<u8>, n: usize) -> Result<Vec<u8>, Self::Err> {
        if n >= 256 {
            panic!("Pkcs7 does not work for block sizes >= 256");
        }

        let m: usize = data
            .last()
            .ok_or(InvalidPadding)?
            .to_owned()
            .try_into()
            .unwrap();
        if m == 0 || m > n {
            return Err(InvalidPadding);
        }
        let padding = &data[data.len() - m..];
        if !padding.iter().all(|&b| usize::try_from(b).unwrap() == m) {
            return Err(InvalidPadding);
        }
        data.truncate(data.len() - m);
        Ok(data)
    }
}

#[derive(Debug)]
pub struct InvalidPadding;

impl fmt::Display for InvalidPadding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid padding")
    }
}
