use docext::docext;

/// Pkcs7 is a simple approach to padding.
///
/// If the message needs to be padded with $n$ bytes and the block size is $B$,
/// this padding scheme will append $n$ bytes with the value $n$. If $n = 0$,
/// then an entire block of padding is added, i.e. $B$ bytes with the value $B$.
///
/// # Examples
#[docext]
pub struct Pkcs7<const N: usize>;
