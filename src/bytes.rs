use std::slice;

/// A fixed-size byte array.
///
/// Once expressions in generic constants are usable, this trait should be
/// removed and replaced with `[u8; N]`.
pub trait Bytes:
    'static
    + for<'a> TryFrom<&'a [u8], Error = std::array::TryFromSliceError>
    + for<'a> TryFrom<&'a mut [u8], Error = std::array::TryFromSliceError>
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Clone
    + Copy
    + Sized
    + IntoIterator<Item = u8>
    + std::fmt::Debug
{
    fn iter_mut(&mut self) -> slice::IterMut<'_, u8>;
}

impl<const N: usize> Bytes for [u8; N] {
    fn iter_mut(&mut self) -> slice::IterMut<'_, u8> {
        <[u8]>::iter_mut(self)
    }
}
