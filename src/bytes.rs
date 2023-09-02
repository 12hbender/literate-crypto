/// A fixed-size byte array.
pub trait Bytes:
    'static
    + for<'a> TryFrom<&'a [u8], Error = std::array::TryFromSliceError>
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Clone
    + Copy
    + Sized
    + IntoIterator<Item = u8>
    + std::fmt::Debug
{
}

impl<const N: usize> Bytes for [u8; N] {}
