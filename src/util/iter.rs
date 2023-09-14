pub(crate) trait IterChunks: Iterator
where
    Self: Sized,
{
    /// Iterate over chunks of `N` items, collecting them into arrays. Similar
    /// to [`slice::chunks`].
    fn chunks<const N: usize>(self) -> Chunks<Self, N> {
        Chunks(self)
    }
}

impl<T> IterChunks for T
where
    T: Iterator,
    T::Item: Default + Copy,
{
}

pub(crate) struct Chunks<T, const N: usize>(T);

impl<T, const N: usize> Iterator for Chunks<T, N>
where
    T: Iterator,
    T::Item: Default + Copy,
{
    type Item = [T::Item; N];

    fn next(&mut self) -> Option<Self::Item> {
        let mut result = [T::Item::default(); N];
        result[0] = self.0.next()?;
        for r in result.iter_mut().skip(1) {
            *r = self
                .0
                .next()
                .expect("chunk should be complete, otherwise this is a bug");
        }
        Some(result)
    }
}

/// An iterator which yields items from one of two different iterator types.
/// Models a logical "OR" combination for iterator types.
pub(crate) enum EitherIter<A, B> {
    A(A),
    B(B),
}

impl<Item, A, B> Iterator for EitherIter<A, B>
where
    A: Iterator<Item = Item>,
    B: Iterator<Item = Item>,
{
    type Item = Item;

    fn next(&mut self) -> Option<Item> {
        match self {
            EitherIter::A(a) => a.next(),
            EitherIter::B(b) => b.next(),
        }
    }
}