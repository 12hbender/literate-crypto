pub trait IterChunks: Iterator
where
    Self: Sized,
{
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

pub struct Chunks<T, const N: usize>(T);

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
