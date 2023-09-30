mod fortuna;

/// Cryptographically secure pseudorandom number generator.
///
/// TODO Explain what this means and how it's different from a regular PRNG.
pub trait Csprng {
    fn next(&mut self) -> u8;

    fn iter(&mut self) -> impl Iterator<Item = u8>
    where
        Self: Sized,
    {
        CsprngIter(self)
    }
}

/// A source of entropy.
///
/// Typically, this is a hardware component which generates "true randomness"
/// based on the environment, such as the environmental noise, typing and mouse
/// movement patterns, static noise coming from other hardware components, and
/// other similar unpredictable sources.
pub trait Entropy {
    fn get(&mut self, buf: &mut [u8]);
}

struct CsprngIter<'a, C>(&'a mut C);

impl<C: Csprng> Iterator for CsprngIter<'_, C> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0.next())
    }
}
