mod fortuna;

use std::ops::Range;

pub use fortuna::Fortuna;

/// Cryptographically secure pseudorandom number generator.
///
/// A pseudorandom number generator generates random-looking numbers. The reason
/// why they are referred to as _pseudo_ random is because they're not truly
/// random: they're deterministically computed from an initial value called the
/// _seed_. On the other hand, true randomness is referred to as
/// [entropy](Entropy), and typically the seed is generated using a source of
/// entropy.
///
/// The random numbers are yielded by [`into_iter`](IntoIterator::into_iter).
pub trait Csprng: IntoIterator<Item = u8> {}

/// A source of entropy.
///
/// Typically, this is a hardware component which generates "true randomness"
/// based on the environment, such as the environmental noise, typing and mouse
/// movement patterns, static noise coming from other hardware components, and
/// other similar unpredictable sources.
///
/// In practical implementations, the source of entropy is usually implemented
/// by the operating system. For example, Linux's [`getrandom`](https://web.archive.org/web/20231003160929/https://man7.org/linux/man-pages/man2/getrandom.2.html).
pub trait Entropy {
    /// Fetch some random bytes from the entropy source.
    fn get(&mut self, buf: &mut [u8]);
}

/// Draw a uniformly random number from a range.
///
/// Being uniformly random means that every number in the range has equal chance
/// of being drawn, except negligible difference.
pub fn uniform_random(rand: &mut impl Iterator<Item = u8>, range: Range<u32>) -> u32 {
    let draw = u32::from_le_bytes([
        rand.next().unwrap(),
        rand.next().unwrap(),
        rand.next().unwrap(),
        rand.next().unwrap(),
    ]);
    let result = u64::from(range.start)
        + u64::from(range.end - range.start) * u64::from(draw) / u64::from(u32::MAX);
    result.try_into().unwrap()
}

/// Randomly shuffle the elements of a slice.
///
/// This works by walking the slice and swapping the current element with a
/// random element picked from the remainder of the slice to the right. This is
/// equivalent to randomly removing elements from the slice and pushing them
/// into an empty container, but more efficient since it operates in-place.
pub fn shuffle<T>(rand: &mut impl Iterator<Item = u8>, elems: &mut [T]) {
    let len = u32::try_from(elems.len()).unwrap();
    for i in 0..len - 1 {
        let j = uniform_random(rand, i + 1..len);
        elems.swap(i.try_into().unwrap(), j.try_into().unwrap());
    }
}
