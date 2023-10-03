mod fortuna;

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
