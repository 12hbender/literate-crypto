//! SHA-3 is a modern hash function.
//!
//! SHA-3 is based on the [_sponge construction_](sponge). It keeps an internal
//! state, splits the input data into blocks and processes them one by one,
//! updating the state. Each step is carried out in a fixed number of rounds.
//! This is called the absorbing phase, an analogy to a sponge soaking up water.
//!
//! After all blocks are processed, part of the internal state is used to
//! extract a piece of the hash output, and then the entirety of the internal
//! state is processed again to generate a new state. This is repeated until the
//! desired output length is reached. This is called the squeezing phase,
//! an analogy to a sponge being squeezed out.
//!
//! The block size (r, also known as rate) and the output size (d) are
//! parameters of the hashing algorithm. There is also an implicit parameter
//! called the capacity (c), which is the difference between the block size and
//! the size of the internal state. The capacity is important for security, and
//! if it is too small, the hash function becomes vulnerable to attacks.
//!
//! The SHA-3 hash is specified in [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf).

use {
    super::Hash,
    crate::util::{EitherIter, IterChunks},
    docext::docext,
    std::iter,
};

mod rctable;

pub use rctable::rctable;

/// [SHA-3 hash](self) with 224-bit output.
#[derive(Debug, Default)]
pub struct Sha3_224(());

impl Hash for Sha3_224 {
    type Output = [u8; 28];

    fn hash(&self, input: &[u8]) -> Self::Output {
        sponge::<144, 28>(input)
    }
}

/// [SHA-3 hash](self) with 256-bit output.
#[derive(Debug, Default)]
pub struct Sha3_256(());

impl Hash for Sha3_256 {
    type Output = [u8; 32];

    fn hash(&self, input: &[u8]) -> Self::Output {
        sponge::<136, 32>(input)
    }
}

/// [SHA-3 hash](self) with 384-bit output.
#[derive(Debug, Default)]
pub struct Sha3_384(());

impl Hash for Sha3_384 {
    type Output = [u8; 48];

    fn hash(&self, input: &[u8]) -> Self::Output {
        sponge::<104, 48>(input)
    }
}

/// [SHA-3 hash](self) with 512-bit output.
#[derive(Debug, Default)]
pub struct Sha3_512(());

impl Hash for Sha3_512 {
    type Output = [u8; 64];

    fn hash(&self, input: &[u8]) -> Self::Output {
        sponge::<72, 64>(input)
    }
}

const NUM_ROWS: usize = 5;
const NUM_COLS: usize = 5;

/// Number of rounds in the [Keccak-p permutation](keccak_p).
pub const NUM_ROUNDS: usize = 24;

/// The internal state of the [SHA-3 algorithm](self), also referred to as $A$.
/// This is a 5x5 matrix of 64-bit words.
///
/// The state is accessed as $A_{x, y, z}$, where $x$ is the column, $y$ is the
/// row and $z$ is the _bit_ being accessed, $x, y \in \\{ 0, 1, \dots, 4 \\}$,
/// $z \in \\{ 0, 1, \dots, 63 \\}$. The bit can be omitted to access the entire
/// word.
#[docext]
pub type State = [[u64; NUM_COLS]; NUM_ROWS];

/// The offsets used by the $\rho$ step.
#[docext]
pub const RHO_OFFSETS: [[u32; NUM_COLS]; NUM_ROWS] = [
    [0, 1, 190, 28, 91],
    [36, 300, 6, 55, 276],
    [3, 10, 171, 153, 231],
    [105, 45, 15, 21, 136],
    [210, 66, 253, 120, 78],
];

/// The round constants used by the $\iota$ step. These were generated via
/// [`rctable`](rctable::rctable).
#[docext]
pub const RC: [u64; NUM_ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// The sponge construction with the rate (block size) `R` and output size `D`,
/// and function [Keccak-p](keccak_p).
///
/// This process is described in the [module documentation](self).
pub fn sponge<const R: usize, const D: usize>(input: &[u8]) -> [u8; D] {
    let mut state = State::default();

    // Absorbing phase.
    for block in pad10star1::<R>(input) {
        block
            .into_iter()
            .chain(iter::repeat(0))
            .chunks::<8>()
            .zip(state.iter_mut().flatten())
            .for_each(|(b, r)| *r ^= u64::from_le_bytes(b));
        keccak_p(&mut state);
    }

    // Squeezing phase.
    let mut output = [0; D];
    state
        .iter()
        .flatten()
        .flat_map(|b| b.to_le_bytes())
        .zip(output.iter_mut())
        .for_each(|(s, r)| *r = s);
    output
}

/// The Keccak-p permutation specified in Section 3.3 of the specification.
///
/// Applies [`NUM_ROUNDS`] rounds of the [$\theta$](theta), [$\rho$](rho),
/// [$\pi$](pi), [$\chi$](chi), and [$\iota$](iota) steps.
///
/// The $\theta$, $\rho$, and $\pi$ steps add diffusion.
///
/// The $\chi$ step adds non-linearity with AND operations, which is crucial for
/// security.
///
/// The $\iota$ step adds a round constant to the state.
#[docext]
pub fn keccak_p(state: &mut State) {
    for ir in 0..NUM_ROUNDS {
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, ir);
    }
}

/// The $\theta$ step specified in Section 3.2.1 of the specification.
///
/// First, a new word array $C$ is computed:
///
/// $$
/// C_{x, z} = A_ {x, 0, z} \oplus A_{x, 1, z} \oplus A_{x, 2, z} \oplus A_{x,
/// 3, z} \oplus A_{x, 4, z},\newline
/// x \in \\{0, 1, \dots, 4\\},
/// z \in \\{0, 1, \dots, 63\\}
/// $$
///
/// Where $A$ is the [internal state](State). To operate on words instead of
/// bits, the $z$ index can be omitted:
///
/// $$
/// C_{x} = A_ {x, 0} \oplus A_{x, 1} \oplus A_{x, 2} \oplus A_{x, 3} \oplus
/// A_{x, 4},\newline
/// x \in \\{0, 1, \dots, 4\\},
/// $$
///
/// Clearly, $C_{x}$ is the XOR of all words in column $x$ of $A$.
///
/// Next, a word array $D$ is computed:
///
/// $$
/// D_{x, z} = C_{x - 1 \pmod{5}, \space z} \oplus C_{x + 1 \pmod{5}, \space z -
/// 1 \pmod{64}},\newline
/// x \in \\{0, 1, \dots, 4\\},
/// z \in \\{0, 1, \dots, 63\\}
/// $$
///
/// The only interesting bit is that $D_{\dots, \space z}$ is computed using
/// $C_{\dots, \space z - 1 \pmod{64}}$. The $z - 1 \pmod{64}$ represents a
/// rotation of the word by one bit to the right. However, due to the specific
/// bit convention used by SHA-3 (described in Section B.1 of the
/// specification — essentially, the bit order in the specification is left to
/// right, whereas computers order bits right to left, the rightmost bit being
/// the least significant), this rotation is actually a rotation to the left:
///
/// $$
/// D_{x} = C_{x - 1 \pmod{5}} \oplus \mathrm{ROTL}(C_{x + 1 \pmod{5}}),\newline
/// x \in \\{0, 1, \dots, 4\\},
/// z \in \\{0, 1, \dots, 63\\}
/// $$
///
/// Where $\mathrm{ROTL}$ is the left rotation by one bit.
///
/// Finally, the state is updated:
/// $$
/// A_{x, y, z}^{\prime} = A_{x, y, z} \oplus D_{x, z},\newline
/// x, y \in \\{0, 1, \dots, 4\\},
/// z \in \\{0, 1, \dots, 63\\}
/// $$
///
/// Which is equivalent to the following operations on words:
/// $$
/// A_{x, y}^{\prime} = A_{x, y} \oplus D_{x},\newline
/// x, y \in \\{0, 1, \dots, 4\\}
/// $$
///
/// Since $D$ only depends on $C$, and $C$ is never updated, the $D$ array can
/// be inlined:
///
/// $$
/// A_{x, y}^{\prime} = A_{x, y} \oplus C_{x - 1 \pmod{5}} \oplus
/// \mathrm{ROTL}(C_{x + 1 \pmod{5}}),\newline
/// x, y \in \\{0, 1, \dots, 4\\},\newline
/// A \gets A^{\prime}
/// $$
#[docext]
#[allow(clippy::needless_range_loop)]
pub fn theta(state: &mut State) {
    // Set c[x] to the XOR of all rows at column x.
    let mut c = [0u64; NUM_COLS];
    for y in 0..NUM_ROWS {
        for x in 0..NUM_COLS {
            c[x] ^= state[y][x];
        }
    }

    for y in 0..NUM_ROWS {
        for x in 0..NUM_COLS {
            state[y][x] ^= c[if x == 0 { NUM_COLS - 1 } else { x - 1 }];
            state[y][x] ^= c[(x + 1) % NUM_COLS].rotate_left(1);
        }
    }
}

/// The $\rho$ step specified in Section 3.2.2 of the specification.
///
/// This step rotates each word in the state by a fixed amount of bits, encoded
/// in the [`RHO_OFFSETS`](RHO_OFFSETS) table, referred to as $\rho$.
///
/// $$
/// A_{x, y, z} \gets A_{x, y, z - \rho(x, y)} \Rightarrow
/// A_{x, y} \gets \mathrm{ROTL}(A_{x, y}, \rho(x, y)),\newline
/// x, y \in \\{0, 1, \dots, 4\\},
/// z \in \\{0, 1, \dots, 63\\}
/// $$
///
/// Where $\mathrm{ROTL}(b, n)$ is the binary left rotation of number $b$ by $n$
/// bits.
#[docext]
#[allow(clippy::needless_range_loop)]
pub fn rho(state: &mut State) {
    for y in 0..NUM_ROWS {
        for x in 0..NUM_COLS {
            state[y][x] = state[y][x].rotate_left(RHO_OFFSETS[y][x]);
        }
    }
}

/// The $\pi$ step specified in Section 3.2.3 of the specification.
///
/// Shuffles the words in the state:
///
/// $$
/// A_{x, y, z}^{\prime} = A_{(x + 3y) \pmod{5}, \space x, \space z},
/// \Rightarrow A_{x, y}^{\prime} = A_{(x + 3y) \pmod{5}, \space x}, \newline
/// x, y \in \\{0, 1, \dots, 4\\},
/// z \in \\{0, 1, \dots, 63\\},\newline
/// A \gets A^{\prime}
/// $$
#[docext]
#[allow(clippy::needless_range_loop)]
pub fn pi(state: &mut State) {
    let copy = *state;
    for y in 0..NUM_ROWS {
        for x in 0..NUM_COLS {
            state[y][x] = copy[x][(x + 3 * y) % NUM_COLS];
        }
    }
}

/// The $\chi$ step specified in Section 3.2.4 of the specification.
///
/// Adds nonlinearity by applying a binary AND operation to words:
///
/// $$
/// A_{x, y, z}^{\prime} = A_{x, y, z} \oplus ((A_{(x+1) \pmod{5}, \space y,
/// \space z} \oplus 1) \cdot A_{(x+2) \pmod{5}, \space y, \space z}),\newline
/// x, y \in \\{0, 1, \dots, 4\\},
/// z \in \\{0, 1, \dots, 63\\}
/// $$
///
/// Where $\cdot$ is the binary AND operation. $b \oplus 1$ is equivalent to a
/// bitwise NOT of bit $b$, hence we can apply the above to words as follows:
///
/// $$
/// A_{x, y}^{\prime} = A_{x, y} \oplus ((\mathrm{NOT}(A_{(x+1) \pmod{5}, \space
/// y })) \cdot A_{(x+2) \pmod{5}, \space y}) \newline
/// x, y \in \\{0, 1, \dots, 4\\},\newline
/// A \gets A^{\prime}
/// $$
#[docext]
#[allow(clippy::needless_range_loop)]
pub fn chi(state: &mut State) {
    let copy = *state;
    for y in 0..NUM_ROWS {
        for x in 0..NUM_COLS {
            state[y][x] = copy[y][x] ^ (!copy[y][(x + 1) % NUM_ROWS] & copy[y][(x + 2) % NUM_ROWS]);
        }
    }
}

/// The $\iota$ step specified in Section 3.2.5 of the specification.
///
/// Applies a round constant to the state, depending on the round number $i_r$:
///
/// $$
/// A_{0, 0} \gets A_{0, 0} \oplus RC_{i_r}
/// $$
///
/// Round constant generation is implemented in [`rctable`](rctable::rctable).
#[docext]
pub fn iota(state: &mut State, ir: usize) {
    state[0][0] ^= RC[ir];
}

/// Pad the input data to a multiple of the block size (r, also known as rate)
/// in the Keccak-p permutation.
///
/// The padding is specified in Section 5.1 of the specification, called
/// pad10*1. It pads the data by adding a single 1 bit, as many 0 bits as
/// needed, and a final 1 bit.
///
/// Additionally, the bit string "10" is appended to the data before padding.
/// This is called the _domain separator_ and serves to disambiguate SHA-3's
/// usage of Keccak-p from other uses of Keccak-p.
#[docext]
pub fn pad10star1<const R: usize>(data: &[u8]) -> impl Iterator<Item = [u8; R]> + '_ {
    // TODO I can simplify this and remove EitherIter

    if data.len() % R == 0 {
        let mut padding = [0; R];
        padding[0] = 0b00000110;
        padding[R - 1] = 0b10000000;
        return EitherIter::A(
            data.chunks(R)
                .map(|block| block.try_into().unwrap())
                .chain(iter::once(padding)),
        );
    }

    EitherIter::B(data.chunks(R).map(|block| {
        if block.len() == R {
            block.try_into().unwrap()
        } else {
            let mut padded = [0; R];
            block
                .iter()
                .copied()
                .chain(iter::repeat(0))
                .zip(padded.iter_mut())
                .enumerate()
                .for_each(|(i, (mut b, r))| {
                    if i == block.len() {
                        // This is the first byte of padding, so start with the domain separator
                        // "10" and a leading "1" bit. The bit order used by the specification
                        // (described in Section B.1) is the opposite of the bit order used by
                        // computers, so these constants are reversed.
                        b |= 0b00000110;
                    }
                    if i == R - 1 {
                        // This is the last byte of padding, so add a final "1" bit.
                        b |= 0b10000000;
                    }
                    *r = b;
                });
            padded
        }
    }))
}
