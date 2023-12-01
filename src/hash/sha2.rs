//! SHA-1 and SHA-2 are hash functions specified by [FIPS
//! 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! SHA-1 and SHA-2 are based on the [Merkle-Damgard](crate::MerkleDamgard) and
//! [Davies-Meyer](crate::DaviesMeyer) constructions. This means that each
//! hashing algorithm uses a block cipher internally, [SHACAL-1](Shacal1) and
//! [SHACAL-2](Shacal2) respectively. The block ciphers are used to mix the
//! internal state of the hash function with padded preimage blocks. The
//! final state (optionally truncated to a smaller size) is the hash digest.

use {
    crate::{
        BlockEncrypt,
        DaviesMeyer,
        DaviesMeyerStep,
        Digest,
        Hash,
        MerkleDamgard,
        MerkleDamgardPad,
        Preimage,
    },
    docext::docext,
    std::{iter, marker::PhantomData},
};

/// The $K_t^{256}$ constants for [SHA-256](Sha256).
#[docext]
pub const KT_256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const BLOCK_BYTES: usize = 64;

/// A preimage block.
pub type Block = [u8; BLOCK_BYTES];

/// The internal state of [SHA-1](Sha1).
pub type Sha1State = [u32; 5];

/// The internal state of [SHA-256](Sha256) and [SHA-224](Sha224).
pub type Sha2State = [u32; 8];

/// SHA-1 hash specified by [FIPS
/// 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
///
/// Note that this is a weak hash function with known vulnerabilities, and
/// should be avoided in practice. It is also vulnerable to [length-extension
/// attacks](MerkleDamgard#length-extension-attacks).
///
/// For more details, see the [module documentation](self).
#[derive(Debug)]
pub struct Sha1(
    MerkleDamgard<
        Sha1State,
        Block,
        DaviesMeyer<Shacal1, ModularAddition<Sha1State>>,
        LengthPadding,
    >,
);

/// SHA-256 hash specified by [FIPS
/// 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
///
/// SHA-256 is vulnerable to [length-extension
/// attacks](MerkleDamgard#length-extension-attacks).
///
/// For more details, see the [module documentation](self).
#[derive(Debug)]
pub struct Sha256(
    MerkleDamgard<
        Sha2State,
        Block,
        DaviesMeyer<Shacal2, ModularAddition<Sha2State>>,
        LengthPadding,
    >,
);

/// SHA-224 hash specified by [FIPS
/// 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
///
/// SHA-224 is the same as [SHA-256](Sha256), with the hash digest truncated to
/// 224 bits. Due to the truncation, SHA-224 is not vulnerable to
/// [length-extension attacks](MerkleDamgard#length-extension-attacks), unlike
/// SHA-256.
///
/// For more details, see the [module documentation](self).
#[derive(Debug)]
pub struct Sha224(
    MerkleDamgard<
        Sha2State,
        Block,
        DaviesMeyer<Shacal2, ModularAddition<Sha2State>>,
        LengthPadding,
    >,
);

/// The underlying block cipher used by [SHA-1](Sha1).
///
/// Applies 80 rounds of the following permutation, where $a, b, c, \dots$
/// represent the current state in 32-bit words, $W_i$ is the message
/// schedule (described below), [$f_t$](ft) is a helper function, [$K_t$](kt)
/// are the round constants, and the $\mathrm{ROTL}$ function is bitwise left
/// rotation:
///
/// $$
/// T = \mathrm{ROTL}(a, 5) + f_t(b, c, d) + e + K_t + W_0 \pmod{2^{32}}\\
/// e \gets d\\
/// d \gets c\\
/// c \gets \mathrm{ROTL}(b, 30)\\
/// b \gets a\\
/// a \gets T\\
/// $$
///
/// The message schedule $W$ is a 16 element array of 32-bit words. It is
/// initialized to the current preimage block, and updated at the end of each
/// round as follows:
///
/// $$
/// T = \mathrm{ROTL}(W_{13} \oplus W_8 \oplus W_2 \oplus W_0, 1)\\
/// W_i \gets W_{i + 1}, \forall i \in \{0, 1, \dots, 14\}\\
/// W_{15} \gets T
/// $$
///
/// Meaning, the entire array is shifted left, and then the last element is
/// updated as a combination of the other elements.
///
/// There are well-known vulnerabilities applicable to SHACAL-1 with a reduced
/// number of rounds.
#[docext]
#[derive(Debug)]
pub struct Shacal1(());

/// The underlying block cipher used by [SHA-265](Sha256) and [SHA-224](Sha224).
///
/// Applies 64 rounds of the following permutation, where $a, b, c, \dots$
/// represent the current state in 32-bit words, $W_i$ is the message
/// schedule (described later), [$\Sigma_0^{256}$](uppercase_sigma_0),
/// [$\Sigma_1^{256}$](uppercase_sigma_1),
/// [$\sigma_0^{256}$](lowercase_sigma_0), [$\sigma_1^{256}$](lowercase_sigma_1)
/// [$Ch$](ch), and [$Maj$](maj) are helper functions, and [$K_t^{256}$](KT_256)
/// are the round constants:
///
/// $$
/// T_1 = h + \Sigma_1^{256}(e) + Ch(e, f, g) + K_t^{256} + W_0
/// \pmod{2^{32}}\\
/// T_2 = \Sigma_0^{256}(a) + Maj(a, b, c) \pmod{2^{32}}\\
/// h \gets g\\
/// g \gets f\\
/// f \gets e\\
/// e \gets d + T_1\\
/// d \gets c\\
/// c \gets b\\
/// b \gets a\\
/// a \gets T_1 + T_2
/// $$
///
/// The message schedule $W$ is a 16 element array of 32-bit words. It is
/// initialized to the current preimage block, and updated at the end of each
/// round as follows:
///
/// $$
/// T = \sigma_1^{256}(W_{14}) + W_9 + \sigma_0^{256}(W_1) + W_0
/// \pmod{2^{32}}\\
/// W_i \gets W_{i + 1}, \forall i \in \{0, 1, \dots, 14\}\\
/// W_{15} \gets T
/// $$
///
/// Meaning, the entire array is shifted left, and then the last element is
/// updated as a combination of the other elements.
///
/// There are well-known vulnerabilities applicable to SHACAL-2 with a reduced
/// number of rounds.
#[docext]
#[derive(Debug)]
pub struct Shacal2(());

impl Default for Sha1 {
    fn default() -> Self {
        Self(MerkleDamgard::new(
            DaviesMeyer::new(Shacal1(()), ModularAddition(Default::default())),
            LengthPadding(()),
            [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
        ))
    }
}

impl Hash for Sha1 {
    type Output = [u8; 20];

    fn hash(&self, preimage: Preimage<&[u8]>) -> Digest<Self::Output> {
        let mut result = [0; 20];
        self.0
            .hash(preimage)
            .0
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .zip(result.iter_mut())
            .for_each(|(b, r)| *r = b);
        Digest(result)
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self(MerkleDamgard::new(
            DaviesMeyer::new(Shacal2(()), ModularAddition(Default::default())),
            LengthPadding(()),
            [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
        ))
    }
}

impl Hash for Sha256 {
    type Output = [u8; 32];

    fn hash(&self, preimage: Preimage<&[u8]>) -> Digest<Self::Output> {
        let mut result = [0; 32];
        self.0
            .hash(preimage)
            .0
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .zip(result.iter_mut())
            .for_each(|(b, r)| *r = b);
        Digest(result)
    }
}

impl Default for Sha224 {
    fn default() -> Self {
        Self(MerkleDamgard::new(
            DaviesMeyer::new(Shacal2(()), ModularAddition(Default::default())),
            LengthPadding(()),
            [
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
                0xbefa4fa4,
            ],
        ))
    }
}

impl Hash for Sha224 {
    type Output = [u8; 28];

    fn hash(&self, preimage: Preimage<&[u8]>) -> Digest<Self::Output> {
        let mut result = [0; 28];
        self.0
            .hash(preimage)
            .0
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .zip(result.iter_mut())
            .for_each(|(b, r)| *r = b);
        Digest(result)
    }
}

impl BlockEncrypt for Shacal1 {
    type EncryptionBlock = Sha1State;
    type EncryptionKey = Block;

    fn encrypt(
        &self,
        data: Self::EncryptionBlock,
        key: Self::EncryptionKey,
    ) -> Self::EncryptionBlock {
        let state = data;
        let block = key;

        // Initialize the message schedule.
        let mut schedule = [0; 16];
        schedule
            .iter_mut()
            .zip(block.array_chunks::<4>())
            .for_each(|(s, b)| *s = u32::from_be_bytes(*b));

        // Execute the rounds.
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        for t in 0..80 {
            let wt = schedule[0];
            let temp = a
                .rotate_left(5)
                .wrapping_add(ft(t, b, c, d))
                .wrapping_add(e)
                .wrapping_add(kt(t))
                .wrapping_add(wt);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;

            // Update the message schedule.
            let next = (schedule[13] ^ schedule[8] ^ schedule[2] ^ schedule[0]).rotate_left(1);
            schedule.rotate_left(1);
            schedule[15] = next;
        }

        [a, b, c, d, e]
    }
}

impl BlockEncrypt for Shacal2 {
    type EncryptionBlock = Sha2State;
    type EncryptionKey = Block;

    fn encrypt(
        &self,
        data: Self::EncryptionBlock,
        key: Self::EncryptionKey,
    ) -> Self::EncryptionBlock {
        let state = data;
        let block = key;

        // Initialize the message schedule.
        let mut schedule = [0; 16];
        schedule
            .iter_mut()
            .zip(block.array_chunks::<4>())
            .for_each(|(s, b)| *s = u32::from_be_bytes(*b));

        // Execute the rounds.
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        #[allow(clippy::needless_range_loop)]
        for t in 0..64 {
            let wt = schedule[0];
            let temp1 = h
                .wrapping_add(uppercase_sigma_1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(KT_256[t])
                .wrapping_add(wt);
            let temp2 = uppercase_sigma_0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);

            // Update the message schedule.
            let next = lowercase_sigma_1(schedule[14])
                .wrapping_add(schedule[9])
                .wrapping_add(lowercase_sigma_0(schedule[1]))
                .wrapping_add(schedule[0]);
            schedule.rotate_left(1);
            schedule[15] = next;
        }

        [a, b, c, d, e, f, g, h]
    }
}

/// Helper function $f_t$ used by [SHA-1](Sha1).
///
/// Uses [$Ch$](ch), [$Maj$](maj), and [$Parity$](parity) functions.
///
/// $$
/// f_t(x, y, z) =
/// \begin{cases}
/// Ch(x, y, z) & 0 \le t < 20\\
/// Maj(x, y, z) & 40 \le t < 60\\
/// Parity(x, y, z) & otherwise \\
/// \end{cases}
/// $$
#[docext]
pub fn ft(t: u32, x: u32, y: u32, z: u32) -> u32 {
    match t {
        0..=19 => ch(x, y, z),
        40..=59 => maj(x, y, z),
        _ => parity(x, y, z),
    }
}

/// Round constant $K_t$ used by [SHA-1](Sha1).
#[docext]
pub fn kt(t: u32) -> u32 {
    match t {
        0..=19 => 0x5a827999,
        20..=39 => 0x6ed9eba1,
        40..=59 => 0x8f1bbcdc,
        _ => 0xca62c1d6,
    }
}

/// Helper function $Ch$.
///
/// $$
/// Ch(x, y, z) = (x \land y) \oplus (\neg x \land z)
/// $$
#[docext]
pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

/// Helper function $Maj$.
///
/// $$
/// Maj(x, y, z) = (x \land y) \oplus (x \land z) \oplus (y \land z)
/// $$
#[docext]
pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Helper function $Parity$.
///
/// $$
/// Parity(x, y, z) = x \oplus y \oplus z
/// $$
#[docext]
pub fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Helper function $\Sigma_0^{256}$.
///
/// $$
/// \Sigma_0^{256}(x) = \mathrm{ROTR}(x, 2) \oplus \mathrm{ROTR}(x, 13) \oplus
/// \mathrm{ROTR}(x, 22) $$
///
/// Where $\mathrm{ROTR}$ is bitwise rotation to the right.
#[docext]
pub fn uppercase_sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Helper function $\Sigma_1^{256}$.
///
/// $$
/// \Sigma_1^{256}(x) = \mathrm{ROTR}(x, 6) \oplus \mathrm{ROTR}(x, 11) \oplus
/// \mathrm{ROTR}(x, 25) $$
///
/// Where $\mathrm{ROTR}$ is bitwise rotation to the right.
#[docext]
pub fn uppercase_sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// Helper function $\sigma_0^{256}$.
///
/// $$
/// \sigma_0^{256}(x) = \mathrm{ROTR}(x, 7) \oplus \mathrm{ROTR}(x, 18) \oplus
/// (x \gg 3) $$
///
/// Where $\mathrm{ROTR}$ is bitwise rotation to the right, and $\gg$ is the
/// bitwise right shift operation.
#[docext]
pub fn lowercase_sigma_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// Helper function $\sigma_1^{256}$.
///
/// $$
/// \sigma_1^{256}(x) = \mathrm{ROTR}(x, 17) \oplus \mathrm{ROTR}(x, 19) \oplus
/// (x \gg 10) $$
///
/// Where $\mathrm{ROTR}$ is bitwise rotation to the right, and $\gg$ is the
/// bitwise right shift operation.
#[docext]
pub fn lowercase_sigma_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Because the new state is derived by adding the "working variables" to the
/// current state, the [Davies-Meyer step](DaviesMeyerStep) in SHA-1 and SHA-2
/// is modular addition.
#[derive(Debug)]
pub struct ModularAddition<State>(PhantomData<State>);

impl<State> DaviesMeyerStep for ModularAddition<State>
where
    State: AsMut<[u32]> + AsRef<[u32]>,
{
    type State = State;

    fn step(&self, prev: Self::State, mut new: Self::State) -> Self::State {
        new.as_mut()
            .iter_mut()
            .zip(prev.as_ref().iter())
            .for_each(|(n, p)| *n = n.wrapping_add(*p));
        new
    }
}

/// SHA-2 length padding.
///
/// The preimage is padded by appending a single 1 bit, followed by as many bits
/// as needed to pad to a multiple of 512 - 64 = 448 bits, followed by the _bit
/// length_ of the preimage encoded as an unsigned big-endian 64 bit integer.
/// This results in a [Merkle-Damgard compliant padding](MerkleDamgardPad) into
/// blocks of 512 bits.
#[derive(Debug)]
pub struct LengthPadding(());

impl MerkleDamgardPad for LengthPadding {
    type Block = Block;

    fn pad(&self, preimage: Preimage<&[u8]>) -> impl Iterator<Item = Self::Block> {
        preimage
            .0
            .chunks(BLOCK_BYTES)
            .chain(
                // If the input is a multiple of the block size, a full block of padding needs to
                // be added.
                iter::once([].as_slice()).take(if preimage.0.len() % BLOCK_BYTES == 0 {
                    1
                } else {
                    0
                }),
            )
            .flat_map(|chunk| {
                if chunk.len() == BLOCK_BYTES {
                    // This block does not need padding.
                    vec![chunk.try_into().unwrap()]
                } else if BLOCK_BYTES - chunk.len() <= 8 {
                    // This block requires an additional block of padding.
                    let mut block = [0u8; BLOCK_BYTES];
                    block[..chunk.len()].copy_from_slice(chunk);
                    block[chunk.len()] = 0x80;
                    let mut next = [0u8; BLOCK_BYTES];
                    next[BLOCK_BYTES - 8..].copy_from_slice(
                        &u64::try_from(8 * preimage.0.len()).unwrap().to_be_bytes(),
                    );
                    vec![block, next]
                } else {
                    // This block needs to be padded.
                    let mut block = [0u8; BLOCK_BYTES];
                    block[..chunk.len()].copy_from_slice(chunk);
                    block[chunk.len()] = 0x80;
                    block[BLOCK_BYTES - 8..].copy_from_slice(
                        &u64::try_from(8 * preimage.0.len()).unwrap().to_be_bytes(),
                    );
                    vec![block]
                }
            })
    }
}
