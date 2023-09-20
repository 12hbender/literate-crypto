use {
    crate::{
        BlockEncrypt,
        Ciphertext,
        DaviesMeyer,
        DaviesMeyerStep,
        Hash,
        Key,
        MerkleDamgard,
        MerkleDamgardPad,
        Plaintext,
    },
    std::{iter, marker::PhantomData},
};

const KT_256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const BLOCK_BYTES: usize = 64;

type Block = [u8; BLOCK_BYTES];

type Sha1State = [u32; 5];

type Sha2State = [u32; 8];

#[derive(Debug)]
pub struct Sha1(
    MerkleDamgard<Sha1State, Block, DaviesMeyer<Shacal1, Plus<Sha1State>>, LengthPadding>,
);

#[derive(Debug)]
pub struct Sha256(
    MerkleDamgard<Sha2State, Block, DaviesMeyer<Shacal2, Plus<Sha2State>>, LengthPadding>,
);

#[derive(Debug)]
pub struct Sha224(
    MerkleDamgard<Sha2State, Block, DaviesMeyer<Shacal2, Plus<Sha2State>>, LengthPadding>,
);

#[derive(Debug)]
struct Shacal1(());

#[derive(Debug)]
struct Shacal2(());

impl Default for Sha1 {
    fn default() -> Self {
        Self(MerkleDamgard::new(
            DaviesMeyer::new(Shacal1(()), Plus(Default::default())),
            LengthPadding(()),
            [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
        ))
    }
}

impl Hash for Sha1 {
    type Output = [u8; 20];

    fn hash(&self, input: &[u8]) -> Self::Output {
        let mut result = [0; 20];
        self.0
            .hash(input)
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .zip(result.iter_mut())
            .for_each(|(b, r)| *r = b);
        result
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self(MerkleDamgard::new(
            DaviesMeyer::new(Shacal2(()), Plus(Default::default())),
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

    fn hash(&self, input: &[u8]) -> Self::Output {
        let mut result = [0; 32];
        self.0
            .hash(input)
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .zip(result.iter_mut())
            .for_each(|(b, r)| *r = b);
        result
    }
}

impl Default for Sha224 {
    fn default() -> Self {
        Self(MerkleDamgard::new(
            DaviesMeyer::new(Shacal2(()), Plus(Default::default())),
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

    fn hash(&self, input: &[u8]) -> Self::Output {
        let mut result = [0; 28];
        self.0
            .hash(input)
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .zip(result.iter_mut())
            .for_each(|(b, r)| *r = b);
        result
    }
}

impl BlockEncrypt for Shacal1 {
    type EncryptionBlock = Sha1State;
    type EncryptionKey = Block;

    fn encrypt(
        &self,
        data: Plaintext<Self::EncryptionBlock>,
        key: Key<Self::EncryptionKey>,
    ) -> Ciphertext<Self::EncryptionBlock> {
        let state = data.0;
        let block = key.0;

        // Initialize the message schedule.
        let mut schedule = [0; 16];
        schedule
            .iter_mut()
            .zip(block.array_chunks::<4>())
            .for_each(|(s, b)| *s = u32::from_be_bytes(*b));

        for (i, w) in schedule.iter().enumerate() {
            println!("W[{}] = {:08x}", i, w);
        }
        println!();

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

            println!(
                "t = {} {:08X} {:08X} {:08X} {:08X} {:08X}",
                t, a, b, c, d, e
            );
        }

        println!();
        Ciphertext([a, b, c, d, e])
    }
}

impl BlockEncrypt for Shacal2 {
    type EncryptionBlock = Sha2State;
    type EncryptionKey = Block;

    fn encrypt(
        &self,
        data: Plaintext<Self::EncryptionBlock>,
        key: Key<Self::EncryptionKey>,
    ) -> Ciphertext<Self::EncryptionBlock> {
        let state = data.0;
        let block = key.0;

        // Initialize the message schedule.
        let mut schedule = [0; 16];
        schedule
            .iter_mut()
            .zip(block.array_chunks::<4>())
            .for_each(|(s, b)| *s = u32::from_be_bytes(*b));

        for (i, w) in schedule.iter().enumerate() {
            println!("W[{}] = {:08x}", i, w);
        }
        println!();

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

            println!(
                "t = {} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X} {:08X}",
                t, a, b, c, d, e, f, g, h
            );
        }

        println!();
        Ciphertext([a, b, c, d, e, f, g, h])
    }
}

fn ft(t: u32, x: u32, y: u32, z: u32) -> u32 {
    match t {
        0..=19 => ch(x, y, z),
        40..=59 => maj(x, y, z),
        _ => parity(x, y, z),
    }
}

fn kt(t: u32) -> u32 {
    match t {
        0..=19 => 0x5a827999,
        20..=39 => 0x6ed9eba1,
        40..=59 => 0x8f1bbcdc,
        _ => 0xca62c1d6,
    }
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn uppercase_sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn uppercase_sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn lowercase_sigma_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn lowercase_sigma_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// TODO The davies-meyer step in SHA-2 is modular addition
#[derive(Debug)]
struct Plus<State>(PhantomData<State>);

impl<State> DaviesMeyerStep for Plus<State>
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

// TODO Talk about length extension attacks, and how the sponge construction
// used by SHA3 mitigates them
// TODO Speaking of which, maybe I should implement the general "sponge
// construction" too similar to MerkleDamgard? Does this make any sense? I think
// so
#[derive(Debug)]
struct LengthPadding(());

impl MerkleDamgardPad for LengthPadding {
    type Block = Block;

    fn pad(&self, input: &[u8]) -> impl Iterator<Item = Self::Block> {
        input
            .chunks(BLOCK_BYTES)
            .chain(
                // If the input is a multiple of the block size, a full block of padding needs to
                // be added.
                iter::once([].as_slice()).take(if input.len() % BLOCK_BYTES == 0 { 1 } else { 0 }),
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
                    next[BLOCK_BYTES - 8..]
                        .copy_from_slice(&u64::try_from(8 * input.len()).unwrap().to_be_bytes());
                    vec![block, next]
                } else {
                    // This block needs to be padded.
                    let mut block = [0u8; BLOCK_BYTES];
                    block[..chunk.len()].copy_from_slice(chunk);
                    block[chunk.len()] = 0x80;
                    block[BLOCK_BYTES - 8..]
                        .copy_from_slice(&u64::try_from(8 * input.len()).unwrap().to_be_bytes());
                    vec![block]
                }
            })
    }
}
