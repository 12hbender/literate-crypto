use {
    crate::{
        DaviesMeyer,
        DaviesMeyerCipher,
        DaviesMeyerStep,
        Hash,
        MerkleDamgard,
        MerkleDamgardPad,
    },
    std::iter,
};

// Block size in bytes.
const BLOCK_BYTES: usize = 64;

type State = [u32; 5];

#[derive(Debug, Default)]
pub struct Sha1(());

impl Hash for Sha1 {
    type Output = [u8; 20];

    fn hash(&self, input: &[u8]) -> Self::Output {
        let mut result = [0; 20];
        MerkleDamgard::new(
            || DaviesMeyer::new(Shacal1(()), Plus(())),
            Sha1Pad(()),
            [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
        )
        .hash(input)
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .zip(result.iter_mut())
        .for_each(|(b, r)| *r = b);
        result
    }
}

#[derive(Debug)]
struct Shacal1(());

impl DaviesMeyerCipher for Shacal1 {
    type Block = [u8; BLOCK_BYTES];
    type State = State;

    fn encrypt(&mut self, state: Self::State, block: Self::Block) -> Self::State {
        // TODO What did I spend my whole day on? Now I think I can go back to
        // BlockEncrypt + BlockDecrypt and make it stateless

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
            let ft = match t {
                0..=19 => (b & c) ^ ((!b) & d),
                40..=59 => (b & c) ^ (b & d) ^ (c & d),
                _ => b ^ c ^ d,
            };
            let kt = match t {
                0..=19 => 0x5a827999,
                20..=39 => 0x6ed9eba1,
                40..=59 => 0x8f1bbcdc,
                _ => 0xca62c1d6,
            };
            let wt = schedule[0];
            let temp = a
                .rotate_left(5)
                .wrapping_add(ft)
                .wrapping_add(e)
                .wrapping_add(kt)
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
        [a, b, c, d, e]
    }
}

// TODO The davies-meyer step in SHA1 is modular addition
struct Plus(());

impl DaviesMeyerStep for Plus {
    type State = [u32; 5];

    fn step(&self, prev: Self::State, new: Self::State) -> Self::State {
        [
            prev[0].wrapping_add(new[0]),
            prev[1].wrapping_add(new[1]),
            prev[2].wrapping_add(new[2]),
            prev[3].wrapping_add(new[3]),
            prev[4].wrapping_add(new[4]),
        ]
    }
}

#[derive(Debug)]
struct Sha1Pad(());

impl MerkleDamgardPad for Sha1Pad {
    type Block = [u8; BLOCK_BYTES];

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
