#![allow(dead_code)]
#![allow(unused_variables)]

mod rctable;

use {super::Hash, crate::util::IterChunks, std::iter};

#[derive(Debug, Default)]
pub struct Sha3_224(());

impl Hash for Sha3_224 {
    type Output = [u8; 28];

    fn hash(&self, input: &[u8]) -> Self::Output {
        sponge::<144, 28>(input)
    }
}

#[derive(Debug, Default)]
pub struct Sha3_256(());

impl Hash for Sha3_256 {
    type Output = [u8; 32];

    fn hash(&self, input: &[u8]) -> Self::Output {
        sponge::<136, 32>(input)
    }
}

#[derive(Debug, Default)]
pub struct Sha3_384(());

impl Hash for Sha3_384 {
    type Output = [u8; 48];

    fn hash(&self, input: &[u8]) -> Self::Output {
        sponge::<104, 48>(input)
    }
}

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
const NUM_ROUNDS: usize = 24;
const L: usize = 6;

type State = [[u64; NUM_COLS]; NUM_ROWS];

const RHO_OFFSETS: [[u32; NUM_COLS]; NUM_ROWS] = [
    [0, 1, 190, 28, 91],
    [36, 300, 6, 55, 276],
    [3, 10, 171, 153, 231],
    [105, 45, 15, 21, 136],
    [210, 66, 253, 120, 78],
];

const RC: [u64; NUM_ROUNDS] = [
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

fn sponge<const R: usize, const D: usize>(input: &[u8]) -> [u8; D] {
    let mut state = State::default();

    // Absorption phase.
    for block in pad10star1::<R>(input) {
        block
            .into_iter()
            .chain(iter::repeat(0))
            .chunks::<8>()
            .zip(state.iter_mut().flatten())
            .for_each(|(b, r)| *r ^= u64::from_le_bytes(b));
        keccak_p(&mut state);
    }

    // Squeeze phase.
    let mut output = [0; D];
    state
        .iter()
        .flatten()
        .flat_map(|b| b.to_le_bytes())
        .zip(output.iter_mut())
        .for_each(|(s, r)| *r = s);
    output
}

fn keccak_p(state: &mut State) {
    for ir in 0..NUM_ROUNDS {
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, ir);
    }
}

// TODO hash() should take a reference as input
// TODO So should encrypt, and I think Pad::pad should accept blocks? Or produce
// blocks?
// TODO Maybe I should have a blocks() method which returns enum Block =
// Complete | Incomplete? And pad accepts IncompleteBlock?
// TODO There's no need for that, just document it. pad
// method should pad blocks to N, and return an iterator of blocks, unpad
// should unpad vectors
// TODO The LE order and the need for "opposite" rotations is explained by
// seciton B.1, the bit string order used in the spec is the opposite of the bit
// string order used by computers

#[allow(clippy::needless_range_loop)]
fn theta(state: &mut State) {
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

#[allow(clippy::needless_range_loop)]
fn rho(state: &mut State) {
    for y in 0..NUM_ROWS {
        for x in 0..NUM_COLS {
            state[y][x] = state[y][x].rotate_left(RHO_OFFSETS[y][x]);
        }
    }
}

#[allow(clippy::needless_range_loop)]
fn pi(state: &mut State) {
    let copy = *state;
    for y in 0..NUM_ROWS {
        for x in 0..NUM_COLS {
            state[y][x] = copy[x][(x + 3 * y) % NUM_COLS];
        }
    }
}

#[allow(clippy::needless_range_loop)]
fn chi(state: &mut State) {
    let copy = *state;
    for y in 0..NUM_ROWS {
        for x in 0..NUM_COLS {
            state[y][x] = copy[y][x] ^ (!copy[y][(x + 1) % NUM_ROWS] & copy[y][(x + 2) % NUM_ROWS]);
        }
    }
}

fn iota(state: &mut State, ir: usize) {
    state[0][0] ^= RC[ir];
}

fn pad10star1<const R: usize>(data: &[u8]) -> Box<dyn Iterator<Item = [u8; R]> + '_> {
    if data.len() % R == 0 {
        let mut padding = [0; R];
        padding[0] = 0b00000110;
        padding[R - 1] = 0b10000000;
        return Box::new(
            data.chunks(R)
                .map(|block| block.try_into().unwrap())
                .chain(iter::once(padding)),
        );
    }

    Box::new(data.chunks(R).map(|block| {
        if block.len() == R {
            block.try_into().unwrap()
        } else {
            let mut padded = [0; R];
            // TODO I think the problem is once again the weird bit convention
            // TODO I need to actually understand what I'm doing, what a bit string is,
            // how to convert it to a state, and how to convert it back
            // Especially the z index of it
            // I don't understand why this would fuck with my padding
            // The padded string doesn't change based on bit order
            // The only thing that should change are the bit shifts
            block
                .iter()
                .copied()
                .chain(iter::repeat(0))
                .zip(padded.iter_mut())
                .enumerate()
                .for_each(|(i, (mut b, r))| {
                    // TODO Maybe this check is incorrect?
                    // TODO Print out the `padded` variable
                    if i == block.len() {
                        // This is the first byte of padding. TODO Explain why this is 0b01100000,
                        // the 01 is the domain separator
                        b |= 0b00000110;
                    }
                    if i == R - 1 {
                        // This is the last byte of padding.
                        b |= 0b10000000;
                    }
                    *r = b;
                });
            padded
        }
    }))
}
