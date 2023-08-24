use crate::{BlockCipher, Ciphertext, Key, Plaintext};

/// AES word size in bytes.
const WORD_SIZE: usize = 4;

/// AES block size in words.
const NB: usize = 4;

const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON: [u8; 15] = [
    0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
];

const AES128_NK: usize = 4;
const AES128_NR: usize = 10;
const AES128_BLOCK_BYTES: usize = NB * WORD_SIZE;
const AES128_KEY_BYTES: usize = AES128_NK * WORD_SIZE;
const AES128_EXPANSION_BYTES: usize = NB * (AES128_NR + 1) * WORD_SIZE;

const AES192_NK: usize = 6;
const AES192_NR: usize = 12;
const AES192_BLOCK_BYTES: usize = NB * WORD_SIZE;
const AES192_KEY_BYTES: usize = AES192_NK * WORD_SIZE;
const AES192_EXPANSION_BYTES: usize = NB * (AES192_NR + 1) * WORD_SIZE;

const AES256_NK: usize = 8;
const AES256_NR: usize = 14;
const AES256_BLOCK_BYTES: usize = NB * WORD_SIZE;
const AES256_KEY_BYTES: usize = AES256_NK * WORD_SIZE;
const AES256_EXPANSION_BYTES: usize = NB * (AES256_NR + 1) * WORD_SIZE;

pub struct Aes128;

impl BlockCipher for Aes128 {
    type Block = [u8; NB * WORD_SIZE];
    type Key = [u8; AES128_NK * WORD_SIZE];

    fn encrypt(data: Plaintext<Self::Block>, key: Key<Self::Key>) -> Ciphertext<Self::Block> {
        encrypt::<AES128_NK, AES128_NR, AES128_BLOCK_BYTES, AES128_KEY_BYTES, AES128_EXPANSION_BYTES>(
            data, key,
        )
    }

    fn decrypt(data: Ciphertext<Self::Block>, key: Key<Self::Key>) -> Plaintext<Self::Block> {
        decrypt::<AES128_NK, AES128_NR, AES128_BLOCK_BYTES, AES128_KEY_BYTES, AES128_EXPANSION_BYTES>(
            data, key,
        )
    }
}

pub struct Aes192;

impl BlockCipher for Aes192 {
    type Block = [u8; NB * WORD_SIZE];
    type Key = [u8; AES192_NK * WORD_SIZE];

    fn encrypt(data: Plaintext<Self::Block>, key: Key<Self::Key>) -> Ciphertext<Self::Block> {
        encrypt::<AES192_NK, AES192_NR, AES192_BLOCK_BYTES, AES192_KEY_BYTES, AES192_EXPANSION_BYTES>(
            data, key,
        )
    }

    fn decrypt(data: Ciphertext<Self::Block>, key: Key<Self::Key>) -> Plaintext<Self::Block> {
        decrypt::<AES192_NK, AES192_NR, AES192_BLOCK_BYTES, AES192_KEY_BYTES, AES192_EXPANSION_BYTES>(
            data, key,
        )
    }
}

pub struct Aes256;

impl BlockCipher for Aes256 {
    type Block = [u8; NB * WORD_SIZE];
    type Key = [u8; AES256_NK * WORD_SIZE];

    fn encrypt(data: Plaintext<Self::Block>, key: Key<Self::Key>) -> Ciphertext<Self::Block> {
        encrypt::<AES256_NK, AES256_NR, AES256_BLOCK_BYTES, AES256_KEY_BYTES, AES256_EXPANSION_BYTES>(
            data, key,
        )
    }

    fn decrypt(data: Ciphertext<Self::Block>, key: Key<Self::Key>) -> Plaintext<Self::Block> {
        decrypt::<AES256_NK, AES256_NR, AES256_BLOCK_BYTES, AES256_KEY_BYTES, AES256_EXPANSION_BYTES>(
            data, key,
        )
    }
}

fn encrypt<
    const NK: usize,
    const NR: usize,
    const BLOCK_BYTES: usize,     // NB * WORD_SIZE
    const KEY_BYTES: usize,       // NK * WORD_SIZE
    const EXPANSION_BYTES: usize, // NB * (NR + 1) * WORD_SIZE
>(
    data: Plaintext<[u8; BLOCK_BYTES]>,
    key: Key<[u8; KEY_BYTES]>,
) -> Ciphertext<[u8; BLOCK_BYTES]> {
    let mut state = data.0;
    let w = key_expansion::<NK, NR, KEY_BYTES, EXPANSION_BYTES>(key);
    add_round_key(&mut state, &w, 0);

    for round in 1..NR {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &w, round);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &w, NR);

    Ciphertext(state)
}

fn decrypt<
    const NK: usize,
    const NR: usize,
    const BLOCK_BYTES: usize,     // NB * WORD_SIZE
    const KEY_BYTES: usize,       // NK * WORD_SIZE
    const EXPANSION_BYTES: usize, // NB * (NR + 1) * WORD_SIZE
>(
    data: Ciphertext<[u8; BLOCK_BYTES]>,
    key: Key<[u8; KEY_BYTES]>,
) -> Plaintext<[u8; BLOCK_BYTES]> {
    let mut state = data.0;
    let w = key_expansion::<NK, NR, KEY_BYTES, EXPANSION_BYTES>(key);
    add_round_key(&mut state, &w, NR);

    for round in (1..NR).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &w, round);
        inv_mix_columns(&mut state);
    }

    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &w, 0);

    Plaintext(state)
}

fn add_round_key(state: &mut [u8], w: &[u8], round: usize) {
    state
        .iter_mut()
        .zip(&w[round * NB * WORD_SIZE..(round + 1) * NB * WORD_SIZE])
        .for_each(|(s, k)| {
            *s ^= k;
        })
}

fn sub_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = S_BOX[usize::try_from(*b).unwrap()];
    }
}

fn inv_sub_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = INV_S_BOX[usize::try_from(*b).unwrap()];
    }
}

fn shift_rows(state: &mut [u8]) {
    // Shift second row.
    state.swap(1, 13);
    state.swap(5, 9);
    state.swap(1, 9);

    // Shift third row.
    state.swap(2, 10);
    state.swap(6, 14);

    // Shift fourth row.
    state.swap(3, 7);
    state.swap(11, 15);
    state.swap(3, 11);
}

fn inv_shift_rows(state: &mut [u8]) {
    // Shift second row.
    state.swap(1, 13);
    state.swap(5, 9);
    state.swap(5, 13);

    // Shift third row.
    state.swap(2, 10);
    state.swap(6, 14);

    // Shift fourth row.
    state.swap(3, 15);
    state.swap(7, 11);
    state.swap(3, 11);
}

fn mix_columns<const BLOCK_BYTES: usize>(state: &mut [u8; BLOCK_BYTES]) {
    let copy = *state;
    state.chunks_mut(4).zip(copy.chunks(4)).for_each(|(s, c)| {
        s[0] = times_02(c[0]) ^ times_03(c[1]) ^ c[2] ^ c[3];
        s[1] = c[0] ^ times_02(c[1]) ^ times_03(c[2]) ^ c[3];
        s[2] = c[0] ^ c[1] ^ times_02(c[2]) ^ times_03(c[3]);
        s[3] = times_03(c[0]) ^ c[1] ^ c[2] ^ times_02(c[3]);
    });
}

fn inv_mix_columns<const BLOCK_BYTES: usize>(state: &mut [u8; BLOCK_BYTES]) {
    let copy = *state;
    state.chunks_mut(4).zip(copy.chunks(4)).for_each(|(s, c)| {
        s[0] = times_0e(c[0]) ^ times_0b(c[1]) ^ times_0d(c[2]) ^ times_09(c[3]);
        s[1] = times_09(c[0]) ^ times_0e(c[1]) ^ times_0b(c[2]) ^ times_0d(c[3]);
        s[2] = times_0d(c[0]) ^ times_09(c[1]) ^ times_0e(c[2]) ^ times_0b(c[3]);
        s[3] = times_0b(c[0]) ^ times_0d(c[1]) ^ times_09(c[2]) ^ times_0e(c[3]);
    });
}

fn times_02(b: u8) -> u8 {
    let mut r = b << 1;
    if b & 0x80 != 0 {
        r ^= 0x1b;
    }
    r
}

fn times_03(b: u8) -> u8 {
    times_02(b) ^ b
}

fn times_04(b: u8) -> u8 {
    times_02(times_02(b))
}

fn times_08(b: u8) -> u8 {
    times_02(times_04(b))
}

fn times_09(b: u8) -> u8 {
    times_08(b) ^ b
}

fn times_0b(b: u8) -> u8 {
    times_08(b) ^ times_03(b)
}

fn times_0d(b: u8) -> u8 {
    times_08(b) ^ times_04(b) ^ b
}

fn times_0e(b: u8) -> u8 {
    times_08(b) ^ times_04(b) ^ times_02(b)
}

fn key_expansion<
    const NK: usize,
    const NR: usize,
    const KEY_BYTES: usize,       // NK * WORD_SIZE
    const EXPANSION_BYTES: usize, // NB * (NR + 1) * WORD_SIZE
>(
    key: Key<[u8; KEY_BYTES]>,
) -> [u8; EXPANSION_BYTES] {
    let mut w = [0; EXPANSION_BYTES];
    w[0..NK * WORD_SIZE].copy_from_slice(&key.0);
    for i in NK..NB * (NR + 1) {
        let mut temp = [0; WORD_SIZE];
        temp.copy_from_slice(&w[(i - 1) * WORD_SIZE..i * WORD_SIZE]);
        if i % NK == 0 {
            rot_word(&mut temp);
            sub_bytes(&mut temp);
            temp[0] ^= RCON[i / NK];
        } else if NK > 6 && i % NK == 4 {
            sub_bytes(&mut temp);
        }
        for j in 0..WORD_SIZE {
            w[i * WORD_SIZE + j] = w[(i - NK) * WORD_SIZE + j];
        }
        w[i * WORD_SIZE..(i + 1) * WORD_SIZE]
            .iter_mut()
            .zip(temp)
            .for_each(|(w, t)| *w ^= t)
    }
    w
}

fn rot_word(word: &mut [u8; WORD_SIZE]) {
    word.rotate_left(1);
}
