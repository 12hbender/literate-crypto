use {super::NUM_ROUNDS, docext::docext};

const L: usize = 6;

/// Generate the round constants used by the $\iota$ step.
///
/// This is not used in the actual implementation, since the constants are
/// hardcoded in [`RC`](super::RC).
#[allow(dead_code)]
#[docext]
pub fn rctable() -> [u64; NUM_ROUNDS] {
    let mut table = [0u64; NUM_ROUNDS];
    for (ir, val) in table.iter_mut().enumerate() {
        for j in 0..=L {
            if rc(j + 7 * ir) {
                *val |= 0x0000000000000001 << (2u32.pow(j as u32) - 1);
            }
        }
    }
    table
}

fn rc(t: usize) -> bool {
    let t = t % 255;

    if t == 0 {
        return true;
    }

    let mut r = 0x80;
    for _ in 1..=t {
        let low = r & 0x01 != 0;
        r >>= 1;
        if low {
            r ^= 0b10001110;
        }
    }
    r & 0x80 != 0
}
