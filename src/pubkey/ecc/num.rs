use std::{cmp, ops};

/// TODO This is little-endian, i.e. least significant byte first.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Num([Digit; DIGITS]);

const DIGITS: usize = 4;
// TODO Hardcode this correctly
const MOD: [Digit; DIGITS] = [0; DIGITS];

type Digit = u64;

impl ops::Add for Num {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (n, carry) = add(self.0, rhs.0);
        // TODO Special handling for carry, figure it out
        Self(reduce(n, MOD))
    }
}

// TODO Verify that I also need inversion

/// Flag to indicate if a subtraction resulted in a borrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Borrow(bool);

/// Flag to indicate if an addition resulted in a carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Carry(bool);

/// The remainder left after a division.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rem<const N: usize>([Digit; N]);

/// Subtract two multi-word unsigned integers.
#[must_use]
fn sub<const N: usize>(a: [Digit; N], b: [Digit; N]) -> ([Digit; N], Borrow) {
    // The easiest way to understand this code is to do subtractions on paper and
    // watch how digits are borrowed from. Some examples to go through might be:
    // 591 - 202, where the middle digit is borrowed from;
    // 201 - 192, where the first two digits are borrowed from;
    // 201 - 292, where the first two digits are borrowed from and the result
    // includes a borrow bit.
    // The only difference is that in this implementation digits range from 0 to
    // Digit::MAX, whereas on paper they range from 0 to 9, and they are stored in
    // little-endian order, whereas on paper they are big-endian.
    let mut borrow = false;
    let mut result = [Digit::default(); N];
    for ((a, b), r) in a.iter().zip(&b).zip(result.iter_mut()) {
        let (sub, overflow) = a.overflowing_sub(*b);
        *r = sub;
        if overflow {
            if borrow {
                // If the subtraction overflowed, and this digit was borrowed from, then
                // subtract the borrow from the result. It is impossible for this subtraction to
                // overflow, because the result must be at least 1 due to the previous
                // subtraction having overflowed.
                *r -= 1;
            }
            // The subtraction overflowed, so borrow from the next digit.
            borrow = true;
        } else {
            // There was no overflow. Subtract the borrow bit.
            let (sub, overflow) = r.overflowing_sub(borrow as Digit);
            *r = sub;
            if overflow {
                // If subtracting the borrow bit overflowed, then the next
                // digit must be borrowed from. Don't clear the borrow bit.
            } else {
                // If subtracting the borrow bit did not overflow, then the
                // borrow bit was either already clear or it was
                // successfully "used", and hence can be cleared.
                borrow = false;
            }
        }
    }
    (result, Borrow(borrow))
}

#[must_use]
fn add<const N: usize>(a: [Digit; N], b: [Digit; N]) -> ([Digit; N], Carry) {
    todo!()
}

// TODO Document this in detail, like the above
#[must_use]
fn div<const N: usize>(n: [Digit; N], d: [Digit; N]) -> ([Digit; N], Rem<N>) {
    let mut q = [Digit::default(); N];
    let mut r = [Digit::default(); N];
    for i in (0..N * Digit::BITS as usize).rev() {
        r = shl(r);
        if get_bit(n, i) {
            r = set_bit(r, 0);
        }
        let (sub, borrow) = sub(r, d);
        if !borrow.0 {
            r = sub;
            q = set_bit(q, i);
        }
    }
    (q, Rem(r))
}

/// Reduce a number modulo another number.
#[must_use]
fn reduce<const N: usize, const P: usize>(n: [Digit; N], p: [Digit; P]) -> [Digit; P] {
    assert!(N >= P);
    let (_div, rem) = div(n, resize(p));
    resize(rem.0)
}

/// Shift all of the bits left by one.
#[must_use]
fn shl<const N: usize>(n: [Digit; N]) -> [Digit; N] {
    let mut res = [Digit::default(); N];
    let mut msb = false;
    for (i, digit) in n.into_iter().enumerate() {
        res[i] = digit.wrapping_shl(1);
        // If the most significant bit was shifted out of the previous digit, the next
        // digit should have the least significant bit set after the shift.
        if msb {
            res[i] |= 1;
        }
        msb = digit & (1 << (Digit::BITS - 1)) != 0;
    }
    res
}

/// Get the bit at the given index. Note that the rightmost bit is at index
/// 0, the leftmost at index 255.
#[must_use]
fn get_bit<const N: usize>(n: [Digit; N], i: usize) -> bool {
    let digit = i / Digit::BITS as usize;
    let i = i % Digit::BITS as usize;
    n[digit] & (1 << i) != 0
}

/// Set the bit at the given index. Note that the rightmost bit is at index
/// 0, the leftmost at index 255.
#[must_use]
fn set_bit<const N: usize>(mut n: [Digit; N], i: usize) -> [Digit; N] {
    let digit = i / Digit::BITS as usize;
    let i = i % Digit::BITS as usize;
    n[digit] |= 1 << i;
    n
}

/// TODO Document this
fn resize<const N: usize, const R: usize>(num: [Digit; N]) -> [Digit; R] {
    let mut result = [Digit::default(); R];
    result.iter_mut().zip(num.iter()).for_each(|(a, b)| *a = *b);
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sub() {
        use super::sub;

        // Single digit, no borrow.
        assert_eq!(sub([18], [15]), ([3], Borrow(false)));
        // Single digit with borrow.
        assert_eq!(sub([15], [18]), ([Digit::MAX - 2], Borrow(true)));
        // Two digits, no borrow.
        assert_eq!(sub([18, 1], [15, 0]), ([3, 1], Borrow(false)));
        // Two digits, last needs a borrow.
        assert_eq!(sub([18, 0], [15, 1]), ([3, Digit::MAX], Borrow(true)));
        // Two digits, first needs a borrow.
        assert_eq!(sub([15, 1], [18, 0]), ([Digit::MAX - 2, 0], Borrow(false)));
        // Two digits, both need a borrow.
        assert_eq!(
            sub([15, 0], [18, 1]),
            ([Digit::MAX - 2, Digit::MAX - 1], Borrow(true)),
        );
        // Three digits, all need a borrow.
        assert_eq!(
            sub([15, 0, 5], [18, 1, 10]),
            (
                [Digit::MAX - 2, Digit::MAX - 1, Digit::MAX - 5],
                Borrow(true)
            ),
        );
        // Edge case subtracting max values from zeros.
        assert_eq!(
            sub([0, 0, 0], [Digit::MAX, Digit::MAX, Digit::MAX]),
            ([1, 0, 0], Borrow(true)),
        );
    }

    #[test]
    fn shl() {
        use super::shl;

        assert_eq!(shl([(1 << Digit::BITS - 1), 0]), [0, 1]);
        assert_eq!(shl([1, 0]), [2, 0]);
    }

    #[test]
    fn div() {
        use super::div;

        // [65, 2] = 65 + 2 * 2^64 = 36893488147419103297
        // [12, 1] = 12 + 1 * 2^64 = 18446744073709551628
        // 36893488147419103297 mod 18446744073709551628 = 41
        let (div, rem) = div([65, 2], [12, 1]);
        assert_eq!(div, [2, 0]);
        assert_eq!(rem.0, [41, 0]);
    }

    #[test]
    fn reduce() {
        use super::reduce;

        assert_eq!(reduce([65], [12]), [5]);
        assert_eq!(reduce([65], [65]), [0]);
        assert_eq!(reduce([66], [65]), [1]);

        // [65, 2] = 65 + 2 * 2^64 = 36893488147419103297
        // [12, 1] = 12 + 1 * 2^64 = 18446744073709551628
        // 36893488147419103297 mod 18446744073709551628 = 41
        assert_eq!(reduce([65, 2], [12, 1]), [41, 0]);

        assert_eq!(
            reduce(
                [
                    Digit::MAX,
                    Digit::MAX,
                    Digit::MAX,
                    Digit::MAX,
                    Digit::MAX,
                    Digit::MAX,
                    Digit::MAX,
                    Digit::MAX,
                ],
                [Digit::MAX, Digit::MAX, Digit::MAX, Digit::MAX, 0, 0, 0, 0],
            ),
            [0, 0, 0, 0, 0, 0, 0, 0],
        );
    }
}
