// TODO Rename this module to field, rename the ecc module to secp256k1

use std::{iter, ops};

/// TODO This is little-endian, i.e. least significant byte first.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Num([Digit; DIGITS]);

const DIGITS: usize = 4;
// TODO Hardcode this correctly
const MOD: [Digit; DIGITS] = [0; DIGITS];

type Digit = u64;
type DoubleDigit = u128;

impl ops::Add for Num {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (n, carry) = add(self.0, rhs.0);
        if carry.0 {
            // To account for the carry bit, extend n by a single most significant byte
            // equal to 1, then do the reduction.
            let mut ext = [Digit::default(); DIGITS + 1];
            ext.iter_mut()
                .zip(n.into_iter().chain(iter::once(1)))
                .for_each(|(a, b)| *a = b);
            Self(resize(reduce(ext, MOD)))
        } else {
            Self(reduce(n, MOD))
        }
    }
}

impl ops::Sub for Num {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let (n, borrow) = sub(self.0, rhs.0);
        if borrow.0 {
            // If there was a borrow, then the result is negative, so add MOD to
            // make it positive. This addition is guaranteed to result in a carry, and the
            // carry and borrow bits "cancel" each other out. Note that adding
            // MOD in a prime field modulus MOD is a no-op, and also note that
            // self and rhs are both already reduced modulus MOD before the
            // subtraction.
            let (add, carry) = add(n, MOD);
            assert!(carry.0);
            Self(add)
        } else {
            Self(n)
        }
    }
}

impl ops::Mul for Num {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(reduce(mul(self.0, rhs.0), MOD))
    }
}

// TODO Verify that I also need inversion - I do

/// Flag to indicate if a subtraction resulted in a borrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Borrow(bool);

/// Flag to indicate if an addition resulted in a carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Carry(bool);

/// The remainder left after a division.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rem<const N: usize>([Digit; N]);

/// Subtract two numbers.
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
    // LSB-first order, whereas on paper they are MSB-first.
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

/// Add two numbers.
#[must_use]
fn add<const N: usize>(a: [Digit; N], b: [Digit; N]) -> ([Digit; N], Carry) {
    // Same as addition on paper.
    let mut carry = false;
    let mut result = [Digit::default(); N];
    for ((a, b), r) in a.iter().zip(&b).zip(result.iter_mut()) {
        let (add, overflow) = a.overflowing_add(*b);
        *r = add;
        if carry {
            // If the carry bit is set, increment the result by one. If this operation
            // overflows, set the carry bit. If it doesn't overflow, then the
            // carry bit was successfully "used", so clear it.
            let (add, overflow) = a.overflowing_add(1);
            *r = add;
            carry = overflow;
        }
        if overflow {
            // If the original addition overflowed, there was a carry. This is true
            // regardless of the current state of the carry bit.
            carry = true;
        }
    }
    (result, Carry(carry))
}

/// Divide two numbers.
#[must_use]
fn div<const N: usize>(n: [Digit; N], d: [Digit; N]) -> ([Digit; N], Rem<N>) {
    // This is an implementation of long division. It's the same as long division
    // done on paper, except it's done in base 2 instead of base 10. The easiest
    // way to understand the algorithm is to do an example on paper in base ten,
    // e.g. 587 / 342, and see how the base 2 algorithm below corresponds to the
    // base 10 algorithm done on paper.
    //
    // The long division algorithm can be roughly explained in words as follows:
    // keep track of a running remainder. For each digit of the dividend, append
    // the digit to the running remainder. Count how many times the divisor can
    // be subtracted from the running remainder, do the subtractions, and append
    // the count to the result as a single digit. Note that the count may be zero.
    // The algorithm finishes when there are no more digits in the dividend,
    // resulting in a quotient and a remainder.
    let mut q = [Digit::default(); N];
    let mut r = [Digit::default(); N];
    for i in (0..N * Digit::BITS as usize).rev() {
        r = shl(r);
        if get_bit(n, i) {
            r = set_bit(r, 0);
        }
        let (sub, borrow) = sub(r, d);
        if !borrow.0 {
            // The subtraction didn't require a borrow, which means that r >= d, i.e. the
            // subtraction was successful.
            r = sub;
            // Because this is long division in base 2, only a 1 or a 0 can be appended
            // to the result. In case of successful division, a 1 is appended, and at most
            // one subtraction is made to the running remainder. This is different from long
            // division in base 10, where any digit from 0 to 9 can be appended,
            // and at most nine subtractions could be made (although in practice
            // a human does not subtract 9 times, instead he divides two small numbers in
            // his head).
            q = set_bit(q, i);
        }
    }
    (q, Rem(r))
}

/// Multiply two numbers.
#[must_use]
fn mul(a: [Digit; DIGITS], b: [Digit; DIGITS]) -> [Digit; 2 * DIGITS] {
    // Same as multiplication on paper.
    let mut result = [Digit::default(); DIGITS * 2];
    for (i, a) in a.into_iter().enumerate() {
        let mut carry = DoubleDigit::default();
        for (j, b) in b.into_iter().enumerate() {
            let m = result[i + j] as DoubleDigit + a as DoubleDigit * b as DoubleDigit + carry;
            // The upper Digit::BITS are the carry part.
            carry = (m & ((Digit::MAX as DoubleDigit) << Digit::BITS)) >> Digit::BITS;
            // The lower Digit::BITS are the digit to store at i + j.
            result[i + j] = Digit::try_from(m & Digit::MAX as DoubleDigit).unwrap();
        }
        // The final carry becomes the next digit over.
        result[i + DIGITS] = Digit::try_from(carry).unwrap();
    }
    result
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

/// Resize a number into a different width by either appending zeros to the more
/// significant bytes, or by dropping the most significant bytes.
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
