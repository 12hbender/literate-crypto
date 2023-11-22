use std::ops;

const DIGITS: usize = 4;

/// TODO This is little-endian.
#[derive(Debug)]
pub struct Num([u64; DIGITS]);

impl ops::Add for Num {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

/// Flag to indicate if a subtraction resulted in a borrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Borrow(bool);

/// Flag to indicate if an addition resulted in a carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Carry(bool);

/// Subtract two multi-word unsigned integers.
fn sub<const N: usize>(a: [u64; N], b: [u64; N]) -> ([u64; N], Borrow) {
    // The easiest way to understand this code is to do subtractions on paper and
    // watch how digits are borrowed from. Some examples to go through might be:
    // 591 - 202, where the middle digit is borrowed from;
    // 201 - 192, where the first two digits are borrowed from;
    // 201 - 292, where the first two digits are borrowed from and the result
    // includes a borrow bit.
    // The only difference is that in this implementation digits range from 0 to
    // u64::MAX, whereas on paper they range from 0 to 9.
    let mut borrow = false;
    let mut result = [0u64; N];
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
            let (sub, overflow) = r.overflowing_sub(borrow as u64);
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

fn extend(num: [u64; DIGITS]) -> [u64; 2 * DIGITS] {
    let mut result = [0u64; 2 * DIGITS];
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
        assert_eq!(sub([15], [18]), ([u64::MAX - 2], Borrow(true)));
        // Two digits, no borrow.
        assert_eq!(sub([18, 1], [15, 0]), ([3, 1], Borrow(false)));
        // Two digits, last needs a borrow.
        assert_eq!(sub([18, 0], [15, 1]), ([3, u64::MAX], Borrow(true)));
        // Two digits, first needs a borrow.
        assert_eq!(sub([15, 1], [18, 0]), ([u64::MAX - 2, 0], Borrow(false)));
        // Two digits, both need a borrow.
        assert_eq!(
            sub([15, 0], [18, 1]),
            ([u64::MAX - 2, u64::MAX - 1], Borrow(true))
        );
        // Three digits, all need a borrow.
        assert_eq!(
            sub([15, 0, 5], [18, 1, 10]),
            ([u64::MAX - 2, u64::MAX - 1, u64::MAX - 5], Borrow(true))
        );
        // Edge case subtracting max values from zeros.
        assert_eq!(
            sub([0, 0, 0], [u64::MAX, u64::MAX, u64::MAX]),
            ([1, 0, 0], Borrow(true))
        );
    }
}
