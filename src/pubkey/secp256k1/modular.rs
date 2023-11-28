//! 256-bit modular arithmetic.

use {
    super::Point,
    docext::docext,
    std::{cmp, iter, mem, ops},
};

/// TODO This is little-endian, i.e. least significant byte first.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Num([Digit; DIGITS]);

const DIGITS: usize = 4;
const ZERO: [Digit; DIGITS] = [0; DIGITS];

type Digit = u64;
type DoubleDigit = u128;

impl Num {
    pub const BITS: usize = DIGITS * Digit::BITS as usize;
    pub const BYTES: usize = Self::BITS / 8;

    pub const ZERO: Self = Self(ZERO);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const TWO: Self = Self([2, 0, 0, 0]);
    pub const THREE: Self = Self([3, 0, 0, 0]);
    pub const SEVEN: Self = Self([7, 0, 0, 0]);

    pub const fn from_le_words(n: [Digit; DIGITS]) -> Self {
        Self(n)
    }

    pub fn from_le_bytes(b: [u8; DIGITS * mem::size_of::<Digit>()]) -> Self {
        const S: usize = mem::size_of::<Digit>();
        Self::from_le_words([
            Digit::from_le_bytes(b[..S].try_into().unwrap()),
            Digit::from_le_bytes(b[S..2 * S].try_into().unwrap()),
            Digit::from_le_bytes(b[2 * S..3 * S].try_into().unwrap()),
            Digit::from_le_bytes(b[3 * S..4 * S].try_into().unwrap()),
        ])
    }

    pub fn to_le_bytes(&self) -> [u8; DIGITS * mem::size_of::<Digit>()] {
        let mut result = [0u8; DIGITS * mem::size_of::<Digit>()];
        result
            .iter_mut()
            .zip(self.0.iter().flat_map(|n| n.to_le_bytes()))
            .for_each(|(a, b)| *a = b);
        result
    }

    /// Modular addition.
    #[must_use]
    pub fn add(&self, n: Self, p: Self) -> Self {
        let (n, carry) = add(self.0, n.0);
        if carry.0 {
            // To account for the carry bit, extend n by a single most significant byte
            // equal to 1, then do the reduction.
            let mut ext = [Digit::default(); DIGITS + 1];
            ext.iter_mut()
                .zip(n.into_iter().chain(iter::once(1)))
                .for_each(|(a, b)| *a = b);
            Self(reduce(ext, p.0))
        } else {
            Self(reduce(n, p.0))
        }
    }

    /// Modular subtraction.
    #[must_use]
    pub fn sub(self, n: Self, p: Self) -> Self {
        let (n, borrow) = sub(self.0, n.0);
        if borrow.0 {
            // If there was a borrow, then the result is negative, so add MOD to
            // make it positive. This addition is guaranteed to result in a carry, and the
            // carry and borrow bits "cancel" each other out. Note that adding
            // MOD in a prime field modulus MOD is a no-op, and also note that
            // self and rhs are both already reduced modulus MOD before the
            // subtraction.
            let (add, carry) = add(n, p.0);
            assert!(carry.0);
            Self(add)
        } else {
            Self(n)
        }
    }

    /// Modular multiplication.
    #[must_use]
    pub fn mul(self, n: Self, p: Self) -> Self {
        // Same as multiplication on paper.
        let mut prod = [Digit::default(); DIGITS * 2];
        for (i, a) in self.0.into_iter().enumerate() {
            let mut carry = DoubleDigit::default();
            for (j, b) in n.0.into_iter().enumerate() {
                let m = prod[i + j] as DoubleDigit + a as DoubleDigit * b as DoubleDigit + carry;
                // The upper Digit::BITS are the carry part.
                carry = (m & ((Digit::MAX as DoubleDigit) << Digit::BITS)) >> Digit::BITS;
                // The lower Digit::BITS are the digit to store at i + j.
                prod[i + j] = Digit::try_from(m & Digit::MAX as DoubleDigit).unwrap();
            }
            // The final carry becomes the next digit over.
            prod[i + DIGITS] = Digit::try_from(carry).unwrap();
        }
        Self(reduce(prod, p.0))
    }

    /// Modular equality.
    pub fn eq(self, n: Self, p: Self) -> bool {
        reduce(self.0, p.0) == reduce(n.0, p.0)
    }

    /// Get the modular multiplicative inverse of the number by using the
    /// extended Euclidean algorithm. Returns `None` for [`Num::ZERO`],
    /// since 0 has no inverse.
    ///
    /// The non-extended Euclidean algorithm computes the greatest common
    /// divisor $gcd(a, b)$ given $a, b, a \leq b$. It relies on the following
    /// fact: $gcd(a, b) = gcd(b - \lfloor \frac{b}{a} \rfloor a, a)$. This fact
    /// allows the algorithm to successively reduce the values of $a$ and
    /// $b$ until one is eventually equal to zero, and the other is equal to
    /// the greatest common divisor. The algorithm operates as follows:
    ///
    /// - Set $u = a, v = b$. The algorithm maintains the invariant that $u \leq
    ///   v$.
    /// - Iteratively update $u$ and $v$. First, get the quotient $q = \lfloor
    ///   \frac{v}{u} \rfloor$, then set the new values $v' = u, u' = v - qu$.
    ///   Note that $v - qu$ is the remainder from dividing $v$ by $u$. Call
    ///   this remainder $r$, so that $u = r$.
    /// - Terminate when $u = 0$. $v$ is the greatest common divisor.
    ///
    /// To extend the algorithm above, apply Bezout's identity. This identity
    /// states that, given two integers $a$ and $b$ with greatest common
    /// divisor $d$, there exist integers $x$ and $y$ such that $ax + by =
    /// d$.
    ///
    /// The extended algorithm will represent $u$ and $v$ as
    ///
    /// $$
    /// u = x_1a + y_1b \\
    /// v = x_2a + y_2b
    /// $$
    ///
    /// Since $u$ should be initialized to $a$, and $v$ should
    /// be initialized to $b$, the initial values for $x_{1, 2}$ and $y_{1,
    /// 2}$ are $x_1 = 1, y_1 = 0, x_2 = 0, y_2 = 1$.
    ///
    /// The rest of the algorithm is exactly the same, except that apart from
    /// updating $u$ and $v$ like the regular Euclidean algorithm, the
    /// extended Euclidean algorithm also updates $x_{1, 2}$ and $y_{1, 2}$.
    /// This is done as follows:
    ///
    /// $$
    /// x_2' = x_1 \\
    /// x_1' = x_2 - qx_1 \\
    /// y_2' = y_1 \\
    /// y_1' = y_2 - qy_1
    /// $$
    ///
    /// Where $q = \lfloor \frac{v}{u} \rfloor$ is the quotient and $r = v - qu$
    /// is the remainder, same as in the non-extended Euclidean algorithm. It is
    /// not difficult to verify that the values for $x_{1, 2}'$ and $y_{1, 2}'$
    /// are correct. Namely, it must be true that $v' = u$ and $u' = r$ as in
    /// the non-extended Euclidean algorithm. This can be shown with a few
    /// substitutions:
    ///
    /// $$
    /// v' = x_2'a + y_2'b \\
    /// v' = x_1a + y_1 b \\
    /// v' = u
    /// $$
    ///
    /// And
    ///
    /// $$
    /// u' = x_1'a + y_1'b \\
    /// u' = (x_2 - qx_1)a + (y_2 - qy_1)b \\
    /// u' = ax_2 + by_2 - (ax_1 + by_1)q \\
    /// u' = v - qu
    /// $$
    ///
    /// So $v' = u, u' = v - qu$ as expected. The algorithm terminates when $u =
    /// 0$, at which point $x_2$, $y_2$, and $v$ are the result of the
    /// algorithm.
    ///
    /// Finally, the above can be used to get a multiplicative inverse. If $b$
    /// (or $a$) is prime, the result of the algorithm will be $v = 1$ because
    /// the greatest common divisor between a prime number and any other
    /// number is 1.
    ///
    /// $$
    /// v = 1 = x_2a + y_2b
    /// $$
    ///
    /// If the operations are done in a prime field with order $b$, then
    ///
    /// $$
    /// y_2b \equiv 0 \pmod b \implies v \equiv x_2a \equiv 1 \pmod b
    /// $$
    ///
    /// This means that $x_2$ is the multiplicative inverse of $a$
    /// in the prime field with order $b$. Finally, since $y_1$ and $y_2$ are
    /// not used, they can be omitted from the algorithm as a small
    /// optimization.
    #[docext]
    #[must_use]
    pub fn inv(&self, p: Self) -> Option<Self> {
        if *self == Self::ZERO {
            return None;
        }

        let mut u = reduce(self.0, p.0);
        let mut v = p.0;
        let mut x1 = Self::ONE;
        let mut x2 = Self::ZERO;
        while u != ZERO {
            let (q, r) = div(v, u);
            v = u;
            u = r.0;
            let x = x2.sub(Self(q).mul(x1, p), p);
            x2 = x1;
            x1 = x;
        }
        Some(x2)
    }

    /// Get the bit at the given index. The rightmost (least significant) bit is
    /// at index 0.
    pub fn get_bit(&self, i: usize) -> bool {
        get_bit(self.0, i)
    }
}

impl cmp::PartialOrd for Num {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for Num {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Compare the digits in most-significant-first order.
        for (a, b) in self.0.iter().zip(other.0.iter()).rev() {
            match a.cmp(b) {
                cmp::Ordering::Less => return cmp::Ordering::Less,
                cmp::Ordering::Equal => {}
                cmp::Ordering::Greater => return cmp::Ordering::Greater,
            }
        }
        cmp::Ordering::Equal
    }
}

impl ops::Mul<Point> for Num {
    type Output = Point;

    fn mul(self, rhs: Point) -> Self::Output {
        rhs.scale(self)
    }
}

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
            let (add, overflow) = r.overflowing_add(1);
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

/// Get the bit at the given index. The rightmost (least significant) bit is at
/// index 0.
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
