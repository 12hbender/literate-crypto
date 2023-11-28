use {
    super::Num,
    std::{fmt, ops},
};

/// TODO Prime field order
pub const P: Num = Num::from_le_words([
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
]);

/// TODO Generator point
pub const G: Point = Point(Coordinates::Finite(
    Num::from_le_words([
        0x59F2815B16F81798,
        0x029BFCDB2DCE28D9,
        0x55A06295CE870B07,
        0x79BE667EF9DCBBAC,
    ]),
    Num::from_le_words([
        0x9C47D08FFB10D4B8,
        0xFD17B448A6855419,
        0x5DA4FBFC0E1108A8,
        0x483ADA7726A3C465,
    ]),
));

/// TODO Order of point G, also order of the curve
pub const N: Num = Num::from_le_words([
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
]);

/// A point on the secp256k1 curve, possibly at infinity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point(Coordinates);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coordinates {
    /// The point at infinity.
    Infinity,
    Finite(Num, Num),
}

/// TODO Document this, write the formulas in docext (I think this works)
impl ops::Add for Point {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self.0, rhs.0) {
            (Coordinates::Infinity, other) | (other, Coordinates::Infinity) => {
                // Infinity is the identity element in the group.
                Self(other)
            }
            (Coordinates::Finite(x1, y1), Coordinates::Finite(x2, y2)) if x1 == x2 && y1 == y2 => {
                // Special formula for adding a point to itself, aka point doubling.
                let Some(inv) = Num::TWO.mul(y1, P).inv(P) else {
                    return Self(Coordinates::Infinity);
                };
                let h = Num::THREE.mul(x1, P).mul(x1, P).mul(inv, P);
                let x = h.mul(h, P).sub(Num::TWO.mul(x1, P), P);
                let s = x1.sub(x, P);
                Self::new(x, h.mul(s, P).sub(y1, P)).unwrap()
            }
            (Coordinates::Finite(x1, y1), Coordinates::Finite(x2, y2)) => {
                // Regular point addition formula.
                let Some(inv) = x2.sub(x1, P).inv(P) else {
                    return Self(Coordinates::Infinity);
                };
                let h = y2.sub(y1, P).mul(inv, P);
                let x = h.mul(h, P).sub(x1, P).sub(x2, P);
                let s = x1.sub(x, P);
                Self::new(x, h.mul(s, P).sub(y1, P)).unwrap()
            }
        }
    }
}

impl ops::AddAssign for Point {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Point {
    pub fn new(x: Num, y: Num) -> Result<Self, InvalidPoint> {
        // Verify that (x, y) lies on the curve.
        if y.mul(y, P) == x.mul(x, P).mul(x, P).add(Num::SEVEN, P) {
            Ok(Self(Coordinates::Finite(x, y)))
        } else {
            Err(InvalidPoint)
        }
    }

    pub fn infinity() -> Self {
        Self(Coordinates::Infinity)
    }

    /// Get the point coordinates, or `None` if the point is at infinity.
    pub fn coordinates(&self) -> Coordinates {
        self.0
    }

    /// Multiply the point by a scalar.
    pub(super) fn scale(&self, n: Num) -> Self {
        // TODO Explain square-and-multiply
        let mut s = *self;
        let mut result = Self::infinity();
        for i in 0..Num::BITS {
            if n.get_bit(i) {
                result += s;
            }
            s += s;
        }
        result
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidPoint;

impl fmt::Display for InvalidPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid point")
    }
}

impl std::error::Error for InvalidPoint {}
