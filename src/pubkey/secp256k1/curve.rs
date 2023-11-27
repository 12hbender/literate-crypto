use {
    super::Num,
    std::{fmt, ops},
};

/// A point on the secp256k1 curve, possibly at infinity.
#[derive(Debug, Clone, Copy)]
pub struct Point(Finiteness);

#[derive(Debug, Clone, Copy)]
enum Finiteness {
    /// The point at infinity.
    Infinite,
    Finite(Num, Num),
}

impl ops::Add for Point {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self.0, rhs.0) {
            (Finiteness::Infinite, other) | (other, Finiteness::Infinite) => {
                // Infinity is the identity element.
                Self(other)
            }
            (Finiteness::Finite(x1, y1), Finiteness::Finite(x2, y2)) if x1 == x2 && y1 == y2 => {
                // Special formula for adding a point to itself, aka point doubling.
                let Some(inv) = (Num::TWO * y1).inv() else {
                    return Self(Finiteness::Infinite);
                };
                let h = Num::THREE * x1 * x1 * inv;
                let x = h * h - Num::TWO * x1;
                Self(Finiteness::Finite(x, h * (x1 - x) - y1))
            }
            (Finiteness::Finite(x1, y1), Finiteness::Finite(x2, y2)) => {
                // Regular point addition formula.
                let Some(inv) = (x2 - x1).inv() else {
                    return Self(Finiteness::Infinite);
                };
                let h = (y2 - y1) * inv;
                let x = h * h - x1 - x2;
                Self(Finiteness::Finite(x, h * (x1 - x) - y1))
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
        if y * y == x * x * x + Num::SEVEN {
            Ok(Self(Finiteness::Finite(x, y)))
        } else {
            Err(InvalidPoint)
        }
    }

    pub fn infinity() -> Self {
        Self(Finiteness::Infinite)
    }

    /// Multiply the point by a scalar.
    pub fn mult(&self, n: Num) -> Self {
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
