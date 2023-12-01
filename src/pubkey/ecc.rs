//! Elliptic curve cryptography.

use {
    docext::docext,
    std::{fmt, marker::PhantomData, ops},
};

pub mod ecdsa;
pub mod modular;
mod secp256k1;

pub use {ecdsa::Ecdsa, secp256k1::Secp256k1};

pub trait Curve: Sized {
    /// Size of [`Curve::P`] and [`Curve::N`] in bytes.
    const SIZE: usize;

    /// Order of the prime field this curve is constructed over.
    const P: modular::Num;

    /// Order of the generator point.
    const N: modular::Num;

    /// The $a$ parameter for the elliptic curve equation $y^2 = x^3 + ax + b$.
    #[docext]
    const A: modular::Num;

    /// The $b$ parameter for the elliptic curve equation $y^2 = x^3 + ax + b$.
    #[docext]
    const B: modular::Num;

    /// The generator point for this curve.
    fn g() -> Point<Self>;
}

/// A point on the secp256k1 curve, possibly at infinity.
#[derive(Debug)]
pub struct Point<C>(Coordinates, PhantomData<C>);

impl<C> Clone for Point<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Point<C> {}

impl<C> PartialEq for Point<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<C> Eq for Point<C> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coordinates {
    /// The point at infinity.
    Infinity,
    Finite(modular::Num, modular::Num),
}

/// TODO Document this, write the formulas in docext (I think this works)
impl<C: Curve> ops::Add for Point<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self.0, rhs.0) {
            (Coordinates::Infinity, other) | (other, Coordinates::Infinity) => {
                // Infinity is the identity element in the group.
                Self(other, Default::default())
            }
            (Coordinates::Finite(x1, y1), Coordinates::Finite(x2, y2)) if x1 == x2 && y1 == y2 => {
                // Special formula for adding a point to itself, aka point doubling.
                let Some(inv) = modular::TWO.mul(y1, C::P).inv(C::P) else {
                    return Self(Coordinates::Infinity, Default::default());
                };
                let h = modular::THREE.mul(x1, C::P).mul(x1, C::P).mul(inv, C::P);
                let x = h.mul(h, C::P).sub(modular::TWO.mul(x1, C::P), C::P);
                let s = x1.sub(x, C::P);
                Self::new(x, h.mul(s, C::P).sub(y1, C::P)).unwrap()
            }
            (Coordinates::Finite(x1, y1), Coordinates::Finite(x2, y2)) => {
                // Regular point addition formula.
                let Some(inv) = x2.sub(x1, C::P).inv(C::P) else {
                    return Self(Coordinates::Infinity, Default::default());
                };
                let h = y2.sub(y1, C::P).mul(inv, C::P);
                let x = h.mul(h, C::P).sub(x1, C::P).sub(x2, C::P);
                let s = x1.sub(x, C::P);
                Self::new(x, h.mul(s, C::P).sub(y1, C::P)).unwrap()
            }
        }
    }
}

impl<C: Curve> ops::AddAssign for Point<C> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<C: Curve> Point<C> {
    pub fn new(x: modular::Num, y: modular::Num) -> Result<Self, InvalidPoint> {
        // Verify that (x, y) lies on the curve.
        let y2 = y.mul(y, C::P);
        let x3 = x.mul(x, C::P).mul(x, C::P);
        let ax = C::A.mul(x, C::P);
        if y2 == x3.add(ax, C::P).add(C::B, C::P) {
            Ok(Self(Coordinates::Finite(x, y), Default::default()))
        } else {
            Err(InvalidPoint)
        }
    }

    pub fn infinity() -> Self {
        Self(Coordinates::Infinity, Default::default())
    }

    /// Get the point coordinates, or `None` if the point is at infinity.
    pub fn coordinates(&self) -> Coordinates {
        self.0
    }

    /// Multiply the point by a scalar.
    pub(super) fn scale(&self, n: modular::Num) -> Self {
        // TODO Explain square-and-multiply
        let mut s = *self;
        let mut result = Self::infinity();
        for i in 0..modular::Num::BITS {
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
