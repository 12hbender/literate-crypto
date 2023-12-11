//! Elliptic curve cryptography.

use {
    docext::docext,
    std::{fmt, marker::PhantomData, ops},
};

pub mod ecdsa;
pub mod modular;
mod secp256k1;

pub use {ecdsa::Ecdsa, secp256k1::Secp256k1};

/// An elliptic curve.
///
/// Elliptic curves can be expressed in a few different forms, but the most
/// common is
///
/// $$
/// y^2 = x^3 + ax + b
/// $$
///
/// For some $a, b$. When this equation is plotted over $\mathbb{R}^2$, it
/// results in the following curve:
///
/// ![curve](img/curve.svg)
///
/// Two points on the curve can be added by drawing a line through them and
/// finding the intersection. For example, $A + B = C$:
///
/// ![addition](img/curve-addition.svg)
///
/// A point can be added to itself by drawing a tangent instead of a line,
/// referred to as _point doubling_. For example, $2A = B$:
///
/// ![doubling](img/curve-doubling.svg)
///
/// When a line is drawn through two points, it is possible that there is no
/// intersection. A similar situation can happen with tangents as well.
///
/// ![doubling](img/curve-addition-inf.svg)
///
/// For this reason, there is a special point referred to as _the point at
/// infinity_ and designated by $\infty$. By definition, for any point $A$, $A +
/// \infty = A$. This rule also defines point negation: if $A + B = \infty$ then
/// $A = -B$. Any line which does not intersect the curve must be parallel to
/// the y-axis, hence for any point $(x, y)$ the negation is simply $(x, -y)$.
/// The example above also demostrates this, since $A = -B$ and the line through
/// $A$ and $B$ is parallel to the y-axis.
///
/// Finally, any point $P$ can be multiplied by a non-negative integer $k$, $Q =
/// kP$. This _point multiplication_ is defined simply as repeated point
/// addition. By definition, $0 \cdot P = \infty$.
///
/// The elliptic curve point arithmetic defined above constitutes a _group_.
/// This means that the operations within this arithmetic behave in a
/// mathematically reasonable way, similar to integer arithmetic.
///
/// In the graphical examples, the curve is defined over $\mathbb{R}$. The
/// conclusions and laws above are true if the curve is defined over any
/// _field_, not just $\mathbb{R}$. In practice (as well as in this
/// implementation), usually a prime field is used and operations are carried
/// out via modular arithmetic.
#[docext]
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
    ///
    /// During cryptographic operations, this point is used to generate all
    /// other points on the curve via point multiplication. This point
    /// must generate a cyclic subgroup of the curve. The cardinality of the
    /// subgroup should be as large as possible.
    fn g() -> Point<Self>;
}

/// A point on an elliptic curve curve, possibly at infinity.
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

/// Finite point coordinates $(x, y)$ or infinity $\infty$.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[docext]
pub enum Coordinates {
    /// The point at infinity.
    Infinity,
    Finite(modular::Num, modular::Num),
}

/// [Elliptic curve](Curve) points are added together by first constructing a
/// line through the two points, then finding the intersection of that line with
/// the curve. The intersection is the result. If the two points are equal, a
/// tangent should be constructed instead of a line.
///
/// If the points are not equal:
/// $$
/// (x_1, y_1) + (x_2, y_2) = (x_3, y_3) \\
/// H = \frac{y_2 - y_1}{x_2 - x_1} \\
/// x_3 = H^2 - x_1 - x_2 \\
/// y_3 = H(x_1 - x_3) - y_1 \\
/// $$
///
/// If the points are equal:
/// $$
/// 2 \cdot (x_1, y_1) = (x_3, y_3) \\
/// H = \frac{3x_1^2 + a}{2y_1} \\
/// x_3 = H^2 - 2x_1 \\
/// y_3 = H(x_1 - x_3) - y_1 \\
/// $$
#[docext]
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

    pub fn coordinates(&self) -> Coordinates {
        self.0
    }

    pub(super) fn scale(&self, n: modular::Num) -> Self {
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
