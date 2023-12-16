use {
    crate::{
        ecc::{Curve, Point},
        pubkey::ecc::{modular, Coordinates},
        Hash,
        InvalidPrivateKey,
        InvalidSignature,
        SignatureScheme,
    },
    docext::docext,
    std::marker::PhantomData,
};

/// [Elliptic curve](crate::ecc::Curve) digital [signature
/// algorithm](crate::SignatureScheme).
///
/// This signature algorithm relies on the elliptic-curve digital logarithm
/// problem (ECDLP): the assumption that given points $G$ and $Q$, where $Q =
/// kG$, and $k$ is unknown, it is computationally unfeasible to calculate the
/// scalar $k$. There is some evidence which implies this assumption might be
/// true, but it has not been proven. It has yet to be broken in practice.
///
/// Given a message $m$, private key $p$, curve with [generator point
/// $G$](crate::ecc::Curve::g) of [order $n$](crate::ecc::Curve::N), and a [hash
/// function $H$](crate::Hash), the algorithm to sign $m$ operates as follows:
/// 1. Generate a random number $k \in [1, n-1]$ from the curve's prime field,
///    or derive it deterministically from $m$ and $p$.
/// 2. Calculate $R = kG$, $r = R_x$, where $R_x$ is the x-coordinate of $R$. If
///    $R = \infty$, go back to step 1.
/// 3. Hash the message: $e = H(m) \pmod n$.
/// 4. Calculate $s = k^{-1}(e + rp) \pmod n$. If $s = 0$, go back to step 1.
/// 5. Return the pair $(r, s)$ as the message signature.
///
/// The algorithm to verify signature $(r, s)$ with public key $P = pG$ operates
/// as follows:
/// 1. Hash the message: $e = H(m) \pmod n$.
/// 2. Calculate $u = es^{-1} \pmod n$, $v = rs^{-1} \pmod n$
/// 3. Calculate $R = uG + vP$.
/// 4. Check that $R_x = r \pmod n$
///
/// This works because
///
/// $$
/// R = uG + vP \\
/// R = es^{-1}G + rs^{-1}pG \\
/// R = (e + rp)s^{-1}G \\
/// R = (e + rp)\left(k^{-1}(e + rp)\right)^{-1}G \\
/// R = (e + rp)k(e + rp)^{-1}G \\
/// R = kG
/// $$
///
/// Which is the original definition of R from the signing algorithm.
#[docext]
#[derive(Debug)]
pub struct Ecdsa<C, H> {
    _curve: C,
    hash: H,
}

impl<C, H> Ecdsa<C, H> {
    pub fn new(curve: C, hash: H) -> Self {
        Self {
            _curve: curve,
            hash,
        }
    }
}

impl<C, H, const DIGEST_SIZE: usize> SignatureScheme for Ecdsa<C, H>
where
    H: Hash<Digest = [u8; DIGEST_SIZE]>,
    C: Curve,
{
    type PublicKey = PublicKey<C>;
    type PrivateKey = PrivateKey<C>;
    type Signature = Signature<C>;

    fn sign(&self, key: Self::PrivateKey, msg: &[u8]) -> Self::Signature {
        assert!(DIGEST_SIZE >= C::SIZE);
        let e = self.hash.hash(msg);
        let e = modular::Num::from_le_bytes(resize(e));
        let mut preimage: Vec<u8> = Default::default();
        preimage.extend(msg);
        preimage.extend(key.0.to_le_bytes());
        let mut k = modular::Num::from_le_bytes(resize(self.hash.hash(&preimage)));
        let mut r;
        let mut s;
        'retry: loop {
            k = modular::Num::from_le_bytes(resize(self.hash.hash(&k.to_le_bytes())));
            r = match (k * C::g()).coordinates() {
                Coordinates::Infinity => continue 'retry,
                Coordinates::Finite(x, _) => x,
            };
            s = e.add(r.mul(key.0, C::N), C::N);
            // k * G is finite, so k must not be zero and thus has an inverse.
            s = k.inv(C::N).unwrap().mul(s, C::N);
            if s == modular::ZERO {
                continue 'retry;
            }
            return Signature {
                r,
                s,
                _curve: Default::default(),
            };
        }
    }

    fn verify(
        &self,
        key: Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), InvalidSignature> {
        assert!(DIGEST_SIZE >= C::SIZE);
        let e = modular::Num::from_le_bytes(resize(self.hash.hash(msg)));
        let i = sig.s.inv(C::N).unwrap();
        let u = e.mul(i, C::N);
        let v = sig.r.mul(i, C::N);
        match (u * C::g() + v * key.0).coordinates() {
            Coordinates::Finite(x, _) => {
                if x.eq(sig.r, C::N) {
                    Ok(())
                } else {
                    Err(InvalidSignature)
                }
            }
            Coordinates::Infinity => Err(InvalidSignature),
        }
    }
}

fn resize<const N: usize, const R: usize>(num: [u8; N]) -> [u8; R] {
    let mut result = [0; R];
    result.iter_mut().zip(num.iter()).for_each(|(a, b)| *a = *b);
    result
}

#[derive(Debug)]
pub struct PrivateKey<C>(modular::Num, PhantomData<C>);

impl<C> Clone for PrivateKey<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for PrivateKey<C> {}

impl<C: Curve> PrivateKey<C> {
    pub fn new(n: modular::Num) -> Result<Self, InvalidPrivateKey> {
        // Verify that the private key is reduced modulo N.
        if n < C::N {
            Ok(Self(n, Default::default()))
        } else {
            Err(InvalidPrivateKey)
        }
    }
}

#[derive(Debug)]
pub struct PublicKey<C>(Point<C>);

impl<C> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for PublicKey<C> {}

impl<C: Curve> PublicKey<C> {
    pub fn new(p: Point<C>) -> Self {
        Self(p)
    }

    /// Derive the public key from a [private key](PrivateKey).
    ///
    /// This is done by simply multiplying the private key with the [generator
    /// point](crate::ecc::Curve::g).
    pub fn derive(key: PrivateKey<C>) -> Self {
        Self(key.0 * C::g())
    }
}

#[derive(Debug)]
pub struct Signature<C> {
    r: modular::Num,
    s: modular::Num,
    _curve: PhantomData<C>,
}

impl<C> Clone for Signature<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Signature<C> {}

impl<C: Curve> Signature<C> {
    pub fn new(r: modular::Num, s: modular::Num) -> Result<Self, InvalidSignature> {
        // Verify that r and s are reduced modulo N.
        if r < C::N && s < C::N {
            Ok(Self {
                r,
                s,
                _curve: Default::default(),
            })
        } else {
            Err(InvalidSignature)
        }
    }

    pub fn r(&self) -> modular::Num {
        self.r
    }

    pub fn s(&self) -> modular::Num {
        self.s
    }
}
