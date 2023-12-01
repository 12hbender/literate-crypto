use {
    crate::{
        ecc::{Curve, Point},
        pubkey::ecc::{modular, Coordinates},
        Hash,
        InvalidPrivateKey,
        InvalidSignature,
        Preimage,
        SignatureScheme,
    },
    std::marker::PhantomData,
};

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

impl<C, H, const HO: usize> SignatureScheme for Ecdsa<C, H>
where
    H: Hash<Output = [u8; HO]>,
    C: Curve,
{
    type PublicKey = PublicKey<C>;
    type PrivateKey = PrivateKey<C>;
    type Signature = Signature<C>;

    fn sign(&self, key: Self::PrivateKey, data: &[u8]) -> Self::Signature {
        assert!(HO >= C::SIZE);
        let e = self.hash.hash(Preimage(data));
        let e = modular::Num::from_le_bytes(resize(e.0));
        let mut preimage: Vec<u8> = Default::default();
        preimage.extend(data);
        preimage.extend(key.0.to_le_bytes());
        let mut k = modular::Num::from_le_bytes(resize(self.hash.hash(Preimage(&preimage)).0));
        let mut r;
        let mut s;
        'retry: loop {
            k = modular::Num::from_le_bytes(resize(self.hash.hash(Preimage(&k.to_le_bytes())).0));
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
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), InvalidSignature> {
        assert!(HO >= C::SIZE);
        let e = modular::Num::from_le_bytes(resize(self.hash.hash(Preimage(data)).0));
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

    /// Derive the public key from a private key.
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
