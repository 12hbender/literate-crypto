use {
    crate::{
        ecc::{modular, Coordinates, Curve, PrivateKey, PublicKey},
        util::{self, CollectVec},
        Csprng,
        Hash,
        InvalidSignature,
        SignatureScheme,
    },
    std::{array, marker::PhantomData},
};

#[derive(Debug)]
pub struct Schnorr<C, H, R: Csprng> {
    hash: H,
    rng: R::IntoIter,
    _curve: C,
}

impl<C, H, R: Csprng> Schnorr<C, H, R> {
    pub fn new(curve: C, hash: H, rng: R) -> Self {
        Self {
            hash,
            rng: rng.into_iter(),
            _curve: curve,
        }
    }
}

impl<C, H, R, const DIGEST_SIZE: usize> SignatureScheme for Schnorr<C, H, R>
where
    C: Curve,
    H: Hash<Digest = [u8; DIGEST_SIZE]>,
    R: Csprng,
{
    type PublicKey = PublicKey<C>;
    type PrivateKey = PrivateKey<C>;
    type Signature = Signature<C, H>;

    fn sign(&mut self, key: Self::PrivateKey, msg: &[u8]) -> Self::Signature {
        assert!(DIGEST_SIZE >= C::SIZE);
        'retry: loop {
            let k = modular::Num::from_le_bytes(array::from_fn(|_| self.rng.next().unwrap()));
            let r = match (k * C::g()).coordinates() {
                super::Coordinates::Infinity => continue 'retry,
                super::Coordinates::Finite(x, _) => x,
            };
            let e = self.hash.hash(
                &r.to_le_bytes()
                    .into_iter()
                    .chain(msg.iter().copied())
                    .collect_vec(),
            );
            let e = modular::Num::from_le_bytes(util::resize(e));
            let e = e.reduce(C::N);
            let s = k.sub(key.0.mul(e, C::N), C::N);
            return Signature {
                s,
                e,
                _curve: Default::default(),
                _hash: Default::default(),
            };
        }
    }

    fn verify(
        &mut self,
        key: Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), crate::InvalidSignature> {
        match (sig.s * C::g() + sig.e * key.0).coordinates() {
            Coordinates::Infinity => Err(InvalidSignature),
            Coordinates::Finite(r, _) => {
                let e = self.hash.hash(
                    &r.to_le_bytes()
                        .into_iter()
                        .chain(msg.iter().copied())
                        .collect_vec(),
                );
                let e = modular::Num::from_le_bytes(util::resize(e));
                let e = e.reduce(C::N);
                if e == sig.e {
                    Ok(())
                } else {
                    Err(InvalidSignature)
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Signature<C, H> {
    s: modular::Num,
    e: modular::Num,
    _curve: PhantomData<C>,
    _hash: PhantomData<H>,
}

impl<C, H> Clone for Signature<C, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C, H> Copy for Signature<C, H> {}

impl<C: Curve, H> Signature<C, H> {
    pub fn new(s: modular::Num, e: modular::Num) -> Result<Self, InvalidSignature> {
        // Verify that r and s are reduced modulo N.
        if s < C::N && e < C::N {
            Ok(Self {
                s,
                e,
                _curve: Default::default(),
                _hash: Default::default(),
            })
        } else {
            Err(InvalidSignature)
        }
    }

    pub fn s(&self) -> modular::Num {
        self.s
    }

    pub fn e(&self) -> modular::Num {
        self.e
    }
}
