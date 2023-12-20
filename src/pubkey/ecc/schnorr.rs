use {
    crate::{
        ecc::{num, Coordinates, Curve, PrivateKey, PublicKey},
        util::{self, CollectVec},
        Csprng,
        Hash,
        InvalidSignature,
        SignatureScheme,
    },
    std::{array, marker::PhantomData},
};

mod multisig;

pub use multisig::MultiSchnorr;

#[derive(Debug)]
pub struct Schnorr<C, H, R: Csprng> {
    _curve: C,
    hash: H,
    rng: R::IntoIter,
}

impl<C, H, R: Csprng> Schnorr<C, H, R> {
    pub fn new(curve: C, hash: H, rng: R) -> Self {
        Self {
            _curve: curve,
            hash,
            rng: rng.into_iter(),
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
    type Signature = SchnorrSignature<C, H>;

    fn sign(&mut self, key: Self::PrivateKey, msg: &[u8]) -> Self::Signature {
        assert!(DIGEST_SIZE >= C::SIZE);
        let pubkey = key.derive();
        'retry: loop {
            let k = num::Num::from_le_bytes(array::from_fn(|_| self.rng.next().unwrap()));
            let r = match (k * C::g()).coordinates() {
                Coordinates::Infinity => continue 'retry,
                Coordinates::Finite(x, _) => x,
            };
            let e = self.hash.hash(
                &pubkey
                    .x()
                    .to_le_bytes()
                    .into_iter()
                    .chain(r.to_le_bytes())
                    .chain(msg.iter().copied())
                    .collect_vec(),
            );
            let e = num::Num::from_le_bytes(util::resize(e));
            let e = e.reduce(C::N);
            let s = k.sub(key.0.mul(e, C::N), C::N);
            return SchnorrSignature {
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
    ) -> Result<(), InvalidSignature> {
        match (sig.s * C::g() + sig.e * key.point()).coordinates() {
            Coordinates::Infinity => Err(InvalidSignature),
            Coordinates::Finite(r, _) => {
                let e = self.hash.hash(
                    &key.x()
                        .to_le_bytes()
                        .into_iter()
                        .chain(r.to_le_bytes())
                        .chain(msg.iter().copied())
                        .collect_vec(),
                );
                let e = num::Num::from_le_bytes(util::resize(e));
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
pub struct SchnorrSignature<C, H> {
    s: num::Num,
    e: num::Num,
    _curve: PhantomData<C>,
    _hash: PhantomData<H>,
}

impl<C, H> Default for SchnorrSignature<C, H> {
    fn default() -> Self {
        Self {
            s: Default::default(),
            e: Default::default(),
            _curve: Default::default(),
            _hash: Default::default(),
        }
    }
}

impl<C, H> Clone for SchnorrSignature<C, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C, H> Copy for SchnorrSignature<C, H> {}

impl<C: Curve, H> SchnorrSignature<C, H> {
    pub fn new(s: num::Num, e: num::Num) -> Result<Self, InvalidSignature> {
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

    pub fn s(&self) -> num::Num {
        self.s
    }

    pub fn e(&self) -> num::Num {
        self.e
    }
}
