use {
    crate::{
        ecc::{Curve, Num, PrivateKey, PublicKey},
        util::{self, CollectVec},
        Csprng,
        Hash,
        InvalidSignature,
        MultisigScheme,
        Schnorr,
        SchnorrSignature,
        SignatureScheme,
    },
    std::{iter, marker::PhantomData},
};

pub struct MultiSchnorr<C, H, R: Csprng>(Schnorr<C, H, R>);

impl<C, H, R: Csprng> MultiSchnorr<C, H, R> {
    pub fn new(curve: C, hash: H, rng: R) -> Self {
        Self(Schnorr::new(curve, hash, rng))
    }
}

impl<C, H, R, const DIGEST_SIZE: usize> MultisigScheme for MultiSchnorr<C, H, R>
where
    C: Curve,
    H: Hash<Digest = [u8; DIGEST_SIZE]>,
    R: Csprng,
{
    type PublicKey = PublicKey<C>;
    type PrivateKey = (PrivateKey<C>, Vec<PublicKey<C>>, SchnorrRandomness<C>);
    type Multisig = SchnorrSignature<C, H>;

    fn sign(&mut self, key: Self::PrivateKey, msg: &[u8], sig: Self::Multisig) -> Self::Multisig {
        assert!(DIGEST_SIZE >= C::SIZE);
        let (key, pubkeys, randomness) = key;
        let pubkey = key.derive();
        let h_agg = h_agg(&self.0.hash, &pubkeys, pubkey);
        let h_sig = h_sig(&self.0.hash, &pubkeys, randomness, msg);
        let c = h_agg.mul(h_sig, C::N);
        let s = randomness.local.add(key.0.mul(c, C::N), C::N);
        SchnorrSignature::new(sig.s().add(s, C::N), randomness.total).unwrap()
    }

    fn verify(
        &mut self,
        keys: &[Self::PublicKey],
        msg: &[u8],
        sig: &Self::Multisig,
    ) -> Result<(), InvalidSignature> {
        assert!(DIGEST_SIZE >= C::SIZE);
        let key = combine(&self.0.hash, keys);
        self.0.verify(key, msg, sig)
    }
}

fn h_agg<C: Curve, const DIGEST_SIZE: usize>(
    hash: &impl Hash<Digest = [u8; DIGEST_SIZE]>,
    pubkeys: &[PublicKey<C>],
    pubkey: PublicKey<C>,
) -> Num {
    Num::from_le_bytes(util::resize(
        hash.hash(
            &encode(pubkeys)
                .into_iter()
                .chain(pubkey.x().to_le_bytes())
                .collect_vec(),
        ),
    ))
}

fn h_sig<C: Curve, const DIGEST_SIZE: usize>(
    hash: &impl Hash<Digest = [u8; DIGEST_SIZE]>,
    pubkeys: &[PublicKey<C>],
    randomness: SchnorrRandomness<C>,
    msg: &[u8],
) -> Num {
    Num::from_le_bytes(util::resize(
        hash.hash(
            &combine(hash, pubkeys)
                .x()
                .to_le_bytes()
                .into_iter()
                .chain(randomness.total.to_le_bytes())
                .chain(msg.iter().copied())
                .collect_vec(),
        ),
    ))
}

// TODO Explain this, explain the exchange protocol
#[derive(Debug)]
pub struct SchnorrRandomness<C> {
    local: Num,
    total: Num,
    _curve: PhantomData<C>,
}

impl<C> Clone for SchnorrRandomness<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for SchnorrRandomness<C> {}

impl<C: Curve> SchnorrRandomness<C> {
    pub fn new(local: Num, others: &[Num]) -> Self {
        let total = iter::once(&local)
            .chain(others)
            .fold(Num::ZERO, |a, b| a.add(*b, C::N));
        Self {
            local,
            total,
            _curve: Default::default(),
        }
    }
}

// /Combine multiple pubkeys into a single multisig pubkey.
fn combine<C: Curve, const DIGEST_SIZE: usize>(
    hash: &impl Hash<Digest = [u8; DIGEST_SIZE]>,
    keys: &[PublicKey<C>],
) -> PublicKey<C> {
    PublicKey::new(
        keys.iter()
            .map(|&key| h_agg(hash, keys, key) * key.point())
            .reduce(|a, b| a + b)
            .unwrap(),
    )
    .unwrap()
}

/// Encode multiple pubkeys into a unique binary representation.
fn encode<C: Curve>(keys: &[PublicKey<C>]) -> [u8; 32] {
    keys.iter()
        .map(|p| p.x())
        .fold(Num::ZERO, |a, b| a.add(b, C::N))
        .to_le_bytes()
}
