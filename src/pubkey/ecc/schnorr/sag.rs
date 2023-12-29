use {
    crate::{
        ecc::{Coordinates, Curve, Num, PrivateKey, PublicKey},
        uniform_random,
        util::{self, CollectVec},
        Csprng,
        Hash,
        InvalidSignature,
        RingScheme,
    },
    docext::docext,
    std::array,
};

/// Spontaneous anonymous group signatures.
///
/// This is a [ring signature scheme](crate::RingScheme) inspired by [Schnorr
/// signatures](crate::Schnorr). Given a randomly selected list of decoy pubkeys
/// $P_1, P_2, \dots, P_{n-1}$ and the real private key $p_n$ with the
/// corresponding pubkey $P_n$, the scheme results in a signature which can be
/// verified to have been signed by one of the private keys corresponding to
/// $P_1, P_2, \dots, P_n$ without knowing which private key was actually used.
///
/// Scalars $r_1, r_2, \dots, r_{n-1}$ and $\alpha$ are selected
/// randomly. The series of challenges $c_i$ starts with
///
/// $$
/// c_1 = H(\langle L \rangle, m, \alpha G)
/// $$
///
/// where $H$ is a [hash function](crate::Hash), $\langle L \rangle$ is a unique
/// encoding  of the pubkeys $(P_1, P_2, \dots, P_n)$, $m$ is the message to be
/// signed, and $G$ is the [elliptic curve generator
/// point](crate::ecc::Curve::g).
///
/// The remaining values $c_2, c_3, \dots, c_n$ are calculated as
///
/// $$
/// c_{i+1} = H(\langle L \rangle, m, r_iG + c_iP_i)
/// $$
///
/// Finally, set $r_n = \alpha - c_np_n$ so that the ring is closed:
///
/// $$
/// r_n = \alpha - c_np_n \implies \alpha = r_n + c_np_n \\
/// c_1 = H(\langle L \rangle, m, \alpha G) \\
/// c_1 = H(\langle L \rangle, m, (r_n + c_np_n) G) \\
/// c_1 = H(\langle L \rangle, m, r_nG + c_nP_n)
/// $$
///
/// Which corresponds to the formula $c_{i+1} = H(\langle L \rangle, m, r_iG +
/// c_iK_i)$ for all consecutive values of $i$, where $i = n+1$ is replaced with
/// $i = 1$.
///
/// Finally, pick a random number $q$ and rotate all of the sequences $r_1, r_2,
/// \dots, r_n$, $c_1, c_2, \dots, c_n$ and $P_1, P_2, \dots, P_n$ by $q$ so
/// that
///
/// $$
/// r_i \gets r_{i + q} \\
/// c_i \gets c_{i + q} \\
/// P_i \gets P_{i + q}
/// $$
///
/// The resulting signature is $(c1, r_1, r_2, \dots, r_n, P_1, P_2, \dots,
/// P_n)$. The rotation by $q$ is necessary since otherwise $P_n$ would always
/// correspond to the true signer of the message, and his identity would not be
/// concealed at all.
///
/// To verify the signature, simply check that it forms a ring:
///
/// $$
/// c_{i+1} \stackrel{?}{=} H(\langle L \rangle, m, r_iG + c_iK_i)
/// $$
///
/// where $i = n + 1$ is replaced with $i = 1$.
///
/// The scheme works because it's impossible to form a ring without knowing one
/// private key, while it is unnecessary to know any of the other private keys.
#[docext]
pub struct SchnorrSag<C, H, R: Csprng> {
    _curve: C,
    hash: H,
    rng: R::IntoIter,
}

impl<C, H, R: Csprng> SchnorrSag<C, H, R> {
    pub fn new(curve: C, hash: H, rng: R) -> Self {
        Self {
            _curve: curve,
            hash,
            rng: rng.into_iter(),
        }
    }
}

impl<C, H, R, const DIGEST_SIZE: usize> RingScheme for SchnorrSag<C, H, R>
where
    C: Curve,
    H: Hash<Digest = [u8; DIGEST_SIZE]>,
    R: Csprng,
{
    type RingSignature = SchnorrSagSignature<C>;
    type PublicKey = PublicKey<C>;
    type PrivateKey = PrivateKey<C>;

    fn sign(
        &mut self,
        key: Self::PrivateKey,
        decoys: &[Self::PublicKey],
        msg: &[u8],
    ) -> Self::RingSignature {
        assert!(DIGEST_SIZE >= C::SIZE);

        let mut pubkeys = decoys.to_vec();
        pubkeys.push(key.derive());

        let l = encode(&pubkeys);

        // Generate a random number alpha and multiply the generator point by it.
        let mut alpha;
        let x0;
        'retry: loop {
            alpha = Num::from_le_bytes(array::from_fn(|_| self.rng.next().unwrap()));
            x0 = match (alpha * C::g()).coordinates() {
                Coordinates::Finite(x, _) => x,
                Coordinates::Infinity => continue 'retry,
            };
            break;
        }

        // Generate the initial c value to start the ring.
        let mut c = vec![Num::from_le_bytes(util::resize(
            self.hash.hash(
                &l.iter()
                    .copied()
                    .chain(msg.iter().copied())
                    .chain(x0.to_le_bytes())
                    .collect_vec(),
            ),
        ))
        .reduce(C::N)];
        let mut r = Vec::new();

        for decoy in decoys {
            // Generate a random number ri and use it to calculate the next c value in the
            // ring.
            'retry: loop {
                let ci = c.last().unwrap().to_owned();
                let ri =
                    Num::from_le_bytes(array::from_fn(|_| self.rng.next().unwrap())).reduce(C::N);
                let cx = match (ri * C::g() + ci * decoy.point()).coordinates() {
                    Coordinates::Finite(x, _) => x,
                    Coordinates::Infinity => continue 'retry,
                };
                r.push(ri);
                c.push(
                    Num::from_le_bytes(util::resize(
                        self.hash.hash(
                            &l.iter()
                                .copied()
                                .chain(msg.iter().copied())
                                .chain(cx.to_le_bytes())
                                .collect_vec(),
                        ),
                    ))
                    .reduce(C::N),
                );
                break;
            }
        }

        // Calculate the final r value in the ring based on the initial random number
        // alpha.
        let cn = c.last().unwrap().to_owned();
        let rn = alpha.sub(cn.mul(key.0, C::N), C::N);
        r.push(rn);

        // At this point, the ring should be complete. There should be the same number
        // of r values, c values, and keys in the ring.
        assert_eq!(r.len(), c.len());
        assert_eq!(c.len(), pubkeys.len());

        // Rotate the ring randomly so the start of the ring can't be predicted. If this
        // didn't happen, the real signer of the ring signature would always
        // correspond to the first pubkey, and his identity would not be hidden at all.
        let shift = uniform_random(&mut self.rng, 0..u32::try_from(r.len()).unwrap());
        c.rotate_left(usize::try_from(shift).unwrap());
        r.rotate_left(usize::try_from(shift).unwrap());
        pubkeys.rotate_left(usize::try_from(shift).unwrap());

        SchnorrSagSignature {
            c: c.first().unwrap().to_owned(),
            r,
            keys: pubkeys,
        }
    }

    fn verify(&mut self, msg: &[u8], sig: &Self::RingSignature) -> Result<(), InvalidSignature> {
        assert!(DIGEST_SIZE >= C::SIZE);

        // Start with the first c value and use the sequence of r values and pubkeys to
        // produce the next c value in the sequence.
        let mut c = sig.c;
        let l = encode(&sig.keys);
        for (&r, k) in sig.r.iter().zip(sig.keys.iter()) {
            let x = match (r * C::g() + c * k.point()).coordinates() {
                Coordinates::Finite(x, _) => x,
                Coordinates::Infinity => return Err(InvalidSignature),
            };
            c = Num::from_le_bytes(util::resize(
                self.hash.hash(
                    &l.iter()
                        .copied()
                        .chain(msg.iter().copied())
                        .chain(x.to_le_bytes())
                        .collect_vec(),
                ),
            ))
            .reduce(C::N);
        }

        // At the end of the process, the ring should be closed.
        if c == sig.c {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}

#[derive(Debug)]
pub struct SchnorrSagSignature<C> {
    c: Num,
    r: Vec<Num>,
    keys: Vec<PublicKey<C>>,
}

impl<C> SchnorrSagSignature<C> {
    pub fn c(&self) -> Num {
        self.c
    }

    pub fn r(&self) -> &[Num] {
        &self.r
    }

    pub fn keys(&self) -> &[PublicKey<C>] {
        &self.keys
    }
}

/// Encode multiple pubkeys into a unique binary representation.
fn encode<C: Curve>(keys: &[PublicKey<C>]) -> [u8; 32] {
    keys.iter()
        .map(|p| p.x())
        .fold(Num::ZERO, |a, b| a.add(b, C::N))
        .to_le_bytes()
}
