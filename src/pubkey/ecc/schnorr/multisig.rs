use {
    crate::{
        ecc,
        ecc::{Curve, Num, Point, PrivateKey, PublicKey},
        util::{self, CollectVec},
        Csprng,
        Hash,
        InvalidSignature,
        MultisigScheme,
        Schnorr,
        SchnorrSignature,
        SignatureScheme,
    },
    core::fmt,
    docext::docext,
    std::marker::PhantomData,
};

// TODO link to simple approach
/// A [multisig scheme](crate::Multisig) based on [Schnorr
/// signatures](crate::Schnorr).
///
/// Using Schnorr signatures has multiple advantages over the [simple approach
/// to multisig](TODO). Most importantly, the resulting signature is
/// indistinguishable from a regular Schnorr signature created by a single
/// private key. Consequently, this scheme is also more efficient: the size of
/// the signature is the same no matter the number of signers.
///
/// Before signing, $n$ signers with private keys $p_i$ and public keys $P_i$
/// each pick [random secret numbers $r_i$](SchnorrRandomness). They share the
/// public counterparts of the secret numbers $R_i = r_iG$, where $G$ is the
/// [generator point](crate::ecc::Curve::g) of the underlying [elliptic
/// curve](crate::ecc::Curve), and calculate $R = \sum_{i=1}^{n} R_i$.
///
/// They start with $s = 0$. When it's $p_i$'s turn to sign, s is updated as
/// follows:
///
/// $$
/// c_i = H_{agg}(\langle L \rangle \parallel P_i) \cdot H_{sig}(\tilde P
/// \parallel R \parallel m) \\
/// s_i = r_i - p_ic_i \\
/// s \gets s + s_i
/// $$
///
/// Where $H_{agg}$ and $H_{sig}$ are hash functions returning numbers in the
/// range $[1, N-1]$ (which don't have to be the same, but in this
/// implementation they are), $\langle L \rangle$ is a unique encoding of the
/// pubkeys $P_1, P_2, \dotsc, P_n$, and $c_i$ is called the "challenge" for
/// $p_i$. $\tilde P$ is the combined pubkey:
///
/// $$
/// \tilde P = \sum_{i = 1}^{n} P_i \cdot H_{agg}(\langle L \rangle \parallel
/// P_i) $$
///
/// The resulting signature is $(s, e)$ where $e = H_{sig}(\tilde P \parallel R
/// \parallel m)$.
///
/// A [regular Schnorr signature](crate::Schnorr) $(s, e)$ is verified using the
/// following formula, where $e$ is the hash $H(P \parallel R \parallel m)$ and
/// $P$ is the public key:
///
/// $$
/// R = sG + eP \\
/// R = sG + H(P \parallel R \parallel m)P
/// $$
///
/// A Schnorr multisig is verified the exact same way, using $\tilde P$ as the
/// pubkey and $H_{sig}$ as the hash function:
///
/// $$
/// R = sG + e\tilde P \\
/// R = sG + H_{sig}(\tilde P \parallel R \parallel m)\tilde P
/// $$
///
/// After every actor has signed, the signature $s$ will be $s = \sum_{i =
/// 1}^{n} s_i$. Substituting this into the equation for $R$:
///
/// $$
/// R = \Big(\sum_{i = 1}^{n} s_i\Big)G + e\tilde P \\
/// R = \Big(\sum_{i = 1}^{n} r_i - p_ic_i\Big)G + e\tilde P \\
/// R = \Big(\sum_{i = 1}^{n} r_i - p_iH_{agg}(\langle L \rangle \parallel P_i)
/// H_{sig}(\tilde P \parallel R \parallel m)\Big)G + e\tilde P \\
/// $$
///
/// Since in this case $e = H_{sig}(\tilde P \parallel R \parallel m)$, the
/// equation can be made slightly shorter:
///
/// $$
/// R = \Big(\sum_{i = 1}^{n} r_i - p_iH_{agg}(\langle L \rangle \parallel P_i)
/// e\Big)G + e\tilde P \\
/// $$
///
/// The sum can be split around the subtraction operation and multiplied by $G$:
///
/// $$
/// R = \Big(\sum_{i = 1}^{n} r_i - \sum_{i = 1}^{n} p_iH_{agg}(\langle L
/// \rangle \parallel P_i) e\Big)G + e\tilde P \\
/// R = \Big(\sum_{i = 1}^{n} r_iG - \sum_{i = 1}^{n} p_iGH_{agg}(\langle L
/// \rangle \parallel P_i) e\Big) + e\tilde P \\
/// R = \Big(R - \sum_{i = 1}^{n} P_iH_{agg}(\langle L
/// \rangle \parallel P_i) e\Big) + e\tilde P \\
/// $$
///
/// Every element in the remaining sum is multiplied by $e = H_{sig}(\tilde P
/// \parallel R \parallel m)$ which doesn't depend on $i$, so it can be factored
/// out:
///
/// $$
/// R = \Big(R - e\sum_{i = 1}^{n} P_iH_{agg}(\langle L
/// \rangle \parallel P_i)\Big) + e\tilde P \\
/// $$
///
/// Finally since $\tilde P = \sum_{i = 1}^{n} P_iH_{agg}(\langle L \rangle
/// \parallel P_i)$:
///
/// $$
/// R = R - e\tilde P + e\tilde P \\
/// R = R
/// $$
///
/// Which shows that Schnorr multisigs can be verified the same way as regular
/// Schnorr signatures, so long as they use the same hash function. Note that
/// the key reason why this works is because the expression for $s$ has the same
/// form for multisigs as it does for regular signatures, except for summation
/// over $r_i$ and $p_i$. Compare the form of a regular Schnorr signature:
///
/// $$
/// s = {\color{red}r} - \color{yellow}e\color{green}p
/// $$
///
/// with the form of a Schnorr multisig:
///
/// $$
/// s = \sum_{i = 1}^n r_i - ep_iH_{agg}(\langle L \rangle \parallel P_i) \\
/// s = {\color{red}\sum_{i = 1}^n r_i} - \color{yellow}e\color{green}\sum_{i =
/// 1}^np_iH_{agg}(\langle L \rangle \parallel P_i) $$
///
/// The private keys $p_i$ are multiplied by $H_{agg}(\langle L \rangle
/// \parallel P_i)$ for two reasons:
///
/// 1. $H_{agg}$ hashes over $\langle L \rangle$ so that no actor accidentally
///    signs a multisig for the wrong group of pubkeys.
/// 2. $H_{agg}$ hashes over $P_i$ so that no actor can maliciously fake his
///    public key. For example, if $p_i$ was not multiplied by $H_{agg}(P_i)$
///    then the formula for the combined pubkey would be simply $\tilde P =
///    \sum_{i = 1}^n P_i$, allowing a malicious actor to set his pubkey to $P_1
///    = P_1' - P_2 - P_3 - \dots - P_n$, where $P_1' = p_1'G$ is the actor's
///    actual pubkey. This results in $\tilde P = P_1'$ which allows him to make
///    signatures for the whole group using his private key $p_i'$ alone.
///    Multiplying private keys with the hash of their corresponding public keys
///    prevents this problem, since the malicious actor would end up multiplying
///    $p_1'$ with the hash of $P_1$ resulting in an invalid signature.
#[docext]
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
        let a = h_agg(&self.0.hash, &pubkeys, pubkey);
        let e = h_sig(&self.0.hash, &pubkeys, randomness, msg);
        let c = a.mul(e, C::N);
        let s = randomness.local.sub(key.0.mul(c, C::N), C::N);
        SchnorrSignature::new(sig.s().add(s, C::N), e).unwrap()
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
    .reduce(C::N)
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
    .reduce(C::N)
}

/// Before creating a [Schnorr multisig](MultiSchnorr), the actors must each
/// commit to a secret random number $r_i$. They proceed in two rounds:
///
/// 1. Each actor generates his secret random number $r_i$ and the public
///    counterpart $R_i = r_iG$, where $G$ is the [generator
///    point](crate::ecc::Curve::g) of the underlying [elliptic
///    curve](crate::ecc::Curve). He reveals his commitment $t_i = H(R_i)$ to
///    the other actors, where $H$ is a hash function.
/// 2. After all commitments $t_i$ have been revealed, each actor shares his
///    value of $R_i$ and verifies the $R_i$ values of other actors against
///    their corresponding commitments $t_i$.
///
/// This two-round protocol serves to prevent any actor from maliciously
/// changing his secret number $r_i$ based on the $R_i$ values of other actors.
#[docext]
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
    pub fn new(local: Num, others: &[Point<C>]) -> Result<Self, InvalidSchnorrRandomness> {
        let total = others.iter().fold(local * C::g(), |a, b| a + *b);
        match total.coordinates() {
            ecc::Coordinates::Infinity => Err(InvalidSchnorrRandomness),
            ecc::Coordinates::Finite(x, _) => Ok(Self {
                local,
                total: x,
                _curve: Default::default(),
            }),
        }
    }
}

/// Combine multiple pubkeys into a single multisig pubkey.
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

#[derive(Debug)]
pub struct InvalidSchnorrRandomness;

impl fmt::Display for InvalidSchnorrRandomness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid randomness (bad luck, regenerate local randomness)"
        )
    }
}

impl<C, H, R: Csprng> fmt::Debug for MultiSchnorr<C, H, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MultiSchnorr").finish()
    }
}
