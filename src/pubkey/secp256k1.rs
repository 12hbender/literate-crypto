use {
    super::InvalidSignature,
    crate::{Hash, Preimage, SignatureScheme},
    std::fmt,
};

mod curve;
mod modular;

pub use {
    curve::{Coordinates, Point, G, N, P},
    modular::Num,
};

/// TODO Note that the entropy of H should be at least 128 bits, also I should
/// probably write something about entropy
#[derive(Debug)]
pub struct Secp256k1Ecdsa<H> {
    hash: H,
}

impl<H> Secp256k1Ecdsa<H> {
    pub fn new(hash: H) -> Self {
        Self { hash }
    }
}

impl<H> SignatureScheme for Secp256k1Ecdsa<H>
where
    H: Hash<Output = [u8; Num::BYTES]>,
{
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type Signature = Signature;

    fn sign(&self, key: Self::PrivateKey, data: &[u8]) -> Self::Signature {
        let e = self.hash.hash(Preimage(data));
        let e = Num::from_le_bytes(e.0);
        let mut preimage: Vec<u8> = Default::default();
        preimage.extend(data);
        preimage.extend(key.0.to_le_bytes());
        let mut k = Num::from_le_bytes(self.hash.hash(Preimage(&preimage)).0);
        let mut r;
        let mut s;
        'retry: loop {
            k = Num::from_le_bytes(self.hash.hash(Preimage(&k.to_le_bytes())).0);
            r = match (k * G).coordinates() {
                Coordinates::Infinity => continue 'retry,
                Coordinates::Finite(x, _) => x,
            };
            s = e.add(r.mul(key.0, N), N);
            // k * G is finite, so k must not be zero and thus has an inverse.
            s = k.inv(N).unwrap().mul(s, N);
            if s == Num::ZERO {
                continue 'retry;
            }
            return Signature { r, s };
        }
    }

    fn verify(
        &self,
        key: Self::PublicKey,
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), InvalidSignature> {
        let e = Num::from_le_bytes(self.hash.hash(Preimage(data)).0);
        let i = sig.s.inv(N).unwrap();
        let u = e.mul(i, N);
        let v = sig.r.mul(i, N);
        match (u * G + v * key.0).coordinates() {
            Coordinates::Finite(x, _) => {
                if x.eq(sig.r, N) {
                    Ok(())
                } else {
                    Err(InvalidSignature)
                }
            }
            Coordinates::Infinity => Err(InvalidSignature),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PrivateKey(Num);

impl PrivateKey {
    pub fn new(n: Num) -> Result<Self, InvalidPrivateKey> {
        // Verify that the private key is reduced modulo N.
        if n < N {
            Ok(Self(n))
        } else {
            Err(InvalidPrivateKey)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PublicKey(Point);

impl PublicKey {
    pub fn new(p: Point) -> Self {
        Self(p)
    }

    /// Derive the public key from a private key.
    pub fn derive(key: PrivateKey) -> Self {
        Self(key.0 * G)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Signature {
    r: Num,
    s: Num,
}

impl Signature {
    pub fn new(r: Num, s: Num) -> Result<Self, InvalidSignature> {
        // Verify that r and s are reduced modulo N.
        if r < N && s < N {
            Ok(Self { r, s })
        } else {
            Err(InvalidSignature)
        }
    }

    pub fn r(&self) -> Num {
        self.r
    }

    pub fn s(&self) -> Num {
        self.s
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidPrivateKey;

impl fmt::Display for InvalidPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid private key")
    }
}

impl std::error::Error for InvalidPrivateKey {}
