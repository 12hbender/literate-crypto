pub mod ecc;

pub struct PublicKey<T>(pub T);

pub struct PrivateKey<T>(pub T);

pub enum EitherKey<T, U> {
    Public(PublicKey<T>),
    Private(PrivateKey<U>),
}

pub trait DiffieHellman {}
