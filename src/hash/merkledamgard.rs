use {
    crate::{Digest, Hash, Preimage},
    docext::docext,
};

mod daviesmeyer;

pub use daviesmeyer::{DaviesMeyer, DaviesMeyerStep};

/// The Merkle-Damgard construction, used as a building block for [hash
/// functions](crate::Hash).
///
/// The Merkle-Damgard construction builds a hash function from a [compression
/// function](CompressionFn). Internally, the hash function maintains a state
/// and splits the [preimage](crate::Preimage) into blocks with
/// [padding](MerkleDamgardPad). Each block is fed into the compression function
/// along with the current state, and the output of the compression function
/// becomes the new state. The final state is the hash of the input. The initial
/// state is a fixed value called the initialization vector (IV).
///
/// If the compression function is [secure](CompressionFn) and the padding
/// scheme is secure [secure](MerkleDamgardPad), the Merkle-Damgard construction
/// is provably secure, meaning that a collision in the Merkle-Damgard hash
/// function must stem from a collision in the underlying compression function.
/// (Note that the opposite is not necessarily true: if the underlying
/// compression function has known collision vulnerabilities, these might still
/// not affect the Merkle-Damgard construction. But this is a dangerous
/// situation nonetheless.)
///
/// # Length-extension Attacks
///
/// Imagine an attacker which knows some hash $H$ but doesn't know the preimage
/// $M$ which was hashed. If the Merkle-Damgard construction was used for
/// hashing, the hash $H$ corresponds to the internal state $S$ at the end of
/// the hashing process.
///
/// Imagine that the Merkle-Damgard construction was used with the padding
/// function $Pad$. The attacker can initialize the Merkle-Damgard construction
/// with the internal state $S = H$ and calculate the hash of $Pad(M) \parallel
/// X$ by simply feeding the message $X$ into the Merkle-Damgard construction.
///
/// This vulnerability can be practically exploited, for example, in a scheme
/// where a cloud storage provider is supposed to prove to a user that it has
/// stored some data $D$. The most inefficient way to do this would be for the
/// user to simply request all the data (possibly many tens of GiBs) from the
/// server. A more efficient way would be for the user to send a challenge $C$
/// and expect the server to respond with $Hash(D \parallel C)$. The user
/// compares this hash with his own $Hash(D \parallel C)$. The server shouldn't
/// be able to do any pre-computation since the challenge $C$ is unpredictable,
/// and hence must have the data stored to calculate the hash.
///
/// However, if the $Hash$ function is vulnerable to length-extension attacks,
/// this is not the case. The server can simply store $Hash(D)$ instead of $D$
/// and calculate $Hash(D \parallel C)$ using a length extension.
///
/// To mitigate this issue, the Merkle-Damgard state can be truncated to
/// generate the hash digest instead of being used in full. Alternatively, the
/// above challenge-response scheme can be amended to prepend $C$ instead
/// of appending it: require $Hash(C \parallel D)$ rather than $Hash(D \parallel
/// C)$.
///
/// [SHA-256](crate::Sha256) is a widely used hash function vulnerable to this
/// attack.
#[docext]
#[derive(Debug)]
pub struct MerkleDamgard<
    State,
    Block,
    F: CompressionFn<State = State, Block = Block>,
    Pad: MerkleDamgardPad<Block = Block>,
> {
    f: F,
    pad: Pad,
    iv: State,
}

/// A compression function used internally by the [Merkle-Damgard
/// construction](MerkleDamgard).
///
/// The compression function takes the current state and an input block, and
/// produces a new state. To be secure, the output of the compression function
/// should be unpredictable and one-way, meaning it should be impossible to get
/// to an old state given the current state. Ideally, it should also be
/// impossible to get to an old state given the current state and the
/// corresponding [preimage](crate::Preimage) block.
pub trait CompressionFn {
    type Block;
    type State;

    fn compress(&self, state: Self::State, block: Self::Block) -> Self::State;
}

/// The padding scheme used by the [Merkle-Damgard construction](MerkleDamgard).
///
/// The padding scheme splits the hash input into blocks of fixed size,
/// with padding. To be formally secure ("Merkle-Damgard compliant"), the
/// padding scheme $Pad$ must uphold the following contracts:
///
/// 1. Given the message $M$, $M$ must be a prefix of $Pad(M)$.
/// 2. Given two messages $M_1$ and $M_2$, if $len(M_1) = len(M_2)$, then
///    $len(Pad(M_1)) = len(Pad(M_2))$.
/// 3. If $len(M_1) \neq len(M_2)$, then the last blocks of $Pad(M_1)$ and
///    $Pad(M_2)$ must be different.
#[docext]
pub trait MerkleDamgardPad {
    type Block;

    fn pad(&self, preimage: Preimage<&[u8]>) -> impl Iterator<Item = Self::Block>;
}

impl<
        State,
        Block,
        F: CompressionFn<State = State, Block = Block>,
        Pad: MerkleDamgardPad<Block = Block>,
    > MerkleDamgard<State, Block, F, Pad>
{
    pub fn new(f: F, pad: Pad, iv: State) -> Self {
        Self { f, pad, iv }
    }
}

/// Implementation of the Merkle-Damgard construction.
impl<
        State: Clone,
        Block,
        F: CompressionFn<State = State, Block = Block>,
        Pad: MerkleDamgardPad<Block = Block>,
    > Hash for MerkleDamgard<State, Block, F, Pad>
{
    type Output = State;

    fn hash(&self, preimage: Preimage<&[u8]>) -> Digest<Self::Output> {
        Digest(
            self.pad
                .pad(preimage)
                .fold(self.iv.clone(), |state, block| {
                    self.f.compress(state, block)
                }),
        )
    }
}
