use {
    crate::{Bytes, Hash},
    std::fmt,
};

mod daviesmeyer;

pub use daviesmeyer::{DaviesMeyer, DaviesMeyerCipher, DaviesMeyerStep};

// TODO The Merkle-Damgard construction
pub struct MerkleDamgard<
    State,
    Block,
    BuildF: Fn() -> F,
    F: CompressionFn<State = State, Block = Block>,
    Pad: MerkleDamgardPad<Block = Block>,
> {
    f: BuildF,
    pad: Pad,
    iv: State,
}

// TODO Compression function used by the Merkle-Damgard construction
pub trait CompressionFn {
    type Block;
    type State;

    fn compress(&mut self, state: Self::State, block: Self::Block) -> Self::State;
}

// TODO MD-compliant padding
pub trait MerkleDamgardPad {
    type Block;

    fn pad(&self, input: &[u8]) -> impl Iterator<Item = Self::Block>;
}

impl<
        State,
        Block,
        BuildF: Fn() -> F,
        F: CompressionFn<State = State, Block = Block>,
        Pad: MerkleDamgardPad<Block = Block>,
    > MerkleDamgard<State, Block, BuildF, F, Pad>
{
    pub fn new(f: BuildF, pad: Pad, iv: State) -> Self {
        Self { f, pad, iv }
    }
}

/// Implementation of the Merkle-Damgard construction.
impl<
        State: Clone,
        Block,
        BuildF: Fn() -> F,
        F: CompressionFn<State = State, Block = Block>,
        Pad: MerkleDamgardPad<Block = Block>,
    > Hash for MerkleDamgard<State, Block, BuildF, F, Pad>
{
    type Output = State;

    fn hash(&self, input: &[u8]) -> Self::Output {
        let mut f = (self.f)();
        self.pad
            .pad(input)
            .fold(self.iv.clone(), |state, block| f.compress(state, block))
    }
}

impl<
        State: Bytes,
        Block: Bytes,
        BuildF: Fn() -> F,
        F: CompressionFn<State = State, Block = Block>,
        Pad: MerkleDamgardPad<Block = Block>,
    > fmt::Debug for MerkleDamgard<State, Block, BuildF, F, Pad>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleDamgard").finish()
    }
}
