use crate::Hash;

mod daviesmeyer;

pub use daviesmeyer::{DaviesMeyer, DaviesMeyerStep};

// TODO The Merkle-Damgard construction
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

// TODO Compression function used by the Merkle-Damgard construction
pub trait CompressionFn {
    type Block;
    type State;

    fn compress(&self, state: Self::State, block: Self::Block) -> Self::State;
}

// TODO MD-compliant padding
pub trait MerkleDamgardPad {
    type Block;

    fn pad(&self, input: &[u8]) -> impl Iterator<Item = Self::Block>;
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

    fn hash(&self, input: &[u8]) -> Self::Output {
        self.pad.pad(input).fold(self.iv.clone(), |state, block| {
            self.f.compress(state, block)
        })
    }
}
