use crate::{BlockCipher, CompressionFn, Key, Plaintext};

// TODO Davies-Meyer construction
#[derive(Debug)]
pub struct DaviesMeyer<Cip, Step> {
    cip: Cip,
    step: Step,
}

/// A step in the Davies-Meyer construction.
///
/// Defines how the previous hash state should be combined with the new hash
/// state. Often this is just XOR.
pub trait DaviesMeyerStep {
    type State;

    fn step(&self, prev: Self::State, new: Self::State) -> Self::State;
}

impl<Cip, Step> DaviesMeyer<Cip, Step> {
    pub fn new(cip: Cip, step: Step) -> Self {
        Self { cip, step }
    }
}

// TODO Explain this, and difference between this and BlockCipher
// This one does not need to be as secure
pub trait DaviesMeyerCipher {
    type Block;
    type State;

    fn encrypt(&mut self, state: Self::State, block: Self::Block) -> Self::State;
}

impl<Cip: BlockCipher> DaviesMeyerCipher for Cip {
    type Block = Cip::Key;
    type State = Cip::Block;

    fn encrypt(&mut self, state: Self::State, block: Self::Block) -> Self::State {
        Cip::encrypt(self, Plaintext(state), Key(block)).0
    }
}

impl<Cip: DaviesMeyerCipher, Step: DaviesMeyerStep<State = Cip::State>> CompressionFn
    for DaviesMeyer<Cip, Step>
where
    Cip::State: Clone,
{
    type Block = Cip::Block;
    type State = Cip::State;

    fn compress(&mut self, state: Self::State, block: Self::Block) -> Self::State {
        self.step
            .step(state.clone(), self.cip.encrypt(state, block))
    }
}
