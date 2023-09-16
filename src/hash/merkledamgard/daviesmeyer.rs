use crate::{BlockEncrypt, Bytes, CompressionFn, Key, Plaintext};

// TODO Davies-Meyer construction
pub struct DaviesMeyer<Enc: BlockEncrypt, Step: DaviesMeyerStep<State = Enc::EncryptionBlock>> {
    enc: Enc,
    step: Step,
}

/// A step in the Davies-Meyer construction.
///
/// Defines how the previous hash state should be combined with the new hash
/// state. Often this is just XOR.
pub trait DaviesMeyerStep {
    type State: Bytes;

    fn step(&self, prev: Self::State, new: Self::State) -> Self::State;
}

impl<Enc: BlockEncrypt, Step: DaviesMeyerStep<State = Enc::EncryptionBlock>>
    DaviesMeyer<Enc, Step>
{
    pub fn new(enc: Enc, step: Step) -> Self {
        Self { enc, step }
    }
}

impl<Enc: BlockEncrypt, Step: DaviesMeyerStep<State = Enc::EncryptionBlock>> CompressionFn
    for DaviesMeyer<Enc, Step>
{
    type Block = Enc::EncryptionKey;
    type State = Enc::EncryptionBlock;

    fn compress(&self, state: Self::State, block: Self::Block) -> Self::State {
        self.step
            .step(state, self.enc.encrypt(Plaintext(state), Key(block)).0)
    }
}
