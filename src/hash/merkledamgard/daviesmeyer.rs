use {
    crate::{BlockEncrypt, CompressionFn, Key, Plaintext},
    docext::docext,
};

/// The Davies-Meyer construction turns a [block cipher](BlockEncrypt)
/// into a [Merkle-Damgard compression function](CompressionFn).
///
/// Given a [Merkle-Damgard](crate::MerkleDamgard) state $S$, an input block
/// $B$, a block cipher $E_{key}$ and a [step function](DaviesMeyerStep) $Step$
/// used to combine states, the Davies-Meyer construction runs the block cipher
/// as follows:
///
/// $$
/// S^{\prime} = Step(S, E_{B}(S))
/// $$
///
/// Meaning, the new state is generated by using $Step$ to combine the old state
/// with the result of encrypting the old state, while using the input block as
/// the key. The step function should be one-way, making it impossible to go
/// back to a previous state. Often a simple XOR is used.
///
/// Note that there isn't really a special reason why the input block is used as
/// the key, and not the state. Applying the block cipher as $E_{S}(B)$ would
/// have also been a valid design.
#[docext]
#[derive(Debug)]
pub struct DaviesMeyer<Enc, Step> {
    enc: Enc,
    step: Step,
}

/// The step function of the [Davies-Meyer](DaviesMeyer) construction defines
/// how the previous hash state is combined with the new hash state.
///
/// This must be a one-way function, meaning that it should be impossible to
/// go back to a previous state given the current state. XOR is often used as
/// the step function.
pub trait DaviesMeyerStep {
    type State;

    fn step(&self, prev: Self::State, new: Self::State) -> Self::State;
}

impl<Enc, Step> DaviesMeyer<Enc, Step> {
    pub fn new(enc: Enc, step: Step) -> Self {
        Self { enc, step }
    }
}

impl<Enc: BlockEncrypt, Step: DaviesMeyerStep<State = Enc::EncryptionBlock>> CompressionFn
    for DaviesMeyer<Enc, Step>
where
    Enc::EncryptionBlock: Clone,
{
    type Block = Enc::EncryptionKey;
    type State = Enc::EncryptionBlock;

    fn compress(&self, state: Self::State, block: Self::Block) -> Self::State {
        self.step.step(
            state.clone(),
            self.enc.encrypt(Plaintext(state), Key(block)).0,
        )
    }
}
