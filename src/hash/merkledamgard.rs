#![allow(dead_code)]

use crate::Bytes;

// TODO The Merkle-Damgard construction
pub struct MerkleDamgard /* <Cf: CompressionFn> */;

// TODO Compression function used by the Merkle-Damgard construction
pub trait CompressionFn {
    type State: Bytes;
    type Block: Bytes;

    fn compress(&self, state: Self::State, input: Self::Block) -> Self::State;
}

// TODO MD-compliant padding, split Padding into Pad and Unpad, change the
// interface into what it was before, and rename Padding into PaddingScheme
// TODO Do the same thing for BlockCipher = BlockEncrypt + BlockDecrypt
pub trait MdCompliantPad /* : Pad */ {}
