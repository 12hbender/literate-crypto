//! AES is a commonly used block cipher.
//!
//! AES works on 128-bit blocks, and supports key sizes of 128, 192, and 256
//! bits. It works by applying a series of rounds of substitutions and
//! permutations to the plaintext, using a substitution box (S-box) and XORing
//! the output with a different key every round. The round keys are derived from
//! the decryption key.
//!
//! The S-box is a fixed, non-linear mapping from original to substituted bytes.
//! It's implemented as a lookup table. This achieves
//! [confusion](crate::doc::encryption#confusion). In particular, for
//! AES, the S-box is a matrix with some desirable properties.
//!
//! The permutations are achieved by first treating the plaintext block as a 4x4
//! matrix, and then shifting rows and mixing columns together. This ensures
//! [diffusion](crate::doc::encryption#diffusion).
//!
//! The specification for this cipher is available as [FIPS 197](https://doi.org/10.6028/NIST.FIPS.197).
