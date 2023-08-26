//! Encryption can only be considered secure if the ciphertext is statistically
//! indistinguishable from random noise.
//!
//! For this to be the case, two major properties must be achieved.
//!
//! # Confusion
//!
//! Confusion is achieved when the relationship between the plaintext, key, and
//! ciphertext is non-linear, and therefore unpredictable. In this context,
//! non-linearity means that the three are not related with a linear equation,
//! or otherwise easily expressed as a linear equation.
//!
//! # Diffusion
//!
//! Diffusion is achieved when each individual bit of the plaintext and key has
//! equal influence on potentially all bits of the ciphertext, meaning that a
//! change in a single bit should cause unpredictable changes in possibly all
//! bits of the ciphertext.
