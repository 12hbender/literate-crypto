mod iter;

pub(crate) use iter::{CollectVec, IterChunks};

/// Resize an array by either appending the default value or truncating.
pub fn resize<T: Default + Copy, const N: usize, const R: usize>(num: [T; N]) -> [T; R] {
    let mut result = [Default::default(); R];
    result.iter_mut().zip(num.iter()).for_each(|(a, b)| *a = *b);
    result
}
