// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{
    fmt::{Debug, LowerHex},
    slice,
};
use math::{FieldElement, StarkField};
use utils::{ByteReader, Deserializable, DeserializationError, Serializable, SliceReader};

mod blake;
pub use blake::{Blake3_192, Blake3_256};

mod blake2s;
pub use blake2s::Blake2s_256;

mod sha;
pub use sha::Sha3_256;

mod rescue;
pub use rescue::{Rp62_248, Rp64_256};

// HASHER TRAITS
// ================================================================================================

/// Defines a cryptographic hash function.
///
/// This trait defined hash procedures for the following inputs:
/// * A sequence of bytes.
/// * Two digests - this is intended for use in Merkle tree constructions.
/// * A digests and a u64 value - this intended for use in PRNG or PoW contexts.
pub trait Hasher {
    /// Specifies a digest type returned by this hasher.
    type Digest: Digest;

    /// Returns a hash of the provided sequence of bytes.
    fn hash(bytes: &[u8]) -> Self::Digest;

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

    /// Returns hash(`seed` || `value`). This method is intended for use in PRNG and PoW contexts.
    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest;
}

/// Defines a cryptographic hash function for hashing field elements.
///
/// This trait defines a hash procedure for a sequence of field elements. The elements can be
/// either in the base field specified for this hasher, or in an extension of the base field.
pub trait ElementHasher: Hasher {
    /// Specifies a base field for elements which can be hashed with this hasher.
    type BaseField: StarkField;

    /// Returns a hash of the provided field elements.
    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>;
}

// DIGEST TRAIT
// ================================================================================================

/// Defines output type for a cryptographic hash function.
pub trait Digest:
    Debug
    + Default
    + Copy
    + Clone
    + Eq
    + PartialEq
    + Send
    + Sync
    + Serializable
    + Deserializable
    + LowerHex
{
    /// Returns this digest serialized into an array of bytes.
    ///
    /// Ideally, the length of the returned array should be defined by an associated constant, but
    /// using associated constants in const generics is not supported by Rust yet. Thus, we put an
    /// upper limit on the possible digest size. For digests which are smaller than 32 bytes, the
    /// unused bytes should be set to 0.
    fn as_bytes(&self) -> [u8; 32];

    #[cfg(feature = "wasm")]
    fn into_js_value(self) -> wasm_bindgen::JsValue {
        let bytes = self.as_bytes();
        let h = hex::encode(bytes);
        wasm_bindgen::JsValue::from_str(&h)
    }

    #[cfg(feature = "wasm")]
    fn from_js_value(value: wasm_bindgen::JsValue) -> Self
    where
        Self: Sized,
    {
        let h = value.as_string().unwrap();
        let bytes = hex::decode(h).unwrap();
        let mut reader = SliceReader::new(&bytes);
        Self::read_from(&mut reader).unwrap()
    }
}

// BYTE DIGEST
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ByteDigest<const N: usize>(pub [u8; N]);

impl<const N: usize> ByteDigest<N> {
    pub fn new(value: [u8; N]) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn bytes_as_digests(bytes: &[[u8; N]]) -> &[ByteDigest<N>] {
        let p = bytes.as_ptr();
        let len = bytes.len();
        unsafe { slice::from_raw_parts(p as *const ByteDigest<N>, len) }
    }

    #[inline(always)]
    pub fn digests_as_bytes(digests: &[ByteDigest<N>]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * N;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }

    pub fn to_words(&self) -> Vec<u32> {
        let mut result = Vec::new();
        for i in self.0.chunks(4) {
            result.push(u32::from_le_bytes(i.try_into().unwrap()));
        }
        result
    }
}

impl<const N: usize> Digest for ByteDigest<N> {
    fn as_bytes(&self) -> [u8; 32] {
        let mut result = [0; 32];
        result[..N].copy_from_slice(&self.0);
        result
    }
}

impl<const N: usize> LowerHex for ByteDigest<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for word in self.0.chunks(4) {
            write!(f, "{:08x}", u32::from_le_bytes(word.try_into().unwrap()))?;
        }
        Ok(())
    }
}

impl<const N: usize> Default for ByteDigest<N> {
    fn default() -> Self {
        ByteDigest([0; N])
    }
}

impl<const N: usize> Serializable for ByteDigest<N> {
    fn write_into<W: utils::ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.0);
    }
}

impl<const N: usize> Deserializable for ByteDigest<N> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(ByteDigest(source.read_u8_array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteDigest, Digest};

    #[test]
    fn byte_digest_as_bytes() {
        let d = ByteDigest::new([255_u8; 32]);
        assert_eq!([255_u8; 32], d.as_bytes());

        let d = ByteDigest::new([255_u8; 31]);
        let mut expected = [255_u8; 32];
        expected[31] = 0;
        assert_eq!(expected, d.as_bytes());
    }
}
