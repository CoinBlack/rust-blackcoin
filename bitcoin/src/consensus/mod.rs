// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.
//!

pub mod encode;
pub mod params;
#[cfg(feature = "bitcoinconsensus")]
pub mod validation;

use core::fmt;

use hex::{HexToBytesError, HexToBytesIter};
use internals::write_err;

pub use self::encode::{
    deserialize, deserialize_partial, serialize, Decodable, Encodable, ReadExt, WriteExt,
};
pub use self::params::Params;
#[cfg(feature = "bitcoinconsensus")]
pub use self::validation::{
    verify_script, verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
};

/// Deserialize any decodable type from a hex string.
pub fn deserialize_hex<T: Decodable>(hex: &str) -> Result<T, DecodeHexError> {
    let mut decoder = HexToBytesIter::new(hex)?;
    let rv = Decodable::consensus_decode_from_finite_reader(&mut decoder)?;
    Ok(rv)
}

/// Hex decoding error.
#[derive(Debug)]
pub enum DecodeHexError {
    /// Hex decoding error.
    Decode(HexToBytesError),
    /// Consensus deserialization error.
    Deser(encode::Error),
}

impl fmt::Display for DecodeHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeHexError::*;

        match *self {
            Decode(ref e) => write_err!(f, "hex decoding erorr"; e),
            Deser(ref e) => write_err!(f, "consensus deserialization error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeHexError::*;

        match *self {
            Decode(_) | Deser(_) => None,
        }
    }
}

impl From<HexToBytesError> for DecodeHexError {
    fn from(e: HexToBytesError) -> Self { Self::Decode(e) }
}

impl From<encode::Error> for DecodeHexError {
    fn from(e: encode::Error) -> Self { Self::Deser(e) }
}

#[cfg(feature = "serde")]
pub mod serde;
