// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses.
//!
//! Support for ordinary base58 Bitcoin addresses and private keys.
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! # #[cfg(feature = "rand-std")] {
//! use bitcoin::{Address, PublicKey, Network};
//! use bitcoin::secp256k1::{rand, Secp256k1};
//!
//! // Generate random key pair.
//! let s = Secp256k1::new();
//! let public_key = PublicKey::new(s.generate_keypair(&mut rand::thread_rng()).1);
//!
//! // Generate pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! # }
//! ```
//!
//! # Note: creating a new address requires the rand-std feature flag
//!
//! ```toml
//! bitcoin = { version = "...", features = ["rand-std"] }
//! ```

use core::convert::{TryFrom, TryInto};
use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::primitives::hrp::{self, Hrp};
use hashes::{sha256, Hash, HashEngine};
use secp256k1::{Secp256k1, Verification, XOnlyPublicKey};

use crate::base58;
use crate::blockdata::constants::{
    MAX_SCRIPT_ELEMENT_SIZE, PUBKEY_ADDRESS_PREFIX_MAIN, PUBKEY_ADDRESS_PREFIX_TEST,
    SCRIPT_ADDRESS_PREFIX_MAIN, SCRIPT_ADDRESS_PREFIX_TEST,
};
use crate::blockdata::script::witness_program::WitnessProgram;
use crate::blockdata::script::witness_version::WitnessVersion;
use crate::blockdata::script::{self, Script, ScriptBuf, ScriptHash};
use crate::crypto::key::{PubkeyHash, PublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey};
use crate::network::Network;
use crate::prelude::*;
use crate::script::PushBytesBuf;
use crate::taproot::TapNodeHash;

/// Error code for the address module.
pub mod error;
pub use self::error::{Error, ParseError, UnknownAddressTypeError};

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to witness pubkey hash.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// Pay to taproot.
    P2tr,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2pkh => "p2pkh",
            AddressType::P2sh => "p2sh",
            AddressType::P2wpkh => "p2wpkh",
            AddressType::P2wsh => "p2wsh",
            AddressType::P2tr => "p2tr",
        })
    }
}

impl FromStr for AddressType {
    type Err = UnknownAddressTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            "p2wpkh" => Ok(AddressType::P2wpkh),
            "p2wsh" => Ok(AddressType::P2wsh),
            "p2tr" => Ok(AddressType::P2tr),
            _ => Err(UnknownAddressTypeError(s.to_owned())),
        }
    }
}

/// The method used to produce an address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Payload {
    /// P2PKH address.
    PubkeyHash(PubkeyHash),
    /// P2SH address.
    ScriptHash(ScriptHash),
    /// Segwit address.
    WitnessProgram(WitnessProgram),
}

impl Payload {
    /// Constructs a [Payload] from an output script (`scriptPubkey`).
    pub fn from_script(script: &Script) -> Result<Payload, Error> {
        Ok(if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            Payload::PubkeyHash(PubkeyHash::from_byte_array(bytes))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            Payload::ScriptHash(ScriptHash::from_byte_array(bytes))
        } else if script.is_witness_program() {
            let opcode = script.first_opcode().expect("witness_version guarantees len() > 4");

            let witness_program = script.as_bytes()[2..].to_vec();

            let witness_program =
                WitnessProgram::new(WitnessVersion::try_from(opcode)?, witness_program)?;
            Payload::WitnessProgram(witness_program)
        } else {
            return Err(Error::UnrecognizedScript);
        })
    }

    /// Generates a script pubkey spending to this [Payload].
    pub fn script_pubkey(&self) -> ScriptBuf {
        match *self {
            Payload::PubkeyHash(ref hash) => ScriptBuf::new_p2pkh(hash),
            Payload::ScriptHash(ref hash) => ScriptBuf::new_p2sh(hash),
            Payload::WitnessProgram(ref prog) => ScriptBuf::new_witness_program(prog),
        }
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script: &Script) -> bool {
        match *self {
            Payload::PubkeyHash(ref hash) if script.is_p2pkh() =>
                &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(hash),
            Payload::ScriptHash(ref hash) if script.is_p2sh() =>
                &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(hash),
            Payload::WitnessProgram(ref prog) if script.is_witness_program() =>
                &script.as_bytes()[2..] == prog.program().as_bytes(),
            Payload::PubkeyHash(_) | Payload::ScriptHash(_) | Payload::WitnessProgram(_) => false,
        }
    }

    /// Creates a pay to (compressed) public key hash payload from a public key
    #[inline]
    pub fn p2pkh(pk: &PublicKey) -> Payload { Payload::PubkeyHash(pk.pubkey_hash()) }

    /// Creates a pay to script hash P2SH payload from a script
    #[inline]
    pub fn p2sh(script: &Script) -> Result<Payload, Error> {
        if script.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(Error::ExcessiveScriptSize);
        }
        Ok(Payload::ScriptHash(script.script_hash()))
    }

    /// Create a witness pay to public key payload from a public key
    pub fn p2wpkh(pk: &PublicKey) -> Result<Payload, Error> {
        let prog = WitnessProgram::new(
            WitnessVersion::V0,
            pk.wpubkey_hash().ok_or(Error::UncompressedPubkey)?,
        )?;
        Ok(Payload::WitnessProgram(prog))
    }

    /// Create a pay to script payload that embeds a witness pay to public key
    pub fn p2shwpkh(pk: &PublicKey) -> Result<Payload, Error> {
        let builder = script::Builder::new()
            .push_int(0)
            .push_slice(pk.wpubkey_hash().ok_or(Error::UncompressedPubkey)?);

        Ok(Payload::ScriptHash(builder.into_script().script_hash()))
    }

    /// Create a witness pay to script hash payload.
    pub fn p2wsh(script: &Script) -> Payload {
        let prog = WitnessProgram::new(WitnessVersion::V0, script.wscript_hash())
            .expect("wscript_hash has len 32 compatible with segwitv0");
        Payload::WitnessProgram(prog)
    }

    /// Create a pay to script payload that embeds a witness pay to script hash address
    pub fn p2shwsh(script: &Script) -> Payload {
        let ws = script::Builder::new().push_int(0).push_slice(script.wscript_hash()).into_script();

        Payload::ScriptHash(ws.script_hash())
    }

    /// Create a pay to taproot payload from untweaked key
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Payload {
        let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
        let prog = WitnessProgram::new(WitnessVersion::V1, output_key.to_inner().serialize())
            .expect("taproot output key has len 32 <= 40");
        Payload::WitnessProgram(prog)
    }

    /// Create a pay to taproot payload from a pre-tweaked output key.
    ///
    /// This method is not recommended for use and [Payload::p2tr()] should be used where possible.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey) -> Payload {
        let prog = WitnessProgram::new(WitnessVersion::V1, output_key.to_inner().serialize())
            .expect("taproot output key has len 32 <= 40");
        Payload::WitnessProgram(prog)
    }

    /// Returns a byte slice of the inner program of the payload. If the payload
    /// is a script hash or pubkey hash, a reference to the hash is returned.
    fn inner_prog_as_bytes(&self) -> &[u8] {
        match self {
            Payload::ScriptHash(hash) => hash.as_ref(),
            Payload::PubkeyHash(hash) => hash.as_ref(),
            Payload::WitnessProgram(prog) => prog.program().as_bytes(),
        }
    }
}

/// A utility struct to encode an address payload with the given parameters.
/// This is a low-level utility struct. Consider using `Address` instead.
pub struct AddressEncoding<'a> {
    /// The address payload to encode.
    pub payload: &'a Payload,
    /// base58 version byte for p2pkh payloads (e.g. 0x00 for "1..." addresses).
    pub p2pkh_prefix: u8,
    /// base58 version byte for p2sh payloads (e.g. 0x05 for "3..." addresses).
    pub p2sh_prefix: u8,
    /// The bech32 human-readable part.
    pub hrp: Hrp,
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl<'a> fmt::Display for AddressEncoding<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.p2pkh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Payload::ScriptHash(hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.p2sh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Payload::WitnessProgram(witness_program) => {
                let hrp = &self.hrp;
                let version = witness_program.version().to_fe();
                let program = witness_program.program().as_bytes();

                if fmt.alternate() {
                    bech32::segwit::encode_upper_to_fmt_unchecked(fmt, *hrp, version, program)
                } else {
                    bech32::segwit::encode_lower_to_fmt_unchecked(fmt, *hrp, version, program)
                }
            }
        }
    }
}

mod sealed {
    pub trait NetworkValidation {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}
}

/// Marker of status of address's network validation. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
pub trait NetworkValidation: sealed::NetworkValidation + Sync + Send + Sized + Unpin {
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker that address's network has been successfully validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkChecked {}

/// Marker that address's network has not yet been validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

/// The inner representation of an address, without the network validation tag.
///
/// An `Address` is composed of a payload and a network. This struct represents the inner
/// representation of an address without the network validation tag, which is used to ensure that
/// addresses are used only on the appropriate network.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AddressInner {
    payload: Payload,
    network: Network,
}

/// A Bitcoin address.
///
/// ### Parsing addresses
///
/// When parsing string as an address, one has to pay attention to the network, on which the parsed
/// address is supposed to be valid. For the purpose of this validation, `Address` has
/// [`is_valid_for_network`](Address<NetworkUnchecked>::is_valid_for_network) method. In order to provide more safety,
/// enforced by compiler, `Address` also contains a special marker type, which indicates whether network of the parsed
/// address has been checked. This marker type will prevent from calling certain functions unless the network
/// verification has been successfully completed.
///
/// The result of parsing an address is `Address<NetworkUnchecked>` suggesting that network of the parsed address
/// has not yet been verified. To perform this verification, method [`require_network`](Address<NetworkUnchecked>::require_network)
/// can be called, providing network on which the address is supposed to be valid. If the verification succeeds,
/// `Address<NetworkChecked>` is returned.
///
/// The types `Address` and `Address<NetworkChecked>` are synonymous, i. e. they can be used interchangeably.
///
/// ```rust
/// use std::str::FromStr;
/// use bitcoin::{Address, Network};
/// use bitcoin::address::{NetworkUnchecked, NetworkChecked};
///
/// // variant 1
/// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
/// let address: Address<NetworkChecked> = address.require_network(Network::Bitcoin).unwrap();
///
/// // variant 2
/// let address: Address = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap()
///                .require_network(Network::Bitcoin).unwrap();
///
/// // variant 3
/// let address: Address<NetworkChecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse::<Address<_>>()
///                .unwrap().require_network(Network::Bitcoin).unwrap();
/// ```
///
/// ### Formatting addresses
///
/// To format address into its textual representation, both `Debug` (for usage in programmer-facing,
/// debugging context) and `Display` (for user-facing output) can be used, with the following caveats:
///
/// 1. `Display` is implemented only for `Address<NetworkChecked>`:
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap().assume_checked();
/// assert_eq!(address.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
/// ```
///
/// ```ignore
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap();
/// let s = address.to_string(); // does not compile
/// ```
///
/// 2. `Debug` on `Address<NetworkUnchecked>` does not produce clean address but address wrapped by
/// an indicator that its network has not been checked. This is to encourage programmer to properly
/// check the network and use `Display` in user-facing context.
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkUnchecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap();
/// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM)");
/// ```
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap().assume_checked();
/// assert_eq!(format!("{:?}", address), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
/// ```
///
/// ### Relevant BIPs
///
/// * [BIP13 - Address Format for pay-to-script-hash](https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki)
/// * [BIP16 - Pay to Script Hash](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
/// * [BIP141 - Segregated Witness (Consensus layer)](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
/// * [BIP142 - Address Format for Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki)
/// * [BIP341 - Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
/// * [BIP350 - Bech32m format for v1+ witness addresses](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
///
/// The `#[repr(transparent)]` attribute is used to guarantee that the layout of the
/// `Address` struct is the same as the layout of the `AddressInner` struct. This attribute is
/// an implementation detail and users should not rely on it in their code.
///
#[repr(transparent)]
pub struct Address<V = NetworkChecked>(AddressInner, PhantomData<V>)
where
    V: NetworkValidation;

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a, N: NetworkValidation>(&'a Address<N>);

#[cfg(feature = "serde")]
impl<N: NetworkValidation> fmt::Display for DisplayUnchecked<'_, N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { self.0.fmt_internal(fmt) }
}

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_deserialize_impl!(Address<NetworkUnchecked>, "a Bitcoin address");

#[cfg(feature = "serde")]
impl<N: NetworkValidation> serde::Serialize for Address<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&DisplayUnchecked(self))
    }
}

/// Methods on [`Address`] that can be called on both `Address<NetworkChecked>` and
/// `Address<NetworkUnchecked>`.
impl<V: NetworkValidation> Address<V> {
    /// Returns a reference to the payload of this address.
    pub fn payload(&self) -> &Payload { &self.0.payload }

    /// Returns a reference to the network of this address.
    pub fn network(&self) -> &Network { &self.0.network }

    /// Returns a reference to the unchecked address, which is dangerous to use if the address
    /// is invalid in the context of `NetworkUnchecked`.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        unsafe { &*(self as *const Address<V> as *const Address<NetworkUnchecked>) }
    }

    /// Extracts and returns the network and payload components of the `Address`.
    pub fn into_parts(self) -> (Network, Payload) {
        let AddressInner { payload, network } = self.0;
        (network, payload)
    }

    /// Gets the address type of the address.
    ///
    /// This method is publicly available as [`address_type`](Address<NetworkChecked>::address_type)
    /// on `Address<NetworkChecked>` but internally can be called on `Address<NetworkUnchecked>` as
    /// `address_type_internal`.
    ///
    /// # Returns
    /// None if unknown, non-standard or related to the future witness version.
    fn address_type_internal(&self) -> Option<AddressType> {
        match self.payload() {
            Payload::PubkeyHash(_) => Some(AddressType::P2pkh),
            Payload::ScriptHash(_) => Some(AddressType::P2sh),
            Payload::WitnessProgram(ref prog) => {
                // BIP-141 p2wpkh or p2wsh addresses.
                match prog.version() {
                    WitnessVersion::V0 => match prog.program().len() {
                        20 => Some(AddressType::P2wpkh),
                        32 => Some(AddressType::P2wsh),
                        _ => unreachable!(
                            "Address creation invariant violation: invalid program length"
                        ),
                    },
                    WitnessVersion::V1 if prog.program().len() == 32 => Some(AddressType::P2tr),
                    _ => None,
                }
            }
        }
    }

    /// Format the address for the usage by `Debug` and `Display` implementations.
    fn fmt_internal(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let p2pkh_prefix = match self.network() {
            Network::Bitcoin => PUBKEY_ADDRESS_PREFIX_MAIN,
            Network::Testnet | Network::Signet | Network::Regtest => PUBKEY_ADDRESS_PREFIX_TEST,
        };
        let p2sh_prefix = match self.network() {
            Network::Bitcoin => SCRIPT_ADDRESS_PREFIX_MAIN,
            Network::Testnet | Network::Signet | Network::Regtest => SCRIPT_ADDRESS_PREFIX_TEST,
        };
        let hrp = match self.network() {
            Network::Bitcoin => hrp::BLK,
            Network::Testnet | Network::Signet => hrp::TBLK,
            Network::Regtest => hrp::BLRT,
        };
        let encoding = AddressEncoding { payload: self.payload(), p2pkh_prefix, p2sh_prefix, hrp };

        use fmt::Display;

        encoding.fmt(fmt)
    }

    /// Create new address from given components, infering the network validation
    /// marker type of the address.
    #[inline]
    pub fn new(network: Network, payload: Payload) -> Self {
        Self(AddressInner { network, payload }, PhantomData)
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: &PublicKey, network: Network) -> Address {
        Address::new(network, Payload::p2pkh(pk))
    }

    /// Creates a pay to script hash P2SH address from a script.
    ///
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh(script: &Script, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::p2sh(script)?))
    }

    /// Creates a witness pay to public key address from a public key.
    ///
    /// This is the native segwit address type for an output redeemable with a single signature.
    ///
    /// # Errors
    /// Will only return an error if an uncompressed public key is provided.
    pub fn p2wpkh(pk: &PublicKey, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::p2wpkh(pk)?))
    }

    /// Creates a pay to script address that embeds a witness pay to public key.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    ///
    /// # Errors
    /// Will only return an Error if an uncompressed public key is provided.
    pub fn p2shwpkh(pk: &PublicKey, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::p2shwpkh(pk)?))
    }

    /// Creates a witness pay to script hash address.
    pub fn p2wsh(script: &Script, network: Network) -> Address {
        Address::new(network, Payload::p2wsh(script))
    }

    /// Creates a pay to script address that embeds a witness pay to script hash address.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwsh(script: &Script, network: Network) -> Address {
        Address::new(network, Payload::p2shwsh(script))
    }

    /// Creates a pay to taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
        network: Network,
    ) -> Address {
        Address::new(network, Payload::p2tr(secp, internal_key, merkle_root))
    }

    /// Creates a pay to taproot address from a pre-tweaked output key.
    ///
    /// This method is not recommended for use, [`Address::p2tr()`] should be used where possible.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey, network: Network) -> Address {
        Address::new(network, Payload::p2tr_tweaked(output_key))
    }

    /// Gets the address type of the address.
    ///
    /// # Returns
    /// None if unknown, non-standard or related to the future witness version.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> { self.address_type_internal() }

    /// Checks whether or not the address is following Bitcoin standardness rules when
    /// *spending* from this address. *NOT* to be called by senders.
    ///
    /// <details>
    /// <summary>Spending Standardness</summary>
    ///
    /// For forward compatibility, the senders must send to any [`Address`]. Receivers
    /// can use this method to check whether or not they can spend from this address.
    ///
    /// SegWit addresses with unassigned witness versions or non-standard program sizes are
    /// considered non-standard.
    /// </details>
    ///
    pub fn is_spend_standard(&self) -> bool { self.address_type().is_some() }

    /// Constructs an [`Address`] from an output script (`scriptPubkey`).
    pub fn from_script(script: &Script, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::from_script(script)?))
    }

    /// Generates a script pubkey spending to this address.
    pub fn script_pubkey(&self) -> ScriptBuf { self.payload().script_pubkey() }

    /// Creates a URI string *bitcoin:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, the address becomes uppercase.
    /// If the address is base58, the address is left mixed case.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    ///
    /// Note however that despite BIP21 explicitly stating that the `bitcoin:` prefix should be
    /// parsed as case-insensitive many wallets got this wrong and don't parse correctly.
    /// [See compatibility table.](https://github.com/btcpayserver/btcpayserver/issues/2110)
    ///
    /// If you want to avoid allocation you can use alternate display instead:
    /// ```
    /// # use core::fmt::Write;
    /// # const ADDRESS: &str = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
    /// # let address = ADDRESS.parse::<bitcoin::Address<_>>().unwrap().assume_checked();
    /// # let mut writer = String::new();
    /// # // magic trick to make error handling look better
    /// # (|| -> Result<(), core::fmt::Error> {
    ///
    /// write!(writer, "{:#}", address)?;
    ///
    /// # Ok(())
    /// # })().unwrap();
    /// # assert_eq!(writer, ADDRESS);
    /// ```
    pub fn to_qr_uri(&self) -> String { format!("blackcoin:{:#}", self) }

    /// Returns true if the given pubkey is directly related to the address payload.
    ///
    /// This is determined by directly comparing the address payload with either the
    /// hash of the given public key or the segwit redeem hash generated from the
    /// given key. For taproot addresses, the supplied key is assumed to be tweaked
    pub fn is_related_to_pubkey(&self, pubkey: &PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload().inner_prog_as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);

        (*pubkey_hash.as_byte_array() == *payload)
            || (xonly_pubkey.serialize() == *payload)
            || (*segwit_redeem_hash(&pubkey_hash).as_byte_array() == *payload)
    }

    /// Returns true if the supplied xonly public key can be used to derive the address.
    ///
    /// This will only work for Taproot addresses. The Public Key is
    /// assumed to have already been tweaked.
    pub fn is_related_to_xonly_pubkey(&self, xonly_pubkey: &XOnlyPublicKey) -> bool {
        let payload = self.payload().inner_prog_as_bytes();
        payload == xonly_pubkey.serialize()
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script_pubkey: &Script) -> bool {
        self.payload().matches_script_pubkey(script_pubkey)
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address.
    /// This function is dangerous in case the address is not a valid checked address.
    pub fn assume_checked_ref(&self) -> &Address {
        unsafe { &*(self as *const Address<NetworkUnchecked> as *const Address) }
    }
    /// Parsed addresses do not always have *one* network. The problem is that legacy testnet,
    /// regtest and signet addresse use the same prefix instead of multiple different ones. When
    /// parsing, such addresses are always assumed to be testnet addresses (the same is true for
    /// bech32 signet addresses). So if one wants to check if an address belongs to a certain
    /// network a simple comparison is not enough anymore. Instead this function can be used.
    ///
    /// ```rust
    /// use bitcoin::{Address, Network};
    /// use bitcoin::address::NetworkUnchecked;
    ///
    /// let address: Address<NetworkUnchecked> = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet));
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert!(address.is_valid_for_network(Network::Signet));
    ///
    /// assert_eq!(address.is_valid_for_network(Network::Bitcoin), false);
    ///
    /// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Bitcoin));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet), false);
    /// ```
    pub fn is_valid_for_network(&self, network: Network) -> bool {
        let is_legacy = matches!(
            self.address_type_internal(),
            Some(AddressType::P2pkh) | Some(AddressType::P2sh)
        );

        match (self.network(), network) {
            (a, b) if *a == b => true,
            (Network::Bitcoin, _) | (_, Network::Bitcoin) => false,
            (Network::Regtest, _) | (_, Network::Regtest) if !is_legacy => false,
            (Network::Testnet, _) | (Network::Regtest, _) | (Network::Signet, _) => true,
        }
    }

    /// Checks whether network of this address is as required.
    ///
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn require_network(self, required: Network) -> Result<Address, Error> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(Error::NetworkValidation { found: *self.network(), required, address: self })
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    ///
    /// Improper use of this method may lead to loss of funds. Reader will most likely prefer
    /// [`require_network`](Address<NetworkUnchecked>::require_network) as a safe variant.
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn assume_checked(self) -> Address {
        let (network, payload) = self.into_parts();
        Address::new(network, payload)
    }
}

// For NetworkUnchecked , it compare Addresses and if network and payload matches then return true.
impl PartialEq<Address<NetworkUnchecked>> for Address {
    fn eq(&self, other: &Address<NetworkUnchecked>) -> bool {
        self.network() == other.network() && self.payload() == other.payload()
    }
}

impl PartialEq<Address> for Address<NetworkUnchecked> {
    fn eq(&self, other: &Address) -> bool { other == self }
}

impl From<Address> for script::ScriptBuf {
    fn from(a: Address) -> Self { a.script_pubkey() }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { self.fmt_internal(fmt) }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            self.fmt_internal(f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            self.fmt_internal(f)?;
            write!(f, ")")
        }
    }
}

/// Extracts the bech32 prefix.
///
/// # Returns
/// The input slice if no prefix is found.
fn find_bech32_prefix(bech32: &str) -> &str {
    // Split at the last occurrence of the separator character '1'.
    match bech32.rfind('1') {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
impl FromStr for Address<NetworkUnchecked> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // try bech32
        let bech32_network = match find_bech32_prefix(s) {
            // note that upper or lowercase is allowed but NOT mixed case
            "blk" | "BLK" => Some(Network::Bitcoin),
            "tblk" | "TBLK" => Some(Network::Testnet), // this may also be signet
            "blrt" | "BLRT" => Some(Network::Regtest),
            _ => None,
        };
        if let Some(network) = bech32_network {
            let (_hrp, version, data) = bech32::segwit::decode(s)?;
            let version = WitnessVersion::try_from(version).expect("we know this is in range 0-16");
            let program = PushBytesBuf::try_from(data).expect("decode() guarantees valid length");
            let witness_program = WitnessProgram::new(version, program)?;

            return Ok(Address::new(network, Payload::WitnessProgram(witness_program)));
        }

        // Base58
        if s.len() > 50 {
            return Err(ParseError::Base58(base58::Error::InvalidLength(s.len() * 11 / 15)));
        }
        let data = base58::decode_check(s)?;
        if data.len() != 21 {
            return Err(ParseError::Base58(base58::Error::InvalidLength(data.len())));
        }

        let (network, payload) = match data[0] {
            PUBKEY_ADDRESS_PREFIX_MAIN =>
                (Network::Bitcoin, Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap())),
            SCRIPT_ADDRESS_PREFIX_MAIN =>
                (Network::Bitcoin, Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap())),
            PUBKEY_ADDRESS_PREFIX_TEST =>
                (Network::Testnet, Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap())),
            SCRIPT_ADDRESS_PREFIX_TEST =>
                (Network::Testnet, Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap())),
            x => return Err(ParseError::Base58(base58::Error::InvalidAddressVersion(x))),
        };

        Ok(Address::new(network, payload))
    }
}

/// Convert a byte array of a pubkey hash into a segwit redeem hash
fn segwit_redeem_hash(pubkey_hash: &PubkeyHash) -> crate::hashes::hash160::Hash {
    let mut sha_engine = sha256::Hash::engine();
    sha_engine.input(&[0, 20]);
    sha_engine.input(pubkey_hash.as_ref());
    crate::hashes::hash160::Hash::from_engine(sha_engine)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use hex_lit::hex;
    use secp256k1::XOnlyPublicKey;

    use super::*;
    use crate::crypto::key::PublicKey;
    use crate::network::Network::{Bitcoin, Testnet};

    fn roundtrips(addr: &Address) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap().assume_checked(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), *addr.network()).as_ref(),
            Ok(addr),
            "script round-trip failed for {}",
            addr,
        );

        #[cfg(feature = "serde")]
        {
            let ser = serde_json::to_string(addr).expect("failed to serialize address");
            let back: Address<NetworkUnchecked> =
                serde_json::from_str(&ser).expect("failed to deserialize address");
            assert_eq!(back.assume_checked(), *addr, "serde round-trip failed for {}", addr)
        }
    }

    #[test]
    fn test_p2pkh_address_58() {
        let addr = Address::new(
            Bitcoin,
            Payload::PubkeyHash("0f3d16a50264456bbc771f40b36fefe69d30dc05".parse().unwrap()),
        );

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("76a9140f3d16a50264456bbc771f40b36fefe69d30dc0588ac").unwrap()
        );
        assert_eq!(&addr.to_string(), "B5qew6MwFjfH3fqNCb2eqbbMbRmaN67MD3");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = "04178abe9710e08f04b423be5a90c2b8d6987697dc53c0f2958e64e3d893fcc7c51ecdc85e997eec2c73cdcc21f70e3f3601d100fbb1f3275c48b65a519e327827".parse::<PublicKey>().unwrap();
        let addr = Address::p2pkh(&key, Bitcoin);
        assert_eq!(&addr.to_string(), "BHbXiw6Zvezk7pYYwbKyPrgprFkHLggcn1");

        let key = "0378c706a3c41ef40aff9e503d6e1410d62a9833512e1d38f30905c11e707e93ba"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2pkh(&key, Testnet);
        assert_eq!(&addr.to_string(), "n3vpYCTpWg4Bw7k3tW3KTwAEnCcVmBDMbx");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_address_58() {
        let addr = Address::new(
            Bitcoin,
            Payload::ScriptHash("fc7d8105ebd93eddc1a1a5b5af26a049cb14d58e".parse().unwrap()),
        );

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("a914fc7d8105ebd93eddc1a1a5b5af26a049cb14d58e87").unwrap(),
        );
        assert_eq!(&addr.to_string(), "bbkKKk2GT6wB5Qmpgtdd3gCnnsykXfD8Qu");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae").unwrap();
        let addr = Address::p2sh(&script, Testnet).unwrap();
        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_parse_for_large_script() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123").unwrap();
        assert_eq!(Address::p2sh(&script, Testnet), Err(Error::ExcessiveScriptSize));
    }

    #[test]
    fn test_p2wpkh() {
        let mut key = "03818de5f3d676fc0ab82b9dfa298e4e01105cebb36e28256b414348596246a235"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2wpkh(&key, Bitcoin).unwrap();
        assert_eq!(&addr.to_string(), "blk1qf5w5dpa5mx5mwhghd5gf5qmy6d3q6g36d4sf5p");
        assert_eq!(addr.address_type(), Some(AddressType::P2wpkh));
        roundtrips(&addr);

        // Test uncompressed pubkey
        key.compressed = false;
        assert_eq!(Address::p2wpkh(&key, Bitcoin), Err(Error::UncompressedPubkey));
    }

    #[test]
    fn test_p2wsh() {
        let script = ScriptBuf::from_hex("512102547e587315dbb62c5a9b0e7756a8bdf0e2a6330902f3ad78597ecc62de4a806551ae").unwrap();
        let addr = Address::p2wsh(&script, Bitcoin);
        assert_eq!(
            &addr.to_string(),
            "blk1qsu6jyu4cnm7x36w3lsj2c0tyt6glsgmun2n6cg0nr8fp0vgdva8qp5lux2"
        );
        assert_eq!(addr.address_type(), Some(AddressType::P2wsh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2shwpkh() {
        let mut key = "02af4ad6e0f1b81b6636e07139fc4948532e0dc1bca915fc0d0c3a231029ca3292"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2shwpkh(&key, Bitcoin).unwrap();
        assert_eq!(&addr.to_string(), "bWJbbsS2rSdf6LqWMxpr2AUamXzgfpB6S4");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);

        // Test uncompressed pubkey
        key.compressed = false;
        assert_eq!(Address::p2wpkh(&key, Bitcoin), Err(Error::UncompressedPubkey));
    }

    #[test]
    fn test_p2shwsh() {
        // stolen from Bitcoin transaction f9ee2be4df05041d0e0a35d7caa3157495ca4f93b233234c9967b6901dacf7a9
        let script = ScriptBuf::from_hex("522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae").unwrap();
        let addr = Address::p2shwsh(&script, Bitcoin);
        assert_eq!(&addr.to_string(), "36EqgNnsWW94SreZgBWc1ANC6wpFZwirHr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_non_existent_segwit_version() {
        // 40-byte program
        let program = hex!(
            "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4"
        );
        let witness_prog = WitnessProgram::new(WitnessVersion::V13, program.to_vec()).unwrap();
        let addr = Address::new(Bitcoin, Payload::WitnessProgram(witness_prog));
        roundtrips(&addr);
    }

    #[test]
    fn test_address_debug() {
        // This is not really testing output of Debug but the ability and proper functioning
        // of Debug derivation on structs generic in NetworkValidation.
        #[derive(Debug)]
        #[allow(unused)]
        struct Test<V: NetworkValidation> {
            address: Address<V>,
        }

        let addr_str = "bSzmVGyeqRJPDanTWovPvNSqD2HrWkMY8C";
        let unchecked = Address::from_str(addr_str).unwrap();

        assert_eq!(
            format!("{:?}", Test { address: unchecked.clone() }),
            format!("Test {{ address: Address<NetworkUnchecked>({}) }}", addr_str)
        );

        assert_eq!(
            format!("{:?}", Test { address: unchecked.assume_checked() }),
            format!("Test {{ address: {} }}", addr_str)
        );
    }

    #[test]
    fn test_address_type() {
        let addresses = [
            ("BPDTrrn91hQ7tuDDqtbMUxW7assCoLsUni", Some(AddressType::P2pkh)),
            ("bVvWZytGW27hMnn8ojUF6MnV65xviuBmoH", Some(AddressType::P2sh)),
            ("blk1q57ntsj2v2aqpfepsk6lct6jmyr8wcedmx3ts73", Some(AddressType::P2wpkh)),
            (
                "blk1qslnt20heyvy9zz8urgzp9rdvc0sm8e6q5qc98hrmn7wjsy2387rqp5kwms",
                Some(AddressType::P2wsh),
            ),
            (
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                Some(AddressType::P2tr),
            ),
            // Related to future extensions, addresses are valid but have no type
            // segwit v1 and len != 32
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", None),
            // segwit v2
            ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", None),
        ];
        for (address, expected_type) in &addresses {
            let addr = Address::from_str(address)
                .unwrap()
                .require_network(Network::Bitcoin)
                .expect("mainnet");
            assert_eq!(&addr.address_type(), expected_type);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialize() {
        use serde_json;

        let addr =
            Address::from_str("BK1iscer7M7aiTBPo9iLFuits6pqYyEKQ8").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("BK1iscer7M7aiTBPo9iLFuits6pqYyEKQ8".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("76a9149fbe2c1802902016679f34446dc7a4b09872173e88ac").unwrap()
        );

        let addr =
            Address::from_str("bCoDCTKxY9vNAatcgs8UfbsQbTrdy85szS").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("bCoDCTKxY9vNAatcgs8UfbsQbTrdy85szS".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("a91400bebed3b50b139d9f7632ace2a774f373675bea87").unwrap()
        );

        let addr: Address<NetworkUnchecked> =
            Address::from_str("blk1q2ny6tzxcj3pmph5uf0ph4rgz5396lku8eqxtsxj4g797pwjlpqcqg2h7sn")
                .unwrap();
        let json = serde_json::to_value(addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "blk1q2ny6tzxcj3pmph5uf0ph4rgz5396lku8eqxtsxj4g797pwjlpqcqg2h7sn".to_owned()
            )
        );

        let addr =
            Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
                .unwrap()
                .assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex(
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
            )
            .unwrap()
        );

        let addr = Address::from_str("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl")
            .unwrap()
            .assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("001454d26dddb59c7073c6a197946ea1841951fa7a74").unwrap()
        );
    }

    #[test]
    fn test_qr_string() {
        for el in
            ["B6721rwWhbAK35A64Nra9mrpakimnsr8Jg", "bEJd6m9KbsMvvscqEhuKFJDvNqUJCEMz2J"].iter()
        {
            let addr =
                Address::from_str(el).unwrap().require_network(Network::Bitcoin).expect("mainnet");
            assert_eq!(addr.to_qr_uri(), format!("blackcoin:{}", el));
        }

        for el in [
            "blrt1qyjq8htmgedctnhssw6tth7gyrkyrgpxktqxlhe",
            "blk1qycd4vmshwf8vxcqxk4qae2egykwuz974nfdzfwwm4hs56tqsanvs3k5q8a",
        ]
        .iter()
        {
            let addr = Address::from_str(el).unwrap().assume_checked();
            assert_eq!(addr.to_qr_uri(), format!("blackcoin:{}", el.to_ascii_uppercase()));
        }
    }

    #[test]
    fn test_valid_networks() {
        let legacy_payload = &[
            Payload::PubkeyHash(PubkeyHash::all_zeros()),
            Payload::ScriptHash(ScriptHash::all_zeros()),
        ];
        let segwit_payload = (0..=16)
            .map(|version| {
                Payload::WitnessProgram(
                    WitnessProgram::new(
                        WitnessVersion::try_from(version).unwrap(),
                        vec![0xab; 32], // Choose 32 to make test case valid for all witness versions(including v0)
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        const LEGACY_EQUIVALENCE_CLASSES: &[&[Network]] =
            &[&[Network::Bitcoin], &[Network::Testnet, Network::Regtest, Network::Signet]];
        const SEGWIT_EQUIVALENCE_CLASSES: &[&[Network]] =
            &[&[Network::Bitcoin], &[Network::Regtest], &[Network::Testnet, Network::Signet]];

        fn test_addr_type(payloads: &[Payload], equivalence_classes: &[&[Network]]) {
            for pl in payloads {
                for addr_net in equivalence_classes.iter().flat_map(|ec| ec.iter()) {
                    for valid_net in equivalence_classes
                        .iter()
                        .filter(|ec| ec.contains(addr_net))
                        .flat_map(|ec| ec.iter())
                    {
                        let addr = Address::new(*addr_net, pl.clone());
                        assert!(addr.is_valid_for_network(*valid_net));
                    }

                    for invalid_net in equivalence_classes
                        .iter()
                        .filter(|ec| !ec.contains(addr_net))
                        .flat_map(|ec| ec.iter())
                    {
                        let addr = Address::new(*addr_net, pl.clone());
                        assert!(!addr.is_valid_for_network(*invalid_net));
                    }
                }
            }
        }

        test_addr_type(legacy_payload, LEGACY_EQUIVALENCE_CLASSES);
        test_addr_type(&segwit_payload, SEGWIT_EQUIVALENCE_CLASSES);
    }

    #[test]
    fn p2tr_from_untweaked() {
        //Test case from BIP-086
        let internal_key = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        let secp = Secp256k1::verification_only();
        let address = Address::p2tr(&secp, internal_key, None, Network::Bitcoin);
        assert_eq!(
            address.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(address.address_type(), Some(AddressType::P2tr));
        roundtrips(&address);
    }

    #[test]
    fn test_is_related_to_pubkey_p2wpkh() {
        let address_string = "blk1qjpe9zucdpxffkeyrnue45tap2jwx7khhefnjag";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0397aca21423436fbf3dae2121fd1d3ae3b46dff47df38e4fe339a38a9273ff8c5";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02e81c12b9db45dac0d775515679683c56210080fc66aca3676121fc376abd5b4d",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2shwpkh() {
        let address_string = "bJdU95jNeufixTM8edTxgeBAda2aetC22x";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "03f07fde9478fd494384407aa6583977b3fc8a2ed890980d2b11299947ca5049f4";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02160813f7bfdf2a3bc9bdf0cbbe17d678f02acbb2c57d37ebd67781f437de6427",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh() {
        let address_string = "B4VsKWxKdXYsRiwavyNXGgWmqs2n8F7jSM";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "034730e15d59bf36c80ebc540c05fa6b281078ce45079d9f5a2e187ca4f201e65a";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "0253f61cf0191f2186613c268129bba94f394c8bd8e4b574441a6c073536669035",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh_uncompressed_key() {
        let address_string = "msvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6p";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Testnet)
            .expect("testnet");

        let pubkey_string = "04e96e22004e3db93530de27ccddfdf1463975d2138ac018fc3e7ba1a2e5e0aad8e424d0b55e2436eb1d0dcd5cb2b8bcc6d53412c22f358de57803a6a655fbbd04";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2tr() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, Network::Bitcoin);

        assert_eq!(
            address,
            Address::from_str("bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e")
                .expect("address")
                .require_network(Network::Bitcoin)
                .expect("mainnet")
        );

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey));
    }

    #[test]
    fn test_is_related_to_xonly_pubkey() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, Network::Bitcoin);

        assert_eq!(
            address,
            Address::from_str("bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e")
                .expect("address")
                .require_network(Network::Bitcoin)
                .expect("mainnet")
        );

        let result = address.is_related_to_xonly_pubkey(&xonly_pubkey);
        assert!(result);
    }

    #[test]
    fn test_fail_address_from_script() {
        use crate::witness_program;

        let bad_p2wpkh = ScriptBuf::from_hex("0014dbc5b0a8f9d4353b4b54c3db48846bb15abfec").unwrap();
        let bad_p2wsh = ScriptBuf::from_hex(
            "00202d4fa2eb233d008cc83206fa2f4f2e60199000f5b857a835e3172323385623",
        )
        .unwrap();
        let invalid_segwitv0_script =
            ScriptBuf::from_hex("001161458e330389cd0437ee9fe3641d70cc18").unwrap();
        let expected = Err(Error::UnrecognizedScript);

        assert_eq!(Address::from_script(&bad_p2wpkh, Network::Bitcoin), expected);
        assert_eq!(Address::from_script(&bad_p2wsh, Network::Bitcoin), expected);
        assert_eq!(
            Address::from_script(&invalid_segwitv0_script, Network::Bitcoin),
            Err(Error::WitnessProgram(witness_program::Error::InvalidSegwitV0Length(17)))
        );
    }

    #[test]
    fn valid_address_parses_correctly() {
        let addr = AddressType::from_str("p2tr").expect("false negative while parsing address");
        assert_eq!(addr, AddressType::P2tr);
    }

    #[test]
    fn invalid_address_parses_error() {
        let got = AddressType::from_str("invalid");
        let want = Err(UnknownAddressTypeError("invalid".to_string()));
        assert_eq!(got, want);
    }

    #[test]
    fn test_matches_script_pubkey() {
        let addresses = [
            "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY",
            "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx",
            "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k",
            "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE",
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e",
        ];
        for addr in &addresses {
            let addr = Address::from_str(addr).unwrap().require_network(Network::Bitcoin).unwrap();
            for another in &addresses {
                let another =
                    Address::from_str(another).unwrap().require_network(Network::Bitcoin).unwrap();
                assert_eq!(addr.matches_script_pubkey(&another.script_pubkey()), addr == another);
            }
        }
    }
}
