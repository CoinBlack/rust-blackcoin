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

pub mod error;

use core::convert::{TryFrom, TryInto};
use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::primitives::hrp::Hrp;
use hashes::{sha256, Hash, HashEngine};
use secp256k1::{Secp256k1, Verification, XOnlyPublicKey};

use crate::base58;
use crate::blockdata::constants::{
    MAX_SCRIPT_ELEMENT_SIZE, PUBKEY_ADDRESS_PREFIX_MAIN, PUBKEY_ADDRESS_PREFIX_TEST,
    SCRIPT_ADDRESS_PREFIX_MAIN, SCRIPT_ADDRESS_PREFIX_TEST,
};
use crate::blockdata::script::witness_program::WitnessProgram;
use crate::blockdata::script::witness_version::WitnessVersion;
use crate::blockdata::script::{self, PushBytesBuf, Script, ScriptBuf, ScriptHash};
use crate::crypto::key::{
    CompressedPublicKey, PubkeyHash, PublicKey, TweakedPublicKey, UntweakedPublicKey,
};
use crate::network::{Network, NetworkKind};
use crate::prelude::*;
use crate::taproot::TapNodeHash;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    error::{Error, ParseError, UnknownAddressTypeError, UnknownHrpError},
};

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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AddressInner {
    P2pkh { hash: PubkeyHash, network: NetworkKind },
    P2sh { hash: ScriptHash, network: NetworkKind },
    Segwit { program: WitnessProgram, hrp: KnownHrp },
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for AddressInner {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use AddressInner::*;
        match self {
            P2pkh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => PUBKEY_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => PUBKEY_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => SCRIPT_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => SCRIPT_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Segwit { program, hrp } => {
                let hrp = hrp.to_hrp();
                let version = program.version().to_fe();
                let program = program.program().as_ref();

                if fmt.alternate() {
                    bech32::segwit::encode_upper_to_fmt_unchecked(fmt, hrp, version, program)
                } else {
                    bech32::segwit::encode_lower_to_fmt_unchecked(fmt, hrp, version, program)
                }
            }
        }
    }
}

/// Known bech32 human-readable parts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
enum KnownHrp {
    /// The main Bitcoin network.
    Mainnet,
    /// The test networks, testnet and signet.
    Testnets,
    /// The regtest network.
    Regtest,
}

impl KnownHrp {
    /// Creates a `KnownHrp` from `network`.
    fn from_network(network: Network) -> Self {
        use Network::*;

        match network {
            Bitcoin => Self::Mainnet,
            Testnet | Signet => Self::Testnets,
            Regtest => Self::Regtest,
        }
    }

    /// Creates a `KnownHrp` from a [`bech32::Hrp`].
    fn from_hrp(hrp: Hrp) -> Result<Self, UnknownHrpError> {
        if hrp == bech32::hrp::BLK {
            Ok(Self::Mainnet)
        } else if hrp.is_valid_on_testnet() || hrp.is_valid_on_signet() {
            Ok(Self::Testnets)
        } else if hrp == bech32::hrp::BLRT {
            Ok(Self::Regtest)
        } else {
            Err(UnknownHrpError(hrp.to_lowercase()))
        }
    }

    /// Converts, infallibly a known HRP to a [`bech32::Hrp`].
    fn to_hrp(self) -> Hrp {
        match self {
            Self::Mainnet => bech32::hrp::BLK,
            Self::Testnets => bech32::hrp::TBLK,
            Self::Regtest => bech32::hrp::BLRT,
        }
    }
}

impl From<Network> for KnownHrp {
    fn from(n: Network) -> Self { Self::from_network(n) }
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
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0 .0, fmt) }
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
    /// Returns a reference to the unchecked address, which is dangerous to use if the address
    /// is invalid in the context of `NetworkUnchecked`.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        unsafe { &*(self as *const Address<V> as *const Address<NetworkUnchecked>) }
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: impl Into<PubkeyHash>, network: impl Into<NetworkKind>) -> Address {
        let hash = pk.into();
        Self(AddressInner::P2pkh { hash, network: network.into() }, PhantomData)
    }

    /// Creates a pay to script hash P2SH address from a script.
    ///
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh(script: &Script, network: impl Into<NetworkKind>) -> Result<Address, Error> {
        if script.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(Error::ExcessiveScriptSize);
        }
        let hash = script.script_hash();
        Ok(Address::p2sh_from_hash(hash, network))
    }

    // This is intentionally not public so we enforce script length checks.
    fn p2sh_from_hash(hash: ScriptHash, network: impl Into<NetworkKind>) -> Address {
        Self(AddressInner::P2sh { hash, network: network.into() }, PhantomData)
    }

    /// Creates a witness pay to public key address from a public key.
    ///
    /// This is the native segwit address type for an output redeemable with a single signature.
    pub fn p2wpkh(pk: &CompressedPublicKey, network: Network) -> Self {
        let program = WitnessProgram::p2wpkh(pk);
        Address::from_witness_program(program, network)
    }

    /// Creates a pay to script address that embeds a witness pay to public key.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwpkh(pk: &CompressedPublicKey, network: impl Into<NetworkKind>) -> Address {
        let builder = script::Builder::new().push_int(0).push_slice(pk.wpubkey_hash());
        let script_hash = builder.as_script().script_hash();
        Address::p2sh_from_hash(script_hash, network)
    }

    /// Creates a witness pay to script hash address.
    pub fn p2wsh(script: &Script, network: Network) -> Address {
        let program = WitnessProgram::p2wsh(script);
        Address::from_witness_program(program, network)
    }

    /// Creates a pay to script address that embeds a witness pay to script hash address.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwsh(script: &Script, network: impl Into<NetworkKind>) -> Address {
        let builder = script::Builder::new().push_int(0).push_slice(script.wscript_hash());
        let script_hash = builder.as_script().script_hash();
        Address::p2sh_from_hash(script_hash, network)
    }

    /// Creates a pay to taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
        network: Network,
    ) -> Address {
        let program = WitnessProgram::p2tr(secp, internal_key, merkle_root);
        Address::from_witness_program(program, network)
    }

    /// Creates a pay to taproot address from a pre-tweaked output key.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey, network: Network) -> Address {
        let program = WitnessProgram::p2tr_tweaked(output_key);
        Address::from_witness_program(program, network)
    }

    /// Creates an address from an arbitrary witness program.
    ///
    /// This only exists to support future witness versions. If you are doing normal mainnet things
    /// then you likely do not need this constructor.
    // TODO: This is still arguably wrong, could take a KnownHrp/Hrp instead of Network.
    pub fn from_witness_program(program: WitnessProgram, network: Network) -> Address {
        let hrp = KnownHrp::from_network(network);
        let inner = AddressInner::Segwit { program, hrp };
        Address(inner, PhantomData)
    }

    /// Gets the address type of the address.
    ///
    /// # Returns
    ///
    /// None if unknown, non-standard or related to the future witness version.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        match self.0 {
            AddressInner::P2pkh { .. } => Some(AddressType::P2pkh),
            AddressInner::P2sh { .. } => Some(AddressType::P2sh),
            AddressInner::Segwit { ref program, hrp: _ } =>
                if program.is_p2wpkh() {
                    Some(AddressType::P2wpkh)
                } else if program.is_p2wsh() {
                    Some(AddressType::P2wsh)
                } else if program.is_p2tr() {
                    Some(AddressType::P2tr)
                } else {
                    None
                },
        }
    }

    /// Gets the pubkey hash for this address if this is a P2PKH address.
    pub fn pubkey_hash(&self) -> Option<PubkeyHash> {
        use AddressInner::*;

        match self.0 {
            P2pkh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the script hash for this address if this is a P2SH address.
    pub fn script_hash(&self) -> Option<ScriptHash> {
        use AddressInner::*;

        match self.0 {
            P2sh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

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
        if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            let hash = PubkeyHash::from_byte_array(bytes);
            Ok(Address::p2pkh(hash, network))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            let hash = ScriptHash::from_byte_array(bytes);
            Ok(Address::p2sh_from_hash(hash, network))
        } else if script.is_witness_program() {
            let opcode = script.first_opcode().expect("is_witness_program guarantees len > 4");

            let buf = PushBytesBuf::try_from(script.as_bytes()[2..].to_vec())
                .expect("is_witness_program guarantees len <= 42 bytes");
            let version = WitnessVersion::try_from(opcode)?;
            let program = WitnessProgram::new(version, buf)?;
            Ok(Address::from_witness_program(program, network))
        } else {
            Err(Error::UnrecognizedScript)
        }
    }

    /// Generates a script pubkey spending to this address.
    pub fn script_pubkey(&self) -> ScriptBuf {
        use AddressInner::*;
        match self.0 {
            P2pkh { ref hash, network: _ } => ScriptBuf::new_p2pkh(hash),
            P2sh { ref hash, network: _ } => ScriptBuf::new_p2sh(hash),
            Segwit { ref program, hrp: _ } => {
                let prog = program.program();
                let version = program.version();
                ScriptBuf::new_witness_program_unchecked(version, prog)
            }
        }
    }

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
        let payload = self.payload_as_bytes();
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
        xonly_pubkey.serialize() == *self.payload_as_bytes()
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script: &Script) -> bool {
        use AddressInner::*;
        match self.0 {
            P2pkh { ref hash, network: _ } if script.is_p2pkh() =>
                &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(hash),
            P2sh { ref hash, network: _ } if script.is_p2sh() =>
                &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(hash),
            Segwit { ref program, hrp: _ } if script.is_witness_program() =>
                &script.as_bytes()[2..] == program.program().as_bytes(),
            P2pkh { .. } | P2sh { .. } | Segwit { .. } => false,
        }
    }

    /// Returns the "payload" for this address.
    ///
    /// The "payload" is the useful stuff excluding serialization prefix, the exact payload is
    /// dependent on the inner address:
    ///
    /// - For p2sh, the payload is the script hash.
    /// - For p2pkh, the payload is the pubkey hash.
    /// - For segwit addresses, the payload is the witness program.
    fn payload_as_bytes(&self) -> &[u8] {
        use AddressInner::*;
        match self.0 {
            P2sh { ref hash, network: _ } => hash.as_ref(),
            P2pkh { ref hash, network: _ } => hash.as_ref(),
            Segwit { ref program, hrp: _ } => program.program().as_bytes(),
        }
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
    pub fn is_valid_for_network(&self, n: Network) -> bool {
        use AddressInner::*;
        match self.0 {
            P2pkh { hash: _, ref network } => *network == NetworkKind::from(n),
            P2sh { hash: _, ref network } => *network == NetworkKind::from(n),
            Segwit { program: _, ref hrp } => *hrp == KnownHrp::from_network(n),
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
            Err(Error::NetworkValidation { required, address: self })
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
        use AddressInner::*;

        let inner = match self.0 {
            P2pkh { hash, network } => P2pkh { hash, network },
            P2sh { hash, network } => P2sh { hash, network },
            Segwit { program, hrp } => Segwit { program, hrp },
        };
        Address(inner, PhantomData)
    }
}

impl From<Address> for script::ScriptBuf {
    fn from(a: Address) -> Self { a.script_pubkey() }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, fmt) }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            fmt::Display::fmt(&self.0, f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            fmt::Display::fmt(&self.0, f)?;
            write!(f, ")")
        }
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
impl FromStr for Address<NetworkUnchecked> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Address<NetworkUnchecked>, ParseError> {
        if let Ok((hrp, witness_version, data)) = bech32::segwit::decode(s) {
            let version = WitnessVersion::try_from(witness_version)?;
            let buf = PushBytesBuf::try_from(data).expect("bech32 guarantees valid program length");
            let program = WitnessProgram::new(version, buf)
                .expect("bech32 guarantees valid program length for witness");

            let hrp = KnownHrp::from_hrp(hrp)?;
            let inner = AddressInner::Segwit { program, hrp };
            return Ok(Address(inner, PhantomData));
        }

        // If segwit decoding fails, assume its a legacy address.

        if s.len() > 50 {
            return Err(ParseError::Base58(base58::Error::InvalidLength(s.len() * 11 / 15)));
        }
        let data = base58::decode_check(s)?;
        if data.len() != 21 {
            return Err(ParseError::Base58(base58::Error::InvalidLength(data.len())));
        }

        let (prefix, data) = data.split_first().expect("length checked above");
        let data: [u8; 20] = data.try_into().expect("length checked above");

        let inner = match *prefix {
            PUBKEY_ADDRESS_PREFIX_MAIN => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: NetworkKind::Main }
            }
            PUBKEY_ADDRESS_PREFIX_TEST => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: NetworkKind::Test }
            }
            SCRIPT_ADDRESS_PREFIX_MAIN => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Main }
            }
            SCRIPT_ADDRESS_PREFIX_TEST => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Test }
            }
            x => return Err(ParseError::Base58(base58::Error::InvalidAddressVersion(x))),
        };

        Ok(Address(inner, PhantomData))
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

    fn roundtrips(addr: &Address, network: Network) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap().assume_checked(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), network)
                .expect("failed to create inner address from script_pubkey"),
            *addr,
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
        let hash = "0f3d16a50264456bbc771f40b36fefe69d30dc05".parse::<PubkeyHash>().unwrap();
        let addr = Address::p2pkh(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("76a9140f3d16a50264456bbc771f40b36fefe69d30dc0588ac").unwrap()
        );
        assert_eq!(&addr.to_string(), "B5qew6MwFjfH3fqNCb2eqbbMbRmaN67MD3");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = "04178abe9710e08f04b423be5a90c2b8d6987697dc53c0f2958e64e3d893fcc7c51ecdc85e997eec2c73cdcc21f70e3f3601d100fbb1f3275c48b65a519e327827".parse::<PublicKey>().unwrap();
        let addr = Address::p2pkh(key, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "BHbXiw6Zvezk7pYYwbKyPrgprFkHLggcn1");

        let key = "0378c706a3c41ef40aff9e503d6e1410d62a9833512e1d38f30905c11e707e93ba"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2pkh(key, NetworkKind::Test);
        assert_eq!(&addr.to_string(), "n3vpYCTpWg4Bw7k3tW3KTwAEnCcVmBDMbx");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Testnet);
    }

    #[test]
    fn test_p2sh_address_58() {
        let hash = "fc7d8105ebd93eddc1a1a5b5af26a049cb14d58e".parse::<ScriptHash>().unwrap();
        let addr = Address::p2sh_from_hash(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("a914fc7d8105ebd93eddc1a1a5b5af26a049cb14d58e87").unwrap(),
        );
        assert_eq!(&addr.to_string(), "bbkKKk2GT6wB5Qmpgtdd3gCnnsykXfD8Qu");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae").unwrap();
        let addr = Address::p2sh(&script, NetworkKind::Test).unwrap();
        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Testnet);
    }

    #[test]
    fn test_p2sh_parse_for_large_script() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123").unwrap();
        assert_eq!(Address::p2sh(&script, NetworkKind::Test), Err(Error::ExcessiveScriptSize));
    }

    #[test]
    fn test_p2wpkh() {
        let key = "03818de5f3d676fc0ab82b9dfa298e4e01105cebb36e28256b414348596246a235"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let addr = Address::p2wpkh(&key, Bitcoin);
        assert_eq!(&addr.to_string(), "blk1qf5w5dpa5mx5mwhghd5gf5qmy6d3q6g36d4sf5p");
        assert_eq!(addr.address_type(), Some(AddressType::P2wpkh));
        roundtrips(&addr, Bitcoin);
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
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2shwpkh() {
        let key = "02af4ad6e0f1b81b6636e07139fc4948532e0dc1bca915fc0d0c3a231029ca3292"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let addr = Address::p2shwpkh(&key, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "bWJbbsS2rSdf6LqWMxpr2AUamXzgfpB6S4");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2shwsh() {
        // stolen from Bitcoin transaction f9ee2be4df05041d0e0a35d7caa3157495ca4f93b233234c9967b6901dacf7a9
        let script = ScriptBuf::from_hex("522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae").unwrap();
        let addr = Address::p2shwsh(&script, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "36EqgNnsWW94SreZgBWc1ANC6wpFZwirHr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_non_existent_segwit_version() {
        // 40-byte program
        let program = PushBytesBuf::from(hex!(
            "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4"
        ));
        let program = WitnessProgram::new(WitnessVersion::V13, program).expect("valid program");

        let addr = Address::from_witness_program(program, Bitcoin);
        roundtrips(&addr, Bitcoin);
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

        let addr_str = "bbkKKk2GT6wB5Qmpgtdd3gCnnsykXfD8Qu";
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
            ("BHbXiw6Zvezk7pYYwbKyPrgprFkHLggcn1", Some(AddressType::P2pkh)),
            ("bbkKKk2GT6wB5Qmpgtdd3gCnnsykXfD8Qu", Some(AddressType::P2sh)),
            ("blk1qf5w5dpa5mx5mwhghd5gf5qmy6d3q6g36d4sf5p", Some(AddressType::P2wpkh)),
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
            Address::from_str("tblk1qvefhvq4xays9m098zdydtjkyje6ss4uyt9rj2y")
                .unwrap()
                .assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tblk1qvefhvq4xays9m098zdydtjkyje6ss4uyt9rj2y".to_owned()
            )
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex(
                "001466537602a6e9205dbca71348d5cac49675085784"
            )
            .unwrap()
        );

        let addr = Address::from_str("blrt1qk6d7rz5e3ur7u7ma36sfqe6k4y90863h7vs0aj")
            .unwrap()
            .assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("blrt1qk6d7rz5e3ur7u7ma36sfqe6k4y90863h7vs0aj".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("0014b69be18a998f07ee7b7d8ea0906756a90af3ea37").unwrap()
        );
    }

    #[test]
    fn test_qr_string() {
        for el in
            ["B6721rwWhbAK35A64Nra9mrpakimnsr8Jg", "bbkKKk2GT6wB5Qmpgtdd3gCnnsykXfD8Qu"].iter()
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
        roundtrips(&address, Bitcoin);
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
            "BHbXiw6Zvezk7pYYwbKyPrgprFkHLggcn1",
            "B4VsKWxKdXYsRiwavyNXGgWmqs2n8F7jSM",
            "bbkKKk2GT6wB5Qmpgtdd3gCnnsykXfD8Qu",
            "bWJbbsS2rSdf6LqWMxpr2AUamXzgfpB6S4",
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "blk1qf5w5dpa5mx5mwhghd5gf5qmy6d3q6g36d4sf5p",
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
