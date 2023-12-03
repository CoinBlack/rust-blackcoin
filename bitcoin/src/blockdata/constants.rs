// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;

use hashes::{sha256d, Hash};
use hex_lit::hex;
use internals::impl_array_newtype;

use crate::blockdata::block::{self, Block};
use crate::blockdata::locktime::absolute;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script;
use crate::blockdata::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut};
use crate::blockdata::witness::Witness;
use crate::internal_macros::impl_bytes_newtype;
use crate::network::Network;
use crate::pow::CompactTarget;
use crate::Amount;

/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;

/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (blackcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 25;
/// Mainnet (blackcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 85;
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block.
fn bitcoin_genesis_tx(time: u32) -> Transaction {
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        time,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new()
        .push_int(0)
        .push_int_non_minimal(42)
        .push_slice(b"20 Feb 2014 Bitcoin ATMs come to USA")
        .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
    let out_script =
        script::Builder::new().push_slice(script_bytes).push_opcode(OP_CHECKSIG).into_script();
    ret.output.push(TxOut { value: Amount::from_sat(0), script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let blocktime = 1393221600;
    let txdata = vec![bitcoin_genesis_tx(blocktime)];
    let signature = vec![];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Bitcoin => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: blocktime,
                bits: CompactTarget::from_consensus(0x1e0fffff),
                nonce: 164482,
            },
            txdata,
            signature,
        },
        Network::Testnet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: blocktime,
                bits: CompactTarget::from_consensus(0x1f00ffff),
                nonce: 216178,
            },
            txdata,
            signature,
        },
        Network::Signet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: blocktime,
                bits: CompactTarget::from_consensus(0x1f00ffff),
                nonce: 216178,
            },
            txdata,
            signature,
        },
        Network::Regtest => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: blocktime,
                bits: CompactTarget::from_consensus(0x1f00ffff),
                nonce: 216178,
            },
            txdata,
            signature,
        },
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet blackcoin.
    // Blackcoin mainnet: "0x000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563"
    pub const BITCOIN: Self = Self([
        99, 69, 30, 145, 1, 177, 165, 11, 61, 38, 47, 35, 191, 131, 193, 242, 29, 98, 66, 98,
        110, 144, 207, 251, 196, 222, 37, 239, 250, 1, 0, 0
    ]);
    /// `ChainHash` for testnet blackcoin.
    // Blackcoin testnet: "0x0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d"
    pub const TESTNET: Self = Self([
        45, 100, 67, 232, 141, 196, 171, 237, 211, 150, 217, 7, 191, 42, 41, 92, 97, 119, 149,
        251, 203, 65, 212, 9, 150, 59, 251, 149, 69, 114, 0, 0
    ]);
    /// `ChainHash` for signet blackcoin.
    // Blackcoin signet: "0x0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d"
    pub const SIGNET: Self = Self([
        45, 100, 67, 232, 141, 196, 171, 237, 211, 150, 217, 7, 191, 42, 41, 92, 97, 119, 149,
        251, 203, 65, 212, 9, 150, 59, 251, 149, 69, 114, 0, 0
    ]);
    /// `ChainHash` for regtest blackcoin.
    // Blackcoin regtest: "0x0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d"
    pub const REGTEST: Self = Self([
        45, 100, 67, 232, 141, 196, 171, 237, 211, 150, 217, 7, 191, 42, 41, 92, 97, 119, 149,
        251, 203, 65, 212, 9, 150, 59, 251, 149, 69, 114, 0, 0
    ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::BITCOIN, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }

    /// Converts genesis block hash into `ChainHash`.
    pub fn from_genesis_block_hash(block_hash: crate::BlockHash) -> Self {
        ChainHash(block_hash.to_byte_array())
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::blockdata::locktime::absolute;
    use crate::blockdata::transaction;
    use crate::consensus::encode::serialize;
    use crate::network::Network;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx(1393221600);

        assert_eq!(gen.version, transaction::Version::ONE);
        assert_eq!(gen.time, 1393221600);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("2800012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"));
        assert_eq!(gen.output[0].value, Amount::from_str("0 BTC").unwrap());
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        // Blackcoin ToDo!
        // assert_eq!(
        //     gen.wtxid().to_string(),
        //     "12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90"
        // );
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        // Blackcoin ToDo!
        // assert_eq!(
        //     gen.header.merkle_root.to_string(),
        //     "12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90"
        // );

        assert_eq!(gen.header.time, 1393221600);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0fffff));
        assert_eq!(gen.header.nonce, 164482);
        // Blackcoin ToDo!
        // assert_eq!(
        //     gen.header.block_hash().to_string(),
        //     "000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563"
        // );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        // Blackcoin ToDo!
        // assert_eq!(
        //     gen.header.merkle_root.to_string(),
        //     "12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90"
        // );
        assert_eq!(gen.header.time, 1393221600);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1f00ffff));
        assert_eq!(gen.header.nonce, 216178);
        // Blackcoin ToDo!
        // assert_eq!(
        //     gen.header.block_hash().to_string(),
        //     "0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d"
        // );
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(Network::Signet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        // Blackcoin ToDo!
        // assert_eq!(
        //     gen.header.merkle_root.to_string(),
        //     "12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90"
        // );
        assert_eq!(gen.header.time, 1393221600);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1f00ffff));
        assert_eq!(gen.header.nonce, 216178);
        // Blackcoin ToDo!
        // assert_eq!(
        //     gen.header.block_hash().to_string(),
        //     "0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d"
        // );
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        // Blackcoin ToDo!
        /*
        use hashes::sha256;

        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);
        */

        #[allow(unreachable_patterns)] // This is specifically trying to catch later added variants.
        match network {
            Network::Bitcoin => {},
            Network::Testnet => {},
            Network::Signet => {},
            Network::Regtest => {},
            _ => panic!("Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants"),
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Bitcoin;
        testnet_chain_hash_genesis_block, Network::Testnet;
        signet_chain_hash_genesis_block, Network::Signet;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Test vector taken from: https://github.com/lightning/bolts/blob/master/00-introduction.md
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block(Network::Bitcoin).to_string();
        let want = "63451e9101b1a50b3d262f23bf83c1f21d6242626e90cffbc4de25effa010000";
        assert_eq!(got, want);
    }
}
