//! The canonical bitcoin transactions of a statecoin.
//!
//! ```text
//! funding output ──► node tx ──► exit tx (owner at level 0, timelock T0)
//!  (coin key)        (coin key)  exit tx (owner at level 1, timelock T0 - Δ)
//!        │                       ...
//!        └─────────► peg-out tx (cooperative, no timelock)
//! ```
//!
//! The node transaction has no timelock and is identical for every owner. Its
//! confirmation starts the relative timelocks of the exit transactions, so the
//! latest owner's exit, which has the shortest timelock, always confirms
//! first. All three transactions are key-path spends of the coin key, which is
//! the BIP-86 tweak of the user key plus the operator key.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::SECP256K1;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use secp256k1::PublicKey;
use secp256k1::schnorr::Signature;

use crate::Funding;

/// Outputs below this value are non-standard for most script types.
pub const DUST_LIMIT: Amount = Amount::from_sat(546);

/// The P2TR script of the coin with the given aggregate key
pub fn coin_script(aggregate_pk: PublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr(SECP256K1, aggregate_pk.x_only_public_key().0, None)
}

fn spend(previous_output: bitcoin::OutPoint, sequence: Sequence, output: TxOut) -> Transaction {
    Transaction {
        // Version 2 is required for the relative timelocks of BIP-68.
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![output],
    }
}

/// The node transaction moves the funding output to a new output with the
/// same key; its confirmation starts the exit timelocks.
pub fn node_tx(funding: Funding, coin_script: ScriptBuf, fee: Amount) -> Option<Transaction> {
    Some(spend(
        funding.outpoint,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        TxOut {
            value: funding.amount.checked_sub(fee)?,
            script_pubkey: coin_script,
        },
    ))
}

/// An owner's exit transaction spends the node transaction's output after
/// `timelock` blocks.
pub fn exit_tx(
    node_tx: &Transaction,
    timelock: u16,
    exit_script: ScriptBuf,
    fee: Amount,
) -> Option<Transaction> {
    let value = node_tx.output[0]
        .value
        .checked_sub(fee)
        .filter(|value| *value >= DUST_LIMIT)?;

    Some(spend(
        bitcoin::OutPoint {
            txid: node_tx.compute_txid(),
            vout: 0,
        },
        Sequence::from_height(timelock),
        TxOut {
            value,
            script_pubkey: exit_script,
        },
    ))
}

/// The cooperative peg-out transaction spends the funding output directly.
pub fn pegout_tx(funding: Funding, destination: ScriptBuf, fee: Amount) -> Option<Transaction> {
    let value = funding
        .amount
        .checked_sub(fee)
        .filter(|value| *value >= DUST_LIMIT)?;

    Some(spend(
        funding.outpoint,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        TxOut {
            value,
            script_pubkey: destination,
        },
    ))
}

/// The BIP-341 key-path sighash of the transaction's single input
pub fn key_spend_sighash(tx: &Transaction, prevout: &TxOut) -> [u8; 32] {
    SighashCache::new(tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
        .expect("The transaction has one input and we provide one prevout")
        .to_byte_array()
}

/// Attaches a key-path signature with the default sighash type
pub fn with_signature(mut tx: Transaction, signature: &Signature) -> Transaction {
    tx.input[0].witness = Witness::from_slice(&[signature.as_ref()]);

    tx
}

#[cfg(test)]
mod tests;
