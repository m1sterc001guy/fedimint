use std::collections::BTreeMap;

use bitcoin::Network;
use bitcoin::hashes::{Hash, sha256};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, PeerId, plugin_types_trait_impl_config, weight_to_vbytes};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::{WalletCommonInit, descriptor};

plugin_types_trait_impl_config!(
    WalletCommonInit,
    WalletConfig,
    WalletConfigPrivate,
    WalletConfigConsensus,
    WalletClientConfig
);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub private: WalletConfigPrivate,
    pub consensus: WalletConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfigPrivate {
    pub bitcoin_sk: SecretKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct WalletConfigConsensus {
    /// The public keys for the bitcoin multisig
    pub bitcoin_pks: BTreeMap<PeerId, PublicKey>,
    /// The kind of descriptor the federation uses for the multisig.
    pub descriptor: WalletDescriptor,
    /// Total vbytes of a pegout bitcoin transaction
    pub send_tx_vbytes: u64,
    /// Total vbytes of a pegin bitcoin transaction
    pub receive_tx_vbytes: u64,
    /// The minimum feerate doubles for each pending transaction in the stack,
    /// protecting against catastrophic feerate estimation errors
    pub feerate_base: u64,
    /// The minimum amount a user can send on chain
    pub dust_limit: bitcoin::Amount,
    /// Fees taken by the guardians to process wallet inputs and outputs
    pub fee_consensus: FeeConsensus,
    /// Bitcoin network (e.g. testnet, bitcoin)
    pub network: Network,
}

impl WalletConfigConsensus {
    /// The constructor will derive the following number of vbytes for a send
    /// and receive transaction with respect to the number of guardians:
    ///
    /// | Guardians | Send | Receive |
    /// |-----------|------|---------|
    /// | 1         | 166  | 192     |
    /// | 4         | 228  | 316     |
    /// | 5         | 255  | 369     |
    /// | 6         | 281  | 423     |
    /// | 7         | 290  | 440     |
    /// | 8         | 317  | 494     |
    /// | 9         | 344  | 548     |
    /// | 10        | 352  | 565     |
    /// | 11        | 379  | 618     |
    /// | 12        | 406  | 672     |
    /// | 13        | 414  | 689     |
    /// | 14        | 441  | 742     |
    /// | 15        | 468  | 796     |
    /// | 16        | 476  | 813     |
    /// | 17        | 503  | 867     |
    /// | 18        | 530  | 920     |
    /// | 19        | 539  | 937     |
    /// | 20        | 565  | 991     |
    pub fn new(
        bitcoin_pks: BTreeMap<PeerId, PublicKey>,
        fee_consensus: FeeConsensus,
        network: Network,
    ) -> Self {
        let tx_overhead_weight = 4 * 4 // nVersion
            + 1 // SegWit marker
            + 1 // SegWit flag
            + 4 // up to 2 inputs
            + 4 // up to 2 outputs
            + 4 * 4; // nLockTime

        let change_witness_weight = descriptor(&bitcoin_pks, &sha256::Hash::all_zeros())
            .max_weight_to_satisfy()
            .expect("Cannot satisfy the change descriptor.")
            .to_wu();

        let change_input_weight = 32 * 4 // txid
            + 4 * 4 // vout
            + 4 // Script length
            + 4 * 4 // nSequence
            + change_witness_weight;

        let change_output_weight = 8 * 4 // nValue
            + 4 // scriptPubKey length
            + 34 * 4; // scriptPubKey

        let destination_output_weight = 8 * 4 // nValue
            + 4 // scriptPubKey length
            + 34 * 4; // scriptPubKey

        Self {
            bitcoin_pks,
            descriptor: WalletDescriptor::Wsh,
            send_tx_vbytes: weight_to_vbytes(
                tx_overhead_weight
                    + change_input_weight
                    + change_output_weight
                    + destination_output_weight,
            ),
            receive_tx_vbytes: weight_to_vbytes(
                tx_overhead_weight
                    + change_input_weight
                    + change_input_weight
                    + change_output_weight,
            ),
            // This is intentionally lower than the 1 sat/vB minimum feerate
            // vote floor. This allows for at least three pending transactions
            // which only pay the consensus feerate before the exponential
            // doubling kicks in.
            feerate_base: 250,
            dust_limit: bitcoin::Amount::from_sat(10_000),
            fee_consensus,
            network,
        }
    }
}

/// Weight of the `CompactSize` encoding of `n`, in witness units.
const fn varint_weight(n: u64) -> u64 {
    if n < 253 {
        4
    } else if n <= u16::MAX as u64 {
        12
    } else {
        20
    }
}

impl WalletConfigConsensus {
    /// Weight of a single input spending a federation multisig output.
    pub fn multisig_input_weight(&self) -> u64 {
        let witness_weight = descriptor(&self.bitcoin_pks, &sha256::Hash::all_zeros())
            .max_weight_to_satisfy()
            .expect("Cannot satisfy the change descriptor.")
            .to_wu();

        32 * 4 // txid
            + 4 * 4 // vout
            + 4 // Script length
            + 4 * 4 // nSequence
            + witness_weight
    }

    /// Weight of a single output. Every standard script pubkey we can pay to
    /// fits in 34 bytes, so this is an upper bound for change and destinations
    /// alike.
    pub const fn output_weight() -> u64 {
        8 * 4 // nValue
            + 4 // scriptPubKey length
            + 34 * 4 // scriptPubKey
    }

    /// Total vbytes of a batch transaction with `inputs` multisig inputs and
    /// `outputs` outputs.
    ///
    /// This generalises [`Self::send_tx_vbytes`] and
    /// [`Self::receive_tx_vbytes`]: `batch_vbytes(1, 2)` equals the former and
    /// `batch_vbytes(2, 1)` the latter, which the unit tests below assert. That
    /// equality is what guarantees a batch never collects less in fees than it
    /// costs to broadcast, since a single-item batch collects exactly the fee
    /// quoted for a standalone transaction of the same shape.
    pub fn batch_vbytes(&self, inputs: u64, outputs: u64) -> u64 {
        let tx_overhead_weight = 4 * 4 // nVersion
            + 1 // SegWit marker
            + 1 // SegWit flag
            + varint_weight(inputs)
            + varint_weight(outputs)
            + 4 * 4; // nLockTime

        weight_to_vbytes(
            tx_overhead_weight
                + inputs * self.multisig_input_weight()
                + outputs * Self::output_weight(),
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl FeeConsensus {
    /// The wallet module will charge a non-configurable base fee of one hundred
    /// satoshis per transaction input and output to account for the costs
    /// incurred by the federation for processing the transaction. On top of
    /// that the federation may charge an additional relative fee per input and
    /// output of up to ten thousand parts per million which equals one
    /// percent.
    ///
    /// # Errors
    /// - This constructor returns an error if the relative fee is in excess of
    ///   ten thousand parts per million.
    pub fn new(parts_per_million: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            parts_per_million <= 10_000,
            "Relative fee over ten thousand parts per million is excessive"
        );

        Ok(Self {
            base: Amount::from_sats(100),
            parts_per_million,
        })
    }

    pub fn fee(&self, amount: Amount) -> Amount {
        Amount::from_msats(self.fee_msats(amount.msats))
    }

    fn fee_msats(&self, msats: u64) -> u64 {
        msats
            .saturating_mul(self.parts_per_million)
            .saturating_div(1_000_000)
            .checked_add(self.base.msats)
            .expect("The division creates sufficient headroom to add the base fee")
    }
}

#[test]
fn test_fee_consensus() {
    let fee_consensus = FeeConsensus::new(10_000).expect("Relative fee is within range");

    assert_eq!(
        fee_consensus.fee(Amount::from_msats(99)),
        Amount::from_sats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1)),
        Amount::from_msats(10) + Amount::from_sats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1000)),
        Amount::from_sats(10) + Amount::from_sats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(1)),
        Amount::from_sats(1_000_000) + Amount::from_sats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(10_000)),
        Amount::from_bitcoins(100) + Amount::from_sats(100)
    );
}

/// Which kind of bitcoin descriptor the federation uses. Currently only `Wsh`
/// is defined, we can expand in the future.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum WalletDescriptor {
    Wsh,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct WalletClientConfig {
    /// The public keys for the bitcoin multisig
    pub bitcoin_pks: BTreeMap<PeerId, PublicKey>,
    /// The kind of descriptor the federation uses for the multisig.
    pub descriptor: WalletDescriptor,
    /// Total vbytes of a pegout bitcoin transaction
    pub send_tx_vbytes: u64,
    /// Total vbytes of a pegin bitcoin transaction
    pub receive_tx_vbytes: u64,
    /// The minimum feerate doubles for each pending transaction in the stack,
    /// protecting against catastrophic feerate estimation errors
    pub feerate_base: u64,
    /// The minimum amount a user can send on chain
    pub dust_limit: bitcoin::Amount,
    /// Fees taken by the guardians to process wallet inputs and outputs
    pub fee_consensus: FeeConsensus,
    /// Bitcoin network (e.g. testnet, bitcoin)
    pub network: Network,
}

impl std::fmt::Display for WalletClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletClientConfig {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_consensus(num_peers: u16) -> WalletConfigConsensus {
        let bitcoin_pks = (0..num_peers)
            .map(|index| {
                let mut bytes = [1u8; 32];
                bytes[1..3].copy_from_slice(&index.to_be_bytes());

                let secret = SecretKey::from_slice(&bytes).expect("Valid secret key");

                (PeerId::from(index), secret.public_key(secp256k1::SECP256K1))
            })
            .collect();

        WalletConfigConsensus::new(
            bitcoin_pks,
            FeeConsensus::new(0).expect("Relative fee is within range"),
            Network::Regtest,
        )
    }

    /// A batch of a single peg-out has exactly the shape of a standalone send,
    /// and a batch consolidating a single deposit exactly that of a standalone
    /// receive. This is what makes the deferred fee model safe: a one-item
    /// batch collects precisely the fee quoted for it, never less.
    #[test]
    fn batch_vbytes_generalises_the_standalone_shapes() {
        for num_peers in [1, 4, 7, 10, 20] {
            let cfg = config_consensus(num_peers);

            assert_eq!(
                cfg.batch_vbytes(1, 2),
                cfg.send_tx_vbytes,
                "Single-send batch differs from a standalone send at {num_peers} peers"
            );

            assert_eq!(
                cfg.batch_vbytes(2, 1),
                cfg.receive_tx_vbytes,
                "Single-receive batch differs from a standalone receive at {num_peers} peers"
            );
        }
    }

    /// Larger batches must never collect less than they cost, or a batch could
    /// be broadcast underfunded.
    #[test]
    fn batch_vbytes_never_exceed_the_fees_collected() {
        let cfg = config_consensus(4);

        for receives in 0..8u64 {
            for sends in 0..8u64 {
                if receives + sends == 0 {
                    continue;
                }

                let collected = receives * cfg.receive_tx_vbytes + sends * cfg.send_tx_vbytes;
                let cost = cfg.batch_vbytes(1 + receives, 1 + sends);

                assert!(
                    cost <= collected,
                    "Batch of {receives} receives and {sends} sends costs {cost} vB but only \
                     collects {collected} vB worth of fees"
                );
            }
        }
    }
}
