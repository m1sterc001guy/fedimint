use std::collections::BTreeMap;

use bitcoin::Network;
use bitcoin::hashes::{Hash, sha256};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, PeerId, plugin_types_trait_impl_config, weight_to_vbytes};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::{WalletCommonInit, descriptor, descriptor_tr};

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

#[derive(Clone, Debug, Serialize, Deserialize, Encodable)]
pub struct WalletConfigConsensus {
    /// The public keys for the bitcoin multisig
    pub bitcoin_pks: BTreeMap<PeerId, PublicKey>,
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
    /// Whether the federation uses a Taproot (P2TR + Schnorr) multisig
    /// instead of the default `SegWit` v0 (P2WSH + ECDSA) multisig.
    ///
    /// This field was added in walletv2 module consensus version 1.1.
    /// Configs persisted by older versions decode with this field defaulting
    /// to `false`; see the manual `Decodable` impl below.
    pub use_taproot: bool,
}

// Manual `Decodable` impl for backwards compatibility with module consensus
// version 1.0, which did not have a `use_taproot` field. When the trailing
// byte is missing we default to `false` (SegWit), which is exactly the
// behavior every existing federation already has.
impl Decodable for WalletConfigConsensus {
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bitcoin_pks = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let send_tx_vbytes = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let receive_tx_vbytes = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let feerate_base = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let dust_limit = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let fee_consensus = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let network = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let use_taproot =
            bool::consensus_decode_partial_from_finite_reader(r, modules).unwrap_or(false);
        Ok(Self {
            bitcoin_pks,
            send_tx_vbytes,
            receive_tx_vbytes,
            feerate_base,
            dust_limit,
            fee_consensus,
            network,
            use_taproot,
        })
    }
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
        use_taproot: bool,
    ) -> Self {
        let tx_overhead_weight = 4 * 4 // nVersion
            + 1 // SegWit marker
            + 1 // SegWit flag
            + 4 // up to 2 inputs
            + 4 // up to 2 outputs
            + 4 * 4; // nLockTime

        let change_witness_weight = if use_taproot {
            descriptor_tr(&bitcoin_pks, &sha256::Hash::all_zeros())
                .max_weight_to_satisfy()
                .expect("Cannot satisfy the taproot change descriptor.")
                .to_wu()
        } else {
            descriptor(&bitcoin_pks, &sha256::Hash::all_zeros())
                .max_weight_to_satisfy()
                .expect("Cannot satisfy the change descriptor.")
                .to_wu()
        };

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
            use_taproot,
        }
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

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable)]
pub struct WalletClientConfig {
    /// The public keys for the bitcoin multisig
    pub bitcoin_pks: BTreeMap<PeerId, PublicKey>,
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
    /// Whether the federation uses a Taproot multisig instead of `SegWit` v0.
    /// Added in walletv2 module consensus version 1.1; old client configs
    /// decode with `false` via the manual `Decodable` impl below.
    pub use_taproot: bool,
}

impl Decodable for WalletClientConfig {
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bitcoin_pks = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let send_tx_vbytes = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let receive_tx_vbytes = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let feerate_base = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let dust_limit = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let fee_consensus = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let network = Decodable::consensus_decode_partial_from_finite_reader(r, modules)?;
        let use_taproot =
            bool::consensus_decode_partial_from_finite_reader(r, modules).unwrap_or(false);
        Ok(Self {
            bitcoin_pks,
            send_tx_vbytes,
            receive_tx_vbytes,
            feerate_base,
            dust_limit,
            fee_consensus,
            network,
            use_taproot,
        })
    }
}

impl std::fmt::Display for WalletClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletClientConfig {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use fedimint_core::PeerId;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use secp256k1::SECP256K1;

    use super::*;

    fn sample_consensus(use_taproot: bool) -> WalletConfigConsensus {
        let (_, pk) = secp256k1::generate_keypair(&mut secp256k1::rand::thread_rng());
        let mut bitcoin_pks = BTreeMap::new();
        bitcoin_pks.insert(PeerId::from(0), pk);
        WalletConfigConsensus::new(
            bitcoin_pks,
            FeeConsensus::new(0).expect("zero ppm is in range"),
            Network::Regtest,
            use_taproot,
        )
    }

    /// A `WalletConfigConsensus` blob written by walletv2 module consensus
    /// version 1.0 has every field of the current struct *except* the
    /// trailing `use_taproot` byte. Truncating one byte off the new encoding
    /// is the cheapest way to construct an authentic v1.0 blob without
    /// vendoring the old struct.
    #[test]
    fn wallet_config_consensus_decodes_old_format_with_default_use_taproot() {
        let _ = SECP256K1; // ensure the linker keeps secp around in test builds

        let new = sample_consensus(false);
        let mut bytes = Vec::new();
        new.consensus_encode(&mut bytes)
            .expect("encode should succeed");

        // The encoded `bool` for `use_taproot = false` is exactly one trailing
        // byte. Drop it to simulate a v1.0 blob.
        let truncated = &bytes[..bytes.len() - 1];

        let decoded = WalletConfigConsensus::consensus_decode_whole(
            truncated,
            &ModuleDecoderRegistry::default(),
        )
        .expect("v1.0 blobs must decode under the new manual Decodable impl");

        assert!(
            !decoded.use_taproot,
            "missing use_taproot must default to false (SegWit)"
        );
        assert_eq!(decoded.bitcoin_pks, new.bitcoin_pks);
        assert_eq!(decoded.send_tx_vbytes, new.send_tx_vbytes);
        assert_eq!(decoded.receive_tx_vbytes, new.receive_tx_vbytes);
        assert_eq!(decoded.feerate_base, new.feerate_base);
        assert_eq!(decoded.dust_limit, new.dust_limit);
        assert_eq!(decoded.fee_consensus, new.fee_consensus);
        assert_eq!(decoded.network, new.network);
    }

    #[test]
    fn wallet_config_consensus_roundtrips_with_use_taproot_true() {
        let new = sample_consensus(true);
        let mut bytes = Vec::new();
        new.consensus_encode(&mut bytes).expect("encode succeeds");

        let decoded = WalletConfigConsensus::consensus_decode_whole(
            &bytes,
            &ModuleDecoderRegistry::default(),
        )
        .expect("encoded blob must round-trip");

        assert!(decoded.use_taproot);
        assert_eq!(decoded.bitcoin_pks, new.bitcoin_pks);
    }
}
