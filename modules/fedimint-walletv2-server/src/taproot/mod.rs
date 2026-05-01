pub mod frost;
mod multisig;

use bitcoin::hashes::sha256;
use bitcoin::taproot::LeafVersion;
use bitcoin::{ScriptBuf, TapLeafHash, TxOut};
use fedimint_walletv2_common::config::WalletDescriptor;
use fedimint_walletv2_common::taproot::{descriptor_tr, nums_point};

use crate::{FederationTx, Wallet};

impl Wallet {
    pub(crate) fn script_pubkey_for(&self, tweak: &sha256::Hash) -> ScriptBuf {
        match self.cfg.consensus.descriptor {
            WalletDescriptor::Wsh => self.descriptor(tweak).script_pubkey(),
            WalletDescriptor::Tr => {
                descriptor_tr(&self.cfg.consensus.bitcoin_pks, tweak, nums_point()).script_pubkey()
            }
            WalletDescriptor::Frost(internal_key) => {
                descriptor_tr(&self.cfg.consensus.bitcoin_pks, tweak, internal_key).script_pubkey()
            }
        }
    }

    pub(crate) fn tap_leaf_hash(&self, tweak: &sha256::Hash) -> TapLeafHash {
        let tr = descriptor_tr(&self.cfg.consensus.bitcoin_pks, tweak, nums_point());
        let (_, ms) = tr
            .iter_scripts()
            .next()
            .expect("Taproot descriptor always has exactly one script leaf");
        TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript)
    }

    fn build_prevouts(&self, unsigned_tx: &FederationTx) -> Vec<TxOut> {
        unsigned_tx
            .spent_tx_outs
            .iter()
            .map(|utxo| TxOut {
                value: utxo.value,
                script_pubkey: self.script_pubkey_for(&utxo.tweak),
            })
            .collect()
    }
}
