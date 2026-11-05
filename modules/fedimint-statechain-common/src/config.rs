use bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use serde::{Deserialize, Serialize};

use crate::StatechainCommonInit;

/// The consensus parameters that determine the shape of every statecoin's
/// bitcoin transactions. Clients and guardians build the same canonical
/// transactions from them, so they are shared verbatim with clients.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct StatechainParams {
    /// Bitcoin network (e.g. regtest, bitcoin)
    pub network: Network,
    /// Relative timelock, in blocks, of the depositor's exit transaction. Every
    /// transfer lowers the next owner's exit timelock by `timelock_delta` so
    /// that the newest owner can always exit before any previous owner.
    pub initial_timelock: u16,
    /// How many blocks each transfer lowers the exit timelock by. It is also
    /// the lowest exit timelock, which bounds the number of transfers.
    pub timelock_delta: u16,
    /// Fixed fee paid by the pre-signed node transaction
    pub node_tx_fee: bitcoin::Amount,
    /// Fixed fee paid by each pre-signed exit transaction
    pub exit_tx_fee: bitcoin::Amount,
    /// The smallest deposit the federation accepts. It must leave a spendable
    /// exit output after both pre-signed transaction fees.
    pub min_deposit: bitcoin::Amount,
}

impl StatechainParams {
    pub fn new(network: Network) -> Self {
        // Regtest timelocks are kept short so that tests can mine through a
        // unilateral exit quickly; every other network uses Spark-like values.
        let (initial_timelock, timelock_delta) = match network {
            Network::Regtest => (60, 10),
            _ => (2_000, 100),
        };

        Self {
            network,
            initial_timelock,
            timelock_delta,
            node_tx_fee: bitcoin::Amount::from_sat(1_000),
            exit_tx_fee: bitcoin::Amount::from_sat(1_000),
            min_deposit: bitcoin::Amount::from_sat(10_000),
        }
    }

    /// The relative timelock of the exit transaction for the owner at `level`,
    /// or `None` once the transfers have exhausted the timelock range.
    pub fn exit_timelock(&self, level: u16) -> Option<u16> {
        self.initial_timelock
            .checked_sub(level.checked_mul(self.timelock_delta)?)
            .filter(|timelock| *timelock >= self.timelock_delta)
    }
}

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatechainConfig {
    pub private: StatechainConfigPrivate,
    pub consensus: StatechainConfigConsensus,
}

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct StatechainConfigConsensus {
    pub params: StatechainParams,
}

/// The module holds no long-lived secrets: every coin's operator key is
/// generated when the coin is created and its shares live in the database,
/// where they are replaced and deleted as ownership moves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatechainConfigPrivate;

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct StatechainClientConfig {
    pub params: StatechainParams,
}

impl std::fmt::Display for StatechainClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StatechainClientConfig {self:?}")
    }
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    StatechainCommonInit,
    StatechainConfig,
    StatechainConfigPrivate,
    StatechainConfigConsensus,
    StatechainClientConfig
);
