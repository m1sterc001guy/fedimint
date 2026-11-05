use std::{ffi, iter};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Transaction};
use clap::Parser;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_statechain_common::{CoinId, StatechainAddress};
use serde::Serialize;
use serde_json::{Value, json};

use crate::StatechainClientModule;

#[derive(Parser, Serialize)]
enum Opts {
    /// Create a statecoin and print the address to fund. Its exit transactions
    /// will pay to `exit_address`.
    Deposit {
        #[arg(long)]
        exit_address: Address<NetworkUnchecked>,
    },
    /// Co-sign a coin's backup transactions with the guardians for a funding
    /// transaction that is signed but NOT yet broadcast. Broadcast it after
    /// this command succeeds.
    Fund {
        coin: CoinId,
        /// The funding transaction as consensus-encoded hex
        funding_tx: String,
    },
    /// Wait until the federation sees the funding transaction confirmed.
    AwaitDeposit { coin: CoinId },
    /// Create a statechain address to receive coins at. Exit transactions of
    /// received coins pay to `exit_address`.
    ReceiveAddress {
        #[arg(long)]
        exit_address: Address<NetworkUnchecked>,
    },
    /// Send a coin to a statechain address.
    Send {
        coin: CoinId,
        address: StatechainAddress,
    },
    /// Claim all coins sent to our statechain addresses.
    Claim,
    /// Cooperatively peg a coin out to a bitcoin address; the guardians
    /// broadcast the transaction.
    PegOut {
        coin: CoinId,
        address: Address<NetworkUnchecked>,
        /// The on-chain fee in satoshis, paid from the coin's value
        #[arg(long, default_value_t = 1_000)]
        fee_sats: u64,
    },
    /// Print the signed transactions of a unilateral exit. Broadcast the node
    /// transaction, then the exit transaction once the node transaction has
    /// `timelock` confirmations. Works without the guardians.
    Exit { coin: CoinId },
    /// Show our and the federation's view of a coin.
    Info { coin: CoinId },
    /// List our coins.
    List,
    /// The federation's consensus block count.
    BlockCount,
}

pub(crate) async fn handle_cli_command(
    module: &StatechainClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("statechain")).chain(args.iter()));

    match opts {
        Opts::Deposit { exit_address } => {
            let deposit = module.deposit(exit_address).await?;

            Ok(json!({
                "coin": deposit.coin,
                "address": deposit.address.assume_checked(),
            }))
        }
        Opts::Fund { coin, funding_tx } => {
            let funding_tx = Transaction::consensus_decode_hex(
                &funding_tx,
                &fedimint_core::module::registry::ModuleRegistry::default(),
            )?;

            let funding = module.fund(coin, &funding_tx).await?;

            Ok(json!({
                "coin": coin,
                "funding_outpoint": funding.outpoint,
                "amount_sats": funding.amount.to_sat(),
                "next_step": "The backup transactions are signed. Broadcast the funding transaction now.",
            }))
        }
        Opts::AwaitDeposit { coin } => Ok(json!({
            "coin": coin,
            "status": module.await_deposit(coin).await?,
        })),
        Opts::ReceiveAddress { exit_address } => Ok(json!({
            "address": module.receive_address(exit_address).await?.to_string(),
        })),
        Opts::Send { coin, address } => {
            module.send(coin, address).await?;

            Ok(json!({ "coin": coin }))
        }
        Opts::Claim => Ok(serde_json::to_value(module.claim().await?)?),
        Opts::PegOut {
            coin,
            address,
            fee_sats,
        } => {
            let tx = module
                .peg_out(coin, address, bitcoin::Amount::from_sat(fee_sats))
                .await?;

            Ok(json!({
                "txid": tx.compute_txid(),
                "tx": tx.consensus_encode_to_hex(),
            }))
        }
        Opts::Exit { coin } => {
            let exit = module.exit_transactions(coin).await?;

            Ok(json!({
                "node_txid": exit.node_tx.compute_txid(),
                "node_tx": exit.node_tx.consensus_encode_to_hex(),
                "exit_txid": exit.exit_tx.compute_txid(),
                "exit_tx": exit.exit_tx.consensus_encode_to_hex(),
                "timelock": exit.timelock,
            }))
        }
        Opts::Info { coin } => Ok(serde_json::to_value(module.coin_info(coin).await)?),
        Opts::List => Ok(serde_json::to_value(module.list_coins().await)?),
        Opts::BlockCount => Ok(json!(module.block_count().await?)),
    }
}
