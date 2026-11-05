//! End-to-end test of the statechain CLI against a devimint federation and
//! bitcoind, which validates every transaction the module produces.

use std::time::Duration;

use anyhow::{Context, ensure};
use bitcoin::Transaction;
use bitcoincore_rpc::RpcApi;
use devimint::cmd;
use devimint::external::Bitcoind;
use devimint::federation::Client;
use fedimint_core::encoding::Decodable;
use fedimint_core::task::sleep_in_test;
use fedimint_statechain_common::BLOCK_COUNT_VOTE_DELAY;
use serde_json::{Value, json};
use tracing::info;

const DEPOSIT_SATS: u64 = 100_000;

async fn statechain(client: &Client, args: &[&str]) -> anyhow::Result<Value> {
    let mut command = cmd!(client, "module", "statechain");

    for arg in args {
        command = command.arg(arg);
    }

    command.out_json().await
}

fn string(value: &Value, field: &str) -> anyhow::Result<String> {
    value[field]
        .as_str()
        .map(ToString::to_string)
        .with_context(|| format!("Missing field {field} in {value}"))
}

async fn new_address(bitcoind: &Bitcoind) -> anyhow::Result<String> {
    Ok(bitcoind.get_new_address().await?.to_string())
}

/// Mines past the federation's finality delay and waits for its consensus
/// block count to catch up.
async fn mine_to_finality(client: &Client, bitcoind: &Bitcoind) -> anyhow::Result<()> {
    bitcoind.mine_blocks(1 + BLOCK_COUNT_VOTE_DELAY).await?;

    let target = bitcoind.get_block_count().await? - BLOCK_COUNT_VOTE_DELAY;

    loop {
        let block_count: u64 = serde_json::from_value(statechain(client, &["block-count"]).await?)?;

        if block_count >= target {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for the consensus block count to reach {target}"),
            Duration::from_secs(1),
        )
        .await;
    }
}

/// Builds and signs a transaction paying `address` from bitcoind's wallet
/// without broadcasting it.
fn funding_tx(bitcoind: &Bitcoind, address: &str) -> anyhow::Result<String> {
    let response: Value = bitcoind.client.call(
        "send",
        &[
            json!([{ address: bitcoin::Amount::from_sat(DEPOSIT_SATS).to_btc() }]),
            Value::Null,
            json!("unset"),
            json!(2),
            json!({ "add_to_wallet": false }),
        ],
    )?;

    string(&response, "hex")
}

fn broadcast(bitcoind: &Bitcoind, tx_hex: &str) -> anyhow::Result<bitcoin::Txid> {
    Ok(bitcoind.client.send_raw_transaction(tx_hex)?)
}

/// Whether one of the last hundred blocks contains the transaction. Devimint's
/// bitcoind has no transaction index, so we look through the blocks.
fn is_mined(bitcoind: &Bitcoind, txid: &bitcoin::Txid) -> anyhow::Result<bool> {
    let tip = bitcoind.client.get_block_count()?;

    for height in tip.saturating_sub(100)..=tip {
        let block = bitcoind
            .client
            .get_block(&bitcoind.client.get_block_hash(height)?)?;

        if block.txdata.iter().any(|tx| tx.compute_txid() == *txid) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Creates, funds and confirms a coin owned by `client`.
async fn deposit(client: &Client, bitcoind: &Bitcoind) -> anyhow::Result<String> {
    let exit_address = new_address(bitcoind).await?;
    let deposit = statechain(client, &["deposit", "--exit-address", &exit_address]).await?;
    let coin = string(&deposit, "coin")?;
    let address = string(&deposit, "address")?;

    info!(%coin, %address, "Created coin; funding it");

    let funding_tx = funding_tx(bitcoind, &address)?;

    let funded = statechain(client, &["fund", &coin, &funding_tx]).await?;

    ensure!(funded["amount_sats"] == json!(DEPOSIT_SATS));

    info!("Backups are signed; broadcasting the funding transaction");

    broadcast(bitcoind, &funding_tx)?;

    mine_to_finality(client, bitcoind).await?;

    let status = statechain(client, &["await-deposit", &coin]).await?;

    ensure!(
        status["status"] == json!("Active"),
        "Unexpected status {status}"
    );

    Ok(coin)
}

async fn transfer(
    from: &Client,
    to: &Client,
    bitcoind: &Bitcoind,
    coin: &str,
) -> anyhow::Result<()> {
    let exit_address = new_address(bitcoind).await?;
    let address = statechain(to, &["receive-address", "--exit-address", &exit_address]).await?;

    statechain(from, &["send", coin, &string(&address, "address")?]).await?;

    let claimed = statechain(to, &["claim"]).await?;

    ensure!(
        claimed["claimed"] == json!([coin]),
        "Unexpected claim {claimed}"
    );

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    unsafe { std::env::set_var("FM_ENABLE_MODULE_STATECHAIN", "true") };

    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            let (fed, bitcoind) = tokio::try_join!(dev_fed.fed(), dev_fed.bitcoind())?;
            let bitcoind = bitcoind.wallet_client().await?.clone();

            let alice = fed.new_joined_client("statechain-alice").await?;
            let bob = fed.new_joined_client("statechain-bob").await?;

            mine_to_finality(&alice, &bitcoind).await?;

            info!("Deposit, transfer back and forth, and peg out cooperatively");

            let coin = deposit(&alice, &bitcoind).await?;

            transfer(&alice, &bob, &bitcoind, &coin).await?;
            transfer(&bob, &alice, &bitcoind, &coin).await?;

            ensure!(
                statechain(&bob, &["exit", &coin]).await.is_err(),
                "Bob no longer owns the coin"
            );

            let peg_out_address = new_address(&bitcoind).await?;
            let peg_out = statechain(&alice, &["peg-out", &coin, &peg_out_address]).await?;
            let peg_out_txid: bitcoin::Txid = string(&peg_out, "txid")?.parse()?;

            bitcoind.poll_get_transaction(peg_out_txid).await?;
            mine_to_finality(&alice, &bitcoind).await?;

            ensure!(is_mined(&bitcoind, &peg_out_txid)?, "The peg-out was mined");

            let info = statechain(&alice, &["info", &coin]).await?;
            ensure!(
                info["federation"]["status"]["Closed"]["txid"] == json!(peg_out_txid),
                "Unexpected coin info {info}"
            );

            info!("A received coin exits before its previous owner can");

            let coin = deposit(&alice, &bitcoind).await?;

            // Alice keeps her backups before she sends the coin.
            let alice_exit = statechain(&alice, &["exit", &coin]).await?;

            transfer(&alice, &bob, &bitcoind, &coin).await?;

            let bob_exit = statechain(&bob, &["exit", &coin]).await?;

            ensure!(alice_exit["node_tx"] == bob_exit["node_tx"]);

            let alice_timelock = alice_exit["timelock"].as_u64().context("timelock")?;
            let bob_timelock = bob_exit["timelock"].as_u64().context("timelock")?;

            ensure!(bob_timelock < alice_timelock);

            // Bob also lists the first coin, which he sent back to Alice.
            let list = statechain(&bob, &["list"]).await?;
            let owned = list
                .as_array()
                .context("list returns an array")?
                .iter()
                .filter(|info| info["local"]["state"] == json!("Owned"))
                .map(|info| info["coin"].clone())
                .collect::<Vec<Value>>();
            ensure!(owned == vec![json!(coin)], "Unexpected coin list {list}");

            // A previous owner can start the exit; the node transaction is the same
            // for everyone.
            let node_txid = broadcast(&bitcoind, &string(&alice_exit, "node_tx")?)?;
            bitcoind.mine_blocks(1).await?;
            ensure!(
                is_mined(&bitcoind, &node_txid)?,
                "The node transaction was mined"
            );

            ensure!(
                broadcast(&bitcoind, &string(&bob_exit, "exit_tx")?).is_err(),
                "Bob's exit transaction is timelocked"
            );

            bitcoind.mine_blocks(bob_timelock - 1).await?;

            ensure!(
                broadcast(&bitcoind, &string(&alice_exit, "exit_tx")?).is_err(),
                "Alice's exit transaction is still timelocked"
            );

            let bob_exit_txid = broadcast(&bitcoind, &string(&bob_exit, "exit_tx")?)?;
            bitcoind.mine_blocks(1).await?;
            ensure!(is_mined(&bitcoind, &bob_exit_txid)?, "Bob exited");

            bitcoind.mine_blocks(alice_timelock - bob_timelock).await?;

            ensure!(
                broadcast(&bitcoind, &string(&alice_exit, "exit_tx")?).is_err(),
                "Alice's exit transaction spends an already spent output"
            );

            let exit_tx = Transaction::consensus_decode_hex(
                &string(&bob_exit, "exit_tx")?,
                &Default::default(),
            )?;

            ensure!(
                exit_tx.output[0].value.to_sat() == DEPOSIT_SATS - 2_000,
                "Bob receives the deposit minus the pre-signed transaction fees"
            );

            mine_to_finality(&bob, &bitcoind).await?;

            let info = statechain(&bob, &["info", &coin]).await?;
            ensure!(
                info["federation"]["status"] == json!("Exiting"),
                "Unexpected coin info {info}"
            );

            info!("A wallet lists its coins while the guardians are offline");

            fed.clone().terminate_all_servers().await?;

            let list = statechain(&bob, &["list"]).await?;
            let info = list
                .as_array()
                .context("list returns an array")?
                .iter()
                .find(|info| info["coin"] == json!(coin))
                .with_context(|| format!("Bob lists the exited coin: {list}"))?;
            ensure!(
                info["stale"] == json!(true) && info["federation"]["status"] == json!("Exiting"),
                "Unexpected coin info {info}"
            );

            info!("Statechain CLI test succeeded");

            Ok(())
        })
        .await
}
