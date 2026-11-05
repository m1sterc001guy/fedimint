//! Statechain flows against an in-process federation. With
//! `FM_TEST_USE_REAL_DAEMONS` set they run against bitcoind, which also checks
//! the signatures and timelocks of every transaction we broadcast.

use std::sync::Arc;
use std::time::Duration;

use anyhow::ensure;
use bitcoin::Amount;
use fedimint_client::ClientHandleArc;
use fedimint_core::task::sleep_in_test;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_statechain_client::{StatechainClientInit, StatechainClientModule};
use fedimint_statechain_common::{BLOCK_COUNT_VOTE_DELAY, CoinId, CoinStatus};
use fedimint_statechain_server::StatechainInit;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::fixtures::Fixtures;
use tracing::info;

const DEPOSIT: Amount = Amount::from_sat(100_000);

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit)
        .with_module(StatechainClientInit, StatechainInit)
}

fn statechain(
    client: &ClientHandleArc,
) -> anyhow::Result<fedimint_client::ClientModuleInstance<'_, StatechainClientModule>> {
    Ok(client.get_first_module::<StatechainClientModule>()?)
}

/// Mines enough blocks for everything broadcast so far to become final for
/// the federation, then waits until the consensus block count has caught up.
async fn mine_to_finality(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<()> {
    bitcoin.mine_blocks(1 + BLOCK_COUNT_VOTE_DELAY).await;

    let target = bitcoin.get_block_count().await - BLOCK_COUNT_VOTE_DELAY;

    while statechain(client)?.block_count().await? < target {
        sleep_in_test(
            format!("Waiting for the consensus block count to reach {target}"),
            Duration::from_millis(500),
        )
        .await;
    }

    Ok(())
}

async fn await_status(
    client: &ClientHandleArc,
    coin: CoinId,
    condition: impl Fn(&CoinStatus) -> bool,
) -> anyhow::Result<CoinStatus> {
    loop {
        let status = statechain(client)?
            .coin_info(coin)
            .await?
            .federation
            .map(|record| record.status);

        if let Some(status) = status
            && condition(&status)
        {
            return Ok(status);
        }

        sleep_in_test(
            format!("Waiting for coin {coin}"),
            Duration::from_millis(500),
        )
        .await;
    }
}

/// Creates, funds and confirms a coin owned by `client`.
async fn deposit(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<CoinId> {
    mine_to_finality(client, bitcoin).await?;

    let module = statechain(client)?;
    let exit_address = bitcoin.get_new_address().await;

    let deposit = module.deposit(exit_address.as_unchecked().clone()).await?;

    info!(coin = %deposit.coin, "Created coin, funding it");

    // The fixture's helper broadcasts right away; in production the funding
    // transaction is only broadcast once `fund` returned.
    let funding_tx = bitcoin
        .send_without_mining(&deposit.address.clone().assume_checked(), DEPOSIT)
        .await;

    let funding = module.fund(deposit.coin, &funding_tx).await?;

    ensure!(funding.amount == DEPOSIT);

    mine_to_finality(client, bitcoin).await?;

    ensure!(module.await_deposit(deposit.coin).await? == CoinStatus::Active);

    Ok(deposit.coin)
}

#[tokio::test(flavor = "multi_thread")]
async fn deposit_transfer_claim_and_peg_out() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let alice = fed.new_client().await;
    let bob = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    let coin = deposit(&alice, &bitcoin).await?;

    let alice_exit = statechain(&alice)?.exit_transactions(coin).await?;
    let params = statechain(&alice)?.params().clone();

    assert_eq!(Some(alice_exit.timelock), params.exit_timelock(0));

    info!("Alice sends the coin to Bob");

    let bob_exit_address = bitcoin.get_new_address().await;
    let address = statechain(&bob)?
        .receive_address(bob_exit_address.as_unchecked().clone())
        .await?;

    statechain(&alice)?.send(coin, address.clone()).await?;

    assert!(
        statechain(&alice)?.send(coin, address).await.is_err(),
        "Alice no longer owns the coin"
    );

    assert_eq!(statechain(&bob)?.claim().await?.claimed, vec![coin]);
    assert_eq!(
        statechain(&bob)?.claim().await?.claimed,
        Vec::<CoinId>::new()
    );

    let bob_exit = statechain(&bob)?.exit_transactions(coin).await?;

    assert_eq!(
        bob_exit.node_tx, alice_exit.node_tx,
        "The node transaction is shared"
    );
    assert!(
        bob_exit.timelock < alice_exit.timelock,
        "Bob's exit confirms before Alice's"
    );
    assert_eq!(
        bob_exit.exit_tx.output[0].script_pubkey,
        bob_exit_address.script_pubkey()
    );

    info!("Bob sends the coin back to Alice, who pegs it out");

    let alice_exit_address = bitcoin.get_new_address().await;
    let address = statechain(&alice)?
        .receive_address(alice_exit_address.as_unchecked().clone())
        .await?;

    statechain(&bob)?.send(coin, address).await?;
    assert_eq!(statechain(&alice)?.claim().await?.claimed, vec![coin]);

    let peg_out_address = bitcoin.get_new_address().await;
    let peg_out_tx = statechain(&alice)?
        .peg_out(
            coin,
            peg_out_address.as_unchecked().clone(),
            Amount::from_sat(1_000),
        )
        .await?;

    assert_eq!(
        peg_out_tx.output[0].value,
        DEPOSIT - Amount::from_sat(1_000)
    );

    while bitcoin
        .get_mempool_tx(&peg_out_tx.compute_txid())
        .await
        .is_none()
    {
        sleep_in_test(
            "Waiting for the guardians to broadcast the peg-out",
            Duration::from_millis(500),
        )
        .await;
    }

    mine_to_finality(&alice, &bitcoin).await?;

    let status = await_status(&alice, coin, |status| {
        matches!(status, CoinStatus::Closed { .. })
    })
    .await?;

    assert_eq!(
        status,
        CoinStatus::Closed {
            txid: peg_out_tx.compute_txid()
        }
    );

    assert!(
        bitcoin
            .get_tx_block_height(&peg_out_tx.compute_txid())
            .await
            .is_some(),
        "The guardians broadcast the peg-out"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn received_coin_exits_unilaterally() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let alice = fed.new_client().await;
    let bob = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let bitcoin_rpc = fixtures.server_bitcoin_rpc();

    let coin = deposit(&alice, &bitcoin).await?;

    let bob_exit_address = bitcoin.get_new_address().await;
    let address = statechain(&bob)?
        .receive_address(bob_exit_address.as_unchecked().clone())
        .await?;

    statechain(&alice)?.send(coin, address).await?;
    statechain(&bob)?.claim().await?;

    let exit = statechain(&bob)?.exit_transactions(coin).await?;

    info!("Bob broadcasts the node transaction");

    bitcoin_rpc.submit_transaction(exit.node_tx.clone()).await?;

    mine_to_finality(&bob, &bitcoin).await?;

    assert!(
        bitcoin
            .get_tx_block_height(&exit.node_tx.compute_txid())
            .await
            .is_some(),
        "The node transaction is valid"
    );

    await_status(&bob, coin, |status| *status == CoinStatus::Exiting).await?;

    let alice_address = statechain(&alice)?
        .receive_address(bitcoin.get_new_address().await.as_unchecked().clone())
        .await?;

    assert!(
        statechain(&bob)?.send(coin, alice_address).await.is_err(),
        "An exiting coin cannot be transferred"
    );

    if Fixtures::is_real_test() {
        // `mine_to_finality` mined fewer blocks than the timelock.
        assert!(
            bitcoin_rpc
                .submit_transaction(exit.exit_tx.clone())
                .await
                .is_err(),
            "The exit transaction is timelocked"
        );
    }

    bitcoin.mine_blocks(u64::from(exit.timelock)).await;

    info!("Bob broadcasts the exit transaction after its timelock");

    bitcoin_rpc.submit_transaction(exit.exit_tx.clone()).await?;
    bitcoin.mine_blocks(1).await;

    assert!(
        bitcoin
            .get_tx_block_height(&exit.exit_tx.compute_txid())
            .await
            .is_some(),
        "The exit transaction is valid"
    );

    assert_eq!(
        exit.exit_tx.output[0].script_pubkey,
        bob_exit_address.script_pubkey()
    );

    Ok(())
}
