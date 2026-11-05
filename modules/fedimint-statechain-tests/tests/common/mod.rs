//! Helpers shared by the statechain test binaries.

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

pub const DEPOSIT: Amount = Amount::from_sat(100_000);

pub fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit)
        .with_module(StatechainClientInit, StatechainInit)
}

pub fn statechain(
    client: &ClientHandleArc,
) -> anyhow::Result<fedimint_client::ClientModuleInstance<'_, StatechainClientModule>> {
    Ok(client.get_first_module::<StatechainClientModule>()?)
}

/// Mines enough blocks for everything broadcast so far to become final for
/// the federation, then waits until the consensus block count has caught up.
pub async fn mine_to_finality(
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

pub async fn await_status(
    client: &ClientHandleArc,
    coin: CoinId,
    condition: impl Fn(&CoinStatus) -> bool,
) -> anyhow::Result<CoinStatus> {
    loop {
        let info = statechain(client)?.coin_info(coin).await;

        // A stale record may predate the change we are waiting for.
        let status = info
            .federation
            .filter(|_| !info.stale)
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
pub async fn deposit(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<CoinId> {
    mine_to_finality(client, bitcoin).await?;

    let module = statechain(client)?;
    let exit_address = bitcoin.get_new_address().await;

    let deposit = module.deposit().await?;

    info!(coin = %deposit.coin, "Created coin, funding it");

    // The fixture's helper broadcasts right away; in production the funding
    // transaction is only broadcast once `fund` returned.
    let funding_tx = bitcoin
        .send_without_mining(&deposit.address.clone().assume_checked(), DEPOSIT)
        .await;

    let funding = module
        .fund(
            deposit.coin,
            &funding_tx,
            exit_address.as_unchecked().clone(),
        )
        .await?;

    ensure!(funding.amount == DEPOSIT);

    mine_to_finality(client, bitcoin).await?;

    ensure!(module.await_deposit(deposit.coin).await? == CoinStatus::Active);

    Ok(deposit.coin)
}
