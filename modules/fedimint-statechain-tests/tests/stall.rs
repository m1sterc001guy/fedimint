//! Signing with a guardian that hands out nonces but never answers share
//! requests, which ROAST has to route around. A separate test binary, since
//! the stall is configured through a process-wide environment variable.

mod common;

use std::time::Duration;

use bitcoin::Amount;
use common::{await_status, deposit, fixtures, mine_to_finality, statechain};
use fedimint_core::task::sleep_in_test;
use fedimint_statechain_common::CoinStatus;
use fedimint_statechain_server::FM_STATECHAIN_TEST_STALL_SIGNER_ENV;
use tracing::info;

#[tokio::test(flavor = "multi_thread")]
async fn signing_routes_around_a_stalling_guardian() -> anyhow::Result<()> {
    // Peer 0 takes part in key generation but stalls on every signature
    // share request; the hook only works in test environments (nextest).
    unsafe { std::env::set_var(FM_STATECHAIN_TEST_STALL_SIGNER_ENV, "0") };

    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let alice = fed.new_client().await;
    let bob = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    // Funding co-signs the node and the exit transaction.
    let coin = deposit(&alice, &bitcoin).await?;

    info!("Alice sends the coin to Bob while peer 0 stalls");

    let address = statechain(&bob)?
        .receive_address(bitcoin.get_new_address().await.as_unchecked().clone())
        .await?;

    statechain(&alice)?.send(coin, address).await?;
    assert_eq!(statechain(&bob)?.claim().await?.claimed, vec![coin]);

    let peg_out_tx = statechain(&bob)?
        .peg_out(
            coin,
            bitcoin.get_new_address().await.as_unchecked().clone(),
            Amount::from_sat(1_000),
        )
        .await?;

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

    mine_to_finality(&bob, &bitcoin).await?;

    await_status(&bob, coin, |status| {
        *status
            == CoinStatus::Closed {
                txid: peg_out_tx.compute_txid(),
            }
    })
    .await?;

    Ok(())
}
