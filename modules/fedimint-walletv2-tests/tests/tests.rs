use std::collections::BTreeSet;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint as BitcoinOutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoincore_rpc::json::SignRawTransactionInput;
use bitcoincore_rpc::{Auth, Client as BitcoinRpcClient, RpcApi};
use fedimint_client::ClientHandleArc;
use fedimint_core::task::{block_in_place, sleep_in_test};
use fedimint_core::util::SafeUrl;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_walletv2_client::events::{
    ReceivePaymentEvent, ReceivePaymentUpdateEvent, SendPaymentEvent, SendPaymentStatus,
    SendPaymentUpdateEvent,
};
use fedimint_walletv2_client::{
    FinalSendOperationState, SendError, WalletClientInit, WalletClientModule,
};
use fedimint_walletv2_common::KIND;
use fedimint_walletv2_server::{CONFIRMATION_FINALITY_DELAY, WalletInit};
use futures::StreamExt;
use tracing::info;

#[derive(Debug)]
enum WalletEvent {
    Send(SendPaymentEvent),
    SendStatus(SendPaymentUpdateEvent),
    Receive(ReceivePaymentEvent),
    ReceiveStatus(ReceivePaymentUpdateEvent),
}

fn wallet_event_stream(client: &ClientHandleArc) -> impl futures::Stream<Item = WalletEvent> {
    let client = client.clone();
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    stream! {
        loop {
            let events = client.get_event_log(Some(next_id), 100).await;

            for entry in events {
                next_id = entry.id().saturating_add(1);

                if let Some(event) = try_parse_wallet_event(entry.as_raw()) {
                    yield event;
                }
            }

            let _ = log_rx.changed().await;
        }
    }
}

fn try_parse_wallet_event(entry: &EventLogEntry) -> Option<WalletEvent> {
    if entry.module_kind() != Some(&KIND) {
        return None;
    }

    if entry.kind == SendPaymentEvent::KIND {
        return entry.to_event().map(WalletEvent::Send);
    }

    if entry.kind == SendPaymentUpdateEvent::KIND {
        return entry.to_event().map(WalletEvent::SendStatus);
    }

    if entry.kind == ReceivePaymentEvent::KIND {
        return entry.to_event().map(WalletEvent::Receive);
    }

    if entry.kind == ReceivePaymentUpdateEvent::KIND {
        return entry.to_event().map(WalletEvent::ReceiveStatus);
    }

    None
}

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit).with_module(WalletClientInit, WalletInit)
}

// We need the consensus block count to reach a non-zero value before we send in
// any funds such that the UTXO is tracked by the federation.
async fn initialize_consensus(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<()> {
    info!("Wait for the consensus to reach block count one");

    bitcoin.mine_blocks(1 + CONFIRMATION_FINALITY_DELAY).await;

    await_consensus_block_count(client, 1).await
}

async fn await_finality_delay(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<()> {
    info!("Wait for the finality delay of six blocks...");

    let current_consensus = client
        .get_first_module::<WalletClientModule>()?
        .block_count()
        .await?;

    bitcoin.mine_blocks(CONFIRMATION_FINALITY_DELAY).await;

    await_consensus_block_count(client, current_consensus + CONFIRMATION_FINALITY_DELAY).await
}

async fn await_consensus_block_count(
    client: &ClientHandleArc,
    block_count: u64,
) -> anyhow::Result<()> {
    loop {
        if client
            .get_first_module::<WalletClientModule>()?
            .block_count()
            .await?
            >= block_count
        {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for consensus to reach block count {block_count}"),
            Duration::from_secs(1),
        )
        .await;
    }
}

async fn await_federation_total_value(
    client: &ClientHandleArc,
    min_value: bitcoin::Amount,
) -> anyhow::Result<()> {
    loop {
        let current_value = client
            .get_first_module::<WalletClientModule>()?
            .total_value()
            .await?;

        if current_value >= min_value {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for federation total value of {current_value} to reach {min_value}"),
            Duration::from_secs(1),
        )
        .await;
    }
}

// ============================================================================
// Steps 3 and 4: TRUC batches, package broadcast, and anchor settlement
// ============================================================================

/// Mirrors `fedimint_testing_core::envs::FM_TEST_USE_REAL_DAEMONS_ENV`.
const FM_TEST_USE_REAL_DAEMONS: &str = "FM_TEST_USE_REAL_DAEMONS";

/// Mirrors `fedimint_testing_core::envs::FM_TEST_BITCOIND_RPC_ENV`.
const FM_TEST_BITCOIND_RPC: &str = "FM_TEST_BITCOIND_RPC";

/// Output index of the ephemeral anchor in a batch parent.
const PARENT_ANCHOR_VOUT: u32 = 1;

/// Direct bitcoind access, used to inspect mempool policy that the client API
/// cannot see. `None` when not running against real daemons, in which case the
/// caller skips: the mock backend has no TRUC, no ephemeral dust and no package
/// relay, so every assertion here would be vacuous.
fn bitcoind_rpc() -> Option<BitcoinRpcClient> {
    if std::env::var(FM_TEST_USE_REAL_DAEMONS).is_err() {
        eprintln!(
            "SKIPPING TRUC batch test: {FM_TEST_USE_REAL_DAEMONS} is not set. \
             Run it with ./scripts/tests/walletv2-truc-test.sh"
        );

        return None;
    }

    let url: SafeUrl = std::env::var(FM_TEST_BITCOIND_RPC)
        .expect("Must have bitcoind RPC defined for real tests")
        .parse()
        .expect("Failed to parse bitcoind RPC url");

    let auth = Auth::UserPass(
        url.username().to_owned(),
        url.password()
            .expect("Bitcoind url has a password")
            .to_owned(),
    );

    let host = url
        .without_auth()
        .expect("Failed to strip auth from bitcoind url")
        .to_string();

    Some(BitcoinRpcClient::new(&host, auth).expect("Failed to connect to bitcoind"))
}

async fn await_mempool_tx(rpc: &BitcoinRpcClient, txid: bitcoin::Txid) -> Transaction {
    for _ in 0..60 {
        if let Ok(tx) = block_in_place(|| rpc.get_raw_transaction(&txid, None)) {
            return tx;
        }

        sleep_in_test(
            format!("Waiting for {txid} to enter the mempool"),
            Duration::from_secs(1),
        )
        .await;
    }

    panic!("Transaction {txid} never entered the mempool");
}

fn unsigned_txin(previous_output: BitcoinOutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: bitcoin::ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }
}

/// A batch sitting in the mempool, with the pieces a test needs to poke at it.
struct BatchInFlight {
    parent_txid: bitcoin::Txid,
    parent: Transaction,
    child_txid: bitcoin::Txid,
    child: Transaction,
    recipient: bitcoin::Address,
}

/// Funds a federation, submits one peg-out, and returns the resulting batch
/// once both halves are in the mempool.
async fn batch_in_flight(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
    rpc: &BitcoinRpcClient,
) -> anyhow::Result<BatchInFlight> {
    initialize_consensus(client, bitcoin).await?;

    let federation_address = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    bitcoin
        .send_and_mine_block(&federation_address, Amount::from_int_btc(1))
        .await;

    await_finality_delay(client, bitcoin).await?;
    await_federation_total_value(client, Amount::from_sat(99_000_000)).await?;

    let wallet = client.get_first_module::<WalletClientModule>()?;

    // Peg out to an address the test wallet controls, so the recipient output
    // can be used to attempt a pin.
    let recipient = block_in_place(|| rpc.get_new_address(None, None))
        .expect("Failed to get a recipient address")
        .assume_checked();

    let send_op = wallet
        .send(
            recipient.clone().as_unchecked().clone(),
            Amount::from_sat(50_000),
            None,
            serde_json::Value::Null,
        )
        .await?;

    // A block has to be found for the accumulation window to close and the
    // batch to be built.
    bitcoin.mine_blocks(1).await;

    let FinalSendOperationState::Success(parent_txid) =
        wallet.await_final_send_operation_state(send_op).await?
    else {
        panic!("Peg-out was not accepted by the federation");
    };

    let parent = await_mempool_tx(rpc, parent_txid).await;

    let parent_entry = block_in_place(|| rpc.get_mempool_entry(&parent_txid))
        .expect("Batch parent is not in the mempool");

    let child_txid = *parent_entry
        .spent_by
        .first()
        .expect("Batch parent has no child in the mempool");

    let child = await_mempool_tx(rpc, child_txid).await;

    Ok(BatchInFlight {
        parent_txid,
        parent,
        child_txid,
        child,
        recipient,
    })
}

/// The batch is broadcast as a TRUC package, and the pinning attacks that
/// motivated the whole design are rejected by policy.
///
/// This is the assertion the rest of the work exists to support: a peg-out
/// recipient cannot attach *any* child to the batch parent, so neither the
/// oversized low-feerate child nor cluster exhaustion is available to them.
#[tokio::test(flavor = "multi_thread")]
async fn truc_batch_is_packaged_and_cannot_be_pinned() -> anyhow::Result<()> {
    let Some(rpc) = bitcoind_rpc() else {
        return Ok(());
    };

    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    let batch = batch_in_flight(&client, &bitcoin, &rpc).await?;

    let wallet = client.get_first_module::<WalletClientModule>()?;

    // --- the parent is a zero fee TRUC transaction carrying an anchor --------

    assert_eq!(
        batch.parent.version,
        Version(3),
        "Batch parent is not a TRUC transaction"
    );

    let anchor_output = &batch.parent.output[PARENT_ANCHOR_VOUT as usize];

    assert_eq!(
        anchor_output.value,
        Amount::ZERO,
        "Anchor is not a zero value output"
    );

    assert_eq!(
        anchor_output.script_pubkey,
        bitcoin::ScriptBuf::new_p2a(),
        "Anchor is not a pay-to-anchor output"
    );

    let parent_entry = block_in_place(|| rpc.get_mempool_entry(&batch.parent_txid))
        .expect("Batch parent is not in the mempool");

    assert_eq!(
        parent_entry.fees.base,
        Amount::ZERO,
        "Batch parent must pay no fee for its anchor to be ephemeral dust"
    );

    assert_eq!(
        parent_entry.descendant_count, 2,
        "Batch parent should have exactly one child, its fee paying sibling"
    );

    // --- the child spends the change and the anchor, and pays for both -------

    assert_eq!(
        batch.child.version,
        Version(3),
        "Batch child is not a TRUC transaction"
    );

    let child_inputs: BTreeSet<BitcoinOutPoint> = batch
        .child
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();

    assert!(
        child_inputs.contains(&BitcoinOutPoint {
            txid: batch.parent_txid,
            vout: 0,
        }),
        "Child does not spend the parent's change"
    );

    assert!(
        child_inputs.contains(&BitcoinOutPoint {
            txid: batch.parent_txid,
            vout: PARENT_ANCHOR_VOUT,
        }),
        "Child does not spend the parent's anchor, so the parent's dust is not ephemeral"
    );

    let child_entry = block_in_place(|| rpc.get_mempool_entry(&batch.child_txid))
        .expect("Batch child is not in the mempool");

    assert!(
        child_entry.fees.base > Amount::ZERO,
        "Batch child pays no fee, so the package can never be mined"
    );

    // --- the pin is dead ----------------------------------------------------

    let recipient_vout = batch
        .parent
        .output
        .iter()
        .position(|tx_out| tx_out.script_pubkey == batch.recipient.script_pubkey())
        .expect("Parent does not pay the peg-out recipient") as u32;

    let recipient_value = batch.parent.output[recipient_vout as usize].value;

    let burn = block_in_place(|| rpc.get_new_address(None, None))
        .expect("Failed to get an address")
        .assume_checked();

    let prevout = SignRawTransactionInput {
        txid: batch.parent_txid,
        vout: recipient_vout,
        script_pub_key: batch.recipient.script_pubkey(),
        redeem_script: None,
        amount: Some(recipient_value),
    };

    // Version two is what any ordinary wallet would build, and version three is
    // what a determined attacker would reach for. Neither can attach.
    for version in [Version::TWO, Version(3)] {
        let unsigned = Transaction {
            version,
            lock_time: LockTime::ZERO,
            input: vec![unsigned_txin(BitcoinOutPoint {
                txid: batch.parent_txid,
                vout: recipient_vout,
            })],
            output: vec![TxOut {
                value: recipient_value - Amount::from_sat(5_000),
                script_pubkey: burn.script_pubkey(),
            }],
        };

        let signed = block_in_place(|| {
            rpc.sign_raw_transaction_with_wallet(
                &unsigned,
                Some(std::slice::from_ref(&prevout)),
                None,
            )
        })
        .expect("Failed to sign the pinning child")
        .transaction()
        .expect("Failed to decode the signed pinning child");

        assert!(
            block_in_place(|| rpc.send_raw_transaction(&signed)).is_err(),
            "A peg-out recipient attached a version {version:?} child to the batch parent, so \
             the parent can still be pinned"
        );
    }

    // --- and the batch confirms --------------------------------------------

    let block_hash = bitcoin.mine_blocks(1).await[0];

    let block = block_in_place(|| rpc.get_block_info(&block_hash)).expect("Failed to read block");

    assert!(
        block.tx.contains(&batch.parent_txid) && block.tx.contains(&batch.child_txid),
        "Parent and child were not mined together"
    );

    // Once the federation has scanned that block it advances onto the child's
    // output, which is what the child was built to leave behind.
    await_finality_delay(&client, &bitcoin).await?;

    await_federation_total_value(&client, batch.child.output[0].value).await?;

    assert_eq!(
        wallet.total_value().await?,
        batch.child.output[0].value,
        "Federation did not settle onto the child's output"
    );

    assert!(
        wallet.pending_tx_chain().await?.is_empty(),
        "Batch is still pending after it settled"
    );

    Ok(())
}

/// A third party spending the anchor settles the batch on the parent's change.
///
/// This is the Step 4 fallback, and the one adversarial path in the design. The
/// child is permanently invalidated by an outsider, and the federation has to
/// notice and advance onto the parent instead. It costs the federation nothing:
/// the outsider paid for the confirmation, so the child's fee is never spent
/// and stays in the federation's balance.
#[tokio::test(flavor = "multi_thread")]
async fn third_party_anchor_spend_settles_the_batch_on_the_parent() -> anyhow::Result<()> {
    let Some(rpc) = bitcoind_rpc() else {
        return Ok(());
    };

    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    let batch = batch_in_flight(&client, &bitcoin, &rpc).await?;

    let wallet = client.get_first_module::<WalletClientModule>()?;

    let child_fee = block_in_place(|| rpc.get_mempool_entry(&batch.child_txid))
        .expect("Batch child is not in the mempool")
        .fees
        .base;

    // Fund the replacement from a confirmed coin, so the parent remains its
    // only unconfirmed ancestor and TRUC still permits it.
    let funding = block_in_place(|| rpc.list_unspent(Some(1), None, None, None, None))
        .expect("Failed to list unspent outputs")
        .into_iter()
        .find(|utxo| utxo.spendable && utxo.amount >= Amount::from_sat(1_000_000))
        .expect("No confirmed coin to fund the replacement");

    let destination = block_in_place(|| rpc.get_new_address(None, None))
        .expect("Failed to get an address")
        .assume_checked();

    // Replacing the child means outbidding it in both absolute fee and
    // feerate, which is exactly why an eviction can only ever speed the batch
    // up rather than stall it.
    let replacement_fee = child_fee + Amount::from_sat(20_000);

    let unsigned = Transaction {
        version: Version(3),
        lock_time: LockTime::ZERO,
        input: vec![
            unsigned_txin(BitcoinOutPoint {
                txid: batch.parent_txid,
                vout: PARENT_ANCHOR_VOUT,
            }),
            unsigned_txin(BitcoinOutPoint {
                txid: funding.txid,
                vout: funding.vout,
            }),
        ],
        output: vec![TxOut {
            value: funding.amount - replacement_fee,
            script_pubkey: destination.script_pubkey(),
        }],
    };

    // The anchor input is anyone-can-spend and needs no signature, so the
    // wallet reports the transaction as incompletely signed. Only the funding
    // input actually has to be satisfied.
    let signed = block_in_place(|| {
        rpc.sign_raw_transaction_with_wallet(
            &unsigned,
            Some(&[SignRawTransactionInput {
                txid: funding.txid,
                vout: funding.vout,
                script_pub_key: funding.script_pub_key.clone(),
                redeem_script: None,
                amount: Some(funding.amount),
            }]),
            None,
        )
    })
    .expect("Failed to sign the anchor spend")
    .transaction()
    .expect("Failed to decode the anchor spend");

    let replacement_txid = block_in_place(|| rpc.send_raw_transaction(&signed))
        .expect("A third party could not spend the anchor");

    assert!(
        block_in_place(|| rpc.get_mempool_entry(&batch.child_txid)).is_err(),
        "Our child survived a higher paying anchor spend"
    );

    let block_hash = bitcoin.mine_blocks(1).await[0];

    let block = block_in_place(|| rpc.get_block_info(&block_hash)).expect("Failed to read block");

    assert!(
        block.tx.contains(&batch.parent_txid) && block.tx.contains(&replacement_txid),
        "The parent did not confirm alongside the third party's anchor spend"
    );

    assert!(
        !block.tx.contains(&batch.child_txid),
        "Our child confirmed despite being replaced"
    );

    // The federation must fall back onto the parent's change, which is larger
    // than the child's output by exactly the fee the child never got to pay.
    let expected = batch.parent.output[0].value;

    assert_eq!(
        expected,
        batch.child.output[0].value + child_fee,
        "The parent's change should exceed the child's output by the child's fee"
    );

    await_finality_delay(&client, &bitcoin).await?;

    await_federation_total_value(&client, expected).await?;

    assert_eq!(
        wallet.total_value().await?,
        expected,
        "Federation did not fall back onto the parent's change"
    );

    assert!(
        wallet.pending_tx_chain().await?.is_empty(),
        "Batch is still pending after the third party settled it"
    );

    Ok(())
}

/// Peg-outs submitted before a block is found are settled together in a single
/// bitcoin transaction, and the fee quote does not move while they queue.
///
/// This replaces an earlier test that drove the fee past one bitcoin by
/// stacking peg-outs: each one used to create its own chained transaction and
/// pay a fee sized to lift the whole pending stack, doubling the minimum
/// feerate per pending transaction. Batching leaves at most one federation
/// transaction outstanding, so that escalation no longer exists to test.
#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_are_batched_into_a_single_transaction() -> anyhow::Result<()> {
    let fixtures = fixtures();

    let fed = fixtures.new_fed_not_degraded().await;

    let client = fed.new_client().await;

    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    info!("Deposit funds into the federation...");

    let federation_address = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    bitcoin
        .send_and_mine_block(&federation_address, Amount::from_int_btc(100))
        .await;

    await_finality_delay(&client, &bitcoin).await?;

    info!("Wait for deposit to be auto-claimed...");

    await_federation_total_value(&client, Amount::from_sat(99_000_000)).await?;

    let wallet = client.get_first_module::<WalletClientModule>()?;

    let initial_fee = wallet.send_fee().await?;

    let mut events = pin!(wallet_event_stream(&client));

    let Some(WalletEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };

    let Some(WalletEvent::ReceiveStatus(status)) = events.next().await else {
        panic!("Expected ReceiveStatus event");
    };
    assert_eq!(status.operation_id, receive.operation_id);

    // No block is mined until every peg-out has been submitted, so they all
    // queue for the same batch.
    let mut send_ops = Vec::new();

    for _ in 0..3 {
        let address = bitcoin.get_new_address().await.as_unchecked().clone();

        send_ops.push(
            wallet
                .send(
                    address,
                    Amount::from_sat(10_000),
                    None,
                    serde_json::Value::Null,
                )
                .await?,
        );

        assert_eq!(
            wallet.send_fee().await?,
            initial_fee,
            "Fee quote escalated while peg-outs were queued"
        );
    }

    sleep_in_test(
        "Giving consensus time to accept the queued peg-outs",
        Duration::from_secs(5),
    )
    .await;

    // Nothing has been settled yet: the peg-outs are queued, and the
    // federation's wallet still tracks only what has been mined.
    assert!(
        wallet.pending_tx_chain().await?.is_empty(),
        "A batch was constructed before a block was found"
    );

    // The batch is only constructed when the consensus block count advances.
    bitcoin.mine_blocks(1).await;

    let submitted = send_ops.clone();

    let mut txids = BTreeSet::new();

    for send_op in send_ops {
        let FinalSendOperationState::Success(txid) =
            wallet.await_final_send_operation_state(send_op).await?
        else {
            panic!("Peg-out was not accepted by the federation");
        };

        txids.insert(txid);
    }

    assert_eq!(
        txids.len(),
        1,
        "Peg-outs were settled in {} transactions instead of one batch",
        txids.len()
    );

    // The pending chain holds the single batch, not one transaction per
    // peg-out.
    assert_eq!(
        wallet.pending_tx_chain().await?.len(),
        1,
        "Expected exactly one pending batch"
    );

    let mut sends = 0;
    let mut successes = 0;

    for _ in 0..6 {
        match events.next().await {
            Some(WalletEvent::Send(event)) => {
                assert!(
                    submitted.contains(&event.operation_id),
                    "Send event for an operation we never submitted"
                );
                sends += 1;
            }
            Some(WalletEvent::SendStatus(event)) => {
                assert!(matches!(event.status, SendPaymentStatus::Success(_)));
                successes += 1;
            }
            other => panic!("Unexpected wallet event {other:?}"),
        }
    }

    assert_eq!(sends, 3, "Expected one Send event per peg-out");
    assert_eq!(
        successes, 3,
        "Expected one successful SendStatus per peg-out"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_to_a_mainnet_address_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    // A well-known mainnet P2PKH address. The federation runs on regtest.
    let mainnet_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse()?;

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .send(
                mainnet_address,
                Amount::from_sat(100_000),
                None,
                serde_json::Value::Null,
            )
            .await
            .err(),
        Some(SendError::WrongNetwork),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_below_the_dust_limit_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    let address = bitcoin.get_new_address().await.as_unchecked().clone();

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .send(address, Amount::from_sat(1), None, serde_json::Value::Null)
            .await
            .err(),
        Some(SendError::DustValue),
    );

    Ok(())
}

mod db {
    use anyhow::{Context, bail, ensure};
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
    use fedimint_client::module_init::DynClientModuleInit;
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::{OutPoint, PeerId, TransactionId};
    use fedimint_logging::TracingSetup;
    use fedimint_server_core::DynServerModuleInit;
    use fedimint_testing::db::{
        BYTE_32, snapshot_db_migrations, snapshot_db_migrations_client, validate_migrations_client,
        validate_migrations_server,
    };
    use fedimint_walletv2_client::WalletClientModule;
    use fedimint_walletv2_client::db::{
        self, NextOutputIndexKey, ValidAddressIndexKey, ValidAddressIndexPrefix,
    };
    use fedimint_walletv2_common::{FederationWallet, TxInfo, WalletCommonInit};
    use fedimint_walletv2_server::db::{
        BlockCountVoteKey, BlockCountVotePrefix, DbKeyPrefix, FederationWalletKey, FeeRateVoteKey,
        FeeRateVotePrefix, Output, OutputKey, OutputPrefix, PendingBatchPrefix,
        PendingReceivePrefix, PendingSendIndexPrefix, PendingSendPrefix, QueuedBalancePrefix,
        SignaturesKey, SignaturesPrefix, SpentOutputKey, SpentOutputPrefix, TxInfoIndexKey,
        TxInfoIndexPrefix, TxInfoKey, TxInfoPrefix, UnconfirmedTxKey, UnconfirmedTxPrefix,
        UnsignedTxKey, UnsignedTxPrefix,
    };
    use fedimint_walletv2_server::{FederationTx, SpentTxOut};
    use futures::StreamExt;
    use strum::IntoEnumIterator;

    use crate::{WalletClientInit, WalletInit};

    /// The peer every vote in the snapshot is attributed to.
    fn peer() -> PeerId {
        PeerId::from(0)
    }

    /// The fedimint transaction id the client state machines refer to. Nothing
    /// looks it up, it only has to survive a database round-trip.
    fn fedimint_txid() -> TransactionId {
        TransactionId::from_slice(&BYTE_32).expect("BYTE_32 is 32 bytes long")
    }

    /// The wallet's tweak, reused for every record so the validation closure
    /// can compare against a single expected value.
    fn tweak() -> sha256::Hash {
        sha256::Hash::hash(&BYTE_32)
    }

    /// A transaction that is only well-formed enough to survive a database
    /// round-trip; it spends nothing and is never broadcast.
    fn transaction(value: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn federation_tx(value: u64) -> FederationTx {
        FederationTx {
            tx: transaction(value),
            spent_tx_outs: vec![SpentTxOut {
                value: Amount::from_sat(value),
                tweak: tweak(),
            }],
            vbytes: 200,
            fee: Amount::from_sat(1_000),
        }
    }

    /// A signature that parses but verifies against nothing; it only has to
    /// survive a database round-trip.
    fn signature() -> Signature {
        Signature::from_compact(&[BYTE_32, BYTE_32].concat())
            .expect("two 32 byte scalars below the curve order parse as a signature")
    }

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only intended to
    /// provide coverage when reading the database in future code versions. This
    /// function should not be updated when database keys or values change -
    /// instead a new function should be added that creates a new database
    /// backup that can be tested.
    ///
    /// walletv2 has no server migrations yet, so what the paired test asserts
    /// is that every one of these rows still decodes under current code.
    async fn create_server_db_with_v0_data(db: Database) {
        let unsigned = federation_tx(100_000);
        let unconfirmed = federation_tx(200_000);
        let unsigned_txid = unsigned.tx.compute_txid();
        let unconfirmed_txid = unconfirmed.tx.compute_txid();

        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(
            &OutputKey(0),
            &Output(
                bitcoin::OutPoint {
                    txid: unsigned_txid,
                    vout: 0,
                },
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::new(),
                },
            ),
        )
        .await;

        dbtx.insert_new_entry(&SpentOutputKey(0), &()).await;

        dbtx.insert_new_entry(&BlockCountVoteKey(peer()), &128)
            .await;

        dbtx.insert_new_entry(&FeeRateVoteKey(peer()), &Some(2))
            .await;

        dbtx.insert_new_entry(
            &TxInfoKey(0),
            &TxInfo {
                index: 0,
                txid: unsigned_txid,
                input: Amount::from_sat(200_000),
                output: Amount::from_sat(100_000),
                fee: Amount::from_sat(1_000),
                vbytes: 200,
                created: 1,
            },
        )
        .await;

        dbtx.insert_new_entry(
            &TxInfoIndexKey(OutPoint {
                txid: fedimint_txid(),
                out_idx: 0,
            }),
            &0,
        )
        .await;

        dbtx.insert_new_entry(&UnsignedTxKey(unsigned_txid), &unsigned)
            .await;

        dbtx.insert_new_entry(
            &SignaturesKey(unsigned_txid, peer()),
            &vec![signature(), signature()],
        )
        .await;

        dbtx.insert_new_entry(&UnconfirmedTxKey(unconfirmed_txid), &unconfirmed)
            .await;

        dbtx.insert_new_entry(
            &FederationWalletKey,
            &FederationWallet {
                value: Amount::from_sat(300_000),
                outpoint: bitcoin::OutPoint {
                    txid: unconfirmed_txid,
                    vout: 0,
                },
                tweak: tweak(),
            },
        )
        .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, WalletCommonInit>("walletv2-server-v0", |db| {
            Box::pin(async {
                create_server_db_with_v0_data(db).await;
            })
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();
        let module = DynServerModuleInit::from(WalletInit);

        validate_migrations_server(module, "walletv2-server", |db| async move {
            let unsigned_txid = transaction(100_000).compute_txid();
            let unconfirmed_txid = transaction(200_000).compute_txid();

            let mut dbtx = db.begin_transaction_nc().await;

            // Matching every variant explicitly, with no catch-all, is the point of this
            // pattern: adding a new prefix breaks the build here until someone decides
            // how the migration test should cover it.
            for prefix in DbKeyPrefix::iter() {
                match prefix {
                    DbKeyPrefix::Output => {
                        let outputs = dbtx
                            .find_by_prefix(&OutputPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        let [(OutputKey(index), Output(outpoint, tx_out))] = outputs.as_slice()
                        else {
                            bail!("the seeded output must still decode, got {outputs:?}");
                        };

                        ensure!(
                            *index == 0
                                && *outpoint
                                    == bitcoin::OutPoint {
                                        txid: unsigned_txid,
                                        vout: 0,
                                    }
                                && *tx_out
                                    == TxOut {
                                        value: Amount::from_sat(100_000),
                                        script_pubkey: ScriptBuf::new(),
                                    },
                            "the output must round-trip unchanged, got {outputs:?}"
                        );
                    }
                    DbKeyPrefix::SpentOutput => {
                        let spent = dbtx
                            .find_by_prefix(&SpentOutputPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            spent == vec![(SpentOutputKey(0), ())],
                            "the seeded spent output marker must round-trip unchanged, got \
                             {spent:?}"
                        );
                    }
                    // The batching tables did not exist at v0, so a migrated
                    // database must simply come up with them empty. They are
                    // populated only by peg-ins and peg-outs processed after
                    // the upgrade.
                    DbKeyPrefix::PendingSend => {
                        let queued = dbtx
                            .find_by_prefix(&PendingSendPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            queued.is_empty(),
                            "a migrated database must have no queued sends, got {queued:?}"
                        );
                    }
                    DbKeyPrefix::PendingSendIndex => {
                        let index = dbtx
                            .find_by_prefix(&PendingSendIndexPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            index.is_empty(),
                            "a migrated database must have no queued send index, got {index:?}"
                        );
                    }
                    DbKeyPrefix::PendingReceive => {
                        let queued = dbtx
                            .find_by_prefix(&PendingReceivePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            queued.is_empty(),
                            "a migrated database must have no queued receives, got {queued:?}"
                        );
                    }
                    DbKeyPrefix::PendingBatch => {
                        let batch = dbtx
                            .find_by_prefix(&PendingBatchPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            batch.is_empty(),
                            "a migrated database must have no batch in flight, got {batch:?}"
                        );
                    }
                    DbKeyPrefix::QueuedBalance => {
                        let balance = dbtx
                            .find_by_prefix(&QueuedBalancePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            balance.is_empty(),
                            "a migrated database must have no queued balance, got {balance:?}"
                        );
                    }
                    DbKeyPrefix::BlockCountVote => {
                        let votes = dbtx
                            .find_by_prefix(&BlockCountVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        let [(BlockCountVoteKey(voter), count)] = votes.as_slice() else {
                            bail!("the seeded block count vote must still decode, got {votes:?}");
                        };

                        ensure!(
                            *voter == peer() && *count == 128,
                            "the seeded block count vote must round-trip unchanged, got {votes:?}"
                        );
                    }
                    DbKeyPrefix::FeeRateVote => {
                        let votes = dbtx
                            .find_by_prefix(&FeeRateVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        let [(FeeRateVoteKey(voter), feerate)] = votes.as_slice() else {
                            bail!("the seeded fee rate vote must still decode, got {votes:?}");
                        };

                        ensure!(
                            *voter == peer() && *feerate == Some(2),
                            "the seeded fee rate vote must round-trip unchanged, got {votes:?}"
                        );
                    }
                    DbKeyPrefix::TxLog => {
                        let log = dbtx
                            .find_by_prefix(&TxInfoPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        let [(TxInfoKey(index), info)] = log.as_slice() else {
                            bail!(
                                "the seeded transaction log entry must still decode, got {log:?}"
                            );
                        };

                        ensure!(
                            *index == 0
                                && *info
                                    == TxInfo {
                                        index: 0,
                                        txid: unsigned_txid,
                                        input: Amount::from_sat(200_000),
                                        output: Amount::from_sat(100_000),
                                        fee: Amount::from_sat(1_000),
                                        vbytes: 200,
                                        created: 1,
                                    },
                            "the transaction log entry must round-trip unchanged, got {log:?}"
                        );
                    }
                    DbKeyPrefix::TxInfoIndex => {
                        let index = dbtx
                            .find_by_prefix(&TxInfoIndexPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            index.len() == 1
                                && index[0].0.0
                                    == OutPoint {
                                        txid: fedimint_txid(),
                                        out_idx: 0,
                                    }
                                && index[0].1 == 0,
                            "the seeded transaction log index must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::UnsignedTx => {
                        let unsigned = dbtx
                            .find_by_prefix(&UnsignedTxPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            unsigned.len() == 1
                                && unsigned[0].0.0 == unsigned_txid
                                && unsigned[0].1 == federation_tx(100_000),
                            "the seeded unsigned transaction must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::Signatures => {
                        let signatures = dbtx
                            .find_by_prefix(&SignaturesPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            signatures.len() == 1
                                && signatures[0].0.0 == unsigned_txid
                                && signatures[0].0.1 == peer()
                                && signatures[0].1 == vec![signature(), signature()],
                            "the seeded signatures must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::UnconfirmedTx => {
                        let unconfirmed = dbtx
                            .find_by_prefix(&UnconfirmedTxPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            unconfirmed.len() == 1
                                && unconfirmed[0].0.0 == unconfirmed_txid
                                && unconfirmed[0].1 == federation_tx(200_000),
                            "the seeded unconfirmed transaction must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::FederationWallet => {
                        let wallet = dbtx
                            .get_value(&FederationWalletKey)
                            .await
                            .context("the seeded federation wallet must still decode")?;

                        ensure!(
                            wallet
                                == FederationWallet {
                                    value: Amount::from_sat(300_000),
                                    outpoint: bitcoin::OutPoint {
                                        txid: unconfirmed_txid,
                                        vout: 0,
                                    },
                                    tweak: tweak(),
                                },
                            "the federation wallet must round-trip unchanged"
                        );
                    }
                }
            }

            Ok(())
        })
        .await
    }

    /// The client-side counterpart of `create_server_db_with_v0_data`, seeding
    /// the module's isolated namespace.
    async fn create_client_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&NextOutputIndexKey, &3).await;

        dbtx.insert_new_entry(&ValidAddressIndexKey(0), &()).await;
        dbtx.insert_new_entry(&ValidAddressIndexKey(1), &()).await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, WalletCommonInit>(
            "walletv2-client-v0",
            |db| Box::pin(async { create_client_db_with_v0_data(db).await }),
            || (Vec::new(), Vec::new()),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();
        let module = DynClientModuleInit::from(WalletClientInit);

        validate_migrations_client::<_, _, WalletClientModule>(
            module,
            "walletv2-client",
            |db, _, _| async move {
                let mut dbtx = db.begin_transaction_nc().await;

                for prefix in db::DbKeyPrefix::iter() {
                    match prefix {
                        db::DbKeyPrefix::NextOutputIndex => {
                            let index = dbtx
                                .get_value(&NextOutputIndexKey)
                                .await
                                .context("the seeded next output index must still decode")?;

                            ensure!(
                                index == 3,
                                "the next output index must round-trip unchanged, got {index}"
                            );
                        }
                        db::DbKeyPrefix::ValidAddressIndex => {
                            let indices = dbtx
                                .find_by_prefix(&ValidAddressIndexPrefix)
                                .await
                                .map(|(key, ())| key.0)
                                .collect::<Vec<_>>()
                                .await;

                            ensure!(
                                indices == vec![0, 1],
                                "both seeded valid address indices must round-trip unchanged, \
                                 got {indices:?}"
                            );
                        }
                    }
                }

                Ok(())
            },
        )
        .await
    }
}
