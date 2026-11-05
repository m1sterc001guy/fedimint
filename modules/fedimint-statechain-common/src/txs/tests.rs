use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, Network, Sequence, Txid};
use secp256k1::{SECP256K1, SecretKey};

use super::{Funding, ScriptBuf, coin_script, exit_tx, node_tx, pegout_tx};
use crate::config::StatechainParams;

fn funding(amount: Amount) -> Funding {
    Funding {
        outpoint: bitcoin::OutPoint {
            txid: Txid::all_zeros(),
            vout: 1,
        },
        amount,
    }
}

fn script() -> ScriptBuf {
    coin_script(SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1))
}

#[test]
fn exit_timelocks_decrease_until_exhausted() {
    let params = StatechainParams::new(Network::Regtest);

    let timelocks = (0..)
        .map_while(|level| params.exit_timelock(level))
        .collect::<Vec<u16>>();

    assert_eq!(timelocks, vec![60, 50, 40, 30, 20, 10]);

    let mainnet = StatechainParams::new(Network::Bitcoin);

    assert_eq!(mainnet.exit_timelock(0), Some(2_000));
    assert_eq!(mainnet.exit_timelock(19), Some(100));
    assert_eq!(mainnet.exit_timelock(20), None);
    assert_eq!(mainnet.exit_timelock(u16::MAX), None);
}

#[test]
fn exit_tx_spends_the_node_output_after_its_timelock() {
    let coin_script = script();
    let node = node_tx(
        funding(Amount::from_sat(50_000)),
        coin_script.clone(),
        Amount::from_sat(1_000),
    )
    .expect("Funding covers the fee");

    assert_eq!(node.output[0].script_pubkey, coin_script);
    assert_eq!(node.output[0].value, Amount::from_sat(49_000));

    let exit = exit_tx(&node, 40, script(), Amount::from_sat(1_000)).expect("Value covers the fee");

    assert_eq!(exit.input[0].previous_output.txid, node.compute_txid());
    assert_eq!(exit.input[0].sequence, Sequence::from_height(40));
    assert_eq!(exit.output[0].value, Amount::from_sat(48_000));
    assert!(exit.version >= bitcoin::transaction::Version::TWO);
}

#[test]
fn transactions_below_the_dust_limit_are_refused() {
    let node = node_tx(
        funding(Amount::from_sat(2_500)),
        script(),
        Amount::from_sat(1_000),
    )
    .expect("Funding covers the fee");

    assert!(exit_tx(&node, 10, script(), Amount::from_sat(1_000)).is_none());
    assert!(
        pegout_tx(
            funding(Amount::from_sat(1_000)),
            script(),
            Amount::from_sat(500)
        )
        .is_none()
    );
    assert!(
        node_tx(
            funding(Amount::from_sat(500)),
            script(),
            Amount::from_sat(1_000)
        )
        .is_none()
    );
}
