use std::collections::BTreeMap;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, schnorr};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use bitcoincore_rpc::RpcApi;
use fedimint_core::Feerate;
use fedimint_core::runtime::block_in_place;
use frost_secp256k1_tr as frost;
use miniscript::Descriptor;
use miniscript::descriptor::Tr;
use tracing::info;

/// Weight a taproot key-path spend adds to an unsigned transaction: the segwit
/// marker & flag plus a single 64-byte Schnorr signature witness item with its
/// two length prefixes.
const KEY_SPEND_WITNESS_WEIGHT: u64 = 2 + 66;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            let mut rng = rand::rngs::OsRng;

            let max_signers = 4;
            let min_signers = 3;

            let mut round1_secret_packages = BTreeMap::new();

            let mut received_round1_packages = BTreeMap::new();

            // Round 1
            info!("Starting round1...");
            for participant_index in 1..=max_signers {
                let partificpant_identifier =
                    participant_index.try_into().expect("should be nonzero");
                let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
                    partificpant_identifier,
                    max_signers,
                    min_signers,
                    &mut rng,
                )?;

                round1_secret_packages.insert(partificpant_identifier, round1_secret_package);

                // "Broadcast" to the rest of the peers
                info!(
                    %participant_index,
                    "Broadcasting part1 to the rest of the peers...",
                );
                for receiver_participant_index in 1..=max_signers {
                    // we dont need to send to ourselves silly!
                    if receiver_participant_index == participant_index {
                        continue;
                    }

                    let receiver_identifier: frost::Identifier = receiver_participant_index
                        .try_into()
                        .expect("should be nonzero");
                    received_round1_packages
                        .entry(receiver_identifier)
                        .or_insert_with(BTreeMap::new)
                        .insert(partificpant_identifier, round1_package.clone());
                }
            }

            // Round 2
            info!("Starting round2...");
            let mut round2_secret_packages = BTreeMap::new();

            let mut received_round2_packages = BTreeMap::new();

            for participant_index in 1..=max_signers {
                let participant_identifier =
                    participant_index.try_into().expect("should be nonzero");
                let round1_secret_package = round1_secret_packages
                    .remove(&participant_identifier)
                    .unwrap();
                let round1_packages = &received_round1_packages[&participant_identifier];
                let (round2_secret_package, round2_packages) =
                    frost::keys::dkg::part2(round1_secret_package, round1_packages)?;

                round2_secret_packages.insert(participant_identifier, round2_secret_package);

                // "Broadcast" to the rest of the peers
                info!(
                    %participant_index,
                    "Broadcasting part2 to the rest of the peers...",
                );
                for (receiver_identifier, round2_package) in round2_packages {
                    received_round2_packages
                        .entry(receiver_identifier)
                        .or_insert_with(BTreeMap::new)
                        .insert(participant_identifier, round2_package);
                }
            }

            let mut key_packages = BTreeMap::new();
            let mut group_keys = None;

            for participant_index in 1..=max_signers {
                let (key_package, pubkey_package, descriptor) = final_key_generation(
                    participant_index,
                    &round2_secret_packages,
                    &received_round1_packages,
                    &received_round2_packages,
                )?;

                match &group_keys {
                    Some((expected_pubkey_package, expected_descriptor)) => {
                        assert_eq!(
                            &pubkey_package, expected_pubkey_package,
                            "all participants must derive the same group key"
                        );
                        assert_eq!(
                            &descriptor, expected_descriptor,
                            "all participants must derive the same descriptor"
                        );
                    }
                    None => group_keys = Some((pubkey_package, descriptor)),
                }

                key_packages.insert(*key_package.identifier(), key_package);
            }

            let (pubkey_package, descriptor) =
                group_keys.expect("at least one participant ran key generation");

            let address = descriptor.address(bitcoin::Network::Regtest)?;
            info!(%address, "Address");

            // "Peg-in" to the FROST address
            let bitcoin = dev_fed.bitcoind().await?;
            let txid = bitcoin
                .send_to_address(address, Amount::from_sat(1_000_000))
                .await?;
            info!(%txid, "Txid of pegin to address");

            // Find the UTXO the peg-in created for the FROST descriptor. The
            // transaction has to be fetched while it is still in the mempool:
            // bitcoind runs without -txindex, so getrawtransaction cannot look
            // it up once it has been mined.
            let script_pubkey = descriptor.script_pubkey();
            let peg_in_tx = block_in_place(|| bitcoin.client.get_raw_transaction(&txid, None))?;
            bitcoin.mine_blocks(1).await?;
            let vout = peg_in_tx
                .output
                .iter()
                .position(|output| output.script_pubkey == script_pubkey)
                .expect("Peg-in transaction pays to the FROST address");
            let peg_in_output = peg_in_tx.output[vout].clone();

            let peg_out_amount = Amount::from_sat(500_000);
            let destination_address = bitcoin.get_new_address().await?;
            let feerate = Feerate { sats_per_kvb: 1000 };

            let mut peg_out_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid,
                        vout: u32::try_from(vout).expect("vout fits in u32"),
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                }],
                output: vec![
                    TxOut {
                        value: peg_out_amount,
                        script_pubkey: destination_address.script_pubkey(),
                    },
                    // Change back to the federation; value is set below once
                    // the fee is known
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: script_pubkey.clone(),
                    },
                ],
            };

            let fee = feerate.calculate_fee(peg_out_tx.weight().to_wu() + KEY_SPEND_WITNESS_WEIGHT);
            let change_amount = peg_in_output.value - peg_out_amount - fee;
            peg_out_tx.output[1].value = change_amount;
            info!(%fee, %change_amount, "Constructed peg-out transaction");

            let prevouts = [peg_in_output];
            let sighash = SighashCache::new(&peg_out_tx).taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )?;
            info!(%sighash, "Peg-out key-spend sighash");

            // Signing round 1: a threshold of participants generates nonces
            // and commitments
            info!("Starting signing round1...");
            let mut signing_nonces = BTreeMap::new();
            let mut signing_commitments = BTreeMap::new();
            for (identifier, key_package) in key_packages.iter().take(usize::from(min_signers)) {
                let (nonces, commitments) =
                    frost::round1::commit(key_package.signing_share(), &mut rng);
                signing_nonces.insert(*identifier, nonces);
                signing_commitments.insert(*identifier, commitments);
            }

            let signing_package =
                frost::SigningPackage::new(signing_commitments, sighash.as_byte_array());

            // Signing round 2: each participant produces a signature share.
            // The merkle root is `None` because the descriptor commits to a
            // key-path-only output.
            info!("Starting signing round2...");
            let mut signature_shares = BTreeMap::new();
            for (identifier, nonces) in &signing_nonces {
                let signature_share = frost::round2::sign_with_tweak(
                    &signing_package,
                    nonces,
                    &key_packages[identifier],
                    None,
                )?;
                signature_shares.insert(*identifier, signature_share);
            }

            let group_signature = frost::aggregate_with_tweak(
                &signing_package,
                &signature_shares,
                &pubkey_package,
                None,
            )?;

            // Verify the aggregated signature against the output key committed
            // to by the descriptor: this proves the FROST group key and the
            // descriptor's key-path tweak agree.
            let schnorr_signature = schnorr::Signature::from_slice(&group_signature.serialize()?)?;
            let output_key = XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..])
                .expect("P2TR witness program is an x-only key");
            Secp256k1::verification_only().verify_schnorr(
                &schnorr_signature,
                &Message::from_digest(sighash.to_byte_array()),
                &output_key,
            )?;
            info!("Aggregated signature verifies against the taproot output key");

            peg_out_tx.input[0].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
                signature: schnorr_signature,
                sighash_type: TapSighashType::Default,
            });

            let peg_out_txid = block_in_place(|| bitcoin.client.send_raw_transaction(&peg_out_tx))?;
            info!(%peg_out_txid, "Broadcast peg-out transaction");

            bitcoin.mine_blocks(1).await?;
            bitcoin.poll_get_transaction(peg_out_txid).await?;
            info!(%peg_out_txid, "Peg-out transaction confirmed");

            info!("frost playground finished");

            Ok(())
        })
        .await
}

/// Runs the final round of the DKG for the given participant, producing their
/// private key package, the group's public key package and the federation's
/// Taproot descriptor.
fn final_key_generation(
    participant_index: u16,
    round2_secret_packages: &BTreeMap<frost::Identifier, frost::keys::dkg::round2::SecretPackage>,
    received_round1_packages: &BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    >,
    received_round2_packages: &BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    >,
) -> anyhow::Result<(
    frost::keys::KeyPackage,
    frost::keys::PublicKeyPackage,
    Descriptor<XOnlyPublicKey>,
)> {
    info!(%participant_index, "Doing final key generation...");
    let participant_identifier = participant_index.try_into().expect("should be nonzero");
    let round2_secret_package = &round2_secret_packages[&participant_identifier];
    let round1_packages = &received_round1_packages[&participant_identifier];
    let round2_packages = &received_round2_packages[&participant_identifier];
    let (key_package, pubkey_package) =
        frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;
    info!(?key_package, "Key Package");
    info!(?pubkey_package, "Pubkey Package");

    let verifying_key_bytes = pubkey_package.verifying_key().serialize()?;
    let pubkey = PublicKey::from_slice(&verifying_key_bytes).expect("valid compressed pubkey");
    // The group key is already tweaked with the unspendable-script-path
    // TapTweak by the `-tr` ciphersuite's DKG; it serves as the
    // descriptor's internal key, so signing must use `sign_with_tweak`
    // with no merkle root to match the descriptor's key-path tweak.
    let internal_key = pubkey.inner.x_only_public_key().0;
    let descriptor =
        Descriptor::Tr(Tr::new(internal_key, None).expect("Could not create Taproot descriptor"));
    info!(%descriptor, "Taproot Descriptor");

    Ok((key_package, pubkey_package, descriptor))
}
