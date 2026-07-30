use std::collections::BTreeMap;

use bitcoin::sighash::SighashCache;
use bitcoin::{PublicKey, XOnlyPublicKey};
use fedimint_core::Feerate;
use frost_secp256k1_tr as frost;
use miniscript::Descriptor;
use miniscript::descriptor::Tr;
use tracing::info;

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

            let (_key_package_1, descriptor_1) = final_key_generation(
                1,
                &round2_secret_packages,
                &received_round1_packages,
                &received_round2_packages,
            )?;

            let (_key_package_2, descriptor_2) = final_key_generation(
                2,
                &round2_secret_packages,
                &received_round1_packages,
                &received_round2_packages,
            )?;

            assert_eq!(
                descriptor_1, descriptor_2,
                "all participants must derive the same descriptor"
            );

            let address = descriptor_1.address(bitcoin::Network::Regtest)?;
            info!(%address, "Address");

            // "Peg-in" to the FROST address
            let bitcoin = dev_fed.bitcoind().await?;
            let txid = bitcoin
                .send_to_address(address, bitcoin::Amount::from_sat(1_000_000))
                .await?;
            info!(%txid, "Txid of pegin to address");

            let peg_out_amount = bitcoin::Amount::from_sat(500_000);
            let destination_address = bitcoin.get_new_address().await?;
            let feerate = Feerate { sats_per_kvb: 1000 };

            info!("frost playground finished");

            Ok(())
        })
        .await
}

/// Runs the final round of the DKG for the given participant, producing their
/// private key package and the federation's Taproot descriptor.
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
) -> anyhow::Result<(frost::keys::KeyPackage, Descriptor<XOnlyPublicKey>)> {
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

    Ok((key_package, descriptor))
}
