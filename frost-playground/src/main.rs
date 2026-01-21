use std::collections::BTreeMap;

use bitcoin::sighash::SighashCache;
use bitcoin::{PublicKey, secp256k1};
use fedimint_core::Feerate;
use fedimint_wallet_common::keys::CompressedPublicKey;
use fedimint_wallet_common::tweakable::Tweakable;
use frost_secp256k1 as frost;
use miniscript::Descriptor;
use miniscript::descriptor::Tr;
use rand::rngs::OsRng;
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

            info!("Doing final key generation for participant 1...");
            let participant_identifier = 1.try_into().expect("should be nonzero");
            let round2_secret_package = &round2_secret_packages[&participant_identifier];
            let round1_packages = &received_round1_packages[&participant_identifier];
            let round2_packages = &received_round2_packages[&participant_identifier];
            let (key_package, pubkey_package) =
                frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;
            info!(?key_package, "Key Package");
            info!(?pubkey_package, "Pubkey Package");

            let verifying_key_bytes = pubkey_package.verifying_key().serialize()?;
            let pubkey =
                PublicKey::from_slice(&verifying_key_bytes).expect("valid compressed pubkey");
            let compressed = CompressedPublicKey { key: pubkey.inner };
            let descriptor = Descriptor::Tr(
                Tr::new(compressed, None).expect("Could not create Taproot descriptor"),
            );
            info!(%descriptor, "Taproot Descriptor");

            info!("Doing final key generation for participant 2...");
            let participant_identifier = 2.try_into().expect("should be nonzero");
            let round2_secret_package = &round2_secret_packages[&participant_identifier];
            let round1_packages = &received_round1_packages[&participant_identifier];
            let round2_packages = &received_round2_packages[&participant_identifier];
            let (key_package, pubkey_package) =
                frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;
            info!(?key_package, "Key Package");
            info!(?pubkey_package, "Pubkey Package");

            let verifying_key_bytes = pubkey_package.verifying_key().serialize()?;
            let pubkey =
                PublicKey::from_slice(&verifying_key_bytes).expect("valid compressed pubkey");
            let compressed = CompressedPublicKey { key: pubkey.inner };
            let descriptor = Descriptor::Tr(
                Tr::new(compressed, None).expect("Could not create Taproot descriptor"),
            );
            info!(%descriptor, "Taproot Descriptor");

            let secp = secp256k1::Secp256k1::new();
            let tweak_key = secp.generate_keypair(&mut OsRng);
            let public_tweak_key = tweak_key.1;
            let address = descriptor
                .tweak(&public_tweak_key, &secp)
                .address(bitcoin::Network::Regtest)?;
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
