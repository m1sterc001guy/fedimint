use std::collections::BTreeMap;

use bitcoin::PublicKey;
use frost_secp256k1 as frost;

fn main() -> anyhow::Result<()> {
    let mut rng = rand::rngs::OsRng;

    let max_signers = 4;
    let min_signers = 3;

    let mut round1_secret_packages = BTreeMap::new();

    let mut received_round1_packages = BTreeMap::new();

    // Round 1
    println!("Starting round1...");
    for participant_index in 1..=max_signers {
        let partificpant_identifier = participant_index.try_into().expect("should be nonzero");
        let (round1_secret_package, round1_package) =
            frost::keys::dkg::part1(partificpant_identifier, max_signers, min_signers, &mut rng)?;

        round1_secret_packages.insert(partificpant_identifier, round1_secret_package);

        // "Broadcast" to the rest of the peers
        println!(
            "Participant {} broadcasting to the rest of the peers...",
            participant_index
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
    println!("Starting round2...");
    let mut round2_secret_packages = BTreeMap::new();

    let mut received_round2_packages = BTreeMap::new();

    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let round1_secret_package = round1_secret_packages
            .remove(&participant_identifier)
            .unwrap();
        let round1_packages = &received_round1_packages[&participant_identifier];
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, round1_packages)?;

        round2_secret_packages.insert(participant_identifier, round2_secret_package);

        // "Broadcast" to the rest of the peers
        println!(
            "Participant {} broadcasting to the rest of the peers...",
            participant_index
        );
        for (receiver_identifier, round2_package) in round2_packages {
            received_round2_packages
                .entry(receiver_identifier)
                .or_insert_with(BTreeMap::new)
                .insert(participant_identifier, round2_package);
        }
    }

    // Final Key Generation
    //let mut key_packages = BTreeMap::new();

    //let mut pubkey_packages = BTreeMap::new();

    // Each participant will do this on their own
    // Right now I'm just doing it for participant 1

    println!("Doing final key generation for participant 1...");
    let participant_identifier = 1.try_into().expect("should be nonzero");
    let round2_secret_package = &round2_secret_packages[&participant_identifier];
    let round1_packages = &received_round1_packages[&participant_identifier];
    let round2_packages = &received_round2_packages[&participant_identifier];
    let (key_package, pubkey_package) =
        frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;
    println!("Key Package: {:?}", key_package);
    println!("Pubkey Package: {:?}", pubkey_package);

    let verifying_key_bytes = pubkey_package.verifying_key().serialize()?;
    let pubkey = PublicKey::from_slice(&verifying_key_bytes).expect("valid compressed pubkey");
    let (xonly, _parity) = pubkey.inner.x_only_public_key();
    let descriptor_str = format!("tr({xonly})");
    println!("Taproot Descriptor: {descriptor_str}");

    println!();

    println!("Doing final key generation for participant 2...");
    let participant_identifier = 2.try_into().expect("should be nonzero");
    let round2_secret_package = &round2_secret_packages[&participant_identifier];
    let round1_packages = &received_round1_packages[&participant_identifier];
    let round2_packages = &received_round2_packages[&participant_identifier];
    let (key_package, pubkey_package) =
        frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;
    println!("Key Package: {:?}", key_package);
    println!("Pubkey Package: {:?}", pubkey_package);

    let verifying_key_bytes = pubkey_package.verifying_key().serialize()?;
    let pubkey = PublicKey::from_slice(&verifying_key_bytes).expect("valid compressed pubkey");
    let (xonly, _parity) = pubkey.inner.x_only_public_key();
    let descriptor_str = format!("tr({xonly})");
    println!("Taproot Descriptor: {descriptor_str}");

    println!("frost playground finished");

    Ok(())
}
