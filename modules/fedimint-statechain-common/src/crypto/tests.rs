use std::collections::{BTreeMap, BTreeSet};

use bitcoin::hashes::Hash as _;
use fedimint_core::{OutPoint, PeerId, TransactionId};
use rand::rngs::OsRng;
use rand::seq::IteratorRandom;
use schnorr_fun::fun::Scalar;
use schnorr_fun::fun::marker::{Secret, Zero};
use secp256k1::{PublicKey, SecretKey};

use super::{
    DkgContribution, PublicNonce, SECP256K1, SignSession, SigningKey, add_polys, add_shares,
    deal_tweak, decrypt_secret, dkg_contribution, dkg_operator_poly, encrypt_secret,
    encryption_context, generate_nonce, recover_dkg_share, recover_tweak_share, rotation_tweak,
    verify_dkg_contribution, verify_rotation_commitment, verify_share, verify_signature,
};
use crate::CoinId;

const NUM_PEERS: u16 = 4;
const THRESHOLD: usize = 3;

fn peers() -> BTreeSet<PeerId> {
    (0..NUM_PEERS).map(PeerId::from).collect()
}

fn coin() -> CoinId {
    CoinId(OutPoint {
        txid: TransactionId::from_byte_array([7; 32]),
        out_idx: 0,
    })
}

struct Operators {
    poly: Vec<PublicKey>,
    shares: BTreeMap<PeerId, Scalar<Secret, Zero>>,
}

fn ephemeral_keys() -> (BTreeMap<PeerId, SecretKey>, BTreeMap<PeerId, PublicKey>) {
    let sks = peers()
        .into_iter()
        .map(|peer| (peer, SecretKey::new(&mut OsRng)))
        .collect::<BTreeMap<PeerId, SecretKey>>();

    let pks = sks
        .iter()
        .map(|(peer, sk)| (*peer, sk.public_key(SECP256K1)))
        .collect();

    (sks, pks)
}

fn run_dkg() -> Operators {
    let context = encryption_context(coin(), 0, "dkg");
    let (ephemeral_sks, ephemeral_pks) = ephemeral_keys();

    let contributions = peers()
        .into_iter()
        .map(|peer| {
            let contribution =
                dkg_contribution(peer, THRESHOLD, &ephemeral_pks, &context, &mut OsRng);

            assert!(verify_dkg_contribution(
                peer,
                &peers(),
                THRESHOLD,
                &contribution
            ));

            (peer, contribution)
        })
        .collect::<BTreeMap<PeerId, DkgContribution>>();

    let poly = dkg_operator_poly(&contributions).expect("Contributions have equal degree");

    assert_eq!(poly.len(), THRESHOLD);

    let shares = peers()
        .into_iter()
        .map(|peer| {
            let share =
                recover_dkg_share(peer, &ephemeral_sks[&peer], &contributions, &poly, &context)
                    .expect("Every guardian recovers a valid share");

            (peer, share)
        })
        .collect();

    Operators { poly, shares }
}

/// Runs a signing session among the user and a random threshold subset of the
/// guardians and returns the combined signature.
fn sign(
    operators: &Operators,
    user_sk: &SecretKey,
    message: [u8; 32],
) -> Option<secp256k1::schnorr::Signature> {
    let user_pk = user_sk.public_key(SECP256K1);
    let aggregate_pk = user_pk
        .combine(&operators.poly[0])
        .expect("Keys do not cancel out");
    let key = SigningKey::new(&aggregate_pk);

    let signers = peers().into_iter().choose_multiple(&mut OsRng, THRESHOLD);

    let nonces = signers
        .iter()
        .map(|peer| (*peer, generate_nonce(&mut OsRng)))
        .collect::<BTreeMap<PeerId, _>>();

    let public_nonces = nonces
        .iter()
        .map(|(peer, (_, public))| (*peer, *public))
        .collect::<BTreeMap<PeerId, PublicNonce>>();

    let (user_secret_nonce, user_public_nonce) = generate_nonce(&mut OsRng);

    let mut shares = Vec::new();

    for (peer, (secret_nonce, _)) in &nonces {
        // Each guardian builds the session from the request on its own.
        let session = SignSession::new(key, message, &public_nonces, user_public_nonce);
        let share = session.guardian_sign(*peer, operators.shares[peer], secret_nonce);

        assert!(
            SignSession::new(key, message, &public_nonces, user_public_nonce)
                .verify_guardian_share(*peer, &operators.poly, share),
            "A correct guardian share verifies"
        );

        shares.push(share);
    }

    let session = SignSession::new(key, message, &public_nonces, user_public_nonce);

    shares.push(session.user_sign(user_sk, &user_secret_nonce));

    session.combine(shares)
}

#[test]
fn user_and_any_threshold_of_guardians_produce_a_valid_taproot_signature() {
    let operators = run_dkg();

    // Random keys exercise all four parity combinations of the internal and
    // the output key.
    for _ in 0..32 {
        let user_sk = SecretKey::new(&mut OsRng);
        let aggregate_pk = user_sk
            .public_key(SECP256K1)
            .combine(&operators.poly[0])
            .expect("Keys do not cancel out");

        let message = rand::random::<[u8; 32]>();

        let signature = sign(&operators, &user_sk, message).expect("Shares are valid scalars");

        assert!(verify_signature(&aggregate_pk, &message, &signature));
    }
}

#[test]
fn guardians_alone_cannot_sign() {
    let operators = run_dkg();
    let user_sk = SecretKey::new(&mut OsRng);
    let aggregate_pk = user_sk
        .public_key(SECP256K1)
        .combine(&operators.poly[0])
        .expect("Keys do not cancel out");

    // A wrong user key stands in for a signature without the user.
    let message = rand::random::<[u8; 32]>();
    let signature =
        sign(&operators, &SecretKey::new(&mut OsRng), message).expect("Shares are valid scalars");

    assert!(!verify_signature(&aggregate_pk, &message, &signature));
}

#[test]
fn a_tampered_guardian_share_is_detected() {
    let operators = run_dkg();
    let user_sk = SecretKey::new(&mut OsRng);
    let aggregate_pk = user_sk
        .public_key(SECP256K1)
        .combine(&operators.poly[0])
        .expect("Keys do not cancel out");
    let key = SigningKey::new(&aggregate_pk);
    let message = rand::random::<[u8; 32]>();

    let peer = PeerId::from(0);
    let (secret_nonce, public_nonce) = generate_nonce(&mut OsRng);
    let mut public_nonces = BTreeMap::from([(peer, public_nonce)]);

    for other in [PeerId::from(1), PeerId::from(2)] {
        public_nonces.insert(other, generate_nonce(&mut OsRng).1);
    }

    let session = SignSession::new(key, message, &public_nonces, generate_nonce(&mut OsRng).1);

    // A share computed with another guardian's key share is invalid.
    let share = session.guardian_sign(peer, operators.shares[&PeerId::from(1)], &secret_nonce);

    assert!(!session.verify_guardian_share(peer, &operators.poly, share));
}

#[test]
fn rotation_keeps_the_coin_key_and_disables_the_previous_user() {
    let operators = run_dkg();
    let old_sk = SecretKey::new(&mut OsRng);
    let new_sk = SecretKey::new(&mut OsRng);
    let old_pk = old_sk.public_key(SECP256K1);
    let new_pk = new_sk.public_key(SECP256K1);

    let aggregate_pk = old_pk
        .combine(&operators.poly[0])
        .expect("Keys do not cancel out");

    let context = encryption_context(coin(), 1, "rotation");
    let (ephemeral_sks, ephemeral_pks) = ephemeral_keys();

    let tweak = rotation_tweak(&old_sk, &new_sk).expect("Keys differ");
    let deal = deal_tweak(&tweak, THRESHOLD, &ephemeral_pks, &context, &mut OsRng);

    assert!(verify_rotation_commitment(
        &deal, THRESHOLD, &old_pk, &new_pk
    ));
    assert!(!verify_rotation_commitment(
        &deal, THRESHOLD, &new_pk, &old_pk
    ));

    let rotated = Operators {
        poly: add_polys(&operators.poly, &deal.commitments).expect("Equal degree"),
        shares: operators
            .shares
            .iter()
            .map(|(peer, share)| {
                let tweak_share = recover_tweak_share(*peer, &ephemeral_sks[peer], &deal, &context)
                    .expect("The dealt share is consistent");

                (*peer, add_shares(share, &tweak_share))
            })
            .collect(),
    };

    assert_eq!(
        new_pk
            .combine(&rotated.poly[0])
            .expect("Keys do not cancel out"),
        aggregate_pk,
        "The rotation preserves the aggregate key"
    );

    for (peer, share) in &rotated.shares {
        assert!(verify_share(&rotated.poly, *peer, share));
    }

    let message = rand::random::<[u8; 32]>();

    let signature = sign(&rotated, &new_sk, message).expect("Shares are valid scalars");
    assert!(verify_signature(&aggregate_pk, &message, &signature));

    let signature = sign(&rotated, &old_sk, message).expect("Shares are valid scalars");
    assert!(
        !verify_signature(&aggregate_pk, &message, &signature),
        "The previous user's key no longer combines with the rotated shares"
    );
}

#[test]
fn a_share_encrypted_to_another_key_fails_verification() {
    let context = encryption_context(coin(), 1, "rotation");
    let (ephemeral_sks, ephemeral_pks) = ephemeral_keys();
    let tweak = rotation_tweak(&SecretKey::new(&mut OsRng), &SecretKey::new(&mut OsRng))
        .expect("Keys differ");
    let deal = deal_tweak(&tweak, THRESHOLD, &ephemeral_pks, &context, &mut OsRng);

    let peer = PeerId::from(0);

    assert!(recover_tweak_share(peer, &ephemeral_sks[&PeerId::from(1)], &deal, &context).is_none());

    let other_context = encryption_context(coin(), 2, "rotation");

    assert!(recover_tweak_share(peer, &ephemeral_sks[&peer], &deal, &other_context).is_none());
}

#[test]
fn a_dkg_contribution_for_another_guardian_is_rejected() {
    let context = encryption_context(coin(), 0, "dkg");
    let (_, ephemeral_pks) = ephemeral_keys();
    let contribution = dkg_contribution(
        PeerId::from(0),
        THRESHOLD,
        &ephemeral_pks,
        &context,
        &mut OsRng,
    );

    // The proof of possession binds the contributor's slot.
    assert!(!verify_dkg_contribution(
        PeerId::from(1),
        &peers(),
        THRESHOLD,
        &contribution
    ));

    let mut short = contribution.clone();
    short.commitments.pop();

    assert!(!verify_dkg_contribution(
        PeerId::from(0),
        &peers(),
        THRESHOLD,
        &short
    ));
}

#[test]
fn an_encrypted_secret_round_trips() {
    let context = encryption_context(coin(), 1, "secret");
    let recipient_sk = SecretKey::new(&mut OsRng);
    let secret = SecretKey::new(&mut OsRng);

    let encrypted = encrypt_secret(
        &context,
        &recipient_sk.public_key(SECP256K1),
        &secret,
        &mut OsRng,
    );

    assert_eq!(
        decrypt_secret(&context, &encrypted, &recipient_sk),
        Some(secret)
    );

    assert_ne!(
        decrypt_secret(&context, &encrypted, &SecretKey::new(&mut OsRng)),
        Some(secret)
    );
}
