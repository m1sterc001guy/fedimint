use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fedimint_core::{NumPeersExt, OutPoint, PeerId, TransactionId};
use fedimint_statechain_common::crypto::{
    OperatorShare, SecretNonce, SignSession, SigningKey, add_shares, dkg_contribution,
    dkg_operator_poly, encryption_context, generate_nonce, recover_dkg_share, verify_signature,
};
use fedimint_statechain_common::{CoinId, PublicNonce, ScalarBytes};
use rand::rngs::OsRng;
use secp256k1::{PublicKey, SECP256K1, SecretKey};

use super::{Roast, ShareOutcome, ShareRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Behavior {
    Honest,
    /// Hands out nonces but never answers share requests
    Stalling,
    /// Answers share requests with an invalid share
    Invalid,
    /// Fails every request
    Offline,
}

struct Guardian {
    share: OperatorShare,
    behavior: Behavior,
    nonces: BTreeMap<[u8; 32], SecretNonce>,
}

impl Guardian {
    fn nonce(&mut self) -> ([u8; 32], PublicNonce) {
        let nonce_id = rand::random::<[u8; 32]>();
        let (secret, public) = generate_nonce(&mut OsRng);

        self.nonces.insert(nonce_id, secret);

        (nonce_id, public)
    }
}

enum Event {
    Nonce(PeerId, [u8; 32], PublicNonce),
    Share(usize, PeerId, ScalarBytes),
}

struct Federation {
    aggregate_pk: PublicKey,
    operator_poly: Vec<PublicKey>,
    threshold: usize,
    user_sk: SecretKey,
    guardians: BTreeMap<PeerId, Guardian>,
}

fn federation(behaviors: &[Behavior]) -> Federation {
    let peers = (0..behaviors.len())
        .map(|peer| PeerId::from(u16::try_from(peer).expect("Small federation")))
        .collect::<BTreeSet<PeerId>>();

    let threshold = peers.to_num_peers().threshold();

    let coin = CoinId(OutPoint {
        txid: TransactionId::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
        out_idx: 0,
    });

    let context = encryption_context(coin, 0, "test");

    let ephemeral_sks = peers
        .iter()
        .map(|peer| (*peer, SecretKey::new(&mut OsRng)))
        .collect::<BTreeMap<PeerId, SecretKey>>();

    let ephemeral_pks = ephemeral_sks
        .iter()
        .map(|(peer, sk)| (*peer, sk.public_key(SECP256K1)))
        .collect::<BTreeMap<PeerId, PublicKey>>();

    let contributions = peers
        .iter()
        .map(|peer| {
            (
                *peer,
                dkg_contribution(*peer, threshold, &ephemeral_pks, &context, &mut OsRng),
            )
        })
        .collect();

    let operator_poly = dkg_operator_poly(&contributions).expect("Contributions agree");

    let user_sk = SecretKey::new(&mut OsRng);

    let guardians = peers
        .iter()
        .zip(behaviors)
        .map(|(peer, behavior)| {
            let share = recover_dkg_share(
                *peer,
                &ephemeral_sks[peer],
                &contributions,
                &operator_poly,
                &context,
            )
            .expect("The dealt share is consistent");

            (
                *peer,
                Guardian {
                    share,
                    behavior: *behavior,
                    nonces: BTreeMap::new(),
                },
            )
        })
        .collect();

    Federation {
        aggregate_pk: user_sk
            .public_key(SECP256K1)
            .combine(&operator_poly[0])
            .expect("Keys do not cancel out"),
        operator_poly,
        threshold,
        user_sk,
        guardians,
    }
}

struct Run {
    signature: Option<secp256k1::schnorr::Signature>,
    sessions_started: usize,
    excluded: BTreeSet<PeerId>,
}

/// The guardians' answers to share requests, which records that each guardian
/// is now in the requested session.
fn deliver_requests(
    key: SigningKey,
    message: [u8; 32],
    requests: Vec<ShareRequest>,
    open_session: &mut BTreeMap<PeerId, usize>,
    guardians: &mut BTreeMap<PeerId, Guardian>,
    events: &mut VecDeque<Event>,
) {
    for request in requests {
        assert!(
            open_session.insert(request.peer, request.session).is_none(),
            "A guardian is in at most one open session"
        );

        let guardian = guardians.get_mut(&request.peer).expect("Known guardian");
        let secret_nonce = guardian
            .nonces
            .remove(&request.nonce_id)
            .expect("Nonces are used once");

        let session = SignSession::new(key, message, &request.guardian_nonces, request.user_nonce);

        let share = match guardian.behavior {
            Behavior::Honest => session.guardian_sign(request.peer, guardian.share, &secret_nonce),
            Behavior::Invalid => session.guardian_sign(
                request.peer,
                add_shares(&guardian.share, &guardian.share),
                &secret_nonce,
            ),
            Behavior::Stalling | Behavior::Offline => continue,
        };

        events.push_back(Event::Share(request.session, request.peer, share));
    }
}

/// Drives the coordinator against simulated guardians, delivering responses
/// in order, and checks that no guardian is ever in two open sessions.
fn run(federation: &mut Federation, message: [u8; 32]) -> Run {
    let mut roast = Roast::new(
        federation.aggregate_pk,
        message,
        federation.operator_poly.clone(),
        federation.threshold,
        federation.user_sk,
    );

    let key = SigningKey::new(&federation.aggregate_pk);
    let mut events = VecDeque::new();
    let mut open_session = BTreeMap::<PeerId, usize>::new();

    for (peer, guardian) in &mut federation.guardians {
        if guardian.behavior == Behavior::Offline {
            roast.exclude(*peer);
        } else {
            let (nonce_id, nonce) = guardian.nonce();
            events.push_back(Event::Nonce(*peer, nonce_id, nonce));
        }
    }

    while let Some(event) = events.pop_front() {
        match event {
            Event::Nonce(peer, nonce_id, nonce) => {
                let requests = roast.nonce_received(peer, nonce_id, nonce, &mut OsRng);
                deliver_requests(
                    key,
                    message,
                    requests,
                    &mut open_session,
                    &mut federation.guardians,
                    &mut events,
                );
            }
            Event::Share(session, peer, share) => {
                assert_eq!(open_session.remove(&peer), Some(session));

                match roast
                    .share_received(session, peer, share)
                    .expect("Our own share is valid")
                {
                    ShareOutcome::Complete(signature) => {
                        return Run {
                            signature: Some(signature),
                            sessions_started: roast.sessions_started(),
                            excluded: roast.excluded().clone(),
                        };
                    }
                    ShareOutcome::Valid => {
                        let guardian = federation.guardians.get_mut(&peer).expect("Known guardian");
                        let (nonce_id, nonce) = guardian.nonce();
                        events.push_back(Event::Nonce(peer, nonce_id, nonce));
                    }
                    ShareOutcome::Invalid => {}
                }
            }
        }
    }

    Run {
        signature: None,
        sessions_started: roast.sessions_started(),
        excluded: roast.excluded().clone(),
    }
}

fn assert_signs(behaviors: &[Behavior]) -> Run {
    let mut federation = federation(behaviors);
    let message = rand::random::<[u8; 32]>();

    let run = run(&mut federation, message);

    let signature = run.signature.expect("The signing completes");

    assert!(verify_signature(
        &federation.aggregate_pk,
        &message,
        &signature
    ));

    let faulty = behaviors
        .iter()
        .filter(|behavior| **behavior != Behavior::Honest)
        .count();

    assert!(
        run.sessions_started <= faulty + 1,
        "ROAST needs at most f + 1 sessions, used {}",
        run.sessions_started
    );

    run
}

#[test]
fn honest_guardians_sign_in_a_single_session() {
    let run = assert_signs(&[Behavior::Honest; 4]);

    assert_eq!(run.sessions_started, 1);
    assert!(run.excluded.is_empty());
}

#[test]
fn a_stalling_guardian_is_routed_around() {
    // Peer 0 is in the first session because ready guardians are taken in
    // peer order.
    let run = assert_signs(&[
        Behavior::Stalling,
        Behavior::Honest,
        Behavior::Honest,
        Behavior::Honest,
    ]);

    assert_eq!(run.sessions_started, 2);
}

#[test]
fn a_guardian_with_an_invalid_share_is_excluded() {
    let run = assert_signs(&[
        Behavior::Honest,
        Behavior::Invalid,
        Behavior::Honest,
        Behavior::Honest,
    ]);

    assert_eq!(run.excluded, BTreeSet::from([PeerId::from(1)]));
}

#[test]
fn the_maximum_number_of_faulty_guardians_is_tolerated() {
    // Seven guardians tolerate two faults.
    assert_signs(&[
        Behavior::Stalling,
        Behavior::Honest,
        Behavior::Invalid,
        Behavior::Honest,
        Behavior::Honest,
        Behavior::Honest,
        Behavior::Honest,
    ]);

    assert_signs(&[
        Behavior::Offline,
        Behavior::Stalling,
        Behavior::Honest,
        Behavior::Honest,
        Behavior::Honest,
        Behavior::Honest,
        Behavior::Honest,
    ]);
}

#[test]
fn too_many_stalling_guardians_prevent_a_signature() {
    let mut federation = federation(&[
        Behavior::Stalling,
        Behavior::Stalling,
        Behavior::Honest,
        Behavior::Honest,
    ]);

    let run = run(&mut federation, rand::random());

    assert!(run.signature.is_none());
}
