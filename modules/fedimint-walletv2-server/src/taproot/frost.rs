use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::anyhow;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Txid, XOnlyPublicKey};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::{NumPeersExt, PeerId};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt};
use fedimint_walletv2_common::taproot::frost::{FrostSignatureShares, FrostSigningCommitments};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::{
    EvenY, KeyPackage, PublicKeyPackage, SigningShare, Tweak, VerifyingShare,
};
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{Identifier, SigningPackage, VerifyingKey};
use futures::StreamExt;
use itertools::Itertools;
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use secp256k1::{PublicKey, Scalar};

use crate::db::{
    FrostSignatureShareKey, FrostSigningAttempt, FrostSigningAttemptKey,
    FrostSigningAttemptTxidPrefix, FrostSigningCommitmentsPeerPrefix, FrostSigningNoncesKey,
    FrostSigningNoncesPrefix, FrostSigningPackagesKey,
};
use crate::{FederationTx, Wallet};

impl Wallet {
    /// Compute the BIP-341 key-path sighash for the given input of
    /// `unsigned_tx`. This is the message that the FROST signers will
    /// collectively sign.
    pub(crate) fn build_frost_key_spend_message(
        &self,
        unsigned_tx: &FederationTx,
        input_index: usize,
    ) -> [u8; 32] {
        let prevouts = self.build_prevouts(unsigned_tx);
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        sighash_cache
            .taproot_key_spend_signature_hash(
                input_index,
                &Prevouts::All(&prevouts),
                bitcoin::TapSighashType::Default,
            )
            .expect("Failed to compute taproot key spend sighash")
            .to_byte_array()
    }

    /// Build and persist the FROST `SigningPackage` for each input of
    /// `unsigned_tx`. Every peer (signer or not) runs this so the package is
    /// available later for verifying and aggregating shares without it
    /// having to ride along with each `FrostSignatureShare` consensus item.
    /// Signing-session peers additionally consume their per-input nonce and
    /// produce their `SignatureShare`s, stored under their own peer_id for
    /// the next `consensus_proposal` to broadcast.
    ///
    /// `attempt` is `0` when this runs from `process_input` /
    /// `process_output` (initial signing), and `prev.attempt + 1` when
    /// triggered from a successful advance vote — same body, different
    /// hash-shuffle seed.
    pub(crate) async fn compute_and_store_frost_signature_shares(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        unsigned_tx: &FederationTx,
        attempt: u32,
    ) -> anyhow::Result<()> {
        let txid = unsigned_tx.tx.compute_txid();
        let all_peers: Vec<PeerId> = self.cfg.consensus.bitcoin_pks.keys().copied().collect();
        let threshold = self.cfg.consensus.bitcoin_pks.to_num_peers().threshold();

        // Compute suspects: peers who were assigned to a prior attempt of
        // this tx but didn't broadcast their share. Drawn entirely from
        // consensus-replicated DB state — every peer computes the same set,
        // so the resulting signing_session selection is deterministic.
        // Empty for the initial attempt (no prior attempts) and grows as
        // advances accumulate.
        let prior_attempts = dbtx
            .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
            .await
            .collect::<Vec<_>>()
            .await;
        let mut suspects = HashSet::new();
        for (key, attempt_record) in prior_attempts {
            for peer in &attempt_record.signing_session {
                let broadcast = dbtx
                    .get_value(&FrostSignatureShareKey {
                        txid,
                        attempt: key.attempt,
                        peer_id: *peer,
                    })
                    .await
                    .is_some();
                if !broadcast {
                    suspects.insert(*peer);
                }
            }
        }

        // Each input consumes one commitment per signing-session peer, so a
        // peer is only viable if it has at least n_inputs commitments
        // available right now. Skipping under-buffered peers here means the
        // per-input `consume_session_commitments` calls below can't fail
        // halfway through.
        let signing_session = pick_signing_session(
            dbtx,
            &all_peers,
            threshold,
            txid,
            attempt,
            unsigned_tx.tx.input.len(),
            &suspects,
        )
        .await
        .ok_or_else(|| {
            anyhow!("Insufficient FROST commitment buffer across federation for tx {txid}")
        })?;
        let is_signer = signing_session.contains(&self.our_peer_id);

        let key_package = if is_signer {
            Some(
                self.cfg
                    .private
                    .frost_key_package
                    .clone()
                    .ok_or_else(|| anyhow!("FROST federation must have a frost_key_package"))?,
            )
        } else {
            None
        };

        let mut signing_packages: Vec<FrostSigningPackage> =
            Vec::with_capacity(unsigned_tx.tx.input.len());
        let mut signature_shares: Vec<SignatureShare> = Vec::new();

        for input_index in 0..unsigned_tx.tx.input.len() {
            let utxo = &unsigned_tx.spent_tx_outs[input_index];
            let message = self.build_frost_key_spend_message(unsigned_tx, input_index);

            let commitments_map = self
                .consume_session_commitments(dbtx, &signing_session)
                .await?;

            let signing_package_commitments: BTreeMap<Identifier, _> = commitments_map
                .iter()
                .map(|(id, commitment)| (*id, commitment.0.clone()))
                .collect();
            let signing_package = SigningPackage::new(signing_package_commitments, &message);

            if let Some(key_package) = &key_package {
                let nonce = self.consume_our_nonce(dbtx, &commitments_map).await?;

                let tweaked_key_package = apply_utxo_tweak_to_key_package(key_package, &utxo.tweak);
                // Single-leaf TapTree: merkle root = leaf hash.
                let merkle_root = self.tap_leaf_hash(&utxo.tweak).to_byte_array();

                let signature_share = frost::round2::sign_with_tweak(
                    &signing_package,
                    &nonce,
                    &tweaked_key_package,
                    Some(&merkle_root),
                )?;

                tracing::info!(
                    target: LOG_MODULE_WALLETV2,
                    input_index,
                    "Generated FROST signature share for input"
                );

                signature_shares.push(signature_share);
            }

            signing_packages.push(FrostSigningPackage(signing_package));
        }

        dbtx.insert_new_entry(
            &FrostSigningPackagesKey { txid, attempt },
            &signing_packages,
        )
        .await;

        // Persist which signing session this attempt is using so peers'
        // FrostSignatureShare consensus items can be cross-checked
        // against the right session, and consensus_proposal can broadcast
        // our share without re-deriving the session. Each attempt has
        // its own record — advance creates a new (txid, attempt + 1)
        // entry rather than overwriting.
        dbtx.insert_new_entry(
            &FrostSigningAttemptKey { txid, attempt },
            &FrostSigningAttempt {
                signing_session: signing_session.clone(),
            },
        )
        .await;

        if is_signer {
            dbtx.insert_new_entry(
                &FrostSignatureShareKey {
                    txid,
                    attempt,
                    peer_id: self.our_peer_id,
                },
                &FrostSignatureShares { signature_shares },
            )
            .await;
        }

        Ok(())
    }
}

/// Target number of unused FROST signing nonces each peer keeps on disk.
/// Larger buffers let adaptive ROAST advance through more attempts (and let
/// the commitment-aware signer selection still find a viable session) before
/// the federation runs out of fresh nonces. Each unused commitment is also
/// broadcast as a consensus item, so this also caps the per-peer commitment
/// bytes flowing through AlephBFT.
pub(crate) const FROST_NONCE_BUFFER_TARGET: usize = 64;

/// Local wall-clock window each peer waits before broadcasting a
/// `FrostAdvanceVote` for a stuck signing session. Per-peer (not
/// consensus) — peers' clocks may differ, but the consensus is on the
/// *vote count*, not the timing.
pub(crate) fn local_advance_timeout() -> std::time::Duration {
    if fedimint_core::envs::is_running_in_test_env() {
        std::time::Duration::from_secs(2)
    } else {
        std::time::Duration::from_secs(30)
    }
}

/// One-shot startup backfill: top the local FROST nonce buffer up to
/// [`FROST_NONCE_BUFFER_TARGET`] and exit. After this, the buffer is
/// maintained 1:1 by `consume_our_nonce`, which generates a replacement
/// nonce inline every time it consumes one. So this only ever generates
/// nonces on cold start, restart, or recovery — anything that produces
/// a buffer below target.
///
/// `consensus_proposal` broadcasts the matching commitments via
/// `WalletConsensusItem::FrostSigningCommitments` so other guardians can
/// build a `SigningPackage` for us when needed. Each nonce is consumed
/// once (`consume_our_nonce` removes it after use) — FROST nonces must
/// never be reused, or the long-lived signing share is leaked.
pub(crate) fn spawn_initial_nonce_backfill(
    db: Database,
    task_group: &TaskGroup,
    key_package: KeyPackage,
) {
    task_group.spawn_cancellable("frost initial nonce backfill", async move {
        let mut dbtx = db.begin_transaction().await;
        let count = dbtx
            .find_by_prefix(&FrostSigningNoncesPrefix)
            .await
            .count()
            .await;
        for _ in 0..FROST_NONCE_BUFFER_TARGET.saturating_sub(count) {
            let (nonce, commitment) =
                frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);

            dbtx.insert_new_entry(
                &FrostSigningNoncesKey(FrostSigningCommitments(commitment)),
                &FrostSigningNonces(nonce),
            )
            .await;
        }
        dbtx.commit_tx().await;
    });
}

/// Attach BIP-341 key-path witnesses (one 64-byte FROST/Schnorr signature
/// per input) to `federation_tx`. Default sighash, so the witness for
/// each input is just the 64-byte signature with no sighash-type byte
/// appended.
pub(crate) fn finalize_tx_frost(
    federation_tx: &mut FederationTx,
    signatures: &[frost_secp256k1_tr::Signature],
) {
    assert_eq!(
        federation_tx.spent_tx_outs.len(),
        federation_tx.tx.input.len()
    );
    assert_eq!(signatures.len(), federation_tx.tx.input.len());

    for (index, sig) in signatures.iter().enumerate() {
        let sig_bytes = sig
            .serialize()
            .expect("FROST signature serializes to 64-byte BIP-340 form");
        let mut witness = bitcoin::Witness::new();
        witness.push(&sig_bytes);
        federation_tx.tx.input[index].witness = witness;
    }
}

/// Convert a `PeerId` into a FROST `Identifier`.
///
/// FROST identifiers must be non-zero, so we offset by 1.
pub(crate) fn peer_id_to_identifier(peer_id: PeerId) -> Identifier {
    Identifier::try_from(peer_id.to_usize() as u16 + 1)
        .expect("Could not convert PeerId to Identifier")
}

/// Deterministically pick a `threshold`-sized signing session for `(txid,
/// attempt)`. Two phases:
///
/// 1. **Hash-shuffle, non-suspects only.** Walk a shuffle of `all_peers` seeded
///    by `(txid, attempt)`, skipping suspects and peers whose
///    `FrostSigningCommitments` pool is shorter than `required_commitments`
///    (one commitment per input is consumed per session peer). If we collect
///    `threshold` peers, return.
///
/// 2. **Round-robin enumeration of viable subsets.** Phase 1 failed — typically
///    because too many peers are suspects. Walk every threshold-sized subset of
///    viable peers (sorted by `PeerId`) and return the first one whose set
///    doesn't equal a prior attempt's signing session. If every subset has been
///    tried, return `None`. By that point the federation is stuck — every
///    possible signing session is already pending in the DB, so progress has to
///    come from late shares completing a prior attempt or from operator
///    recovery.
///
/// `suspects` only filters Phase 1; Phase 2 explores the full space. All
/// inputs (commitment counts, prior sessions) are read from
/// consensus-replicated DB state, so every peer computes the same answer.
pub(crate) async fn pick_signing_session(
    dbtx: &mut DatabaseTransaction<'_>,
    all_peers: &[PeerId],
    threshold: usize,
    txid: Txid,
    attempt: u32,
    required_commitments: usize,
    suspects: &HashSet<PeerId>,
) -> Option<Vec<PeerId>> {
    // Read commitment counts once and reuse across both phases.
    let mut commitment_counts: HashMap<PeerId, usize> = HashMap::new();
    for &peer in all_peers {
        let count = dbtx
            .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(peer))
            .await
            .count()
            .await;
        commitment_counts.insert(peer, count);
    }
    let viable =
        |peer: &PeerId| commitment_counts.get(peer).copied().unwrap_or(0) >= required_commitments;

    // Phase 1: hash-shuffle, non-suspects with viable buffers.
    let seed: [u8; 32] = (txid, attempt)
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();
    let mut rng = ChaCha8Rng::from_seed(seed);
    let mut shuffled = all_peers.to_vec();
    shuffled.shuffle(&mut rng);

    let phase_1: Vec<PeerId> = shuffled
        .iter()
        .copied()
        .filter(|p| !suspects.contains(p) && viable(p))
        .take(threshold)
        .collect();
    if phase_1.len() == threshold {
        return Some(phase_1);
    }

    // Phase 2: round-robin enumeration over all viable peers. Pick the
    // first threshold-sized subset that doesn't match a prior session.
    let mut viable_peers: Vec<PeerId> = all_peers.iter().copied().filter(|p| viable(p)).collect();
    viable_peers.sort();

    if viable_peers.len() < threshold {
        return None;
    }

    let prior_sessions: Vec<HashSet<PeerId>> = dbtx
        .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
        .await
        .map(|(_, attempt_record)| attempt_record.signing_session.into_iter().collect())
        .collect::<Vec<_>>()
        .await;

    tracing::warn!(
        target: LOG_MODULE_WALLETV2,
        ?txid,
        attempt,
        suspect_count = suspects.len(),
        viable_peers = viable_peers.len(),
        prior_session_count = prior_sessions.len(),
        "Phase 1 (hash-shuffle of non-suspects) couldn't fill the signing session; \
         falling back to round-robin enumeration of viable subsets"
    );

    let candidate = viable_peers
        .into_iter()
        .combinations(threshold)
        .find(|combo| {
            let set: HashSet<PeerId> = combo.iter().copied().collect();
            !prior_sessions.iter().any(|prev| prev == &set)
        });

    if candidate.is_none() {
        tracing::error!(
            target: LOG_MODULE_WALLETV2,
            ?txid,
            attempt,
            prior_session_count = prior_sessions.len(),
            "Cannot form a new FROST signing session: every threshold-sized subset of \
             viable peers has already been tried. Federation is stuck — every prior \
             attempt is still pending; one of them must complete via late shares, or \
             operator recovery is required."
        );
    }
    candidate
}

/// Generate FROST key material centrally via a trusted dealer for
/// `peers`. Used by `trusted_dealer_gen` (the test / scripted path
/// that doesn't run a real DKG). Produces:
/// - One `KeyPackage` per peer, keyed by `PeerId`. Each peer receives only
///   their own package.
/// - The aggregated verifying key as an `XOnlyPublicKey` — this is what gets
///   stored as `WalletDescriptor::Frost(internal_key)`.
/// - The `PublicKeyPackage` (aggregate VK + per-peer verifying shares),
///   replicated to every peer for share verification.
///
/// Threshold is `peers.threshold()` (BFT majority). The dealer holds
/// every share momentarily and so must be trusted; real federations
/// should use [`dkg`] instead. Skipped entirely when `peers.len() ==
/// 1` (caller collapses to `WalletDescriptor::SinglePeer`).
pub(crate) fn trusted_setup(
    peers: &[PeerId],
) -> anyhow::Result<(
    BTreeMap<PeerId, KeyPackage>,
    XOnlyPublicKey,
    PublicKeyPackage,
)> {
    let threshold = peers.to_num_peers().threshold() as u16;
    let total_peers = peers.len() as u16;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        total_peers,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut OsRng,
    )?;
    let internal_key = frost_verifying_key_to_xonly(&pubkey_package);
    let key_packages = peers
        .iter()
        .map(|peer| {
            let identifier = peer_id_to_identifier(*peer);
            let share = shares
                .get(&identifier)
                .cloned()
                .expect("No share for identifier");
            let key_package =
                frost::keys::KeyPackage::try_from(share).expect("Could not convert share");
            (*peer, key_package)
        })
        .collect();
    Ok((key_packages, internal_key, pubkey_package))
}

/// Run a 3-round FROST distributed key generation across `peers` and
/// return our local share of the result. Unlike [`trusted_setup`], no
/// single party ever sees every secret share — each peer's signing
/// key is assembled locally from contributions exchanged over the
/// `PeerHandleOps` channel.
///
/// Returns:
/// - Our `KeyPackage` (private — only this peer's signing share + the aggregate
///   VK).
/// - The aggregated verifying key as an `XOnlyPublicKey`, stored as
///   `WalletDescriptor::Frost(internal_key)`. All honest peers compute the same
///   value.
/// - The `PublicKeyPackage` for share verification (replicated).
///
/// Round structure:
/// 1. `part1` — generate our polynomial commitment + secret; broadcast the
///    commitment to all peers via `exchange_encodable`.
/// 2. `part2` — using everyone's commitments, build per-peer shares; send each
///    peer their share privately (still over `exchange_encodable`, just keyed
///    by recipient).
/// 3. `part3` — combine our received shares with our retained secret to produce
///    our final `KeyPackage` and the aggregate `PublicKeyPackage`.
///
/// Skipped entirely when `peers.num_peers().total() == 1` (caller
/// collapses to `WalletDescriptor::SinglePeer`). Failures of any
/// `part*` propagate as `Err` and abort federation setup.
pub(crate) async fn dkg(
    peers: &(dyn PeerHandleOps + Send + Sync),
) -> anyhow::Result<(KeyPackage, XOnlyPublicKey, PublicKeyPackage)> {
    let our_identifier = peer_id_to_identifier(peers.identity());
    let threshold = peers.num_peers().threshold() as u16;
    let total_peers = peers.num_peers().total() as u16;
    let (round1_secret_package, round1_package) =
        frost::keys::dkg::part1(our_identifier, total_peers, threshold, &mut OsRng)?;

    let round1_packages = peers
        .exchange_encodable(FrostPolynomial(round1_package))
        .await?
        .into_iter()
        .filter(|(peer_id, _)| *peer_id != peers.identity())
        .map(|(peer_id, poly)| (peer_id_to_identifier(peer_id), poly.0))
        .collect::<BTreeMap<_, _>>();

    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(round1_secret_package, &round1_packages)?;

    let our_round2_packages = peers
        .num_peers()
        .peer_ids()
        .filter(|peer_id| *peer_id != peers.identity())
        .map(|peer_id| {
            let identifier = peer_id_to_identifier(peer_id);
            let package = round2_packages
                .get(&identifier)
                .expect("No round2 package for identifier")
                .clone();
            (peer_id, FrostPolynomialCommitment(package))
        })
        .collect::<BTreeMap<_, _>>();

    let round2_packages = peers
        .exchange_encodable(our_round2_packages)
        .await?
        .into_iter()
        .filter(|(peer_id, _)| *peer_id != peers.identity())
        .map(|(sender, mut map)| {
            let package = map
                .remove(&peers.identity())
                .expect("Peer sent us a package")
                .0;
            (peer_id_to_identifier(sender), package)
        })
        .collect::<BTreeMap<_, _>>();

    let (key_package, pubkey_package) =
        frost::keys::dkg::part3(&round2_secret_package, &round1_packages, &round2_packages)?;
    let xonly = frost_verifying_key_to_xonly(&pubkey_package);

    Ok((key_package, xonly, pubkey_package))
}

/// Apply the per-UTXO additive tweak to a FROST `KeyPackage` homomorphically:
///   s_i' = s_i + t,   Q_i' = Q_i + t·G,   Q' = Q + t·G
///
/// The descriptor's internal key for a UTXO is
/// `tweak_xonly_public_key(internal_key, tweak)`, which assumes Even-Y
/// interpretation of the original internal key — so we normalize
/// to Even-Y before adding the tweak. The BIP-341 tap tweak is applied
/// separately by `round2::sign_with_tweak`.
pub(crate) fn apply_utxo_tweak_to_key_package(
    key_package: &KeyPackage,
    tweak: &sha256::Hash,
) -> KeyPackage {
    let key_package = key_package.clone().into_even_y(None);

    let tweak_scalar =
        Scalar::from_be_bytes(tweak.to_byte_array()).expect("Hash is within field order");

    let sk = secp256k1::SecretKey::from_slice(&key_package.signing_share().serialize())
        .expect("FROST signing share is a valid secret key");
    let tweaked_sk = sk
        .add_tweak(&tweak_scalar)
        .expect("Tweaked signing share is non-zero");
    let tweaked_signing_share = SigningShare::deserialize(&tweaked_sk.secret_bytes())
        .expect("Bytes are a valid signing share");

    let vs_bytes = key_package
        .verifying_share()
        .serialize()
        .expect("FROST verifying share serializes");
    let tweaked_vs_pk = secp256k1::PublicKey::from_slice(&vs_bytes)
        .expect("FROST verifying share is a valid public key")
        .add_exp_tweak(secp256k1::SECP256K1, &tweak_scalar)
        .expect("Tweaked verifying share is non-identity");
    let tweaked_verifying_share = VerifyingShare::deserialize(&tweaked_vs_pk.serialize())
        .expect("Bytes are a valid verifying share");

    let vk_bytes = key_package
        .verifying_key()
        .serialize()
        .expect("FROST verifying key serializes");
    let tweaked_vk_pk = secp256k1::PublicKey::from_slice(&vk_bytes)
        .expect("FROST verifying key is a valid public key")
        .add_exp_tweak(secp256k1::SECP256K1, &tweak_scalar)
        .expect("Tweaked verifying key is non-identity");
    let tweaked_verifying_key = VerifyingKey::deserialize(&tweaked_vk_pk.serialize())
        .expect("Bytes are a valid verifying key");

    KeyPackage::new(
        *key_package.identifier(),
        tweaked_signing_share,
        tweaked_verifying_share,
        tweaked_verifying_key,
        *key_package.min_signers(),
    )
}

/// Apply the per-UTXO additive tweak to a FROST `PublicKeyPackage`
/// homomorphically:   Q' = Q + t·G,   Q_i' = Q_i + t·G
///
/// Mirrors `apply_utxo_tweak_to_key_package` on the public side. The BIP-341
/// tap tweak is applied separately by `aggregate_with_tweak`.
pub(crate) fn apply_utxo_tweak_to_pubkey_package(
    pubkey_package: &PublicKeyPackage,
    tweak: &sha256::Hash,
) -> PublicKeyPackage {
    let pubkey_package = pubkey_package.clone().into_even_y(None);

    let tweak_scalar =
        Scalar::from_be_bytes(tweak.to_byte_array()).expect("Hash is within field order");

    let vk_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .expect("FROST verifying key serializes");
    let tweaked_vk_pk = secp256k1::PublicKey::from_slice(&vk_bytes)
        .expect("FROST verifying key is a valid public key")
        .add_exp_tweak(secp256k1::SECP256K1, &tweak_scalar)
        .expect("Tweaked verifying key is non-identity");
    let tweaked_verifying_key = VerifyingKey::deserialize(&tweaked_vk_pk.serialize())
        .expect("Bytes are a valid verifying key");

    let tweaked_verifying_shares = pubkey_package
        .verifying_shares()
        .iter()
        .map(|(id, vs)| {
            let vs_bytes = vs.serialize().expect("FROST verifying share serializes");
            let tweaked_vs_pk = secp256k1::PublicKey::from_slice(&vs_bytes)
                .expect("FROST verifying share is a valid public key")
                .add_exp_tweak(secp256k1::SECP256K1, &tweak_scalar)
                .expect("Tweaked verifying share is non-identity");
            let tweaked_vs = VerifyingShare::deserialize(&tweaked_vs_pk.serialize())
                .expect("Bytes are a valid verifying share");
            (*id, tweaked_vs)
        })
        .collect();

    PublicKeyPackage::new(
        tweaked_verifying_shares,
        tweaked_verifying_key,
        pubkey_package.min_signers(),
    )
}

/// Verify a single peer's signature share against the FROST `pubkey_package`,
/// applying both the per-UTXO additive tweak and the BIP-341 tap tweak so the
/// verifying-share / verifying-key match what the signer used in
/// `sign_with_tweak`. Returns an error if the share doesn't verify (e.g., a
/// malicious or buggy peer).
pub(crate) fn verify_signature_share(
    pubkey_package: &PublicKeyPackage,
    utxo_tweak: &sha256::Hash,
    merkle_root: &[u8],
    peer_id: PeerId,
    signing_package: &SigningPackage,
    signature_share: &SignatureShare,
) -> anyhow::Result<()> {
    let pubkey_package = apply_utxo_tweak_to_pubkey_package(pubkey_package, utxo_tweak);
    let pubkey_package = pubkey_package.tweak(Some(merkle_root));

    let identifier = peer_id_to_identifier(peer_id);
    let verifying_share = pubkey_package
        .verifying_shares()
        .get(&identifier)
        .ok_or_else(|| anyhow::anyhow!("No FROST verifying share for peer {peer_id}"))?;

    frost_core::verify_signature_share(
        identifier,
        verifying_share,
        signature_share,
        signing_package,
        pubkey_package.verifying_key(),
    )
    .map_err(|e| anyhow::anyhow!("FROST signature share from peer {peer_id} is invalid: {e}"))
}

fn frost_verifying_key_to_xonly(pubkey_package: &PublicKeyPackage) -> XOnlyPublicKey {
    let bytes = pubkey_package
        .verifying_key()
        .serialize()
        .expect("FROST verifying key serializes to compressed secp256k1 bytes");
    let pk = PublicKey::from_slice(&bytes).expect("FROST verifying key is a valid secp256k1 point");
    pk.x_only_public_key().0
}

#[derive(Debug, Clone)]
struct FrostPolynomial(frost::keys::dkg::round1::Package);

impl Encodable for FrostPolynomial {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostPolynomial {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        frost::keys::dkg::round1::Package::deserialize(&bytes)
            .map(FrostPolynomial)
            .map_err(DecodeError::from_err)
    }
}

#[derive(Debug, Clone)]
struct FrostPolynomialCommitment(frost_secp256k1_tr::keys::dkg::round2::Package);

impl Encodable for FrostPolynomialCommitment {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostPolynomialCommitment {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        frost_secp256k1_tr::keys::dkg::round2::Package::deserialize(&bytes)
            .map(FrostPolynomialCommitment)
            .map_err(DecodeError::from_err)
    }
}

#[derive(Debug, Clone)]
pub struct FrostSigningNonces(pub frost::round1::SigningNonces);

impl Encodable for FrostSigningNonces {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostSigningNonces {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        frost_secp256k1_tr::round1::SigningNonces::deserialize(&bytes)
            .map(FrostSigningNonces)
            .map_err(DecodeError::from_err)
    }
}

/// `Encodable`/`Decodable` wrapper for `SigningPackage`. Cached in the DB at
/// `FrostSigningPackagesKey(txid)` so that any peer (including non-session
/// peers) can verify and aggregate `FrostSignatureShare` consensus items
/// without the package being re-sent over the wire by every signer.
#[derive(Debug, Clone)]
pub struct FrostSigningPackage(pub SigningPackage);

impl Encodable for FrostSigningPackage {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let bytes = self.0.serialize().map_err(std::io::Error::other)?;
        bytes.consensus_encode(writer)
    }
}

impl Decodable for FrostSigningPackage {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(r, modules)?;
        SigningPackage::deserialize(&bytes)
            .map(FrostSigningPackage)
            .map_err(DecodeError::from_err)
    }
}
