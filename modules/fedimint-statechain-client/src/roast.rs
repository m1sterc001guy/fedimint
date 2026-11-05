//! The coordinator side of ROAST (Ruffing, Ronge, Jin, Schneider-Bensch and
//! Schröder, "ROAST: Robust Asynchronous Schnorr Threshold Signatures", CCS
//! 2022), which makes FROST signing finish despite guardians that stall or
//! send invalid shares.
//!
//! The client is the coordinator and the user is a signer in every session.
//! Guardians with a fresh nonce wait in a ready set; whenever a threshold of
//! them is ready a new session starts with them. A guardian returns to the
//! ready set with a fresh nonce only after handing in a valid share, so it is
//! in at most one open session at a time, and a guardian that stalls holds up
//! only the session it sits in. With at most `n - t` faulty guardians a
//! session of honest guardians therefore always forms, after at most
//! `n - t + 1` sessions, without relying on timeouts. A guardian that sends an
//! invalid share, which the share verification identifies, or that fails a
//! request is never asked again.
//!
//! This type only tracks state; the client module drives it with concurrent
//! requests.

use std::collections::{BTreeMap, BTreeSet};

use fedimint_core::PeerId;
use fedimint_statechain_common::crypto::{
    SecretNonce, SignSession, SigningKey, generate_nonce, verify_signature,
};
use fedimint_statechain_common::{PublicNonce, ScalarBytes};
use rand::{CryptoRng, RngCore};
use secp256k1::schnorr::Signature;
use secp256k1::{PublicKey, SecretKey};

/// A request for a guardian's signature share in a session.
#[derive(Debug, Clone)]
pub struct ShareRequest {
    pub session: usize,
    pub peer: PeerId,
    /// The guardian's own nonce, which the share consumes
    pub nonce_id: [u8; 32],
    pub guardian_nonces: BTreeMap<PeerId, PublicNonce>,
    pub user_nonce: PublicNonce,
}

#[derive(Debug)]
pub enum ShareOutcome {
    /// The share is valid; ask the guardian for a fresh nonce.
    Valid,
    /// The session collected every share and produced this signature.
    Complete(Signature),
    /// The share is invalid; the guardian is excluded.
    Invalid,
}

struct ReadyNonce {
    nonce_id: [u8; 32],
    nonce: PublicNonce,
}

struct Session {
    frost: SignSession,
    guardian_nonces: BTreeMap<PeerId, PublicNonce>,
    user_nonce: SecretNonce,
    shares: BTreeMap<PeerId, ScalarBytes>,
}

pub struct Roast {
    aggregate_pk: PublicKey,
    key: SigningKey,
    message: [u8; 32],
    operator_poly: Vec<PublicKey>,
    threshold: usize,
    user_sk: SecretKey,
    ready: BTreeMap<PeerId, ReadyNonce>,
    excluded: BTreeSet<PeerId>,
    sessions: Vec<Session>,
}

impl Roast {
    pub fn new(
        aggregate_pk: PublicKey,
        message: [u8; 32],
        operator_poly: Vec<PublicKey>,
        threshold: usize,
        user_sk: SecretKey,
    ) -> Self {
        Self {
            aggregate_pk,
            key: SigningKey::new(&aggregate_pk),
            message,
            operator_poly,
            threshold,
            user_sk,
            ready: BTreeMap::new(),
            excluded: BTreeSet::new(),
            sessions: Vec::new(),
        }
    }

    /// The guardians that failed a request or sent an invalid share
    pub fn excluded(&self) -> &BTreeSet<PeerId> {
        &self.excluded
    }

    pub fn sessions_started(&self) -> usize {
        self.sessions.len()
    }

    /// Records a guardian's fresh nonce and starts a session if a threshold of
    /// guardians is now ready, returning the share requests to send.
    pub fn nonce_received(
        &mut self,
        peer: PeerId,
        nonce_id: [u8; 32],
        nonce: PublicNonce,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Vec<ShareRequest> {
        if self.excluded.contains(&peer) {
            return Vec::new();
        }

        self.ready.insert(peer, ReadyNonce { nonce_id, nonce });

        let mut requests = Vec::new();

        while self.ready.len() >= self.threshold {
            let members = self
                .ready
                .keys()
                .take(self.threshold)
                .copied()
                .collect::<Vec<PeerId>>();

            let ready = members
                .iter()
                .map(|peer| (*peer, self.ready.remove(peer).expect("The peer is ready")))
                .collect::<BTreeMap<PeerId, ReadyNonce>>();

            let guardian_nonces = ready
                .iter()
                .map(|(peer, ready)| (*peer, ready.nonce))
                .collect::<BTreeMap<PeerId, PublicNonce>>();

            let (user_nonce, user_public_nonce) = generate_nonce(rng);

            let session = self.sessions.len();

            requests.extend(ready.iter().map(|(peer, ready)| ShareRequest {
                session,
                peer: *peer,
                nonce_id: ready.nonce_id,
                guardian_nonces: guardian_nonces.clone(),
                user_nonce: user_public_nonce,
            }));

            self.sessions.push(Session {
                frost: SignSession::new(
                    self.key,
                    self.message,
                    &guardian_nonces,
                    user_public_nonce,
                ),
                guardian_nonces,
                user_nonce,
                shares: BTreeMap::new(),
            });
        }

        requests
    }

    /// A guardian failed a request; it is not asked again.
    pub fn exclude(&mut self, peer: PeerId) {
        self.excluded.insert(peer);
        self.ready.remove(&peer);
    }

    /// Records a guardian's signature share for a session.
    ///
    /// # Errors
    ///
    /// Fails if the session's verified shares do not combine to a valid
    /// signature, which means our own share is wrong.
    pub fn share_received(
        &mut self,
        session: usize,
        peer: PeerId,
        share: ScalarBytes,
    ) -> anyhow::Result<ShareOutcome> {
        let state = self
            .sessions
            .get_mut(session)
            .expect("Share requests only name sessions we started");

        if !state.guardian_nonces.contains_key(&peer)
            || !state
                .frost
                .verify_guardian_share(peer, &self.operator_poly, share)
        {
            self.exclude(peer);

            return Ok(ShareOutcome::Invalid);
        }

        state.shares.insert(peer, share);

        if state.shares.len() < self.threshold {
            return Ok(ShareOutcome::Valid);
        }

        let user_share = state.frost.user_sign(&self.user_sk, &state.user_nonce);

        let signature = state
            .frost
            .combine(state.shares.values().copied().chain([user_share]))
            .filter(|signature| verify_signature(&self.aggregate_pk, &self.message, signature))
            .ok_or_else(|| anyhow::anyhow!("Our signature share is invalid"))?;

        Ok(ShareOutcome::Complete(signature))
    }
}

#[cfg(test)]
mod tests;
