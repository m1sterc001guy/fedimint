use crate::config::MintConfig;
use crate::db::{
    MintAuditItemKey, MintAuditItemKeyPrefix, NonceKey, OutputOutcomeKey,
    ProposedPartialSignatureKey, ProposedPartialSignaturesKeyPrefix, ReceivedPartialSignatureKey,
    ReceivedPartialSignatureKeyOutputPrefix, ReceivedPartialSignaturesKeyPrefix,
};
use async_trait::async_trait;
use fedimint_api::db::{Database, DatabaseTransaction};
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::audit::Audit;
use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::ApiEndpoint;
use fedimint_api::tiered::InvalidAmountTierError;
use fedimint_api::{
    Amount, FederationModule, InputMeta, OutPoint, PeerId, Tiered, TieredMulti, TieredMultiZip,
};
use itertools::Itertools;
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

use std::hash::Hash;
use std::iter::FromIterator;
use std::ops::Sub;
use tbs::{
    combine_valid_shares, sign_blinded_msg, verify_blind_share, Aggregatable, AggregatePublicKey,
    PublicKeyShare, SecretKeyShare,
};
use thiserror::Error;
use tracing::{debug, error, warn};

pub mod config;

mod db;
/// Data structures taking into account different amount tiers

/// Federated mint member mint
pub struct Mint {
    cfg: MintConfig,
    sec_key: Tiered<SecretKeyShare>,
    pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    pub_key: HashMap<Amount, AggregatePublicKey>,
    db: Database,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct PartiallySignedRequest {
    pub out_point: OutPoint,
    pub partial_signature: PartialSigResponse,
}

/// Request to blind sign a certain amount of coins
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SignRequest(pub TieredMulti<tbs::BlindedMessage>);

// FIXME: optimize out blinded msg by making the mint remember it
/// Blind signature share for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PartialSigResponse(pub TieredMulti<(tbs::BlindedMessage, tbs::BlindedSignatureShare)>);

/// Blind signature for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SigResponse(pub TieredMulti<tbs::BlindedSignature>);

/// An verifiable one time use IOU from the mint.
///
/// Digital version of a "note of deposit" in a free-banking era.
///
/// Consist of a user-generated nonce and a threshold signature over it generated by the
/// federated mint (while in a [`BlindNonce`] form).
///
/// As things are right now the denomination of each note is deteremined by the federation
/// keys that signed over it, and needs to be tracked outside of this type.
///
/// In this form it can only be validated, not spent since for that the corresponding secret
/// spend key is required.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Note(pub Nonce, pub tbs::Signature);

/// Unique ID of a mint note.
///
/// User-generated, random or otherwise unpredictably generated (deterministically derivated).
///
/// Internally a MuSig pub key so that transactions can be signed when being spent.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Nonce(pub secp256k1_zkp::XOnlyPublicKey);

/// [`Nonce`] but blinded by the user key
///
/// Blinding prevents the Mint from being able to link the transaction spending [`Note`]s
/// as an `Input`s of `Transaction` with new [`Note`]s being created in its `Output`s.
///
/// By signing it, the mint commits to the underlying (unblinded) [`Nonce`] as valid
/// (until eventually spent).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct BlindNonce(pub tbs::BlindedMessage);

#[derive(Debug)]
pub struct VerificationCache {
    valid_coins: HashMap<Note, Amount>,
}

#[async_trait(?Send)]
impl FederationModule for Mint {
    type Error = MintError;
    type TxInput = TieredMulti<Note>;
    type TxOutput = TieredMulti<BlindNonce>;
    type TxOutputOutcome = Option<SigResponse>; // TODO: make newtype
    type ConsensusItem = PartiallySignedRequest;
    type VerificationCache = VerificationCache;

    async fn await_consensus_proposal<'a>(&'a self, rng: impl RngCore + CryptoRng + 'a) {
        if self.consensus_proposal(rng).await.is_empty() {
            std::future::pending().await
        }
    }

    async fn consensus_proposal<'a>(
        &'a self,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem> {
        self.db
            .find_by_prefix(&ProposedPartialSignaturesKeyPrefix)
            .map(|res| {
                let (key, partial_signature) = res.expect("DB error");
                PartiallySignedRequest {
                    out_point: key.request_id,
                    partial_signature,
                }
            })
            .collect()
    }

    async fn begin_consensus_epoch<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        for (peer, partial_sig) in consensus_items {
            self.process_partial_signature(
                dbtx,
                peer,
                partial_sig.out_point,
                partial_sig.partial_signature,
            )
        }
    }

    fn build_verification_cache<'a>(
        &'a self,
        inputs: impl Iterator<Item = &'a Self::TxInput> + Send,
    ) -> Self::VerificationCache {
        // We build a lookup table for checking the validity of all coins for certain amounts. This
        // calculation can happen massively in parallel since verification is a pure function and
        // thus has no side effects.
        let valid_coins = inputs
            .flat_map(|inputs| inputs.iter_items())
            .par_bridge()
            .filter_map(|(amount, coin)| {
                let amount_key = self.pub_key.get(&amount)?;
                if coin.verify(*amount_key) {
                    Some((coin.clone(), amount))
                } else {
                    None
                }
            })
            .collect();

        VerificationCache { valid_coins }
    }

    fn validate_input<'a>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        cache: &Self::VerificationCache,
        input: &'a Self::TxInput,
    ) -> Result<InputMeta<'a>, Self::Error> {
        input.iter_items().try_for_each(|(amount, coin)| {
            let coin_valid = cache
                .valid_coins
                .get(coin) // We validated the coin
                .map(|coint_amount| *coint_amount == amount) // It has the right amount tier
                .unwrap_or(false); // If we didn't validate the coin return false

            if !coin_valid {
                return Err(MintError::InvalidSignature);
            }

            if self
                .db
                .get_value(&NonceKey(coin.0.clone()))
                .expect("DB error")
                .is_some()
            {
                return Err(MintError::SpentCoin);
            }

            Ok(())
        })?;

        Ok(InputMeta {
            amount: input.total_amount(),
            puk_keys: Box::new(input.iter_items().map(|(_, coin)| *coin.spend_key())),
        })
    }

    fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b Self::TxInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta<'b>, Self::Error> {
        let meta = self.validate_input(interconnect, cache, input)?;

        input.iter_items().for_each(|(amount, coin)| {
            let key = NonceKey(coin.0.clone());
            dbtx.insert_new_entry(&key.clone(), &()).expect("DB Error");
            dbtx.insert_new_entry(&MintAuditItemKey::Redemption(key), &amount)
                .expect("DB Error");
        });

        Ok(meta)
    }

    fn validate_output(&self, output: &Self::TxOutput) -> Result<Amount, Self::Error> {
        if let Some(amount) = output.iter_items().find_map(|(amount, _)| {
            if self.pub_key.get(&amount).is_none() {
                Some(amount)
            } else {
                None
            }
        }) {
            Err(MintError::InvalidAmountTier(amount))
        } else {
            Ok(output.total_amount())
        }
    }

    fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a Self::TxOutput,
        out_point: OutPoint,
    ) -> Result<Amount, Self::Error> {
        // TODO: move actual signing to worker thread
        // TODO: get rid of clone
        let partial_sig = self.blind_sign(output.clone())?;

        dbtx.insert_new_entry(
            &ProposedPartialSignatureKey {
                request_id: out_point,
            },
            &partial_sig,
        )
        .expect("DB Error");
        dbtx.insert_new_entry(
            &MintAuditItemKey::Issuance(out_point),
            &output.total_amount(),
        )
        .expect("DB Error");
        Ok(output.total_amount())
    }

    async fn end_consensus_epoch<'a>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut DatabaseTransaction<'a>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<PeerId> {
        // Finalize partial signatures for which we now have enough shares
        let req_psigs = self
            .db
            .find_by_prefix(&ReceivedPartialSignaturesKeyPrefix)
            .map(|entry_res| {
                let (key, partial_sig) = entry_res.expect("DB error");
                (key.request_id, (key.peer_id, partial_sig))
            })
            .into_group_map();

        // TODO: use own par iter impl that allows efficient use of accumulators or just decouple it entirely (doesn't need consensus)
        let par_batches = req_psigs
            .into_par_iter()
            .map(|(issuance_id, shares)| {
                let mut dbtx = self.db.begin_transaction();
                let mut drop_peers = Vec::<PeerId>::new();
                let proposal_key = ProposedPartialSignatureKey {
                    request_id: issuance_id,
                };
                let our_contribution = self.db.get_value(&proposal_key).expect("DB error");
                let (bsig, errors) = self.combine(our_contribution, shares.clone());

                // FIXME: validate shares before writing to DB to make combine infallible
                errors.0.iter().for_each(|(peer, error)| {
                    error!("Dropping {:?} for {:?}", peer, error);
                    drop_peers.push(*peer);
                });

                match bsig {
                    Ok(blind_signature) => {
                        debug!(
                            %issuance_id,
                            "Successfully combined signature shares",
                        );

                        shares.into_iter().for_each(|(peer, _)| {
                            dbtx.remove_entry(&ReceivedPartialSignatureKey {
                                request_id: issuance_id,
                                peer_id: peer,
                            })
                            .expect("DB Error");
                        });
                        dbtx.remove_entry(&proposal_key).expect("DB Error");

                        dbtx.insert_entry(&OutputOutcomeKey(issuance_id), &blind_signature)
                            .expect("DB Error");
                    }
                    Err(CombineError::TooFewShares(got, _)) => {
                        for peer in consensus_peers.sub(&HashSet::from_iter(got)) {
                            error!("Dropping {:?} for not contributing shares", peer);
                            drop_peers.push(peer);
                        }
                    }
                    Err(error) => {
                        warn!(%error, "Could not combine shares");
                    }
                }
                dbtx.commit_tx().expect("DB Error");
                drop_peers
            })
            .collect::<Vec<_>>();

        let dropped_peers = par_batches
            .iter()
            .flat_map(|peers| peers)
            .copied()
            .collect();

        let mut redemptions = Amount::from_sat(0);
        let mut issuances = Amount::from_sat(0);
        self.db
            .find_by_prefix(&MintAuditItemKeyPrefix)
            .for_each(|res| {
                let (key, amount) = res.expect("DB error");
                match key {
                    MintAuditItemKey::Issuance(_) => issuances += amount,
                    MintAuditItemKey::IssuanceTotal => issuances += amount,
                    MintAuditItemKey::Redemption(_) => redemptions += amount,
                    MintAuditItemKey::RedemptionTotal => redemptions += amount,
                }
                dbtx.remove_entry(&key).expect("DB Error");
            });
        dbtx.insert_entry(&MintAuditItemKey::IssuanceTotal, &issuances)
            .expect("DB Error");
        dbtx.insert_entry(&MintAuditItemKey::RedemptionTotal, &redemptions)
            .expect("DB Error");

        dropped_peers
    }

    fn output_status(&self, out_point: OutPoint) -> Option<Self::TxOutputOutcome> {
        let we_proposed = self
            .db
            .get_value(&ProposedPartialSignatureKey {
                request_id: out_point,
            })
            .expect("DB error")
            .is_some();
        let was_consensus_outcome = self
            .db
            .find_by_prefix(&ReceivedPartialSignatureKeyOutputPrefix {
                request_id: out_point,
            })
            .any(|res| res.is_ok());

        let final_sig = self
            .db
            .get_value(&OutputOutcomeKey(out_point))
            .expect("DB error");

        if final_sig.is_some() {
            Some(final_sig)
        } else if we_proposed || was_consensus_outcome {
            Some(None)
        } else {
            None
        }
    }

    fn audit(&self, audit: &mut Audit) {
        audit.add_items(&self.db, &MintAuditItemKeyPrefix, |k, v| match k {
            MintAuditItemKey::Issuance(_) => -(v.milli_sat as i64),
            MintAuditItemKey::IssuanceTotal => -(v.milli_sat as i64),
            MintAuditItemKey::Redemption(_) => v.milli_sat as i64,
            MintAuditItemKey::RedemptionTotal => v.milli_sat as i64,
        });
    }

    fn api_base_name(&self) -> &'static str {
        "mint"
    }

    fn api_endpoints(&self) -> &'static [ApiEndpoint<Self>] {
        &[]
    }
}

impl Mint {
    /// Constructs a new mint
    ///
    /// # Panics
    /// * If there are no amount tiers
    /// * If the amount tiers for secret and public keys are inconsistent
    /// * If the pub key belonging to the secret key share is not in the pub key list.
    pub fn new(cfg: MintConfig, db: Database) -> Mint {
        assert!(cfg.tbs_sks.tiers().count() > 0);

        // The amount tiers are implicitly provided by the key sets, make sure they are internally
        // consistent.
        assert!(cfg
            .peer_tbs_pks
            .values()
            .all(|pk| pk.structural_eq(&cfg.tbs_sks)));

        let ref_pub_key = cfg.tbs_sks.to_public();

        // Find our key index and make sure we know the private key for all our public key shares
        let our_id = cfg // FIXME: make sure we use id instead of idx everywhere
            .peer_tbs_pks
            .iter()
            .find_map(|(&id, pk)| if pk == &ref_pub_key { Some(id) } else { None })
            .expect("Own key not found among pub keys.");

        assert_eq!(
            cfg.peer_tbs_pks[&our_id],
            cfg.tbs_sks
                .iter()
                .map(|(amount, sk)| (amount, sk.to_pub_key_share()))
                .collect()
        );

        let aggregate_pub_keys = TieredMultiZip::new(
            cfg.peer_tbs_pks
                .iter()
                .map(|(_, keys)| keys.iter())
                .collect(),
        )
        .map(|(amt, keys)| {
            // TODO: avoid this through better aggregation API allowing references or
            let keys = keys.into_iter().copied().collect::<Vec<_>>();
            (amt, keys.aggregate(cfg.threshold))
        })
        .collect();

        Mint {
            cfg: cfg.clone(),
            sec_key: cfg.tbs_sks,
            pub_key_shares: cfg.peer_tbs_pks,
            pub_key: aggregate_pub_keys,
            db,
        }
    }

    pub fn pub_key(&self) -> HashMap<Amount, AggregatePublicKey> {
        self.pub_key.clone()
    }

    fn blind_sign(&self, output: TieredMulti<BlindNonce>) -> Result<PartialSigResponse, MintError> {
        Ok(PartialSigResponse(output.map(
            |amt, msg| -> Result<_, InvalidAmountTierError> {
                let sec_key = self.sec_key.tier(&amt)?;
                let blind_signature = sign_blinded_msg(msg.0, *sec_key);
                Ok((msg.0, blind_signature))
            },
        )?))
    }

    fn combine(
        &self,
        our_contribution: Option<PartialSigResponse>,
        partial_sigs: Vec<(PeerId, PartialSigResponse)>,
    ) -> (Result<SigResponse, CombineError>, MintShareErrors) {
        // Terminate early if there are not enough shares
        if partial_sigs.len() < self.cfg.threshold {
            return (
                Err(CombineError::TooFewShares(
                    partial_sigs.iter().map(|(peer, _)| peer).cloned().collect(),
                    self.cfg.threshold,
                )),
                MintShareErrors(vec![]),
            );
        }

        // FIXME: decide on right boundary place for this invariant
        // Filter out duplicate contributions, they make share combinations fail
        let peer_contrib_counts = partial_sigs
            .iter()
            .map(|(idx, _)| *idx)
            .collect::<counter::Counter<_>>();
        if let Some((peer, count)) = peer_contrib_counts.into_iter().find(|(_, cnt)| *cnt > 1) {
            return (
                Err(CombineError::MultiplePeerContributions(peer, count)),
                MintShareErrors(vec![]),
            );
        }

        // Determine the reference response to check against
        let our_contribution = match our_contribution {
            Some(psig) => psig,
            None => {
                return (
                    Err(CombineError::NoOwnContribution),
                    MintShareErrors(vec![]),
                )
            }
        };

        let reference_msgs = our_contribution
            .0
            .iter_items()
            .map(|(_amt, (msg, _sig))| msg);

        let mut peer_errors = vec![];

        let partial_sigs = partial_sigs
            .iter()
            .filter(|(peer, sigs)| {
                if !sigs.0.structural_eq(&our_contribution.0) {
                    warn!(
                        %peer,
                        "Peer proposed a sig share of wrong structure (different than ours)",
                    );
                    peer_errors.push((*peer, PeerErrorType::DifferentStructureSigShare));
                    false
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();
        debug!(
            "After length filtering {} sig shares are left.",
            partial_sigs.len()
        );

        let bsigs = TieredMultiZip::new(
            partial_sigs
                .iter()
                .map(|(_peer, sig_share)| sig_share.0.iter_items())
                .collect(),
        )
        .zip(reference_msgs)
        .map(|((amt, sig_shares), ref_msg)| {
            let peer_ids = partial_sigs.iter().map(|(peer, _)| *peer);

            // Filter out invalid peer contributions
            let valid_sigs = sig_shares
                .into_iter()
                .zip(peer_ids)
                .filter_map(|((msg, sig), peer)| {
                    let amount_key = match self.pub_key_shares[&peer].tier(&amt) {
                        Ok(key) => key,
                        Err(_) => {
                            peer_errors.push((peer, PeerErrorType::InvalidAmountTier));
                            return None;
                        }
                    };

                    if msg != ref_msg {
                        peer_errors.push((peer, PeerErrorType::DifferentNonce));
                        None
                    } else if !verify_blind_share(*msg, *sig, *amount_key) {
                        peer_errors.push((peer, PeerErrorType::InvalidSignature));
                        None
                    } else {
                        Some((peer, *sig))
                    }
                })
                .collect::<Vec<_>>();

            // Check that there are still sufficient
            if valid_sigs.len() < self.cfg.threshold {
                return Err(CombineError::TooFewValidShares(
                    valid_sigs.len(),
                    partial_sigs.len(),
                    self.cfg.threshold,
                ));
            }

            let sig = combine_valid_shares(
                valid_sigs
                    .into_iter()
                    .map(|(peer, share)| (peer.to_usize(), share)),
                self.cfg.threshold,
            );

            Ok((amt, sig))
        })
        .collect::<Result<TieredMulti<_>, CombineError>>();

        let bsigs = match bsigs {
            Ok(bs) => bs,
            Err(e) => return (Err(e), MintShareErrors(peer_errors)),
        };

        (Ok(SigResponse(bsigs)), MintShareErrors(peer_errors))
    }

    fn process_partial_signature<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        peer: PeerId,
        output_id: OutPoint,
        partial_sig: PartialSigResponse,
    ) {
        if self
            .db
            .get_value(&OutputOutcomeKey(output_id))
            .expect("DB error")
            .is_some()
        {
            debug!(
                issuance = %output_id,
                "Received sig share for finalized issuance, ignoring",
            );
            return;
        }

        debug!(
            %peer,
            issuance = %output_id,
            "Received sig share"
        );
        dbtx.insert_new_entry(
            &ReceivedPartialSignatureKey {
                request_id: output_id,
                peer_id: peer,
            },
            &partial_sig,
        )
        .expect("DB Error");
    }
}

impl Note {
    /// Verify the coin's validity under a mit key `pk`
    pub fn verify(&self, pk: tbs::AggregatePublicKey) -> bool {
        tbs::verify(self.0.to_message(), self.1, pk)
    }

    /// Access the nonce as the public key to the spend key
    pub fn spend_key(&self) -> &secp256k1_zkp::XOnlyPublicKey {
        &self.0 .0
    }
}

impl Nonce {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bincode::serialize_into(&mut bytes, &self.0).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        // FIXME: handle errors or the client can be crashed
        bincode::deserialize(bytes).unwrap()
    }

    pub fn to_message(&self) -> tbs::Message {
        tbs::Message::from_bytes(&self.0.serialize()[..])
    }
}

impl From<SignRequest> for TieredMulti<BlindNonce> {
    fn from(sig_req: SignRequest) -> Self {
        sig_req
            .0
            .into_iter()
            .map(|(amt, token)| (amt, crate::BlindNonce(token)))
            .collect()
    }
}

/// Represents an array of mint indexes that delivered faulty shares
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MintShareErrors(pub Vec<(PeerId, PeerErrorType)>);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum PeerErrorType {
    InvalidSignature,
    DifferentStructureSigShare,
    DifferentNonce,
    InvalidAmountTier,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum CombineError {
    #[error("Too few shares to begin the combination: got {0:?} need {1}")]
    TooFewShares(Vec<PeerId>, usize),
    #[error(
        "Too few valid shares, only {0} of {1} (required minimum {2}) provided shares were valid"
    )]
    TooFewValidShares(usize, usize, usize),
    #[error("We could not find our own contribution in the provided shares, so we have no validation reference")]
    NoOwnContribution,
    #[error("Peer {0} contributed {1} shares, 1 expected")]
    MultiplePeerContributions(PeerId, usize),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum MintError {
    #[error("One of the supplied coins had an invalid mint signature")]
    InvalidCoin,
    #[error("Insufficient coin value: reissuing {0} but only got {1} in coins")]
    TooFewCoins(Amount, Amount),
    #[error("One of the supplied coins was already spent previously")]
    SpentCoin,
    #[error("One of the coins had an invalid amount not issued by the mint: {0:?}")]
    InvalidAmountTier(Amount),
    #[error("One of the coins had an invalid signature")]
    InvalidSignature,
}

impl From<InvalidAmountTierError> for MintError {
    fn from(e: InvalidAmountTierError) -> Self {
        MintError::InvalidAmountTier(e.0)
    }
}

#[cfg(test)]
mod test {
    use crate::config::{FeeConsensus, MintClientConfig};
    use crate::{BlindNonce, CombineError, Mint, MintConfig, PeerErrorType};
    use fedimint_api::config::GenerateConfig;
    use fedimint_api::db::mem_impl::MemDatabase;
    use fedimint_api::{Amount, PeerId, TieredMulti};
    use rand::rngs::OsRng;
    use tbs::{blind_message, unblind_signature, verify, AggregatePublicKey, Message};

    const THRESHOLD: usize = 1;
    const MINTS: usize = 5;

    fn build_configs() -> (Vec<MintConfig>, MintClientConfig) {
        let peers = (0..MINTS as u16).map(PeerId::from).collect::<Vec<_>>();
        let (mint_cfg, client_cfg) =
            MintConfig::trusted_dealer_gen(&peers, &[Amount::from_sat(1)], OsRng::new().unwrap());

        (mint_cfg.into_iter().map(|(_, c)| c).collect(), client_cfg)
    }

    fn build_mints() -> (AggregatePublicKey, Vec<Mint>) {
        let (mint_cfg, client_cfg) = build_configs();
        let mints = mint_cfg
            .into_iter()
            .map(|config| Mint::new(config, MemDatabase::new().into()))
            .collect::<Vec<_>>();

        let agg_pk = *client_cfg.tbs_pks.get(Amount::from_sat(1)).unwrap();

        (agg_pk, mints)
    }

    #[test_log::test]
    fn test_issuance() {
        let (pk, mut mints) = build_mints();

        let nonce = Message::from_bytes(&b"test coin"[..]);
        let (bkey, bmsg) = blind_message(nonce);
        let blind_tokens = TieredMulti::new(
            vec![(
                Amount::from_sat(1),
                vec![BlindNonce(bmsg), BlindNonce(bmsg)],
            )]
            .into_iter()
            .collect(),
        );

        let psigs = mints
            .iter()
            .enumerate()
            .map(move |(id, m)| {
                (
                    PeerId::from(id as u16),
                    m.blind_sign(blind_tokens.clone()).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let our_sig = psigs[0].1.clone();
        let mint = &mut mints[0];

        // Test happy path
        let (bsig_res, errors) = mint.combine(Some(our_sig.clone()), psigs.clone());
        assert!(errors.0.is_empty());

        let bsig = bsig_res.unwrap();
        assert_eq!(bsig.0.total_amount(), Amount::from_sat(2));

        bsig.0.iter_items().for_each(|(_, bs)| {
            let sig = unblind_signature(bkey, *bs);
            assert!(verify(nonce, sig, pk));
        });

        // Test threshold sig shares
        let (bsig_res, errors) =
            mint.combine(Some(our_sig.clone()), psigs[..(MINTS - THRESHOLD)].to_vec());
        assert!(bsig_res.is_ok());
        assert!(errors.0.is_empty());

        bsig_res.unwrap().0.iter_items().for_each(|(_, bs)| {
            let sig = unblind_signature(bkey, *bs);
            assert!(verify(nonce, sig, pk));
        });

        // Test too few sig shares
        let few_sigs = psigs[..(MINTS - THRESHOLD - 1)].to_vec();
        let (bsig_res, errors) = mint.combine(Some(our_sig.clone()), few_sigs.clone());
        assert_eq!(
            bsig_res,
            Err(CombineError::TooFewShares(
                few_sigs.iter().map(|(peer, _)| peer).cloned().collect(),
                MINTS - THRESHOLD
            ))
        );
        assert!(errors.0.is_empty());

        // Test no own share
        let (bsig_res, errors) = mint.combine(None, psigs[1..].to_vec());
        assert_eq!(bsig_res, Err(CombineError::NoOwnContribution));
        assert!(errors.0.is_empty());

        // Test multiple peer contributions
        let (bsig_res, errors) = mint.combine(
            Some(our_sig.clone()),
            psigs
                .iter()
                .cloned()
                .chain(std::iter::once(psigs[0].clone()))
                .collect(),
        );
        assert_eq!(
            bsig_res,
            Err(CombineError::MultiplePeerContributions(PeerId::from(0), 2))
        );
        assert!(errors.0.is_empty());

        // Test wrong length response
        let (bsig_res, errors) = mint.combine(
            Some(our_sig.clone()),
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psigs)| {
                    if peer == PeerId::from(1) {
                        psigs.0.get_mut(Amount::from_sat(1)).unwrap().pop();
                    }
                    (peer, psigs)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(1), PeerErrorType::DifferentStructureSigShare)));

        let (bsig_res, errors) = mint.combine(
            Some(our_sig.clone()),
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == PeerId::from(2) {
                        psig.0.get_mut(Amount::from_sat(1)).unwrap()[0].1 =
                            psigs[0].1 .0.get(Amount::from_sat(1)).unwrap()[0].1;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(2), PeerErrorType::InvalidSignature)));

        let (_bk, bmsg) = blind_message(Message::from_bytes(b"test"));
        let (bsig_res, errors) = mint.combine(
            Some(our_sig),
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == PeerId::from(3) {
                        psig.0.get_mut(Amount::from_sat(1)).unwrap()[0].0 = bmsg;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(3), PeerErrorType::DifferentNonce)));
    }

    #[test_log::test]
    #[should_panic(expected = "Own key not found among pub keys.")]
    fn test_new_panic_without_own_pub_key() {
        let (mint_server_cfg1, _) = build_configs();
        let (mint_server_cfg2, _) = build_configs();

        Mint::new(
            MintConfig {
                threshold: THRESHOLD,
                tbs_sks: mint_server_cfg1[0].tbs_sks.clone(),
                peer_tbs_pks: mint_server_cfg2[0].peer_tbs_pks.clone(),
                fee_consensus: FeeConsensus::default(),
            },
            MemDatabase::new().into(),
        );
    }
}
