//! FROST signing protocol wiring for walletv2.
//!
//! Handles the per-peer pool of preprocessed commitments (round 1 of FROST)
//! and the per-tx signature-share round (round 2). The pool-and-allocate
//! design removes round 1 from the per-tx critical path — signers top up
//! the pool in the background, and the first thing we broadcast when a new
//! unsigned tx hits consensus is already the round-2 share.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, ensure};
use bitcoin::hashes::sha256;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{ScriptBuf, TxOut, Txid, XOnlyPublicKey};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{BitcoinHash, NumPeers, NumPeersExt, PeerId};
use fedimint_walletv2_common::config::WalletDescriptor;
use fedimint_walletv2_common::{WalletConsensusItem, descriptor_tr};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::{Identifier, SigningPackage, round1, round2};
use futures::StreamExt;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, schnorr};

use crate::db::{
    FrostAllocationKey, FrostAllocationPrefix, FrostCommitmentPoolKey,
    FrostCommitmentPoolPeerPrefix, FrostNoncePoolKey, FrostPoolCursorKey, FrostPoolSizeKey,
    FrostSharesKey, FrostSharesTxidPrefix, UnconfirmedTxKey, UnsignedTxKey, UnsignedTxPrefix,
};
use crate::frost::{
    FrostSignatureShare, FrostSigningCommitments, FrostSigningNonces, frost_signers,
    peer_id_to_identifier, tweak_key_package_with_utxo_tweak, tweak_pubkey_package_with_utxo_tweak,
};
use crate::{FederationTx, Wallet};

/// Target size of the local commitment pool: the number of unused
/// nonce/commitment pairs we want to keep ready at any time. Round-2 signing
/// of a tx with `k` inputs consumes `k` entries from every signing peer's
/// pool, so this value bounds how many tx inputs we can sign before the pool
/// needs to be replenished.
pub(crate) const FROST_POOL_TARGET: u64 = 256;

/// How many entries we top up at a time. Chosen to amortise preprocessing
/// cost and batch-broadcast size.
pub(crate) const FROST_POOL_BATCH: u64 = 64;

fn modules() -> ModuleDecoderRegistry {
    ModuleDecoderRegistry::default()
}

/// Decode our locally-stored FROST `KeyPackage`, if any.
fn decode_key_package(cfg: &crate::WalletConfig) -> Option<KeyPackage> {
    cfg.private.frost_key_package.as_deref().map(|bytes| {
        KeyPackage::deserialize(bytes).expect("stored FROST KeyPackage is always valid")
    })
}

/// Decode the federation's FROST `PublicKeyPackage`, if any.
fn decode_pubkey_package(cfg: &crate::WalletConfig) -> Option<PublicKeyPackage> {
    cfg.consensus.frost_pubkey_package.as_deref().map(|bytes| {
        PublicKeyPackage::deserialize(bytes).expect("stored FROST PublicKeyPackage is always valid")
    })
}

/// Return the FROST internal key if this federation uses the FROST
/// descriptor.
fn frost_internal_key(cfg: &crate::WalletConfig) -> Option<XOnlyPublicKey> {
    match cfg.consensus.descriptor {
        WalletDescriptor::Frost(ik) => Some(ik),
        _ => None,
    }
}

fn num_peers(cfg: &crate::WalletConfig) -> NumPeers {
    NumPeers::from(cfg.consensus.bitcoin_pks.len())
}

/// Derive the TapTree merkle root for a given per-UTXO tweak.
fn merkle_root_for_utxo(
    bitcoin_pks: &BTreeMap<PeerId, PublicKey>,
    utxo_tweak: &sha256::Hash,
    internal_key: XOnlyPublicKey,
) -> Vec<u8> {
    let tr = descriptor_tr(bitcoin_pks, utxo_tweak, internal_key);
    tr.spend_info()
        .merkle_root()
        .expect("Taproot descriptor always commits to a script tree")
        .to_byte_array()
        .to_vec()
}

/// Compute prevout scriptPubKeys for sighash computation. The keypath output
/// key for a given UTXO is the BIP-341 taptweak of the per-UTXO-tweaked
/// internal key against the merkle root for that UTXO.
fn prevouts_for_tx(
    bitcoin_pks: &BTreeMap<PeerId, PublicKey>,
    tx: &FederationTx,
    internal_key: XOnlyPublicKey,
) -> Vec<TxOut> {
    tx.spent_tx_outs
        .iter()
        .map(|utxo| TxOut {
            value: utxo.value,
            script_pubkey: descriptor_tr(bitcoin_pks, &utxo.tweak, internal_key).script_pubkey(),
        })
        .collect()
}

/// Build the per-input keypath sighashes (one message per input).
fn build_keypath_sighashes(tx: &FederationTx, prevouts: &[TxOut]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut cache = SighashCache::new(tx.tx.clone());
    tx.spent_tx_outs
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let sighash = cache.taproot_key_spend_signature_hash(
                index,
                &Prevouts::All(prevouts),
                bitcoin::TapSighashType::Default,
            )?;
            Ok(sighash.to_byte_array().to_vec())
        })
        .collect()
}

/// Assemble a `SigningPackage` for a single input by collecting each signing
/// peer's commitment at the allocated sequence number.
fn build_signing_package(
    message: &[u8],
    signing_peers: &[PeerId],
    commitments_by_peer: &BTreeMap<PeerId, FrostSigningCommitments>,
) -> anyhow::Result<SigningPackage> {
    let commitments: BTreeMap<Identifier, round1::SigningCommitments> = signing_peers
        .iter()
        .map(|peer| {
            let id = peer_id_to_identifier(*peer)?;
            let commitments = commitments_by_peer
                .get(peer)
                .ok_or_else(|| anyhow!("Missing FROST commitments for signing peer {peer}"))?
                .0;
            Ok::<_, anyhow::Error>((id, commitments))
        })
        .collect::<Result<_, _>>()?;
    Ok(SigningPackage::new(commitments, message))
}

/// Produce a round-2 signature share for a single input, applying the
/// per-UTXO additive tweak (Option A) before the crate-managed BIP-341
/// tweak.
fn sign_input(
    signing_package: &SigningPackage,
    nonces: &FrostSigningNonces,
    key_package: &KeyPackage,
    utxo_tweak: &sha256::Hash,
    merkle_root: &[u8],
) -> anyhow::Result<FrostSignatureShare> {
    let tweaked = tweak_key_package_with_utxo_tweak(key_package.clone(), utxo_tweak);
    let share = round2::sign_with_tweak(signing_package, &nonces.0, &tweaked, Some(merkle_root))?;
    Ok(FrostSignatureShare(share))
}

/// Aggregate per-peer signature shares for a single input into a final
/// Schnorr signature valid against the BIP-341 output key.
fn aggregate_input(
    signing_package: &SigningPackage,
    shares: &BTreeMap<PeerId, FrostSignatureShare>,
    pubkey_package: &PublicKeyPackage,
    utxo_tweak: &sha256::Hash,
    merkle_root: &[u8],
) -> anyhow::Result<schnorr::Signature> {
    let tweaked = tweak_pubkey_package_with_utxo_tweak(pubkey_package.clone(), utxo_tweak);
    let shares_by_id: BTreeMap<Identifier, round2::SignatureShare> = shares
        .iter()
        .map(|(peer, share)| Ok::<_, anyhow::Error>((peer_id_to_identifier(*peer)?, share.0)))
        .collect::<Result<_, _>>()?;
    let signature = frost_secp256k1_tr::aggregate_with_tweak(
        signing_package,
        &shares_by_id,
        &tweaked,
        Some(merkle_root),
    )?;
    let bytes = signature.serialize()?;
    Ok(schnorr::Signature::from_slice(&bytes)?)
}

impl Wallet {
    // ---------- Pool management ----------

    /// Produce round-1 preprocessed commitments to replenish our pool if it
    /// has fallen below the target. Nonces are persisted locally in the
    /// same dbtx that emits the consensus item, guaranteeing we never
    /// broadcast a commitment whose nonce we've already lost.
    pub(crate) async fn maybe_refill_frost_pool<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
    ) -> Option<WalletConsensusItem> {
        if frost_internal_key(&self.cfg).is_none() {
            return None;
        }
        if !frost_signers(num_peers(&self.cfg)).contains(&self.our_peer_id) {
            return None;
        }
        let key_package = decode_key_package(&self.cfg)?;

        let size = dbtx
            .get_value(&FrostPoolSizeKey(self.our_peer_id))
            .await
            .unwrap_or(0);
        let cursor = dbtx
            .get_value(&FrostPoolCursorKey(self.our_peer_id))
            .await
            .unwrap_or(0);
        let available = size.saturating_sub(cursor);
        if available >= FROST_POOL_TARGET {
            return None;
        }
        let to_generate = (FROST_POOL_TARGET - available).min(FROST_POOL_BATCH);

        let mut commitments_bytes = Vec::with_capacity(to_generate as usize);
        for i in 0..to_generate {
            let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut OsRng);
            dbtx.insert_new_entry(&FrostNoncePoolKey(size + i), &FrostSigningNonces(nonces))
                .await;
            let wrapper = FrostSigningCommitments(commitments);
            commitments_bytes.push(
                wrapper
                    .0
                    .serialize()
                    .expect("SigningCommitments always serializes"),
            );
        }

        // We advance our own pool-size entry immediately (via consensus
        // processing of our own batch), but we also need the nonces stored
        // now. The size bump happens when the consensus item is processed
        // (`process_frost_commitment_batch` will run for every peer).

        Some(WalletConsensusItem::FrostCommitmentBatch(commitments_bytes))
    }

    // ---------- Allocation ----------

    /// Attempt to allocate sequence numbers from every signing peer's pool
    /// to cover this transaction's inputs. Writes `FrostAllocationKey` and
    /// advances every signing peer's cursor on success.
    pub(crate) async fn try_allocate_frost<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        txid: Txid,
        num_inputs: u64,
    ) -> anyhow::Result<bool> {
        if frost_internal_key(&self.cfg).is_none() {
            return Ok(false);
        }
        if dbtx.get_value(&FrostAllocationKey(txid)).await.is_some() {
            return Ok(true);
        }
        let signers: Vec<PeerId> = frost_signers(num_peers(&self.cfg)).into_iter().collect();

        // Snapshot cursors for every signer and verify each has enough pool.
        let mut new_cursors: BTreeMap<PeerId, u64> = BTreeMap::new();
        for peer in &signers {
            let size = dbtx.get_value(&FrostPoolSizeKey(*peer)).await.unwrap_or(0);
            let cursor = dbtx
                .get_value(&FrostPoolCursorKey(*peer))
                .await
                .unwrap_or(0);
            if size < cursor + num_inputs {
                return Ok(false);
            }
            new_cursors.insert(*peer, cursor + num_inputs);
        }

        // Seq range is the same for every signer: [cursor..cursor+num_inputs).
        // We record it keyed off any one peer's old cursor — they all
        // advance in lockstep.
        let first_signer = signers.first().expect("at least one signing peer");
        let base = new_cursors[first_signer] - num_inputs;
        let seqs: Vec<u64> = (base..base + num_inputs).collect();

        for (peer, new_cursor) in new_cursors {
            dbtx.insert_entry(&FrostPoolCursorKey(peer), &new_cursor)
                .await;
        }
        dbtx.insert_new_entry(&FrostAllocationKey(txid), &seqs)
            .await;
        Ok(true)
    }

    /// Walk all unsigned transactions that don't yet have an allocation and
    /// try to allocate each. Called after a `FrostCommitmentBatch` lands,
    /// since new commitments may unblock waiting txs.
    async fn retry_pending_allocations<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
    ) -> anyhow::Result<()> {
        let pending: Vec<(Txid, u64)> = dbtx
            .find_by_prefix(&UnsignedTxPrefix)
            .await
            .map(|(key, tx)| (key.0, tx.tx.input.len() as u64))
            .collect()
            .await;
        for (txid, num_inputs) in pending {
            self.try_allocate_frost(dbtx, txid, num_inputs).await?;
        }
        Ok(())
    }

    // ---------- Round-2 emission ----------

    /// Produce `FrostSignatureShares` consensus items for every allocated
    /// transaction we haven't yet signed. Called from `consensus_proposal`.
    pub(crate) async fn propose_frost_signatures<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<WalletConsensusItem> {
        let Some(internal_key) = frost_internal_key(&self.cfg) else {
            return Vec::new();
        };
        let signers = frost_signers(num_peers(&self.cfg));
        if !signers.contains(&self.our_peer_id) {
            return Vec::new();
        }
        let Some(key_package) = decode_key_package(&self.cfg) else {
            return Vec::new();
        };

        let unsigned: Vec<(Txid, FederationTx)> = dbtx
            .find_by_prefix(&UnsignedTxPrefix)
            .await
            .map(|(k, v)| (k.0, v))
            .collect()
            .await;

        let signers_vec: Vec<PeerId> = signers.iter().copied().collect();
        let mut out = Vec::new();
        for (txid, tx) in unsigned {
            let Some(seqs) = dbtx.get_value(&FrostAllocationKey(txid)).await else {
                continue;
            };
            if dbtx
                .get_value(&FrostSharesKey(txid, self.our_peer_id))
                .await
                .is_some()
            {
                continue;
            }

            let prevouts = prevouts_for_tx(&self.cfg.consensus.bitcoin_pks, &tx, internal_key);
            let Ok(sighashes) = build_keypath_sighashes(&tx, &prevouts) else {
                continue;
            };

            let mut per_input_shares: Vec<Vec<u8>> = Vec::with_capacity(seqs.len());
            let mut failed = false;
            for (i, (seq, message)) in seqs.iter().zip(sighashes.iter()).enumerate() {
                // Gather every signing peer's commitment at this sequence number.
                let mut commitments_by_peer: BTreeMap<PeerId, FrostSigningCommitments> =
                    BTreeMap::new();
                for peer in &signers_vec {
                    let Some(c) = dbtx.get_value(&FrostCommitmentPoolKey(*peer, *seq)).await else {
                        failed = true;
                        break;
                    };
                    commitments_by_peer.insert(*peer, c);
                }
                if failed {
                    break;
                }

                let Some(nonces) = dbtx.get_value(&FrostNoncePoolKey(*seq)).await else {
                    failed = true;
                    break;
                };

                let signing_package =
                    match build_signing_package(message, &signers_vec, &commitments_by_peer) {
                        Ok(p) => p,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    };

                let utxo_tweak = &tx.spent_tx_outs[i].tweak;
                let merkle_root =
                    merkle_root_for_utxo(&self.cfg.consensus.bitcoin_pks, utxo_tweak, internal_key);
                let share = match sign_input(
                    &signing_package,
                    &nonces,
                    &key_package,
                    utxo_tweak,
                    &merkle_root,
                ) {
                    Ok(s) => s,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                };
                per_input_shares.push(share.0.serialize());
            }
            if !failed {
                out.push(WalletConsensusItem::FrostSignatureShares(
                    txid,
                    per_input_shares,
                ));
            }
        }
        out
    }

    // ---------- Consensus item handlers ----------

    pub(crate) async fn process_frost_commitment_batch<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        batch: Vec<Vec<u8>>,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        ensure!(
            frost_internal_key(&self.cfg).is_some(),
            "Received FROST commitments on a non-FROST federation"
        );
        ensure!(
            frost_signers(num_peers(&self.cfg)).contains(&peer),
            "Received FROST commitments from peer {peer} outside the signing set"
        );
        ensure!(!batch.is_empty(), "FROST commitment batch is empty");

        let start_seq = dbtx.get_value(&FrostPoolSizeKey(peer)).await.unwrap_or(0);
        for (i, bytes) in batch.iter().enumerate() {
            let commitments = FrostSigningCommitments::consensus_decode_whole(bytes, &modules())
                .map_err(|e| anyhow!("Malformed FROST commitment: {e}"))?;
            dbtx.insert_new_entry(
                &FrostCommitmentPoolKey(peer, start_seq + i as u64),
                &commitments,
            )
            .await;
        }
        dbtx.insert_entry(&FrostPoolSizeKey(peer), &(start_seq + batch.len() as u64))
            .await;

        self.retry_pending_allocations(dbtx).await?;
        Ok(())
    }

    pub(crate) async fn process_frost_signature_shares<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        txid: Txid,
        shares: Vec<Vec<u8>>,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let Some(internal_key) = frost_internal_key(&self.cfg) else {
            bail!("Received FROST signature shares on a non-FROST federation");
        };
        let signers = frost_signers(num_peers(&self.cfg));
        ensure!(
            signers.contains(&peer),
            "FROST signature share from peer {peer} outside the signing set"
        );

        let allocation = dbtx
            .get_value(&FrostAllocationKey(txid))
            .await
            .ok_or_else(|| anyhow!("No FROST allocation for txid {txid}"))?;
        ensure!(
            shares.len() == allocation.len(),
            "FROST signature share count mismatch for {txid}"
        );

        let decoded: Vec<FrostSignatureShare> = shares
            .into_iter()
            .map(|b| {
                FrostSignatureShare::consensus_decode_whole(&b, &modules())
                    .map_err(|e| anyhow!("Malformed FROST signature share: {e}"))
            })
            .collect::<Result<_, _>>()?;

        if dbtx
            .insert_entry(&FrostSharesKey(txid, peer), &decoded)
            .await
            .is_some()
        {
            bail!("Duplicate FROST signature shares from peer {peer}");
        }

        // Check if we have a threshold of shares now; if so, aggregate and
        // finalize.
        let shares_by_peer: BTreeMap<PeerId, Vec<FrostSignatureShare>> = dbtx
            .find_by_prefix(&FrostSharesTxidPrefix(txid))
            .await
            .map(|(k, v)| (k.1, v))
            .collect()
            .await;
        if shares_by_peer.len() < num_peers(&self.cfg).threshold() {
            return Ok(());
        }

        self.finalize_frost_tx(dbtx, txid, allocation, shares_by_peer, internal_key)
            .await
    }

    /// Aggregate shares across inputs, attach the schnorr signatures to the
    /// transaction, and move it to `UnconfirmedTxKey`.
    async fn finalize_frost_tx<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        txid: Txid,
        allocation: Vec<u64>,
        shares_by_peer: BTreeMap<PeerId, Vec<FrostSignatureShare>>,
        internal_key: XOnlyPublicKey,
    ) -> anyhow::Result<()> {
        let pubkey_package = decode_pubkey_package(&self.cfg)
            .ok_or_else(|| anyhow!("FROST pubkey package missing from config"))?;
        let mut unsigned = dbtx
            .get_value(&UnsignedTxKey(txid))
            .await
            .ok_or_else(|| anyhow!("UnsignedTx {txid} not found during FROST finalize"))?;

        let signers: Vec<PeerId> = frost_signers(num_peers(&self.cfg)).into_iter().collect();
        // Only the first `threshold` signers' shares participate in aggregation.
        let aggregating_peers: Vec<PeerId> = signers
            .iter()
            .filter(|p| shares_by_peer.contains_key(p))
            .take(num_peers(&self.cfg).threshold())
            .copied()
            .collect();
        ensure!(
            aggregating_peers.len() == num_peers(&self.cfg).threshold(),
            "Not enough signing peers in FROST share pool"
        );

        let prevouts = prevouts_for_tx(&self.cfg.consensus.bitcoin_pks, &unsigned, internal_key);
        let sighashes = build_keypath_sighashes(&unsigned, &prevouts)?;

        let mut final_sigs: Vec<schnorr::Signature> = Vec::with_capacity(allocation.len());
        for (i, (seq, message)) in allocation.iter().zip(sighashes.iter()).enumerate() {
            let mut commitments_by_peer: BTreeMap<PeerId, FrostSigningCommitments> =
                BTreeMap::new();
            for peer in &aggregating_peers {
                let c = dbtx
                    .get_value(&FrostCommitmentPoolKey(*peer, *seq))
                    .await
                    .ok_or_else(|| {
                        anyhow!("Missing FROST commitment for peer {peer} at seq {seq}")
                    })?;
                commitments_by_peer.insert(*peer, c);
            }
            let signing_package =
                build_signing_package(message, &aggregating_peers, &commitments_by_peer)?;
            let mut shares_this_input: BTreeMap<PeerId, FrostSignatureShare> = BTreeMap::new();
            for peer in &aggregating_peers {
                let peer_shares = shares_by_peer
                    .get(peer)
                    .ok_or_else(|| anyhow!("Missing FROST shares for peer {peer}"))?;
                shares_this_input.insert(*peer, peer_shares[i].clone());
            }
            let utxo_tweak = &unsigned.spent_tx_outs[i].tweak;
            let merkle_root =
                merkle_root_for_utxo(&self.cfg.consensus.bitcoin_pks, utxo_tweak, internal_key);
            let sig = aggregate_input(
                &signing_package,
                &shares_this_input,
                &pubkey_package,
                utxo_tweak,
                &merkle_root,
            )?;
            final_sigs.push(sig);
        }

        // Attach keypath witnesses.
        for (input, sig) in unsigned.tx.input.iter_mut().zip(final_sigs.iter()) {
            let sig_bytes = bitcoin::taproot::Signature {
                signature: *sig,
                sighash_type: bitcoin::TapSighashType::Default,
            };
            input.witness = bitcoin::Witness::p2tr_key_spend(&sig_bytes);
        }

        // Move to unconfirmed + broadcast.
        dbtx.remove_entry(&UnsignedTxKey(txid)).await;
        dbtx.insert_new_entry(&UnconfirmedTxKey(txid), &unsigned)
            .await;

        // Clean up per-tx FROST state.
        dbtx.remove_entry(&FrostAllocationKey(txid)).await;
        dbtx.remove_by_prefix(&FrostSharesTxidPrefix(txid)).await;
        for seq in allocation {
            // Our own nonces only (other peers' commitments are pool-scoped).
            dbtx.remove_entry(&FrostNoncePoolKey(seq)).await;
        }

        if let Err(err) = self.btc_rpc.submit_transaction(unsigned.tx).await {
            tracing::debug!(%err, "Error broadcasting FROST-signed tx");
        }
        Ok(())
    }
}

// Silence unused warnings for helpers that may be exported later.
#[allow(dead_code)]
fn _reserved(_: ScriptBuf, _: FrostCommitmentPoolPeerPrefix, _: FrostAllocationPrefix) {}
