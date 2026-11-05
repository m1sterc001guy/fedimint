//! The statechain's threshold cryptography, built on `schnorr_fun`.
//!
//! # Signing with a required user
//!
//! A coin key is `Y = P_user + P_op`, where the operator key `P_op` is shared
//! among the guardians as a FROST `t`-of-`n` key. Following Spark's modified
//! FROST, a signature needs the user plus any `t` guardians: the guardians'
//! Lagrange-weighted signature shares sum to the operator key's share of the
//! signature and the user adds `r_user + c * sk_user` with weight one.
//!
//! The guardians sign with `schnorr_fun`'s FROST [`PartySignSession`]
//! unmodified, paired with the coin's output key instead of the operator key.
//! The user's nonce is aggregated with the guardians' nonces, so the session's
//! binding coefficient covers it. The user signs through the same session by
//! posing as the signer with the smallest index `j` holding the share
//! `sk_user / λ_j`, which makes its share exactly `r_user + c * sk_user`.
//!
//! Coin outputs are BIP-86 taproot outputs, so the signed key is the tweaked
//! output key `Q = even(Y) + t * G`. Every share is negated as needed for the
//! parities of `Y` and `Q` and the user's share also carries the tweak `t`.
//!
//! # Key generation and rotation
//!
//! A coin's operator key comes from `schnorr_fun`'s `SimplePedPop`
//! ([ChillDKG](https://github.com/BlockstreamResearch/bip-frost-dkg)) run
//! among all guardians. Transfers re-split `Y` between the guardians and the
//! new user by having the old user deal a Shamir sharing of
//! `sk_old_user - sk_new_user` that every guardian adds to its share.
//!
//! Shares travel through consensus, which Fedimint keeps forever, so they are
//! encrypted to per-coin ephemeral guardian keys that the guardians delete
//! after use. Only then does deleting an old operator share make it
//! unrecoverable, which is what protects a coin against its previous owners.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::key::{Parity, TapTweak};
use bitcoin::secp256k1::SECP256K1;
use bitcoin::taproot::TapTweakHash;
use fedimint_core::PeerId;
use fedimint_core::encoding::Encodable;
use rand::{CryptoRng, RngCore};
use schnorr_fun::binonce::{self, NonceKeyPair, SecretNonce};
use schnorr_fun::frost::chilldkg::{Party, ShareReceiver, simplepedpop};
use schnorr_fun::frost::{
    self, Frost, PairedSecretShare, PartySignSession, SecretShare, ShareIndex,
};
use schnorr_fun::fun::hash::{HashAdd, Tag};
use schnorr_fun::fun::marker::{EvenY, NonZero, Public, Secret, Zero};
use schnorr_fun::fun::nonce::NoNonces;
use schnorr_fun::fun::{G, Point, Scalar, g, poly, s};
use schnorr_fun::{Message, Schnorr};
use secp256k1::schnorr::Signature;
use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use sha2::Sha256;

use crate::{
    CoinId, DkgContribution, EncryptedSecret, EncryptedShares, PublicNonce, ScalarBytes, TweakDeal,
};

/// Encryption context of the shares of a coin's operator key generation
pub const DKG_CONTEXT: &str = "fedimint-statechain/dkg";

/// Encryption context of the tweak shares of a key rotation
pub const ROTATION_CONTEXT: &str = "fedimint-statechain/rotation";

/// Encryption context of the intermediate key a sender hands to the receiver
pub const SECRET_CONTEXT: &str = "fedimint-statechain/intermediate-secret";

/// The guardian with peer id `p` holds the share at index `p + 1`.
pub fn share_index(peer: PeerId) -> ShareIndex {
    let index = u32::try_from(peer.to_usize() + 1).expect("Peer ids are small");

    ShareIndex::try_from(index).expect("The index is non-zero")
}

fn frost() -> Frost<Sha256, NoNonces> {
    frost::new_without_nonce_generation::<Sha256>()
}

fn point(pk: &PublicKey) -> Point {
    Point::from(*pk)
}

fn public_key(point: Point) -> PublicKey {
    PublicKey::from(point)
}

impl ScalarBytes {
    pub fn from_scalar<S, Z>(scalar: &Scalar<S, Z>) -> Self {
        Self(scalar.to_bytes())
    }

    pub fn to_scalar(self) -> Option<Scalar<Public, Zero>> {
        Scalar::from_bytes(self.0)
    }
}

impl PublicNonce {
    fn from_binonce(nonce: &binonce::Nonce) -> Self {
        let [hiding, binding] = nonce.0;

        Self {
            hiding: public_key(hiding),
            binding: public_key(binding),
        }
    }

    fn to_binonce(self) -> binonce::Nonce {
        binonce::Nonce([point(&self.hiding), point(&self.binding)])
    }
}

/// A fresh pair of secret FROST nonces, to be used for exactly one signature
/// share.
pub fn generate_nonce(rng: &mut (impl RngCore + CryptoRng)) -> (SecretNonce, PublicNonce) {
    let nonce = NonceKeyPair::random(rng);
    let public = PublicNonce::from_binonce(&nonce.public());

    (nonce.secret, public)
}

/// Context separating the encryption of shares of different coins, epochs
/// and protocols.
pub fn encryption_context(coin: CoinId, epoch: u64, purpose: &str) -> [u8; 32] {
    (purpose, coin, epoch)
        .consensus_hash::<sha256::Hash>()
        .to_byte_array()
}

fn encryption_pad(
    context: &[u8; 32],
    dh: Point,
    key: Point,
    index: ShareIndex,
) -> Scalar<Secret, Zero> {
    Scalar::from_hash(
        Sha256::default()
            .tag(b"fedimint-statechain/share-encryption")
            .add(&context[..])
            .add(dh)
            .add(key)
            .add(index),
    )
    .mark_zero()
}

/// Encrypts one share to each recipient's key: the ElGamal-style
/// multi-recipient encryption of `ChillDKG`'s `EncPedPop`, keyed by `context`.
pub fn encrypt_shares(
    context: &[u8; 32],
    recipients: &BTreeMap<PeerId, PublicKey>,
    shares: &BTreeMap<PeerId, Scalar<Secret, Zero>>,
    rng: &mut (impl RngCore + CryptoRng),
) -> EncryptedShares {
    let nonce_sk = Scalar::random(rng);

    let ciphertexts = recipients
        .iter()
        .map(|(peer, key)| {
            let key = point(key);
            let dh = g!(nonce_sk * key).normalize();
            let pad = encryption_pad(context, dh, key, share_index(*peer));
            let share = shares[peer];

            (*peer, ScalarBytes::from_scalar(&s!(share + pad)))
        })
        .collect();

    EncryptedShares {
        nonce: public_key(g!(nonce_sk * G).normalize()),
        ciphertexts,
    }
}

/// Decrypts the share encrypted to `peer` with its key `sk`.
pub fn decrypt_share(
    context: &[u8; 32],
    encrypted: &EncryptedShares,
    peer: PeerId,
    sk: &SecretKey,
) -> Option<Scalar<Secret, Zero>> {
    let sk = Scalar::<Secret, NonZero>::from(*sk);
    let key = g!(sk * G).normalize();
    let dh = g!(sk * { point(&encrypted.nonce) }).normalize();
    let pad = encryption_pad(context, dh, key, share_index(peer));
    let ciphertext = encrypted.ciphertexts.get(&peer)?.to_scalar()?;

    Some(s!(ciphertext - pad).secret())
}

/// Encrypts a secret key to a single public key.
pub fn encrypt_secret(
    context: &[u8; 32],
    recipient: &PublicKey,
    secret: &SecretKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> EncryptedSecret {
    let recipient_peer = PeerId::from(0);
    let shares = BTreeMap::from([(recipient_peer, Scalar::from(*secret).mark_zero())]);
    let encrypted = encrypt_shares(
        context,
        &BTreeMap::from([(recipient_peer, *recipient)]),
        &shares,
        rng,
    );

    EncryptedSecret {
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertexts[&recipient_peer],
    }
}

/// Decrypts a secret encrypted to `sk`'s public key.
pub fn decrypt_secret(
    context: &[u8; 32],
    encrypted: &EncryptedSecret,
    sk: &SecretKey,
) -> Option<SecretKey> {
    let recipient_peer = PeerId::from(0);
    let shares = EncryptedShares {
        nonce: encrypted.nonce,
        ciphertexts: BTreeMap::from([(recipient_peer, encrypted.ciphertext)]),
    };

    let secret = decrypt_share(context, &shares, recipient_peer, sk)?.non_zero()?;

    Some(SecretKey::from(secret))
}

/// The key a coin's signatures verify under, with the adjustments the signers
/// apply to their shares of the aggregate key.
#[derive(Debug, Clone, Copy)]
pub struct SigningKey {
    /// The BIP-86 tweaked taproot output key `Q`
    output_key: Point<EvenY>,
    /// Whether the shares of the aggregate key must be negated, which is the
    /// case when exactly one of `Y` and `Q` has an odd y-coordinate
    negate_shares: bool,
    /// The taproot tweak, negated if `Q` has an odd y-coordinate. The user's
    /// share carries it.
    tweak: Scalar<Public, Zero>,
}

impl SigningKey {
    pub fn new(aggregate_pk: &PublicKey) -> Self {
        let (internal_key, internal_parity) = aggregate_pk.x_only_public_key();
        let (output_key, output_parity) = internal_key.tap_tweak(SECP256K1, None);

        let mut tweak = Scalar::<Public, Zero>::from_bytes(
            TapTweakHash::from_key_and_tweak(internal_key, None)
                .to_scalar()
                .to_be_bytes(),
        )
        .expect("The taproot tweak is a valid scalar");

        tweak.conditional_negate(output_parity == Parity::Odd);

        Self {
            output_key: Point::<EvenY>::from(output_key.to_x_only_public_key()),
            negate_shares: (internal_parity == Parity::Odd) != (output_parity == Parity::Odd),
            tweak,
        }
    }

    pub fn output_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from(self.output_key)
    }
}

/// One signing session over `message`, as seen by the user and by each
/// participating guardian.
pub struct SignSession {
    key: SigningKey,
    message: [u8; 32],
    guardian_nonces: BTreeMap<PeerId, binonce::Nonce>,
    parties: BTreeSet<ShareIndex>,
    agg_binonce: binonce::Nonce<Zero>,
    session: PartySignSession,
}

impl SignSession {
    /// Starts a session in which the guardians that contributed a nonce and
    /// the user sign `message`.
    pub fn new(
        key: SigningKey,
        message: [u8; 32],
        guardian_nonces: &BTreeMap<PeerId, PublicNonce>,
        user_nonce: PublicNonce,
    ) -> Self {
        let guardian_nonces = guardian_nonces
            .iter()
            .map(|(peer, nonce)| (*peer, nonce.to_binonce()))
            .collect::<BTreeMap<PeerId, binonce::Nonce>>();

        let parties = guardian_nonces
            .keys()
            .map(|peer| share_index(*peer))
            .collect::<BTreeSet<ShareIndex>>();

        let agg_binonce = binonce::Nonce::aggregate(
            guardian_nonces
                .values()
                .copied()
                .chain([user_nonce.to_binonce()]),
        );

        let session = frost().party_sign_session(
            key.output_key,
            parties.clone(),
            agg_binonce,
            Message::raw(&message),
        );

        Self {
            key,
            message,
            guardian_nonces,
            parties,
            agg_binonce,
            session,
        }
    }

    /// A guardian's signature share with its share `share` of the operator
    /// key.
    pub fn guardian_sign(
        &self,
        peer: PeerId,
        share: Scalar<Secret, Zero>,
        nonce: &SecretNonce,
    ) -> ScalarBytes {
        let mut share = share;
        share.conditional_negate(self.key.negate_shares);

        self.sign_as(share_index(peer), share, nonce)
    }

    /// The user's signature share with its half `user_sk` of the coin key.
    pub fn user_sign(&self, user_sk: &SecretKey, nonce: &SecretNonce) -> ScalarBytes {
        let index = *self
            .parties
            .first()
            .expect("A signing session has at least one guardian");

        let lambda = poly::eval_basis_poly_at_0(index, self.parties.iter().copied());

        let mut user_sk = Scalar::<Secret, NonZero>::from(*user_sk).mark_zero();
        user_sk.conditional_negate(self.key.negate_shares);

        let tweak = self.key.tweak;

        // Signing as the party at `index` multiplies the share by `lambda`.
        let share = s!((user_sk + tweak) * { lambda.invert() });

        self.sign_as(index, share, nonce)
    }

    fn sign_as(
        &self,
        index: ShareIndex,
        share: Scalar<Secret, Zero>,
        nonce: &SecretNonce,
    ) -> ScalarBytes {
        let paired =
            PairedSecretShare::new_unchecked(SecretShare { index, share }, self.key.output_key);

        ScalarBytes::from_scalar(&self.session.sign(&paired, nonce))
    }

    /// The FROST binding coefficient of the session, computed exactly as
    /// `schnorr_fun` does internally. The session does not expose it, but
    /// verifying an individual guardian's share requires it.
    fn binding_coefficient(&self) -> Scalar<Public> {
        Scalar::from_hash(
            Sha256::default()
                .tag(b"frost/binding")
                .add(self.key.output_key)
                .add(
                    u32::try_from(self.parties.len())
                        .expect("Small signing set")
                        .to_be_bytes(),
                )
                .add(&self.parties)
                .add(self.agg_binonce)
                .add(Message::raw(&self.message)),
        )
        .public()
    }

    /// Verifies a guardian's signature share against its verification share,
    /// the operator polynomial evaluated at its index.
    pub fn verify_guardian_share(
        &self,
        peer: PeerId,
        operator_poly: &[PublicKey],
        share: ScalarBytes,
    ) -> bool {
        let Some(share) = share.to_scalar() else {
            return false;
        };

        let Some([hiding, binding]) = self.guardian_nonces.get(&peer).map(|nonce| nonce.0) else {
            return false;
        };

        let binding_coeff = self.binding_coefficient();
        let (final_nonce, negate_nonce) = self.agg_binonce.bind(binding_coeff);

        // Guards the replicated binding coefficient against schnorr_fun
        // changing its derivation.
        if final_nonce != self.session.final_nonce() {
            return false;
        }

        let challenge = Schnorr::<Sha256>::verify_only().challenge(
            &final_nonce,
            &self.key.output_key,
            Message::raw(&self.message),
        );

        let index = share_index(peer);
        let lambda = poly::eval_basis_poly_at_0(index, self.parties.iter().copied());

        let operator_poly = operator_poly.iter().map(point).collect::<Vec<Point>>();
        let verification_share = poly::point::eval(&operator_poly, index)
            .normalize()
            .conditional_negate(self.key.negate_shares);

        let nonce = g!(hiding + binding_coeff * binding).conditional_negate(negate_nonce);

        g!(nonce + (challenge * lambda) * verification_share - share * G).is_zero()
    }

    /// Sums the signature shares of the user and all guardians.
    pub fn combine(&self, shares: impl IntoIterator<Item = ScalarBytes>) -> Option<Signature> {
        let mut sum = Scalar::<Public, Zero>::zero();

        for share in shares {
            sum = s!(sum + { share.to_scalar()? }).public();
        }

        let signature = schnorr_fun::Signature {
            R: self.session.final_nonce(),
            s: sum,
        };

        Signature::from_slice(&signature.to_bytes()).ok()
    }
}

/// Verifies a key-path signature of `message` by the coin with the given
/// aggregate key.
pub fn verify_signature(
    aggregate_pk: &PublicKey,
    message: &[u8; 32],
    signature: &Signature,
) -> bool {
    SECP256K1
        .verify_schnorr(
            signature,
            &secp256k1::Message::from_digest(*message),
            &SigningKey::new(aggregate_pk).output_key(),
        )
        .is_ok()
}

fn dkg_schnorr() -> Schnorr<
    Sha256,
    schnorr_fun::nonce::Synthetic<Sha256, schnorr_fun::nonce::GlobalRng<rand::rngs::ThreadRng>>,
> {
    schnorr_fun::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>()
}

fn receiver_index(peer: PeerId) -> u32 {
    u32::try_from(peer.to_usize()).expect("Peer ids are small")
}

/// Generates guardian `me`'s contribution to a coin's operator key, a degree
/// `threshold - 1` `SimplePedPop` polynomial whose shares are encrypted to
/// every guardian's ephemeral key.
pub fn dkg_contribution(
    me: PeerId,
    threshold: usize,
    ephemeral_keys: &BTreeMap<PeerId, PublicKey>,
    context: &[u8; 32],
    rng: &mut (impl RngCore + CryptoRng),
) -> DkgContribution {
    let n_receivers = u32::try_from(ephemeral_keys.len()).expect("Small federation");
    let threshold = u32::try_from(threshold).expect("Small federation");

    let (_, input, shares) = simplepedpop::Contributor::<ShareReceiver>::gen_keygen_input(
        &dkg_schnorr(),
        threshold,
        0,
        n_receivers,
        receiver_index(me),
        rng,
    )
    .expect("The threshold and our index are within range");

    let shares = ephemeral_keys
        .keys()
        .copied()
        .zip(shares)
        .collect::<BTreeMap<PeerId, Scalar<Secret, Zero>>>();

    DkgContribution {
        commitments: input.com.into_iter().map(public_key).collect(),
        proof_of_possession: Signature::from_slice(&input.pop.to_bytes())
            .expect("A schnorr_fun signature is a valid BIP-340 signature"),
        shares: encrypt_shares(context, ephemeral_keys, &shares, rng),
    }
}

/// Checks the public parts of a guardian's DKG contribution: one share per
/// guardian, a polynomial of the right degree and, via `schnorr_fun`'s
/// `SimplePedPop` coordinator, the proof of possession.
pub fn verify_dkg_contribution(
    from: PeerId,
    peers: &BTreeSet<PeerId>,
    threshold: usize,
    contribution: &DkgContribution,
) -> bool {
    if !contribution.shares.ciphertexts.keys().eq(peers.iter()) {
        return false;
    }

    let Ok(threshold) = u32::try_from(threshold) else {
        return false;
    };

    let Some(pop) = schnorr_fun::Signature::from_bytes(*contribution.proof_of_possession.as_ref())
    else {
        return false;
    };

    let input = simplepedpop::KeygenInput {
        com: contribution.commitments.iter().map(point).collect(),
        pop,
    };

    let n_receivers = u32::try_from(peers.len()).expect("Small federation");

    simplepedpop::Coordinator::new(threshold, 0, n_receivers)
        .add_input(
            &Schnorr::<Sha256>::verify_only(),
            Party::Receiver(receiver_index(from)),
            input,
        )
        .is_ok()
}

/// Adds two point polynomials coefficient by coefficient.
pub fn add_polys(a: &[PublicKey], b: &[PublicKey]) -> Option<Vec<PublicKey>> {
    if a.len() != b.len() {
        return None;
    }

    a.iter().zip(b).map(|(a, b)| a.combine(b).ok()).collect()
}

/// The operator polynomial: the sum of every contribution's polynomial.
pub fn dkg_operator_poly(
    contributions: &BTreeMap<PeerId, DkgContribution>,
) -> Option<Vec<PublicKey>> {
    let mut polys = contributions.values().map(|c| c.commitments.clone());

    let first = polys.next()?;

    polys.try_fold(first, |acc, poly| add_polys(&acc, &poly))
}

/// Checks a secret share against the Feldman commitments of the polynomial
/// it is supposed to lie on.
pub fn verify_share(poly: &[PublicKey], peer: PeerId, share: &Scalar<Secret, Zero>) -> bool {
    let poly = poly.iter().map(point).collect::<Vec<Point>>();

    g!(share * G) == poly::point::eval(&poly, share_index(peer))
}

/// Decrypts and sums `me`'s shares of all DKG contributions and checks the
/// result against the operator polynomial.
pub fn recover_dkg_share(
    me: PeerId,
    ephemeral_sk: &SecretKey,
    contributions: &BTreeMap<PeerId, DkgContribution>,
    operator_poly: &[PublicKey],
    context: &[u8; 32],
) -> Option<Scalar<Secret, Zero>> {
    let mut share = Scalar::<Secret, Zero>::zero();

    for contribution in contributions.values() {
        let contribution_share = decrypt_share(context, &contribution.shares, me, ephemeral_sk)?;
        share = s!(share + contribution_share);
    }

    verify_share(operator_poly, me, &share).then_some(share)
}

/// Deals a Shamir sharing of `tweak` with a polynomial of degree
/// `threshold - 1` to the guardians holding the given ephemeral keys.
pub fn deal_tweak(
    tweak: &Scalar<Secret, NonZero>,
    threshold: usize,
    recipients: &BTreeMap<PeerId, PublicKey>,
    context: &[u8; 32],
    rng: &mut (impl RngCore + CryptoRng),
) -> TweakDeal {
    let mut secret_poly = poly::scalar::generate(threshold, rng);
    secret_poly[0] = *tweak;

    let shares = recipients
        .keys()
        .map(|peer| (*peer, poly::scalar::eval(&secret_poly, share_index(*peer))))
        .collect::<BTreeMap<PeerId, Scalar<Secret, Zero>>>();

    TweakDeal {
        commitments: poly::scalar::to_point_poly(&secret_poly)
            .into_iter()
            .map(public_key)
            .collect(),
        shares: encrypt_shares(context, recipients, &shares, rng),
    }
}

/// The tweak that hands the user half of a coin key from `old_sk` to the key
/// with secret `new_sk`, or `None` if the keys are equal.
pub fn rotation_tweak(old_sk: &SecretKey, new_sk: &SecretKey) -> Option<Scalar<Secret, NonZero>> {
    let old = Scalar::<Secret, NonZero>::from(*old_sk);
    let new = Scalar::<Secret, NonZero>::from(*new_sk);

    s!(old - new).non_zero()
}

/// Checks that a tweak deal moves the operator key by exactly
/// `old_user_pk - new_user_pk`, keeping the aggregate key unchanged, and that
/// its polynomial has the threshold's degree.
pub fn verify_rotation_commitment(
    deal: &TweakDeal,
    threshold: usize,
    old_user_pk: &PublicKey,
    new_user_pk: &PublicKey,
) -> bool {
    deal.commitments.len() == threshold
        && old_user_pk
            .combine(&new_user_pk.negate(SECP256K1))
            .is_ok_and(|expected| deal.commitments[0] == expected)
}

/// Decrypts `me`'s share of a tweak and checks it against the deal's
/// commitments.
pub fn recover_tweak_share(
    me: PeerId,
    ephemeral_sk: &SecretKey,
    deal: &TweakDeal,
    context: &[u8; 32],
) -> Option<Scalar<Secret, Zero>> {
    let share = decrypt_share(context, &deal.shares, me, ephemeral_sk)?;

    verify_share(&deal.commitments, me, &share).then_some(share)
}

/// Converts a stored operator key share.
pub fn share_from_bytes(bytes: &ScalarBytes) -> Option<Scalar<Secret, Zero>> {
    bytes.to_scalar().map(Scalar::secret)
}

/// Adds a tweak share to an operator key share.
pub fn add_shares(a: &Scalar<Secret, Zero>, b: &Scalar<Secret, Zero>) -> Scalar<Secret, Zero> {
    s!(a + b)
}

#[cfg(test)]
mod tests;
