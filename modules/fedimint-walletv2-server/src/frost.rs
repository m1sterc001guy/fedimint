use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::sha256;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{BitcoinHash, NumPeers, PeerId};
use frost_core::keys::{SigningShare, VerifyingShare};
use frost_core::{Field, Group, Scalar as FrostScalar, VerifyingKey};
use frost_secp256k1_tr::keys::dkg::{round1 as dkg_round1, round2 as dkg_round2};
use frost_secp256k1_tr::keys::{EvenY, KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::{Identifier, Secp256K1Group, Secp256K1Sha256TR, round1, round2};
use secp256k1::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) type FrostCiphersuite = Secp256K1Sha256TR;

/// Convert a `PeerId` into a FROST `Identifier`.
///
/// FROST identifiers must be non-zero, so we offset by 1.
pub(crate) fn peer_id_to_identifier(peer_id: PeerId) -> anyhow::Result<Identifier> {
    Ok(Identifier::try_from(peer_id.to_usize() as u16 + 1)?)
}

/// The set of guardians we consider the "online" signing set. We always pick
/// the first `threshold` peers by `PeerId`. Later this will be replaced by a
/// ROAST-style dynamic set.
pub(crate) fn frost_signers(num_peers: NumPeers) -> BTreeSet<PeerId> {
    num_peers.peer_ids().take(num_peers.threshold()).collect()
}

/// Extract the FROST aggregate verifying key as an `XOnlyPublicKey` suitable
/// for use as a Taproot internal key.
pub(crate) fn frost_verifying_key_to_xonly(pubkey_package: &PublicKeyPackage) -> XOnlyPublicKey {
    let bytes = pubkey_package
        .verifying_key()
        .serialize()
        .expect("FROST verifying key serializes to compressed secp256k1 bytes");
    let pk = PublicKey::from_slice(&bytes).expect("FROST verifying key is a valid secp256k1 point");
    pk.x_only_public_key().0
}

/// Interpret a `sha256::Hash` as a FROST scalar for use as an additive tweak.
fn tweak_hash_to_scalar(tweak: &sha256::Hash) -> FrostScalar<Secp256K1Sha256TR> {
    use frost_secp256k1_tr::Secp256K1ScalarField;
    <Secp256K1ScalarField as Field>::deserialize(&tweak.to_byte_array())
        .expect("sha256 hash is within the secp256k1 scalar field order")
}

/// Apply an additive scalar tweak to a `KeyPackage`, mirroring the BIP-341
/// `Tweak::tweak` flow used inside `frost-secp256k1-tr` but with a user-
/// supplied scalar rather than the TapTweak hash. Composes with BIP-341
/// tweaking: the returned `KeyPackage` can be fed to `sign_with_tweak`.
///
/// The key package is first normalised to even-Y (matching the descriptor's
/// `tweak_xonly_public_key` math, which lifts the internal key as even-Y
/// before applying the tweak).
pub(crate) fn tweak_key_package_with_utxo_tweak(
    kp: KeyPackage,
    utxo_tweak: &sha256::Hash,
) -> KeyPackage {
    let t = tweak_hash_to_scalar(utxo_tweak);
    let tp = Secp256K1Group::generator() * t;
    let kp = kp.into_even_y(None);
    let verifying_key = VerifyingKey::new(kp.verifying_key().to_element() + tp);
    let signing_share = SigningShare::new(kp.signing_share().to_scalar() + t);
    let verifying_share = VerifyingShare::new(kp.verifying_share().to_element() + tp);
    KeyPackage::new(
        *kp.identifier(),
        signing_share,
        verifying_share,
        verifying_key,
        *kp.min_signers(),
    )
}

/// Public counterpart of [`tweak_key_package_with_utxo_tweak`]. Used by
/// verifiers and during aggregation.
pub(crate) fn tweak_pubkey_package_with_utxo_tweak(
    pkp: PublicKeyPackage,
    utxo_tweak: &sha256::Hash,
) -> PublicKeyPackage {
    let t = tweak_hash_to_scalar(utxo_tweak);
    let tp = Secp256K1Group::generator() * t;
    let pkp = pkp.into_even_y(None);
    let verifying_key = VerifyingKey::new(pkp.verifying_key().to_element() + tp);
    let verifying_shares = pkp
        .verifying_shares()
        .iter()
        .map(|(id, vs)| (*id, VerifyingShare::new(vs.to_element() + tp)))
        .collect();
    PublicKeyPackage::new(verifying_shares, verifying_key)
}

/// Wraps a FROST type that only exposes `serialize()` / `deserialize()`,
/// providing the derive-friendly traits fedimint needs (`Encodable`,
/// `Decodable`, `Serialize`, `Deserialize`, `Eq`, `Hash`).
macro_rules! frost_wrapper {
    ($name:ident, $inner:path, $serialize:expr, $deserialize:expr) => {
        #[derive(Debug, Clone)]
        pub struct $name(pub $inner);

        impl $name {
            fn to_bytes(&self) -> Vec<u8> {
                let serialize_fn: fn(&$inner) -> _ = $serialize;
                serialize_fn(&self.0).expect("FROST type serialization never fails on valid input")
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.to_bytes() == other.to_bytes()
            }
        }

        impl Eq for $name {}

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.to_bytes().hash(state);
            }
        }

        impl Encodable for $name {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<(), std::io::Error> {
                self.to_bytes().consensus_encode(writer)
            }
        }

        impl Decodable for $name {
            fn consensus_decode_partial<D: std::io::Read>(
                d: &mut D,
                modules: &ModuleDecoderRegistry,
            ) -> Result<Self, DecodeError> {
                let bytes = Vec::<u8>::consensus_decode_partial(d, modules)?;
                let deserialize_fn: fn(&[u8]) -> _ = $deserialize;
                deserialize_fn(&bytes)
                    .map(Self)
                    .map_err(DecodeError::from_err)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                self.to_bytes().serialize(s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let bytes = Vec::<u8>::deserialize(d)?;
                let deserialize_fn: fn(&[u8]) -> _ = $deserialize;
                deserialize_fn(&bytes)
                    .map(Self)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

frost_wrapper!(
    FrostPolynomial,
    dkg_round1::Package,
    |p: &dkg_round1::Package| p.serialize(),
    |b: &[u8]| dkg_round1::Package::deserialize(b)
);

frost_wrapper!(
    FrostPolynomialCommitment,
    dkg_round2::Package,
    |p: &dkg_round2::Package| p.serialize(),
    |b: &[u8]| dkg_round2::Package::deserialize(b)
);

frost_wrapper!(
    FrostKeyPackage,
    KeyPackage,
    |p: &KeyPackage| p.serialize(),
    |b: &[u8]| KeyPackage::deserialize(b)
);

frost_wrapper!(
    FrostPubkeyPackage,
    PublicKeyPackage,
    |p: &PublicKeyPackage| p.serialize(),
    |b: &[u8]| PublicKeyPackage::deserialize(b)
);

frost_wrapper!(
    FrostSigningCommitments,
    round1::SigningCommitments,
    |p: &round1::SigningCommitments| p.serialize(),
    |b: &[u8]| round1::SigningCommitments::deserialize(b)
);

// `SignatureShare::serialize` returns `Vec<u8>` directly rather than
// `Result<Vec<u8>, _>`, so it can't be plugged into the shared macro as-is.
// Hand-roll it instead.
#[derive(Debug, Clone)]
pub struct FrostSignatureShare(pub round2::SignatureShare);

impl FrostSignatureShare {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.serialize()
    }
}

impl PartialEq for FrostSignatureShare {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for FrostSignatureShare {}

impl Hash for FrostSignatureShare {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl Encodable for FrostSignatureShare {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for FrostSignatureShare {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(d, modules)?;
        round2::SignatureShare::deserialize(&bytes)
            .map(Self)
            .map_err(DecodeError::from_err)
    }
}

impl Serialize for FrostSignatureShare {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(s)
    }
}

impl<'de> Deserialize<'de> for FrostSignatureShare {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        round2::SignatureShare::deserialize(&bytes)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

// `SigningNonces` has no `Eq`/`Hash` on the upstream type. It's only ever
// stored locally and never broadcast, so we don't need consensus-item traits
// — just encoding for the DB and serde for config (config never carries it,
// but keeping the shape uniform makes the DB wiring simpler).
#[derive(Debug, Clone)]
pub struct FrostSigningNonces(pub round1::SigningNonces);

impl Encodable for FrostSigningNonces {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.0
            .serialize()
            .map_err(std::io::Error::other)?
            .consensus_encode(writer)
    }
}

impl Decodable for FrostSigningNonces {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(d, modules)?;
        round1::SigningNonces::deserialize(&bytes)
            .map(Self)
            .map_err(DecodeError::from_err)
    }
}
