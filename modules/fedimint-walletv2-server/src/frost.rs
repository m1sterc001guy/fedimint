use bitcoin::XOnlyPublicKey;
use fedimint_core::PeerId;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::keys::PublicKeyPackage;
use frost_secp256k1_tr::keys::dkg::{round1, round2};
use secp256k1::PublicKey;

/// Convert a `PeerId` into a FROST `Identifier`.
///
/// FROST identifiers must be non-zero, so we offset by 1.
pub(crate) fn peer_id_to_identifier(peer_id: PeerId) -> anyhow::Result<Identifier> {
    Ok(Identifier::try_from(peer_id.to_usize() as u16 + 1)?)
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

#[derive(Debug, Clone)]
pub(crate) struct FrostPolynomial(pub round1::Package);

impl Encodable for FrostPolynomial {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.0
            .serialize()
            .map_err(std::io::Error::other)?
            .consensus_encode(writer)
    }
}

impl Decodable for FrostPolynomial {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(d, modules)?;
        round1::Package::deserialize(&bytes)
            .map(Self)
            .map_err(DecodeError::from_err)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FrostPolynomialCommitment(pub round2::Package);

impl Encodable for FrostPolynomialCommitment {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.0
            .serialize()
            .map_err(std::io::Error::other)?
            .consensus_encode(writer)
    }
}

impl Decodable for FrostPolynomialCommitment {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode_partial(d, modules)?;
        round2::Package::deserialize(&bytes)
            .map(Self)
            .map_err(DecodeError::from_err)
    }
}
