pub mod frost;

use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin::hashes::sha256;
use fedimint_core::{BitcoinHash, NumPeersExt, PeerId};
use miniscript::descriptor::{TapTree, Tr};
use miniscript::{Miniscript, Tap, Terminal, Threshold};
use secp256k1::{PublicKey, Scalar, XOnlyPublicKey};

/// Provably unspendable x-only public key (BIP-341 NUMS point from the
/// BIP-341 spec). Used as the internal key in our Taproot descriptor so
/// that key-path spending is impossible — only the script path may be
/// used.
pub fn nums_point() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&[
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ])
    .expect("Valid x-only public key")
}

pub fn tweak_xonly_public_key(pk: &XOnlyPublicKey, tweak: &sha256::Hash) -> XOnlyPublicKey {
    let full_pk = PublicKey::from_x_only_public_key(*pk, secp256k1::Parity::Even);
    let tweaked = full_pk
        .add_exp_tweak(
            secp256k1::SECP256K1,
            &Scalar::from_be_bytes(tweak.to_byte_array()).expect("Hash is within field order"),
        )
        .expect("Failed to tweak bitcoin public key");
    tweaked.x_only_public_key().0
}

/// Build the federation's Taproot multi-`a` descriptor for the given tweak.
///
/// The internal key is a provably unspendable BIP-341 NUMS point so the
/// only way to spend is via the script path. The script path commits to a
/// `multi_a` of the guardians' tweaked x-only keys.
pub fn descriptor_tr(
    pks: &BTreeMap<PeerId, PublicKey>,
    tweak: &sha256::Hash,
    internal_key: XOnlyPublicKey,
) -> Tr<XOnlyPublicKey> {
    let threshold = pks.to_num_peers().threshold();
    let mut tweaked: Vec<XOnlyPublicKey> = pks
        .values()
        .map(|pk| tweak_xonly_public_key(&pk.x_only_public_key().0, tweak))
        .collect();
    tweaked.sort();

    let thresh = Threshold::new(threshold, tweaked).expect("Failed to create multi_a threshold");
    let ms = Miniscript::<XOnlyPublicKey, Tap>::from_ast(Terminal::MultiA(thresh))
        .expect("Failed to create multi_a miniscript");
    let tree = TapTree::Leaf(Arc::new(ms));

    let internal_tweaked = tweak_xonly_public_key(&internal_key, tweak);

    Tr::new(internal_tweaked, Some(tree)).expect("Failed to construct Tr descriptor")
}
