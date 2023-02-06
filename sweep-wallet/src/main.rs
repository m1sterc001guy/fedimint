use std::str::FromStr;

use bdk::{
    blockchain::ElectrumBlockchain, database::MemoryDatabase, electrum_client::Client,
    wallet::AddressIndex, KeychainKind, SyncOptions, Wallet,
};
use bitcoin::secp256k1::{self, All, Scalar, Secp256k1};

fn main() -> Result<(), bdk::Error> {
    let client = Client::new("ssl://electrum.blockstream.info:60002")?;
    let blockchain = ElectrumBlockchain::from(client);

    let secp: Secp256k1<All> = secp256k1::Secp256k1::new();
    let pubkey_1: secp256k1::PublicKey = secp256k1::PublicKey::from_str(
        "02c27de9d1af517034f0951f16b696cc31ebcd00c578d5f834515496aa13a61131",
    )?;
    println!("PubKey 1 Before Tweak: {:?}", pubkey_1);
    let tweak_1: [u8; 32] = [
        22, 196, 230, 184, 57, 18, 237, 232, 20, 165, 163, 194, 201, 244, 72, 113, 239, 7, 34, 202,
        2, 222, 211, 140, 92, 103, 152, 241, 47, 201, 132, 222,
    ];
    let new_pubkey_1 = pubkey_1
        .add_exp_tweak(&secp, &Scalar::from_be_bytes(tweak_1).expect("cant fail"))
        .expect("tweak is always 32 bytes");
    println!("PubKey 1 After Tweak: {:?}", new_pubkey_1);

    let pubkey_2: secp256k1::PublicKey = secp256k1::PublicKey::from_str(
        "025e9297680120269a61b5da57b35efd72932a7baa0829c93840b68af9760df56f",
    )?;
    println!("PubKey 2 Before Tweak: {:?}", pubkey_2);
    let new_pubkey_2 = pubkey_2
        .add_exp_tweak(&secp, &Scalar::from_be_bytes(tweak_1).expect("cant fail"))
        .expect("tweak is always 32 bytes");
    println!("PubKey 2 After Tweak: {:?}", new_pubkey_2);

    let old_keys = vec![pubkey_1, pubkey_2];
    let keys = vec![new_pubkey_1, new_pubkey_2];

    /*
    let desc = Descriptor::new_wsh_sortedmulti(2, keys)?;

    let wallet = Wallet::new(
        "wsh(sortedmulti(2,02c27de9d1af517034f0951f16b696cc31ebcd00c578d5f834515496aa13a61131,025e9297680120269a61b5da57b35efd72932a7baa0829c93840b68af9760df56f))#g2ckcu0j",
        None,
        bitcoin::Network::Bitcoin,
        MemoryDatabase::default(),
    )?;

    let desc_2 = wallet.public_descriptor(KeychainKind::External)?.unwrap();

    wallet.sync(&blockchain, SyncOptions::default())?;

    println!("Descriptor balance: {} SAT", wallet.get_balance()?);
    println!("Address at index 0: {}", wallet.get_address(AddressIndex::Peek(0))?);
    */

    let desc = miniscript::Descriptor::<bitcoin::PublicKey>::from_str("wsh(sortedmulti(2,02c27de9d1af517034f0951f16b696cc31ebcd00c578d5f834515496aa13a61131,025e9297680120269a61b5da57b35efd72932a7baa0829c93840b68af9760df56f))#g2ckcu0j").unwrap();
    println!("Descriptor: {:?}", desc);
    println!(
        "Address: {}",
        desc.address(bitcoin::Network::Bitcoin).unwrap()
    );

    let desc_2 = miniscript::Descriptor::new_wsh_sortedmulti(2, old_keys).unwrap();
    println!("Descriptor: {:?}", desc_2);
    println!(
        "Address: {}",
        desc_2.address(bitcoin::Network::Bitcoin).unwrap()
    );

    let desc_3 = miniscript::Descriptor::new_wsh_sortedmulti(2, keys).unwrap();
    println!("Descriptor: {:?}", desc_3);
    println!(
        "Address: {}",
        desc_3.address(bitcoin::Network::Bitcoin).unwrap()
    );

    Ok(())
}
