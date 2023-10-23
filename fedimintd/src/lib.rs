use bitcoin::Network;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::ServerModuleConfigGenParamsRegistry;
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::module::ServerModuleInit;
use fedimint_core::util::SafeUrl;
use fedimint_ln_common::config::{
    LightningGenParams, LightningGenParamsConsensus, LightningGenParamsLocal,
};
use fedimint_ln_server::LightningGen;
use fedimint_mint_server::common::config::{MintGenParams, MintGenParamsConsensus};
use fedimint_mint_server::MintGen;
use fedimint_wallet_server::common::config::{
    WalletGenParams, WalletGenParamsConsensus, WalletGenParamsLocal,
};
use fedimint_wallet_server::WalletGen;
use resolvr_common::config::{ResolvrGenParams, ResolvrGenParamsConsensus, ResolvrGenParamsLocal};
use resolvr_server::ResolvrGen;

/// Module for creating `fedimintd` binary with custom modules
pub mod fedimintd;

/// Generates the configuration for the modules configured in the server binary
pub fn attach_default_module_init_params(
    bitcoin_rpc: BitcoinRpcConfig,
    module_init_params: &mut ServerModuleConfigGenParamsRegistry,
    network: Network,
    finality_delay: u32,
) {
    module_init_params
        .attach_config_gen_params(
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            WalletGen::kind(),
            WalletGenParams {
                local: WalletGenParamsLocal {
                    bitcoin_rpc: bitcoin_rpc.clone(),
                },
                consensus: WalletGenParamsConsensus {
                    network,
                    // TODO this is not very elegant, but I'm planning to get rid of it in a next
                    // commit anyway
                    finality_delay,
                    client_default_bitcoin_rpc: default_esplora_server(network),
                },
            },
        )
        .attach_config_gen_params(
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            MintGen::kind(),
            MintGenParams {
                local: Default::default(),
                consensus: MintGenParamsConsensus::new(2),
            },
        )
        .attach_config_gen_params(
            LEGACY_HARDCODED_INSTANCE_ID_LN,
            LightningGen::kind(),
            LightningGenParams {
                local: LightningGenParamsLocal { bitcoin_rpc },
                consensus: LightningGenParamsConsensus { network },
            },
        )
        .attach_config_gen_params(
            3,
            ResolvrGen::kind(),
            ResolvrGenParams {
                local: ResolvrGenParamsLocal {},
                // TODO: Dont hardcode this
                consensus: ResolvrGenParamsConsensus { threshold: 3 },
            },
        );
}

pub fn default_esplora_server(network: Network) -> BitcoinRpcConfig {
    let url = match network {
        Network::Bitcoin => SafeUrl::parse("https://blockstream.info/api/")
            .expect("Failed to parse default esplora server"),
        Network::Testnet => SafeUrl::parse("https://blockstream.info/testnet/api/")
            .expect("Failed to parse default esplora server"),
        Network::Regtest => SafeUrl::parse(&format!(
            "http://127.0.0.1:{}/",
            std::env::var("FM_PORT_ESPLORA").unwrap_or(String::from("50002"))
        ))
        .expect("Failed to parse default esplora server"),
        Network::Signet => SafeUrl::parse("https://mutinynet.com/api/")
            .expect("Failed to parse default esplora server"),
    };
    BitcoinRpcConfig {
        kind: "esplora".to_string(),
        url,
    }
}
