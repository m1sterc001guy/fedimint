use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, format_err};
use fedimint_api::cancellable::{Cancellable, Cancelled};
use fedimint_api::config::{
    BitcoindRpcCfg, ClientConfig, ConfigGenParams, DkgPeerMsg, DkgRunner, Node, ServerModuleConfig,
    TypedServerModuleConfig,
};
use fedimint_api::core::{ModuleKey, MODULE_KEY_GLOBAL};
use fedimint_api::module::FederationModuleConfigGen;
use fedimint_api::net::peers::{IPeerConnections, MuxPeerConnections, PeerConnections};
use fedimint_api::task::TaskGroup;
use fedimint_api::{Amount, PeerId};
pub use fedimint_core::config::*;
use fedimint_core::modules::mint::MintConfigGenParams;
use fedimint_wallet::WalletConfigGenParams;
use hbbft::crypto::serde_impl::SerdeSecret;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tracing::info;
use url::Url;

use crate::fedimint_api::NumPeers;
use crate::net::connect::TlsConfig;
use crate::net::connect::{parse_host_port, Connector};
use crate::net::peers::NetworkConfig;
use crate::{ReconnectPeerConnections, TlsTcpConnector};

/// Default port for communication with peers when not specified (0x1FED)
pub const DEFAULT_P2P_PORT: u16 = 8173;

/// Default port for exposing the API when not specified
pub const DEFAULT_API_PORT: u16 = 8174;

/// The maximum open connections the API can handle
const DEFAULT_MAX_CLIENT_CONNECTIONS: u32 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// All the serializable configuration for the fedimint server
pub struct ServerConfig {
    /// Contains all configuration that needs to be the same for every server
    pub consensus: ServerConfigConsensus,
    /// Contains all configuration that is locally configurable and not secret
    pub local: ServerConfigLocal,
    /// Contains all configuration that will be encrypted such as private key material
    pub private: ServerConfigPrivate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigPrivate {
    /// Secret key for TLS communication, required for peer authentication
    #[serde(with = "serde_tls_key")]
    pub tls_key: rustls::PrivateKey,
    /// Secret key for contributing to HBBFT consensus
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    /// Secret key for signing consensus epochs
    #[serde(with = "serde_binary_human_readable")]
    pub epoch_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    /// Secret material from modules
    pub modules: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigConsensus {
    /// Network addresses and certs for all peers
    pub peers: BTreeMap<PeerId, Peer>,
    /// The version of the binary code running
    pub code_version: String,
    /// Configurable federation name
    pub federation_name: String,
    /// Public keys for HBBFT consensus from all peers
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk_set: hbbft::crypto::PublicKeySet,
    /// Public keys for signing consensus epochs from all peers
    #[serde(with = "serde_binary_human_readable")]
    pub epoch_pk_set: hbbft::crypto::PublicKeySet,
    /// All configuration that needs to be the same for modules
    pub modules: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigLocal {
    /// Our peer id (generally should not change)
    pub identity: PeerId,
    /// Our bind address for communicating with peers
    pub fed_bind: SocketAddr,
    /// Our bind address for our API endpoints
    pub api_bind: SocketAddr,
    /// Our publicly known TLS cert
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
    /// How many API connections we will accept
    pub max_connections: u32,
    /// Non-consensus, non-private configuration from modules
    pub modules: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    /// Certs for TLS communication, required for peer authentication
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
    /// The TLS network address and port, used for HBBFT consensus
    pub hbbft: Url,
    /// The peer's websocket network address and port (e.g. `ws://10.42.0.10:5000`)
    pub api_addr: Url,
    /// human-readable name
    pub name: String,
}

#[derive(Debug, Clone)]
/// network config for a server
pub struct ServerConfigParams {
    pub tls: TlsConfig,
    pub fed_network: NetworkConfig,
    pub api_network: NetworkConfig,
    pub federation_name: String,

    /// extra options for extra settings and modules
    pub modules: ConfigGenParams,
}

impl ServerConfigConsensus {
    pub fn to_client_config_try(
        &self,
        module_config_gens: &ModuleConfigGens,
    ) -> anyhow::Result<ClientConfig> {
        let nodes = self
            .peers
            .values()
            .map(|peer| Node {
                url: peer.api_addr.clone(),
                name: peer.name.clone(),
            })
            .collect();

        Ok(ClientConfig {
            federation_name: self.federation_name.clone(),
            epoch_pk: self.epoch_pk_set.public_key(),
            nodes,
            modules: self
                .modules
                .iter()
                .map(|(k, v)| {
                    Ok((
                        k.clone(),
                        module_config_gens
                            .get(&k.as_str())
                            .ok_or_else(|| anyhow::format_err!("module config gen not found: {k}"))?
                            .to_client_config_from_consensus_value(v.clone())?,
                    ))
                })
                .collect::<anyhow::Result<_>>()?,
        })
    }

    pub fn to_client_config(&self, module_config_gens: &ModuleConfigGens) -> ClientConfig {
        self.to_client_config_try(module_config_gens)
            .expect("configuration mismatch")
    }
}

pub type ModuleConfigGens =
    BTreeMap<&'static str, Arc<dyn FederationModuleConfigGen + Send + Sync>>;

impl ServerConfig {
    /// Creates a new config from the results of a trusted or distributed key setup
    #[allow(clippy::too_many_arguments)]
    pub fn from(
        code_version: &str,
        params: ServerConfigParams,
        identity: PeerId,
        hbbft_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
        hbbft_pk_set: hbbft::crypto::PublicKeySet,
        epoch_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
        epoch_pk_set: hbbft::crypto::PublicKeySet,
        modules: BTreeMap<String, ServerModuleConfig>,
    ) -> Self {
        let private = ServerConfigPrivate {
            tls_key: params.tls.our_private_key.clone(),
            hbbft_sks,
            epoch_sks,
            modules: Default::default(),
        };
        let local = ServerConfigLocal {
            identity,
            fed_bind: params.fed_network.bind_addr,
            api_bind: params.api_network.bind_addr,
            tls_cert: params.tls.our_certificate.clone(),
            max_connections: DEFAULT_MAX_CLIENT_CONNECTIONS,
            modules: Default::default(),
        };
        let consensus = ServerConfigConsensus {
            code_version: code_version.to_string(),
            federation_name: params.federation_name.clone(),
            peers: params.peers(),
            hbbft_pk_set,
            epoch_pk_set,
            modules: Default::default(),
        };
        let mut cfg = Self {
            consensus,
            local,
            private,
        };
        cfg.add_modules(modules);
        cfg
    }

    pub fn add_modules(&mut self, modules: BTreeMap<String, ServerModuleConfig>) {
        for (name, config) in modules.into_iter() {
            let ServerModuleConfig {
                local,
                private,
                consensus,
            } = config;

            self.local.modules.insert(name.clone(), local);
            self.private.modules.insert(name.clone(), private);
            self.consensus.modules.insert(name, consensus);
        }
    }

    /// Constructs a module config by name
    pub fn get_module_config_typed<T: TypedServerModuleConfig>(
        &self,
        name: &str,
    ) -> anyhow::Result<T> {
        let local = Self::get_or_error(&self.local.modules, name)?;
        let private = Self::get_or_error(&self.private.modules, name)?;
        let consensus = Self::get_or_error(&self.consensus.modules, name)?;
        let module = ServerModuleConfig::from(local, private, consensus);

        module.to_typed()
    }

    /// Constructs a module config by name
    pub fn get_module_config(&self, name: &str) -> anyhow::Result<ServerModuleConfig> {
        let local = Self::get_or_error(&self.local.modules, name)?;
        let private = Self::get_or_error(&self.private.modules, name)?;
        let consensus = Self::get_or_error(&self.consensus.modules, name)?;
        Ok(ServerModuleConfig::from(local, private, consensus))
    }

    fn get_or_error(
        json: &BTreeMap<String, serde_json::Value>,
        name: &str,
    ) -> anyhow::Result<serde_json::Value> {
        json.get(name)
            .ok_or_else(|| format_err!("Module {name} not found"))
            .cloned()
    }

    pub fn validate_config(
        &self,
        identity: &PeerId,
        module_config_gens: &ModuleConfigGens,
    ) -> anyhow::Result<()> {
        let peers = self.consensus.peers.clone();
        let consensus = self.consensus.clone();
        let private = self.private.clone();
        let id = identity.to_usize();

        if private.epoch_sks.public_key_share() != consensus.epoch_pk_set.public_key_share(id) {
            bail!("Epoch private key doesn't match pubkey share");
        }
        if private.hbbft_sks.public_key_share() != consensus.hbbft_pk_set.public_key_share(id) {
            bail!("HBBFT private key doesn't match pubkey share");
        }
        if peers.keys().max().copied().map(|id| id.to_usize()) != Some(peers.len() - 1) {
            bail!("Peer ids are not indexed from 0");
        }
        if peers.keys().min().copied() != Some(PeerId::from(0)) {
            bail!("Peer ids are not indexed from 0");
        }

        for module_name in self
            .local
            .modules
            .keys()
            .collect::<BTreeSet<_>>()
            .union(&self.consensus.modules.keys().collect::<BTreeSet<_>>())
            .copied()
            .collect::<BTreeSet<_>>()
            .union(&self.private.modules.keys().collect::<BTreeSet<_>>())
        {
            module_config_gens
                .get(module_name.as_str())
                .ok_or_else(|| format_err!("module config gen not found {module_name}"))?
                .validate_config(identity, self.get_module_config(module_name)?)?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn trusted_dealer_gen(
        code_version: &str,
        peers: &[PeerId],
        params: &HashMap<PeerId, ServerConfigParams>,
        module_config_gens: ModuleConfigGens,
        mut rng: impl RngCore + CryptoRng,
    ) -> BTreeMap<PeerId, Self> {
        let netinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut rng)
            .expect("Could not generate HBBFT netinfo");
        let epochinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut rng)
            .expect("Could not generate HBBFT netinfo");

        let peer0 = &params[&PeerId::from(0)];

        let module_configs: BTreeMap<_, _> = module_config_gens
            .iter()
            .map(|(name, gen)| (name, gen.trusted_dealer_gen(peers, &peer0.modules)))
            .collect();
        let server_config: BTreeMap<_, _> = netinfo
            .iter()
            .map(|(&id, netinf)| {
                let epoch_keys = epochinfo.get(&id).unwrap();
                let config = ServerConfig::from(
                    code_version,
                    params[&id].clone(),
                    id,
                    SerdeSecret(netinf.secret_key_share().unwrap().clone()),
                    netinf.public_key_set().clone(),
                    SerdeSecret(epoch_keys.secret_key_share().unwrap().clone()),
                    epoch_keys.public_key_set().clone(),
                    module_configs
                        .iter()
                        .map(|(name, cfgs)| (name.to_string(), cfgs[&id].clone()))
                        .collect(),
                );
                (id, config)
            })
            .collect();

        server_config
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn distributed_gen(
        code_version: &str,
        connections: &MuxPeerConnections<ModuleKey, DkgPeerMsg>,
        our_id: &PeerId,
        peers: &[PeerId],
        params: &ServerConfigParams,
        module_config_gens: ModuleConfigGens,
        mut rng: impl RngCore + CryptoRng,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Cancellable<Self>> {
        // in case we are running by ourselves, avoid DKG
        if peers.len() == 1 {
            let server = Self::trusted_dealer_gen(
                code_version,
                peers,
                &HashMap::from([(*our_id, params.clone())]),
                module_config_gens,
                rng,
            );
            return Ok(Ok(server[our_id].clone()));
        }
        info!("Peer {} running distributed key generation...", our_id);

        // hbbft uses a lower threshold of signing keys (f+1)
        let mut dkg = DkgRunner::new(KeyType::Hbbft, peers.one_honest(), our_id, peers);
        dkg.add(KeyType::Epoch, peers.threshold());

        // run DKG for epoch and hbbft keys
        let keys = if let Ok(v) = dkg.run_g1(MODULE_KEY_GLOBAL, connections, &mut rng).await {
            v
        } else {
            return Ok(Err(Cancelled));
        };
        let (hbbft_pks, hbbft_sks) = keys[&KeyType::Hbbft].threshold_crypto();
        let (epoch_pks, epoch_sks) = keys[&KeyType::Epoch].threshold_crypto();

        let mut module_cfgs: BTreeMap<String, ServerModuleConfig> = Default::default();

        for (name, gen) in module_config_gens {
            module_cfgs.insert(
                name.to_string(),
                if let Ok(cfgs) = gen
                    .distributed_gen(connections, our_id, peers, &params.modules, task_group)
                    .await?
                {
                    cfgs
                } else {
                    return Ok(Err(Cancelled));
                },
            );
        }

        let server = ServerConfig::from(
            code_version,
            params.clone(),
            *our_id,
            SerdeSecret(hbbft_sks),
            hbbft_pks,
            SerdeSecret(epoch_sks),
            epoch_pks,
            module_cfgs,
        );

        info!("Distributed key generation has completed successfully!");

        Ok(Ok(server))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    Hbbft,
    Epoch,
}

impl ServerConfig {
    pub fn network_config(&self) -> NetworkConfig {
        NetworkConfig {
            identity: self.local.identity,
            bind_addr: self.local.fed_bind,
            peers: self
                .consensus
                .peers
                .iter()
                .map(|(&id, peer)| (id, peer.hbbft.clone()))
                .collect(),
        }
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            our_certificate: self.local.tls_cert.clone(),
            our_private_key: self.private.tls_key.clone(),
            peer_certs: self
                .consensus
                .peers
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.tls_cert.clone()))
                .collect(),
            peer_names: self
                .consensus
                .peers
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.name.to_string()))
                .collect(),
        }
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.local.identity.into()
    }
}

#[derive(Clone)]
pub struct PeerServerParams {
    pub cert: rustls::Certificate,
    pub p2p_url: Url,
    pub api_url: Url,
    pub name: String,
}

impl ServerConfigParams {
    /// Generates denominations as powers of 2 until a `max`
    pub fn gen_denominations(max: Amount) -> Vec<Amount> {
        let mut amounts = vec![];

        let mut denomination = Amount::from_msats(1);
        while denomination < max {
            amounts.push(denomination);
            denomination = denomination * 2;
        }

        amounts
    }

    pub fn peers(&self) -> BTreeMap<PeerId, Peer> {
        self.fed_network
            .peers
            .iter()
            .map(|(peer, hbbft)| {
                (
                    *peer,
                    Peer {
                        tls_cert: self.tls.peer_certs[peer].clone(),
                        name: self.tls.peer_names[peer].clone(),
                        hbbft: hbbft.clone(),
                        api_addr: self.api_network.peers[peer].clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    }

    /// Generates the parameters necessary for running server config generation
    #[allow(clippy::too_many_arguments)]
    pub fn gen_params(
        bind_p2p: SocketAddr,
        bind_api: SocketAddr,
        key: rustls::PrivateKey,
        our_id: PeerId,
        max_denomination: Amount,
        peers: &BTreeMap<PeerId, PeerServerParams>,
        federation_name: String,
        bitcoind_rpc: String,
        network: bitcoin::network::constants::Network,
        finality_delay: u32,
    ) -> ServerConfigParams {
        let peer_certs: HashMap<PeerId, rustls::Certificate> = peers
            .iter()
            .map(|(peer, params)| (*peer, params.cert.clone()))
            .collect::<HashMap<_, _>>();

        let peer_names: HashMap<PeerId, String> = peers
            .iter()
            .map(|(peer, params)| (*peer, params.name.to_string()))
            .collect::<HashMap<_, _>>();

        let tls = TlsConfig {
            our_certificate: peers[&our_id].cert.clone(),
            our_private_key: key,
            peer_certs,
            peer_names,
        };

        ServerConfigParams {
            tls,
            fed_network: Self::gen_network(&bind_p2p, &our_id, DEFAULT_P2P_PORT, peers, |params| {
                params.p2p_url
            }),
            api_network: Self::gen_network(&bind_api, &our_id, DEFAULT_API_PORT, peers, |params| {
                params.api_url
            }),
            federation_name,
            modules: ConfigGenParams::new()
                .attach(WalletConfigGenParams {
                    network,
                    bitcoin_rpc: BitcoindRpcCfg {
                        btc_rpc_address: bitcoind_rpc,
                        btc_rpc_user: "bitcoin".to_string(),
                        btc_rpc_pass: "bitcoin".to_string(),
                    },
                    finality_delay,
                })
                .attach(MintConfigGenParams {
                    mint_amounts: ServerConfigParams::gen_denominations(max_denomination),
                }),
        }
    }

    fn gen_network(
        bind_address: &SocketAddr,
        our_id: &PeerId,
        default_port: u16,
        peers: &BTreeMap<PeerId, PeerServerParams>,
        extract_url: impl Fn(PeerServerParams) -> Url,
    ) -> NetworkConfig {
        NetworkConfig {
            identity: *our_id,
            bind_addr: *bind_address,
            peers: peers
                .iter()
                .map(|(peer, params)| {
                    let mut url = extract_url(params.clone());
                    if url.port().is_none() {
                        url.set_port(Some(default_port)).expect("Can set port");
                    }

                    (*peer, url)
                })
                .collect(),
        }
    }

    /// config for servers running on different ports on a local network
    pub fn gen_local(
        peers: &[PeerId],
        max_denomination: Amount,
        base_port: u16,
        federation_name: &str,
        bitcoind_rpc: &str,
    ) -> HashMap<PeerId, ServerConfigParams> {
        let keys: HashMap<PeerId, (rustls::Certificate, rustls::PrivateKey)> = peers
            .iter()
            .map(|peer| {
                let (cert, key) = gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap();
                (*peer, (cert, key))
            })
            .collect::<HashMap<_, _>>();

        let peer_params: BTreeMap<PeerId, PeerServerParams> = peers
            .iter()
            .map(|peer| {
                let peer_port = base_port + u16::from(*peer) * 10;
                let p2p_url = format!("ws://127.0.0.1:{}", peer_port);
                let api_url = format!("ws://127.0.0.1:{}", peer_port + 1);

                let params: PeerServerParams = PeerServerParams {
                    cert: keys[peer].0.clone(),
                    p2p_url: p2p_url.parse().expect("Should parse"),
                    api_url: api_url.parse().expect("Should parse"),
                    name: format!("peer-{}", peer.to_usize()),
                };
                (*peer, params)
            })
            .collect();

        peers
            .iter()
            .map(|peer| {
                let bind_p2p = parse_host_port(peer_params[peer].clone().p2p_url);
                let bind_api = parse_host_port(peer_params[peer].clone().api_url);

                let params: ServerConfigParams = Self::gen_params(
                    bind_p2p.parse().expect("Should parse"),
                    bind_api.parse().expect("Should parse"),
                    keys[peer].1.clone(),
                    *peer,
                    max_denomination,
                    &peer_params,
                    federation_name.to_string(),
                    bitcoind_rpc.to_string(),
                    bitcoin::network::constants::Network::Regtest,
                    10,
                );
                (*peer, params)
            })
            .collect()
    }
}

pub async fn connect<T>(
    network: NetworkConfig,
    certs: TlsConfig,
    task_group: &mut TaskGroup,
) -> PeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    let connector = TlsTcpConnector::new(certs).into_dyn();
    ReconnectPeerConnections::new(network, connector, task_group)
        .await
        .into_dyn()
}

pub fn gen_cert_and_key(
    name: &str,
) -> Result<(rustls::Certificate, rustls::PrivateKey), anyhow::Error> {
    let keypair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let keypair_ser = keypair.serialize_der();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]);

    params.key_pair = Some(keypair);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = rcgen::IsCa::NoCa;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);

    let cert = rcgen::Certificate::from_params(params)?;

    Ok((
        rustls::Certificate(cert.serialize_der()?),
        rustls::PrivateKey(keypair_ser),
    ))
}

mod serde_tls_cert {
    use std::borrow::Cow;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tokio_rustls::rustls;

    pub fn serialize<S>(cert: &rustls::Certificate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&cert.0);
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::Certificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str.as_ref()).map_err(|_e| D::Error::custom("Invalid hex"))?;
        Ok(rustls::Certificate(bytes))
    }
}

mod serde_tls_key {
    use std::borrow::Cow;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tokio_rustls::rustls;

    pub fn serialize<S>(key: &rustls::PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&key.0);
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str.as_ref()).map_err(|_e| D::Error::custom("Invalid hex"))?;
        Ok(rustls::PrivateKey(bytes))
    }
}
