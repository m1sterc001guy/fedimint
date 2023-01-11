use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritanceConfig {
    /// Contains all configuration that is locally configurable and not secret
    pub local: InheritanceConfigLocal,
    /// Contains all configuration that will be encrypted such as private key material
    pub private: InheritanceConfigPrivate,
    /// Contains all configuration that needs to be the same for every server
    pub consensus: InheritanceConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritanceConfigLocal {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritanceConfigPrivate {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritanceConfigConsensus {}
