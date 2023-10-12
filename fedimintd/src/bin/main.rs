use fedimintd::fedimintd::Fedimintd;
use resolvr_server::ResolvrGen;
use schnorr_fun::frost;
use sha2::Sha256;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new()?
        .with_default_modules()
        .with_module(ResolvrGen {
            frost: frost::new_with_synthetic_nonces::<Sha256, rand::rngs::OsRng>(),
        })
        .with_extra_module_inits_params(
            3,
            resolvr_common::KIND,
            resolvr_common::config::ResolvrGenParams::default(),
        )
        .run()
        .await
}
