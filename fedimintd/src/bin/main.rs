use fedimintd::fedimintd::Fedimintd;
use resolvr_server::ResolvrGen;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new()?
        .with_default_modules()
        .with_module(ResolvrGen)
        .with_extra_module_inits_params(
            3,
            resolvr_common::KIND,
            resolvr_common::config::ResolvrGenParams::default(),
        )
        .run()
        .await
}
