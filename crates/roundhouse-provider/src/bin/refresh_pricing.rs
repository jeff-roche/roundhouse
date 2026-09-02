//! Fetches the two live pricing datasets `roundhouse_provider::pricing`
//! consumes (§9.7) and vendors them under `vendor/` as
//! `include_bytes!`-friendly JSON files. Run manually to refresh, or by
//! `.github/workflows/refresh-pricing.yml` on a weekly schedule; either way,
//! the output is a PR a human reviews before it reaches production (§9.7:
//! "runtime refresh is opt-in and never blocks a request").
//!
//! Uses `ReqwestTransport` rather than constructing its own `reqwest::Client`
//! — per this phase's REALITY-CORRECTIONS §12f, `ReqwestTransport` is "the
//! one sanctioned `reqwest::Client` construction site per §9.10," and a
//! second construction site here would make that claim false.

use futures::StreamExt;
use roundhouse_provider::{HttpRequest, HttpTransport, ReqwestTransport};
use std::path::PathBuf;

const MODELS_DEV_URL: &str = "https://models.dev/api.json";
const LITELLM_URL: &str =
    "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json";

/// Issues one GET through `transport` and returns the fully-collected body,
/// after checking for a non-2xx status and valid-JSON body — never letting a
/// truncated response or an HTML error page silently become the committed
/// vendor file.
async fn fetch_json(transport: &ReqwestTransport, url: &str) -> color_eyre::Result<Vec<u8>> {
    let response = transport
        .send(HttpRequest {
            method: "GET".into(),
            url: url.into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .map_err(|e| color_eyre::eyre::eyre!("GET {url} failed: {e}"))?;

    if !(200..300).contains(&response.status) {
        return Err(color_eyre::eyre::eyre!(
            "GET {url} returned HTTP {}",
            response.status
        ));
    }

    let mut body = Vec::new();
    let mut stream = response.body;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| color_eyre::eyre::eyre!("GET {url}: {e}"))?;
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice::<serde_json::Value>(&body)
        .map_err(|e| color_eyre::eyre::eyre!("GET {url}: response is not valid JSON: {e}"))?;

    Ok(body)
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let out_dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("crates/roundhouse-provider/vendor"));
    std::fs::create_dir_all(&out_dir)?;

    let transport = ReqwestTransport::new();
    let models_dev_body = fetch_json(&transport, MODELS_DEV_URL).await?;
    let litellm_body = fetch_json(&transport, LITELLM_URL).await?;

    std::fs::write(out_dir.join("models_dev_snapshot.json"), &models_dev_body)?;
    std::fs::write(out_dir.join("litellm_pricing_snapshot.json"), &litellm_body)?;
    println!(
        "wrote {} bytes (models.dev), {} bytes (LiteLLM) to {}",
        models_dev_body.len(),
        litellm_body.len(),
        out_dir.display()
    );
    Ok(())
}
