use roundhouse_core::Tier;

#[derive(Debug, Clone)]
pub struct Handle {
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub achieved: Tier,
    pub degradations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Child {
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct Attestation {
    pub tier: Tier,
    pub digest: String,
    pub net_enforced: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    #[error("isolation mechanism unsupported on this host: {0}")]
    Unsupported(String),
    #[error("achieved tier is lower than requested and on_degrade=Refuse")]
    DegradedBelowRequested,
}
