//! Google GenAI (Gemini) wire-format codec: the Interactions API (default,
//! §9.2) and the legacy `generateContent`/`streamGenerateContent` surface,
//! selected by [`EndpointMode`]. Verified against the real fetched spec
//! before being written -- see
//! `docs/decisions/2026-08-27-google-genai-spec-verification.md`, whose
//! headline finding is that the two modes' *content models* genuinely
//! diverge (Interactions: a flat `steps[]`/`input` shape; GenerateContent:
//! `contents[].parts[]`), not just their envelopes -- so `encode`/the stream
//! decoder each dispatch internally per `mode` to two independent
//! construction/decoding paths, rather than sharing one `contents[].parts[]`
//! helper the way the task brief's unverified sketch assumed.
pub mod decode;
pub mod encode;
mod provider;

pub use provider::GoogleGenAiProvider;

/// §9.4: "one codec with an internal `EndpointMode` switch, not two codecs" --
/// held to at the file-structure/`Provider`-impl level even though the two
/// modes' content models do not share an encoder/decoder helper underneath
/// (see this module's doc comment and the decision doc's Divergence 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointMode {
    /// The default surface (§9.2): POST `/v1beta/interactions`, `steps[]`
    /// response shape, `stream: true` in the request body for SSE.
    Interactions,
    /// The legacy surface: POST
    /// `/v1beta/{model=models/*}:streamGenerateContent?alt=sse`,
    /// `contents[].parts[]` request/response shape.
    GenerateContent,
}
