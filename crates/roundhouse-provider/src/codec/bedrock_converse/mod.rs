//! AWS Bedrock `Converse`/`ConverseStream` codec, for the legacy non-Claude
//! model families it fronts. Verified against the real, fetched AWS API
//! Reference (URLs and field names below), not the task plan's unverified
//! sketch -- REALITY-CORRECTIONS §13b's lesson from Task 5 (verify the
//! authoritative discriminator values, not merely that a schema of a similar
//! name exists) applies doubly here, since this is also the one codec in
//! this crate whose response is binary framing
//! (`application/vnd.amazon.eventstream`) rather than SSE.
//!
//! Fetched and verified 2026-09-02 (this branch's Phase 6 Task 7):
//! - <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html>
//! - <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html>
//!   (request/response syntax, the `POST /model/{modelId}/converse-stream`
//!   path, and the full documented exception set)
//! - `ContentBlock`, `ContentBlockDelta`, `ContentBlockStart`, `ContentBlockStartEvent`,
//!   `ContentBlockDeltaEvent`, `MessageStartEvent`, `MessageStopEvent`,
//!   `ReasoningContentBlockDelta`, `ToolUseBlock(Start|Delta)`, `ToolResultBlock`,
//!   `ToolResultContentBlock`, `ToolChoice`, `ToolSpecification`, `ToolInputSchema`,
//!   `Message`, `TokenUsage` -- each fetched individually from
//!   `docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_<Name>.html`.
//! - <https://smithy.io/2.0/aws/amazon-eventstream.html> for the binary
//!   framing layout and the `:message-type`/`:event-type`/`:exception-type`
//!   reserved header names/values.
//!
//! Two genuine, verified divergences worth flagging up front (both handled
//! by failing closed, per REALITY-CORRECTIONS §13b item 5 -- there is no
//! `LossEvent` type anywhere in this codebase, so silently dropping either
//! would be an unobservable degrade):
//!
//! 1. **`ToolChoice::None` is not expressible.** The real `ToolChoice` union
//!    has exactly three members -- `auto`, `any`, `tool` -- confirmed by
//!    fetching `API_runtime_ToolChoice.html`. There is no member meaning "the
//!    model must not call any tool," unlike every other codec in this crate.
//!    `encode::try_encode` returns `Err(EncodeError::ToolChoiceNoneUnsupported)`
//!    for it.
//! 2. **Text/reasoning content blocks have no `contentBlockStart` event.**
//!    `ContentBlockStart`'s union (`API_runtime_ContentBlockStart.html`) has
//!    only `toolUse`/`image`/`toolResult` members -- no `text` or
//!    `reasoningContent` member exists at all. So a text or reasoning block
//!    begins implicitly with its first `contentBlockDelta`, with no prior
//!    "open" event; `decode.rs` synthesizes the `BlockStart` IR expects on
//!    first sight of such a delta, rather than waiting for an event that AWS
//!    never sends for these two block kinds.
pub mod decode;
pub mod encode;
mod provider;

pub use provider::BedrockConverseProvider;
