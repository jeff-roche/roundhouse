//! §9.7/§9.8's provider fallback chain with honest per-attempt cost accounting.
//!
//! Fixes audit finding 11: a provider bills every attempt it actually processes,
//! not only the successful one. `ProviderError::ModelNotFound` is the only
//! failure disposition that is genuinely free — the provider rejected the request
//! before starting work. Every other failure means the provider received and
//! began processing the request, so we bill its input tokens via
//! `Provider::count_tokens` and fold that cost into the running total rather than
//! silently dropping it.
//!
//! The winning attempt's stream is fully consumed and buffered so that usage can
//! be read from the provider's own `StreamEvent::UsageDelta` events; the buffered
//! events are then replayed, so callers never receive an estimated or fabricated
//! usage (§1.1 bug #3).

use crate::retry::{retry_with_policy, AimdSemaphore, BreakerKey, CircuitBreaker};
use crate::{
    ChatRequest, ChatStream, ModelId, Provider, ProviderError, ProviderId, RequestCtx, StreamEvent,
    TokenCount,
};
use futures::StreamExt;
use roundhouse_core::{
    Event, SessionId, TaskError, TaskId, TaskOutput, TaskRunner, Timestamp, Usage,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cost in pico-USD, or an explicit admission that the cost could not be
/// determined. Never silently falls back to zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cost {
    Known(u64),
    Unknown,
}

/// Looks up the cost for a concrete `(usage, provider, model)` triple. In
/// production this will be backed by a pricing snapshot; in tests it can be a
/// simple deterministic function.
pub trait PricingLookup: Send + Sync {
    fn cost_for(&self, usage: &Usage, provider: &ProviderId, model: &ModelId) -> Cost;
}

/// An ordered list of `(provider, model)` steps to try in sequence.
#[derive(Debug, Clone, Default)]
pub struct FallbackChain {
    pub steps: Vec<(ProviderId, ModelId)>,
}

/// Result of a successful fallback attempt: the replay stream, the accumulated
/// cost across all attempts, and the events minted for each attempt.
pub struct FallbackOutcome {
    pub stream: ChatStream,
    pub cost: Cost,
    pub events: Vec<Event>,
}

/// Try each `(provider, model)` step in `chain` in order, retrying each step
/// under the provided `CircuitBreaker`/`AimdSemaphore` policy, until one
/// succeeds. Returns the winning stream (buffered and replayed), the summed cost
/// of every billed attempt, and a vector of `Event`s in chain order.
///
/// Events are minted via `runner` but **not appended** — the caller (typically
/// `roundhouse-engine`) is responsible for writing them to the store.
pub async fn infer_with_fallback(
    chain: &FallbackChain,
    req: &ChatRequest,
    ctx: &RequestCtx,
    providers: &HashMap<ProviderId, Arc<dyn Provider>>,
    breaker: &CircuitBreaker,
    semaphore: &AimdSemaphore,
    pricing: &dyn PricingLookup,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
) -> Result<FallbackOutcome, ProviderError> {
    let mut total_known_pico_usd: u64 = 0;
    let mut any_cost_unknown = false;

    let mut last_err = ProviderError::ModelNotFound;
    let mut events = Vec::new();

    for (attempt_no, (provider_id, model_id)) in chain.steps.iter().enumerate() {
        let Some(provider) = providers.get(provider_id) else {
            continue;
        };
        let key: BreakerKey = (provider_id.clone(), model_id.clone());

        match retry_with_policy(key, breaker, semaphore, |_n| provider.stream_chat(req, ctx)).await
        {
            Ok(stream) => {
                let (usage, replay_stream) = consume_and_replay(stream).await;
                accumulate(
                    &mut total_known_pico_usd,
                    &mut any_cost_unknown,
                    pricing.cost_for(&usage, provider_id, model_id),
                );

                let output = TaskOutput::Json(serde_json::json!({
                    "attempt_no": attempt_no,
                    "provider": provider_id.0,
                    "model": model_id.0,
                }));
                let event = runner.record_task_completed(
                    session_id,
                    0,
                    now_ts(),
                    task_id,
                    output,
                    usage,
                    1,
                );
                events.push(event);

                let cost = finalize(total_known_pico_usd, any_cost_unknown);
                return Ok(FallbackOutcome {
                    stream: replay_stream,
                    cost,
                    events,
                });
            }
            Err(ProviderError::ModelNotFound) => {
                // ModelNotFound means the provider rejected the request before
                // any processing started — genuinely free, so do not bill.
                let error = TaskError {
                    message: format!(
                        "{}/{}: {:?}",
                        provider_id.0,
                        model_id.0,
                        ProviderError::ModelNotFound
                    ),
                    category: "provider_error".into(),
                };
                let event =
                    runner.record_task_failed(session_id, 0, now_ts(), task_id, error, false, 1);
                events.push(event);
                last_err = ProviderError::ModelNotFound;
                continue;
            }
            Err(e) => {
                // The provider accepted and started processing the request but
                // ultimately failed. Bill the input tokens we sent it.
                match provider.count_tokens(req, ctx).await {
                    Ok(TokenCount { tokens }) => {
                        let usage = Usage {
                            input_tokens: tokens,
                            output_tokens: 0,
                            cache_read_tokens: 0,
                        };
                        accumulate(
                            &mut total_known_pico_usd,
                            &mut any_cost_unknown,
                            pricing.cost_for(&usage, provider_id, model_id),
                        );
                    }
                    Err(_) => {
                        any_cost_unknown = true;
                    }
                }

                let error = TaskError {
                    message: format!("{}/{}: {:?}", provider_id.0, model_id.0, e),
                    category: "provider_error".into(),
                };
                let event =
                    runner.record_task_failed(session_id, 0, now_ts(), task_id, error, false, 1);
                events.push(event);
                last_err = e;
                continue;
            }
        }
    }

    Err(last_err)
}

fn accumulate(total: &mut u64, unknown: &mut bool, c: Cost) {
    match c {
        Cost::Known(p) => *total += p,
        Cost::Unknown => *unknown = true,
    }
}

fn finalize(total_known_pico_usd: u64, any_cost_unknown: bool) -> Cost {
    if total_known_pico_usd > 0 || !any_cost_unknown {
        Cost::Known(total_known_pico_usd)
    } else {
        Cost::Unknown
    }
}

/// Consume a `ChatStream`, folding the final `UsageDelta` values into a
/// `Usage`, and return both the folded usage and a fresh `ChatStream` that
/// replays the buffered events.
async fn consume_and_replay(stream: ChatStream) -> (Usage, ChatStream) {
    let mut usage = Usage::default();
    let mut buffered = Vec::new();

    let mut stream = stream;
    while let Some(event) = stream.next().await {
        match event {
            StreamEvent::UsageDelta {
                input_tokens,
                output_tokens,
                cache_read_tokens,
            } => {
                if let Some(v) = input_tokens {
                    usage.input_tokens = v;
                }
                if let Some(v) = output_tokens {
                    usage.output_tokens = v;
                }
                if let Some(v) = cache_read_tokens {
                    usage.cache_read_tokens = v;
                }
            }
            StreamEvent::MessageStop => {
                buffered.push(event);
                break;
            }
            _ => {}
        }
        buffered.push(event);
    }

    (usage, ChatStream(Box::pin(futures::stream::iter(buffered))))
}

fn now_ts() -> Timestamp {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}
