use futures::future::BoxFuture;
use futures::StreamExt;
use roundhouse_core::{EventPayload, SessionId, TaskId, TaskRunner, Usage};
use roundhouse_provider::fallback::{infer_with_fallback, Cost, FallbackChain, PricingLookup};
use roundhouse_provider::retry::{AimdSemaphore, CircuitBreaker};
use roundhouse_provider::{
    Capabilities, ChatRequest, ChatStream, HttpRequest, HttpResponseStream, HttpTransport,
    MessageRole, ModelId, Params, Plan, Provider, ProviderError, ProviderExt, ProviderId,
    ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat, StreamEvent, SystemBlock,
    TokenCount, ToolChoice, TransportError,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock};

static RUNNER: OnceLock<TaskRunner> = OnceLock::new();

struct NoopTransport;

impl HttpTransport for NoopTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async { unreachable!("tests do not perform HTTP") })
    }
}

fn dummy_ctx() -> RequestCtx {
    RequestCtx {
        trace_id: None,
        transport: Arc::new(NoopTransport),
        api_key: String::new(),
    }
}

fn dummy_request() -> ChatRequest {
    ChatRequest {
        model: ModelId("test-model".into()),
        system: vec![SystemBlock {
            text: "you are a test".into(),
            cache: None,
        }],
        messages: vec![roundhouse_provider::Message {
            role: MessageRole::User,
            content: vec![roundhouse_provider::ContentBlock::Text {
                text: "hello".into(),
                cache: None,
                citations: vec![],
            }],
        }],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}

struct FlatPricing;

impl PricingLookup for FlatPricing {
    fn cost_for(&self, usage: &Usage, _p: &ProviderId, _m: &ModelId) -> Cost {
        Cost::Known(usage.input_tokens + usage.output_tokens)
    }
}

struct AlwaysUnknownPricing;

impl PricingLookup for AlwaysUnknownPricing {
    fn cost_for(&self, _usage: &Usage, _p: &ProviderId, _m: &ModelId) -> Cost {
        Cost::Unknown
    }
}

struct ModelNotFoundProvider;

impl Provider for ModelNotFoundProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities {
            streaming: true,
            tools: false,
            thinking: false,
            max_breakpoints: 0,
        }
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "stub".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async { Err(ProviderError::ModelNotFound) })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { todo!("ModelNotFoundProvider does not bill") })
    }
}

struct ServerErrorAfterAcceptingProvider {
    count: u64,
}

impl Provider for ServerErrorAfterAcceptingProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities {
            streaming: true,
            tools: false,
            thinking: false,
            max_breakpoints: 0,
        }
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "stub".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async { Err(ProviderError::Server { status: 500 }) })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        let count = self.count;
        Box::pin(async move { Ok(TokenCount { tokens: count }) })
    }
}

struct EchoProvider {
    input: u64,
    output: u64,
}

impl Provider for EchoProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities {
            streaming: true,
            tools: false,
            thinking: false,
            max_breakpoints: 0,
        }
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "stub".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        let events = vec![
            StreamEvent::UsageDelta {
                input_tokens: Some(self.input),
                output_tokens: Some(self.output),
                cache_read_tokens: None,
            },
            StreamEvent::MessageStop,
        ];
        Box::pin(async move { Ok(ChatStream(Box::pin(futures::stream::iter(events)))) })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        let input = self.input;
        Box::pin(async move { Ok(TokenCount { tokens: input }) })
    }
}

#[tokio::test]
async fn failed_first_attempt_never_reports_zero_cost_and_falls_back() {
    let runner = RUNNER.get_or_init(TaskRunner::bootstrap);
    let chain = FallbackChain {
        steps: vec![
            (ProviderId("flaky".into()), ModelId("test".into())),
            (ProviderId("backup".into()), ModelId("test".into())),
        ],
    };
    let mut providers: HashMap<ProviderId, Arc<dyn Provider>> = HashMap::new();
    providers.insert(ProviderId("flaky".into()), Arc::new(ModelNotFoundProvider));
    providers.insert(
        ProviderId("backup".into()),
        Arc::new(EchoProvider {
            input: 100,
            output: 50,
        }),
    );

    let outcome = infer_with_fallback(
        &chain,
        &dummy_request(),
        &dummy_ctx(),
        &providers,
        &CircuitBreaker::new(),
        &AimdSemaphore::new(),
        &AlwaysUnknownPricing,
        runner,
        SessionId::new(),
        TaskId::new(),
    )
    .await
    .expect("fallback should succeed on second step");

    assert!(
        matches!(outcome.cost, Cost::Unknown),
        "pricing unknown on every attempt must yield Cost::Unknown, not a fabricated zero"
    );
    assert_eq!(
        outcome.events.len(),
        2,
        "expected one failure + one completion"
    );
    assert!(
        matches!(outcome.events[0].payload, EventPayload::TaskFailed { .. }),
        "first event must be the failed attempt"
    );
    assert!(
        matches!(
            outcome.events[1].payload,
            EventPayload::TaskCompleted { .. }
        ),
        "second event must be the winning attempt"
    );

    // The stream must replay the provider's events (not be empty/estimated).
    let replayed: Vec<StreamEvent> = outcome.stream.collect().await;
    assert!(matches!(replayed.last(), Some(StreamEvent::MessageStop)));
}

#[tokio::test]
async fn a_billed_failed_attempt_sums_into_the_returned_total_cost() {
    let runner = RUNNER.get_or_init(TaskRunner::bootstrap);
    let chain = FallbackChain {
        steps: vec![
            (ProviderId("flaky".into()), ModelId("test".into())),
            (ProviderId("backup".into()), ModelId("test".into())),
        ],
    };
    let mut providers: HashMap<ProviderId, Arc<dyn Provider>> = HashMap::new();
    providers.insert(
        ProviderId("flaky".into()),
        Arc::new(ServerErrorAfterAcceptingProvider { count: 40 }),
    );
    providers.insert(
        ProviderId("backup".into()),
        Arc::new(EchoProvider {
            input: 100,
            output: 50,
        }),
    );

    let outcome = infer_with_fallback(
        &chain,
        &dummy_request(),
        &dummy_ctx(),
        &providers,
        &CircuitBreaker::new(),
        &AimdSemaphore::new(),
        &FlatPricing,
        runner,
        SessionId::new(),
        TaskId::new(),
    )
    .await
    .expect("fallback should succeed on second step");

    assert_eq!(
        outcome.cost,
        Cost::Known(190),
        "failed attempt input (40) + winner input/output (100+50) = 190"
    );

    let completed_usage = outcome
        .events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCompleted { usage, .. } => Some(usage.clone()),
            _ => None,
        })
        .expect("winner must emit TaskCompleted");
    assert_eq!(completed_usage.input_tokens, 100);
    assert_eq!(completed_usage.output_tokens, 50);
    assert_eq!(completed_usage.cache_read_tokens, 0);
}

#[tokio::test]
async fn empty_chain_returns_model_not_found() {
    let runner = RUNNER.get_or_init(TaskRunner::bootstrap);
    let chain = FallbackChain { steps: vec![] };
    let providers: HashMap<ProviderId, Arc<dyn Provider>> = HashMap::new();

    let result = infer_with_fallback(
        &chain,
        &dummy_request(),
        &dummy_ctx(),
        &providers,
        &CircuitBreaker::new(),
        &AimdSemaphore::new(),
        &FlatPricing,
        runner,
        SessionId::new(),
        TaskId::new(),
    )
    .await;

    let failure = match result {
        Err(f) => f,
        Ok(_) => panic!("empty chain must fail"),
    };
    assert!(matches!(failure.last_err, ProviderError::ModelNotFound));
    assert_eq!(failure.events.len(), 0);
}

#[tokio::test]
async fn all_steps_fail_returns_last_error() {
    let runner = RUNNER.get_or_init(TaskRunner::bootstrap);
    let chain = FallbackChain {
        steps: vec![
            (ProviderId("a".into()), ModelId("test".into())),
            (ProviderId("b".into()), ModelId("test".into())),
        ],
    };
    let mut providers: HashMap<ProviderId, Arc<dyn Provider>> = HashMap::new();
    providers.insert(
        ProviderId("a".into()),
        Arc::new(ServerErrorAfterAcceptingProvider { count: 10 }),
    );
    providers.insert(
        ProviderId("b".into()),
        Arc::new(ServerErrorAfterAcceptingProvider { count: 20 }),
    );

    let result = infer_with_fallback(
        &chain,
        &dummy_request(),
        &dummy_ctx(),
        &providers,
        &CircuitBreaker::new(),
        &AimdSemaphore::new(),
        &FlatPricing,
        runner,
        SessionId::new(),
        TaskId::new(),
    )
    .await;

    let failure = match result {
        Err(f) => f,
        Ok(_) => panic!("all steps must fail"),
    };
    assert!(
        matches!(failure.last_err, ProviderError::Server { status: 500 }),
        "exhausted chain must surface the last real provider error"
    );
    assert_eq!(
        failure.events.len(),
        2,
        "one TaskFailed event must be returned per attempted step"
    );
}
