use roundhouse_provider::{
    Capabilities, ChatRequest, ChatStream, ContentBlock, ModelId, Plan, Provider, ProviderError,
    RequestCtx, TokenCount,
};
use std::sync::Arc;

struct StubProvider;

impl Provider for StubProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities { streaming: true, tools: true, thinking: false, max_breakpoints: 0 }
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan { endpoint: "stub".into() })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async { todo!("Phase 1: real adapters implement this") })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { todo!("Phase 1: real adapters implement this") })
    }
}

#[test]
fn provider_trait_is_object_safe() {
    let provider: Arc<dyn Provider> = Arc::new(StubProvider);
    let caps = provider.capabilities(&ModelId("claude-test".into()));
    assert!(caps.streaming);
}

#[test]
fn content_block_covers_every_ir_variant() {
    use roundhouse_provider::{IdOrigin, MediaSource, ProviderId, ToolResultPart};

    // §9.3 names 7 variants (Text, Image, Document, ToolUse, ToolResult,
    // Thinking, Opaque). The original test constructed only 2, so a
    // dropped/malformed variant wouldn't have failed this test — build all
    // 7 so the IR's actual shape is what's under test.
    let blocks = vec![
        ContentBlock::Text { text: "hi".into(), cache: None, citations: vec![] },
        ContentBlock::Image {
            source: MediaSource { mime_type: "image/png".into(), data: vec![0x89, 0x50, 0x4e, 0x47] },
            cache: None,
        },
        ContentBlock::Document {
            source: MediaSource { mime_type: "application/pdf".into(), data: vec![0x25, 0x50, 0x44, 0x46] },
            title: Some("spec.pdf".into()),
            cache: None,
        },
        ContentBlock::ToolUse {
            id: roundhouse_provider::ToolCallId("call-1".into()),
            id_origin: IdOrigin::Provider,
            name: "shell".into(),
            input: serde_json::json!({"command": "ls"}),
            cache: None,
        },
        ContentBlock::ToolResult {
            tool_use_id: roundhouse_provider::ToolCallId("call-1".into()),
            content: vec![ToolResultPart { text: "total 0".into() }],
            is_error: false,
            cache: None,
        },
        ContentBlock::Thinking { text: "reasoning".into(), signature: None, redacted: false },
        ContentBlock::Opaque {
            provider: ProviderId("anthropic".into()),
            kind: "server_tool_use".into(),
            raw: serde_json::json!({"vendor_specific": true}),
        },
    ];
    assert_eq!(blocks.len(), 7);
}

#[test]
fn tool_def_input_schema_is_generated_from_a_typed_params_struct() {
    // S-TOOL-9 (§12.7): every tool's `input_schema` comes from `schemars`
    // generation over a typed Rust params struct, never hand-written JSON,
    // so the schema and the deserialization target can never drift.
    let tool = roundhouse_provider::tool_def_from_schema::<roundhouse_provider::ShellToolParams>(
        "shell",
        "Run a shell command in the task's working directory",
    );
    assert_eq!(tool.name(), "shell");

    // Round-trips into a valid, usable serde_json::Value...
    let schema_value: &serde_json::Value = tool.input_schema();
    assert!(schema_value.is_object(), "input_schema must round-trip into a valid JSON Value");

    // ...and matches the expected shape for ShellToolParams specifically.
    let props = schema_value
        .get("properties")
        .expect("generated schema must have a `properties` object");
    assert!(props.get("command").is_some(), "expected `command` in ShellToolParams' generated schema");
    assert!(props.get("cwd").is_some(), "expected `cwd` in ShellToolParams' generated schema");
}

#[tokio::test]
async fn list_models_defaults_to_unsupported() {
    struct NoListModels;
    impl Provider for NoListModels {
        fn capabilities(&self, _model: &ModelId) -> Capabilities {
            Capabilities { streaming: false, tools: false, thinking: false, max_breakpoints: 0 }
        }
        fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
            Ok(Plan { endpoint: "noop".into() })
        }
        fn stream_chat<'a>(
            &'a self,
            _req: &'a ChatRequest,
            _ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
            Box::pin(async { todo!() })
        }
        fn count_tokens<'a>(
            &'a self,
            _req: &'a ChatRequest,
            _ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
            Box::pin(async { todo!() })
        }
    }
    let provider = NoListModels;
    let ctx = RequestCtx::default();
    let result = provider.list_models(&ctx).await;
    assert!(
        matches!(result, Err(ProviderError::Unsupported(ref method)) if method == "list_models"),
        "expected Err(ProviderError::Unsupported(\"list_models\")), got {result:?}"
    );
}
