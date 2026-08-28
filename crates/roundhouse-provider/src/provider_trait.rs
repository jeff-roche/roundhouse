use crate::ir::{Capabilities, ChatRequest, ChatStream, ModelId, ModelInfo, Plan, ProviderError, RequestCtx, TokenCount};
use std::future::Future;
use std::pin::Pin;

/// Boxed futures, not `async_trait` — §9.4: "the registry is
/// `HashMap<ProviderId, Arc<dyn Provider>>` and retry/fallback middleware
/// are decorators over it, so object safety is non-negotiable."
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Provider: Send + Sync + 'static {
    fn capabilities(&self, model: &ModelId) -> Capabilities;

    /// Pure — no I/O, just validates and plans the request shape.
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError>;

    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>>;

    fn count_tokens<'a>(
        &'a self,
        req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>>;

    fn list_models<'a>(&'a self, _ctx: &'a RequestCtx) -> BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async { Err(ProviderError::Unsupported("list_models".into())) })
    }
}
