use futures::future::BoxFuture;

use crate::transport::{
    chunk_body, stream_from_chunks, HttpRequest, HttpResponseStream, HttpTransport, TransportError,
};

/// A test double that replays a pre-recorded HTTP response body, split into
/// fixed-size chunks (for adversarial chunking tests), regardless of the
/// actual request received.
pub struct CassetteTransport {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub chunk_size: usize,
}

impl HttpTransport for CassetteTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async move {
            let chunks = chunk_body(self.body.clone(), self.chunk_size);
            Ok(HttpResponseStream {
                status: self.status,
                headers: self.headers.clone(),
                body: stream_from_chunks(chunks),
            })
        })
    }
}
