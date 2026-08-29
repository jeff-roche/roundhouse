use std::collections::HashMap;

/// Describes the kind of content block being streamed, determined at `BlockStart`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// A text response block.
    Text,
    /// A tool use (function call) block.
    ToolUse {
        /// The name of the tool being called.
        name: String,
        /// Optional provider-specific identifier for the tool.
        provider_id: Option<String>,
    },
    /// A thinking/reasoning block (when supported by the provider).
    Thinking,
}

/// A delta received in a `BlockDelta` event, representing incremental changes to a block.
#[derive(Clone, Debug)]
pub enum BlockDelta {
    /// Incremental text content.
    Text(String),
    /// Incremental tool argument JSON fragment.
    ToolArgsFragment(String),
    /// Thinking block delta with optional signature.
    Thinking {
        /// Incremental thinking text.
        text: String,
        /// Optional signature (provider-specific, e.g., Anthropic thinking signature).
        signature: Option<String>,
    },
}

/// Streaming event representing a chunk of a provider's response stream.
pub enum StreamEvent {
    /// Start of a new content block at the given index with the specified kind.
    BlockStart { index: u32, kind: BlockKind },
    /// Incremental delta for the block at the given index.
    BlockDelta { index: u32, delta: BlockDelta },
    /// End of the block at the given index.
    BlockStop { index: u32 },
    /// Token usage update (any or all fields may be present).
    UsageDelta {
        /// Input tokens consumed so far (if available).
        input_tokens: Option<u64>,
        /// Output tokens generated so far (if available).
        output_tokens: Option<u64>,
        /// Cache read tokens (if available).
        cache_read_tokens: Option<u64>,
    },
    /// End of the entire message stream.
    MessageStop,
}

/// Maps native provider keys (e.g., OpenAI tool-call IDs as strings, Anthropic content block indices)
/// to stable `u32` indices for decode normalization.
///
/// Each provider uses its own keying scheme for blocks in a stream. This struct normalizes those
/// schemes to a single stable index space by assigning indices in first-seen order.
#[derive(Clone, Debug)]
pub struct DeltaKeyer {
    /// Counter for the next index to assign.
    next_index: u32,
    /// Map from native keys to assigned indices.
    keys: HashMap<String, u32>,
}

impl DeltaKeyer {
    /// Creates a new empty keyer.
    pub fn new() -> Self {
        Self { next_index: 0, keys: HashMap::new() }
    }

    /// Maps a native key to a stable `u32` index.
    ///
    /// The first call with a given key assigns a new index (in ascending order starting from 0).
    /// Subsequent calls with the same key return the same index.
    ///
    /// # Arguments
    ///
    /// * `native_key` - The provider's native key for this block (e.g., OpenAI tool-call ID or
    ///   Anthropic content block index as a string).
    ///
    /// # Returns
    ///
    /// The stable index for this key.
    pub fn index_for(&mut self, native_key: &str) -> u32 {
        if let Some(&idx) = self.keys.get(native_key) {
            return idx;
        }
        let idx = self.next_index;
        self.keys.insert(native_key.to_string(), idx);
        self.next_index += 1;
        idx
    }
}

impl Default for DeltaKeyer {
    fn default() -> Self {
        Self::new()
    }
}
