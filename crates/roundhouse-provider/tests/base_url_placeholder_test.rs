//! Fix-round-2 Fix 3 (hardening): `profile/schema.rs`'s `Defaults::base_url`
//! doc comment requires "a real per-provider value (never a placeholder)"
//! on every profile, and `databricks.toml`/`azure-openai.toml`/
//! `microsoft-foundry.toml` correctly follow the `.invalid` placeholder
//! convention for hosts this crate cannot know ahead of time (RFC 2606
//! reserves `.invalid` as guaranteed-unresolvable, so a placeholder there
//! can never accidentally become a real, first-come-registerable domain).
//! But `build.rs` only validates that every profile *deserializes* --
//! nothing mechanically enforces either half of the convention. This exact
//! class of bug already shipped once this phase (two profiles defaulting to
//! a first-come-registerable `my-resource.<vendor>` host), which is the
//! "concrete basis" REALITY-CORRECTIONS asks for before adding a new gate.
//!
//! Modeled on `transport_error_redaction_test.rs`'s discipline (that file's
//! own doc comment: a hand-maintained invariant "has been wrong three audit
//! rounds running"): a mechanical scan over every real `profiles/*.toml`
//! file, plus an explicit per-file allowlist for every host that is a real,
//! known vendor (or intentionally-local) host rather than a placeholder --
//! and a stale allowlist entry (one that no longer matches any profile's
//! actual `base_url` host) fails the build too, so the list cannot rot into
//! blanket permission.
//!
//! Fix round 4, Fix 4: the host check alone left the schema doc comment's
//! "never a placeholder" promise only half enforced -- `vertex-anthropic.
//! toml` and `vertex-gemini.toml` both carry a literal `PROJECT_ID` segment
//! in the URL *path* (host is real Google infrastructure; no squatting risk,
//! the failure mode is a 403 from a real Google endpoint, and the
//! placeholder is intentional and documented on both profiles' own
//! `base_url` comments). The test below now also scans every path segment
//! for the all-caps-with-underscores shape (`[A-Z_]{4,}`) a placeholder like
//! `PROJECT_ID` takes, via its own allowlist with the same
//! cannot-silently-rot discipline as the host allowlist above it.

use roundhouse_provider::profile::ProviderProfile;
use std::path::Path;

/// One profile file whose `base_url` host is a real, known-good host (a
/// vendor's real API host, or an intentionally-local runtime default) --
/// not a `.invalid` placeholder.
struct AllowlistEntry {
    /// Filename under `profiles/`, e.g. `"openai-responses.toml"`.
    file: &'static str,
    /// The exact host `url::Url::host_str()` must return for this profile's
    /// `base_url`.
    host: &'static str,
    /// Why this is a real, resolvable-or-intentionally-local host, not a
    /// placeholder that could be first-come-registered out from under this
    /// crate.
    reason: &'static str,
}

const ALLOWLIST: &[AllowlistEntry] = &[
    AllowlistEntry {
        file: "aws-open-responses.toml",
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        reason: "real AWS Bedrock host, same host family as bedrock-converse.toml",
    },
    AllowlistEntry {
        file: "bedrock-converse.toml",
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        reason: "real AWS Bedrock host",
    },
    AllowlistEntry {
        file: "bedrock-anthropic-messages.toml",
        host: "bedrock-mantle.us-east-1.api.aws",
        reason: "real AWS Bedrock Anthropic-Messages-compatible host (Task 15 correction)",
    },
    AllowlistEntry {
        file: "groq.toml",
        host: "api.groq.com",
        reason: "real Groq API host",
    },
    AllowlistEntry {
        file: "fireworks.toml",
        host: "api.fireworks.ai",
        reason: "real Fireworks API host",
    },
    AllowlistEntry {
        file: "deepinfra-anthropic.toml",
        host: "api.deepinfra.com",
        reason: "real DeepInfra API host",
    },
    AllowlistEntry {
        file: "deepinfra.toml",
        host: "api.deepinfra.com",
        reason: "real DeepInfra API host",
    },
    AllowlistEntry {
        file: "openai-responses.toml",
        host: "api.openai.com",
        reason: "real OpenAI API host",
    },
    AllowlistEntry {
        file: "openai.toml",
        host: "api.openai.com",
        reason: "real OpenAI API host",
    },
    AllowlistEntry {
        file: "openrouter-anthropic.toml",
        host: "openrouter.ai",
        reason: "real OpenRouter API host",
    },
    AllowlistEntry {
        file: "openrouter-responses.toml",
        host: "openrouter.ai",
        reason: "real OpenRouter API host",
    },
    AllowlistEntry {
        file: "openrouter.toml",
        host: "openrouter.ai",
        reason: "real OpenRouter API host",
    },
    AllowlistEntry {
        file: "cohere-v2.toml",
        host: "api.cohere.com",
        reason: "real Cohere API host",
    },
    AllowlistEntry {
        file: "deepseek.toml",
        host: "api.deepseek.com",
        reason: "real DeepSeek API host",
    },
    AllowlistEntry {
        file: "mistral.toml",
        host: "api.mistral.ai",
        reason: "real Mistral API host",
    },
    AllowlistEntry {
        file: "ollama.toml",
        host: "localhost",
        reason: "intentionally-local self-hosted runtime default, not a registerable \
                 external domain -- localhost cannot be squatted",
    },
    AllowlistEntry {
        file: "sglang.toml",
        host: "localhost",
        reason: "intentionally-local self-hosted runtime default, not a registerable \
                 external domain",
    },
    AllowlistEntry {
        file: "lm-studio.toml",
        host: "localhost",
        reason: "intentionally-local self-hosted runtime default, not a registerable \
                 external domain",
    },
    AllowlistEntry {
        file: "vllm.toml",
        host: "localhost",
        reason: "intentionally-local self-hosted runtime default, not a registerable \
                 external domain",
    },
    AllowlistEntry {
        file: "llama-cpp.toml",
        host: "localhost",
        reason: "intentionally-local self-hosted runtime default, not a registerable \
                 external domain",
    },
    AllowlistEntry {
        file: "nvidia-nim.toml",
        host: "integrate.api.nvidia.com",
        reason: "real NVIDIA hosted-catalog API host",
    },
    AllowlistEntry {
        file: "nvidia-open-responses.toml",
        host: "integrate.api.nvidia.com",
        reason: "real NVIDIA hosted-catalog API host (see this profile's own IMPORTANT \
                 DIVERGENCE comment for the /v1/responses caveat)",
    },
    AllowlistEntry {
        file: "xai.toml",
        host: "api.x.ai",
        reason: "real xAI API host",
    },
    AllowlistEntry {
        file: "huggingface.toml",
        host: "router.huggingface.co",
        reason: "real Hugging Face router host",
    },
    AllowlistEntry {
        file: "vercel.toml",
        host: "ai-gateway.vercel.sh",
        reason: "real Vercel AI Gateway host",
    },
    AllowlistEntry {
        file: "google-genai.toml",
        host: "generativelanguage.googleapis.com",
        reason: "real Google Generative Language API host",
    },
    AllowlistEntry {
        file: "vertex-anthropic.toml",
        host: "aiplatform.googleapis.com",
        reason: "real Google Vertex AI platform host",
    },
    AllowlistEntry {
        file: "vertex-gemini.toml",
        host: "aiplatform.googleapis.com",
        reason: "real Google Vertex AI platform host (Task 17, same host family as \
                 vertex-anthropic.toml)",
    },
    AllowlistEntry {
        file: "gemini-generate-content-legacy.toml",
        host: "generativelanguage.googleapis.com",
        reason: "real Google Generative Language API host, same host as google-genai.toml \
                 (Task 17: a separate profile for EndpointMode::GenerateContent)",
    },
    AllowlistEntry {
        file: "qwen-anthropic.toml",
        host: "dashscope-intl.aliyuncs.com",
        reason: "real Alibaba DashScope (Qwen) API host",
    },
    AllowlistEntry {
        file: "qwen.toml",
        host: "dashscope-intl.aliyuncs.com",
        reason: "real Alibaba DashScope (Qwen) API host",
    },
    AllowlistEntry {
        file: "moonshot.toml",
        host: "api.moonshot.ai",
        reason: "real Moonshot AI API host",
    },
    AllowlistEntry {
        file: "cerebras.toml",
        host: "api.cerebras.ai",
        reason: "real Cerebras API host",
    },
    AllowlistEntry {
        file: "zai.toml",
        host: "api.z.ai",
        reason: "real Z.ai API host",
    },
    AllowlistEntry {
        file: "together.toml",
        host: "api.together.xyz",
        reason: "real Together AI API host",
    },
];

/// One profile file whose `base_url` *path* carries an intentional,
/// documented placeholder segment (all-caps-with-underscores, e.g.
/// `PROJECT_ID`) -- as opposed to the *host* allowlist above, which is
/// about hosts that could be squatted. A path placeholder carries no
/// squatting risk (the host is already a real, known vendor host, verified
/// by the host check above); it exists only so the schema doc comment's
/// "never a placeholder" promise stays mechanically enforced rather than
/// silently half-true.
struct PathPlaceholderAllowlistEntry {
    /// Filename under `profiles/`, e.g. `"vertex-anthropic.toml"`.
    file: &'static str,
    /// The exact path segment, e.g. `"PROJECT_ID"`.
    segment: &'static str,
    /// Why this placeholder is intentional and documented, not an oversight.
    reason: &'static str,
}

const PATH_PLACEHOLDER_ALLOWLIST: &[PathPlaceholderAllowlistEntry] = &[
    PathPlaceholderAllowlistEntry {
        file: "vertex-anthropic.toml",
        segment: "PROJECT_ID",
        reason: "Vertex's project id is deployment-specific and cannot be known ahead of \
                 time; this profile's base_url comment documents it as always overridden \
                 via ROUNDHOUSE_VERTEX_ANTHROPIC_BASE_URL. Host is real Google \
                 infrastructure -- no squatting risk, failure mode is a real 403.",
    },
    PathPlaceholderAllowlistEntry {
        file: "vertex-gemini.toml",
        segment: "PROJECT_ID",
        reason: "Same intentional, documented placeholder as vertex-anthropic.toml (Task \
                 17, same host family) -- see that entry's reason.",
    },
];

/// `[A-Z_]{4,}` -- the shape a placeholder path segment like `PROJECT_ID`
/// takes: long enough (4+ chars) that a real short uppercase path token
/// (there are none among today's profiles, but e.g. a hypothetical `V1`
/// version segment) can't false-positive.
fn looks_like_a_placeholder_path_segment(segment: &str) -> bool {
    segment.len() >= 4 && segment.chars().all(|c| c.is_ascii_uppercase() || c == '_')
}

/// Fix-round-2 Fix 3 (host), extended by fix round 4 Fix 4 (path): every
/// profile's `base_url` host is either a known, real vendor/local-runtime
/// host (individually allowlisted with a reason) or ends in `.invalid` (the
/// mechanically-recognizable placeholder convention) -- and every path
/// segment shaped like a placeholder (`[A-Z_]{4,}`, e.g. `PROJECT_ID`) is
/// either absent or individually allowlisted with a reason. A profile whose
/// host is neither known-real nor `.invalid` -- e.g. a first-come-
/// registerable `my-resource.<vendor>` guess -- fails this test, and so does
/// an un-allowlisted placeholder-shaped path segment.
#[test]
fn every_profile_base_url_host_is_a_known_vendor_host_or_dot_invalid() {
    for entry in ALLOWLIST {
        assert!(
            !entry.reason.is_empty(),
            "ALLOWLIST entry for {} (host {:?}) must state why it's exempt",
            entry.file,
            entry.host
        );
    }
    for entry in PATH_PLACEHOLDER_ALLOWLIST {
        assert!(
            !entry.reason.is_empty(),
            "PATH_PLACEHOLDER_ALLOWLIST entry for {} (segment {:?}) must state why it's exempt",
            entry.file,
            entry.segment
        );
    }

    let profiles_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
    let mut used = vec![false; ALLOWLIST.len()];
    let mut path_used = vec![false; PATH_PLACEHOLDER_ALLOWLIST.len()];
    let mut violations = Vec::new();
    let mut checked = 0usize;

    for entry in walkdir::WalkDir::new(&profiles_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.path().extension().is_some_and(|e| e == "toml") {
            continue;
        }
        let file_name = entry
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let contents = std::fs::read_to_string(entry.path()).unwrap();
        let profile: ProviderProfile = toml::from_str(&contents)
            .unwrap_or_else(|e| panic!("{file_name}: failed to parse profile: {e}"));
        let url = url::Url::parse(&profile.defaults.base_url).unwrap_or_else(|e| {
            panic!(
                "{file_name}: invalid base_url {:?}: {e}",
                profile.defaults.base_url
            )
        });
        let host = url.host_str().unwrap_or_else(|| {
            panic!(
                "{file_name}: base_url {:?} has no host",
                profile.defaults.base_url
            )
        });
        checked += 1;

        if !host.ends_with(".invalid") {
            match ALLOWLIST
                .iter()
                .enumerate()
                .find(|(_, a)| a.file == file_name && a.host == host)
            {
                Some((idx, _)) => used[idx] = true,
                None => violations.push(format!(
                    "{file_name}: base_url host {host:?} is neither `.invalid` nor in \
                     ALLOWLIST -- if this is a real vendor host, add it with a reason; if \
                     it is a placeholder, use a `.invalid` host instead"
                )),
            }
        }

        for segment in url.path_segments().into_iter().flatten() {
            if !looks_like_a_placeholder_path_segment(segment) {
                continue;
            }
            match PATH_PLACEHOLDER_ALLOWLIST
                .iter()
                .enumerate()
                .find(|(_, a)| a.file == file_name && a.segment == segment)
            {
                Some((idx, _)) => path_used[idx] = true,
                None => violations.push(format!(
                    "{file_name}: base_url path segment {segment:?} looks like a placeholder \
                     ([A-Z_]{{4,}}) but is not in PATH_PLACEHOLDER_ALLOWLIST -- if this is an \
                     intentional, documented placeholder, add it with a reason; otherwise fix \
                     the path"
                )),
            }
        }
    }

    assert!(
        checked > 0,
        "found no profiles/*.toml files under {profiles_dir:?} -- test wiring is broken"
    );

    assert!(
        violations.is_empty(),
        "found profile base_url host/path placeholder violation(s):\n{}",
        violations.join("\n")
    );

    let stale: Vec<&str> = ALLOWLIST
        .iter()
        .zip(&used)
        .filter(|(_, used)| !**used)
        .map(|(a, _)| a.file)
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWLIST entries that no longer match any profile's actual base_url host \
         (stale -- the host changed, or the profile was renamed/removed): {stale:?}"
    );

    let stale_path: Vec<&str> = PATH_PLACEHOLDER_ALLOWLIST
        .iter()
        .zip(&path_used)
        .filter(|(_, used)| !**used)
        .map(|(a, _)| a.file)
        .collect();
    assert!(
        stale_path.is_empty(),
        "PATH_PLACEHOLDER_ALLOWLIST entries that no longer match any profile's actual \
         base_url path (stale -- the path changed, or the profile was renamed/removed): \
         {stale_path:?}"
    );
}
