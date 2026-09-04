//! The union of "always present" keys and "profile-permitted optional" keys
//! for one codec+profile combination. §9.10's "generic property test that no
//! field outside the resolved `serialize_only` mask ever appears in the
//! encoded body" (the Kimi regression test) is implemented once here and
//! reused by every codec's `ConformanceCase`.

/// A permitted-keys mask for one encoded wire body. `mandatory` and
/// `allowed` are checked identically by [`SerializeOnlyMask::permits`] — the
/// distinction exists so a subject's mask reads as documentation of which
/// fields are *always* sent versus merely *may* be sent, not because the
/// check treats them differently.
#[derive(Debug, Clone, Default)]
pub struct SerializeOnlyMask {
    pub mandatory: Vec<String>,
    pub allowed: Vec<String>,
}

impl SerializeOnlyMask {
    pub fn permits(&self, key: &str) -> bool {
        self.mandatory.iter().any(|k| k == key) || self.allowed.iter().any(|k| k == key)
    }
}

/// Recursively flattens a JSON object's keys into dot-joined paths, so a
/// nested shape (e.g. `generationConfig.temperature`) is checked at the
/// leaf, not just at the top level. Array elements are walked too (an array
/// of objects still has keys worth checking), but array indices are not
/// part of the path — every element at a given array position shares the
/// same mask entry.
pub fn flatten_object_keys(value: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                out.push(path.clone());
                flatten_object_keys(v, &path, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                flatten_object_keys(item, prefix, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn permits_mandatory_and_allowed_keys() {
        let mask = SerializeOnlyMask {
            mandatory: vec!["model".into()],
            allowed: vec!["temperature".into()],
        };
        assert!(mask.permits("model"));
        assert!(mask.permits("temperature"));
        assert!(!mask.permits("frobnicate"));
    }

    #[test]
    fn flattens_nested_object_keys_as_dot_paths() {
        let value = json!({
            "model": "x",
            "generationConfig": {
                "temperature": 0.5,
                "topP": 0.9,
            }
        });
        let mut keys = Vec::new();
        flatten_object_keys(&value, "", &mut keys);
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "generationConfig".to_string(),
                "generationConfig.temperature".to_string(),
                "generationConfig.topP".to_string(),
                "model".to_string(),
            ]
        );
    }

    #[test]
    fn flattens_keys_inside_arrays_without_index_in_the_path() {
        let value = json!({
            "messages": [
                { "role": "user", "content": "hi" },
                { "role": "assistant", "content": "hey" }
            ]
        });
        let mut keys = Vec::new();
        flatten_object_keys(&value, "", &mut keys);
        keys.sort();
        keys.dedup();
        assert_eq!(
            keys,
            vec![
                "messages".to_string(),
                "messages.content".to_string(),
                "messages.role".to_string(),
            ]
        );
    }
}
