//! Compiles dependency-free `roundhouse-config` policy syntax into private
//! executable rules. Keeping this authority here prevents config consumers
//! from forging a `CompiledRule`.

use crate::engine::{CompiledRule, Outcome, Predicate, RuleId, Scope};
use roundhouse_config::{ConfigScope, PolicyLayer, PolicyRuleOutcome};

#[derive(Debug, thiserror::Error)]
pub enum PolicyConfigError {
    #[error("policy rule `{0}` has an empty id")]
    EmptyId(String),
    #[error("policy rule `{0}` names a non-absolute read path")]
    NonAbsolutePath(String),
}

pub fn compile_policy_layers(
    layers: Vec<PolicyLayer>,
) -> Result<Vec<CompiledRule>, PolicyConfigError> {
    let mut compiled = Vec::new();
    for layer in layers {
        let scope = match layer.scope {
            ConfigScope::Builtin => Scope::Builtin,
            ConfigScope::UserGlobal => Scope::UserGlobal,
            ConfigScope::Project => Scope::Project,
            ConfigScope::Workspace => Scope::Workspace,
        };
        for rule in layer.file.rule {
            if rule.id.is_empty() {
                return Err(PolicyConfigError::EmptyId(rule.id));
            }
            if !rule.read.is_absolute() {
                return Err(PolicyConfigError::NonAbsolutePath(rule.id));
            }
            let outcome = match rule.outcome {
                PolicyRuleOutcome::Allow => Outcome::Allow,
                PolicyRuleOutcome::Ask => Outcome::Ask,
                PolicyRuleOutcome::Deny => Outcome::Deny,
            };
            let order = compiled.len();
            compiled.push(CompiledRule::new(
                scope,
                outcome,
                Predicate::FsExact {
                    op: crate::FsOp::Read,
                    path: rule.read,
                },
                order,
                RuleId(rule.id),
            ));
        }
    }
    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FsOp, PolicyEngine, TaskParams};
    use std::path::PathBuf;

    #[test]
    fn an_exact_read_rule_allows_only_its_declared_path() {
        let allowed = PathBuf::from("/workspace/allowed.txt");
        let rules = compile_policy_layers(vec![PolicyLayer {
            scope: ConfigScope::UserGlobal,
            path: PathBuf::from("/operator/policy.toml"),
            contents: String::new(),
            file: roundhouse_config::PolicyFile {
                rule: vec![roundhouse_config::PolicyRule {
                    id: "read-allowed".to_string(),
                    outcome: PolicyRuleOutcome::Allow,
                    read: allowed.clone(),
                }],
            },
        }])
        .unwrap();
        let policy = PolicyEngine::from_rules(rules);
        let params = |path: PathBuf| TaskParams::Fs {
            op: FsOp::Read,
            canonical: Ok(path.clone()),
            path,
        };

        assert_eq!(policy.decide(&params(allowed)).outcome, Outcome::Allow);
        assert_eq!(
            policy
                .decide(&params(PathBuf::from("/workspace/outside.txt")))
                .outcome,
            Outcome::Ask,
            "an undeclared read must retain the engine's fail-closed ask default"
        );
    }
}
