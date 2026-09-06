use roundhouse_policy::{CompiledRule, Outcome, Predicate, Scope};

fn main() {
    let _ = CompiledRule {
        scope: Scope::UserGlobal,
        outcome: Outcome::Allow,
        predicate: Predicate::program("read"),
        file_order: 0,
        id: roundhouse_policy::RuleId("forged".into()),
    };
}
