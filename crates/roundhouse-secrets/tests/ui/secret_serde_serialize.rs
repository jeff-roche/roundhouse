use roundhouse_secrets::secret::Secret;

fn main() {
    let s = Secret::new("shh".to_string());
    let _ = serde_json::to_string(&s); // must fail to compile: no Serialize impl
}
