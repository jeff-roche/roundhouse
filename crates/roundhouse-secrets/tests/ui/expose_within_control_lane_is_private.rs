use roundhouse_secrets::secret::Secret;

fn main() {
    // must fail: expose_within_control_lane is pub(crate), unreachable from
    // an external crate (a trybuild case compiles as its own separate
    // crate) — the only sanctioned callers are this crate's own
    // provider_bridge/mcp_bridge modules.
    let s = Secret::new("shh".to_string());
    let _ = s.expose_within_control_lane(|x| x.to_string());
}
