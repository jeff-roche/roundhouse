use roundhouse_secrets::secret::ControlLaneToken;

fn main() {
    // must fail: mint_within_control_lane is pub(crate), unreachable from an
    // external crate (a trybuild case compiles as its own separate crate)
    let _ = ControlLaneToken::mint_within_control_lane();
}
