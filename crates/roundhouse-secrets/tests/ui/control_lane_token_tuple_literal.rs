use roundhouse_secrets::secret::ControlLaneToken;

fn main() {
    let _ = ControlLaneToken(()); // must fail: the field is private
}
