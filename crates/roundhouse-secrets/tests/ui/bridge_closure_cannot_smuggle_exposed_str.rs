use roundhouse_secrets::provider_bridge::expose_secret_for_provider_call;
use roundhouse_secrets::secret::Secret;

fn main() {
    // must fail: the closure's `&str` argument only lives for the
    // duration of the call — trying to hand it back out as the bridge
    // function's own return value (rather than only using it to compute
    // an owned result inside the closure) is a lifetime error, not just a
    // style violation. This is the compile-time proof that the exposed
    // material genuinely cannot escape the closure's scope as a borrowed
    // value.
    let secret = Secret::new("shh".to_string());
    let leaked: &str = expose_secret_for_provider_call(&secret, |exposed| exposed);
    println!("{leaked}");
}
