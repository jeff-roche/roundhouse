use roundhouse_secrets::secret::Secret;

fn main() {
    let s = Secret::new("shh".to_string());
    println!("{:?}", s); // must fail to compile: no Debug impl
}
