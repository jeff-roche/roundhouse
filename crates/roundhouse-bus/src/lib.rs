#![forbid(unsafe_code)]

mod bus_trait;
mod types;

pub use bus_trait::Bus;
pub use types::{BusError, Undeliverable};
