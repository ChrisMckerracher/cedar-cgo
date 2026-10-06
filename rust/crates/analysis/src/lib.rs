//! Native SymCC analysis uses explicit sessions and a host-owned solver.
//! Cedar's concrete authorizer checks every returned counterexample.

use cgw_abi::{Callback, OpError};
use serde_json::Value;

mod confirm;
mod counterexample;
mod queries;
mod sessions;
mod solver;
mod stateless;

/// Explicit analysis state can move between threads while calls remain serialized.
#[derive(Default)]
pub struct State {
    session: Option<sessions::Session>,
}

/// Binds callbacks only for this synchronous operation.
pub fn execute(
    state: &mut State,
    operation: &str,
    bytes: &[u8],
    callback: Callback,
) -> Result<Value, OpError> {
    match operation {
        "analyze" => serde_json::to_value(stateless::analyze(bytes, callback)?)
            .map_err(|e| OpError::msg("internal", e.to_string())),
        "compiled" => sessions::execute(state, bytes, callback),
        _ => Err(OpError::msg("input", "unknown analysis operation")),
    }
}
