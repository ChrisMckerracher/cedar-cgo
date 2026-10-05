use crate::{
    State,
    queries::{CompiledInput, Query},
    solver::HostSolver,
};
use cedar_policy::{PolicySet, RequestEnv, Schema};
use cedar_policy_symcc::{CedarSymCompiler, SymEnv};
use cgw_abi::{Callback, OpError, Source, parse_input};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

mod check;
mod compile;
mod construction;
mod dispatch;
mod environment;
#[cfg(test)]
mod tests;

const MAX_HANDLES: usize = 128;

struct Entry {
    original: PolicySet,
    compiled: Vec<CompiledInput>,
}

pub(crate) struct Session {
    schema: Schema,
    environments: Vec<RequestEnv>,
    symbolic_environments: Vec<SymEnv>,
    compiler: CedarSymCompiler<HostSolver>,
    entries: BTreeMap<u64, Entry>,
    next_handle: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    principal_type: String,
    action: Value,
    resource_type: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    operation: String,
    schema: Option<Source>,
    environments: Option<Vec<Environment>>,
    policies: Option<Source>,
    first: Option<u64>,
    second: Option<u64>,
    handle: Option<u64>,
    query: Option<Query>,
}

pub(crate) fn execute(
    state: &mut State,
    bytes: &[u8],
    callback: Callback,
) -> Result<Value, OpError> {
    let input: Input = parse_input(bytes)?;
    if input.operation == "open" {
        return construction::open(state, input);
    }
    let session = state
        .session
        .as_mut()
        .ok_or_else(|| OpError::msg("session_closed", "compiled session is not open"))?;
    session.compiler.solver_mut().bind(callback);
    let result = dispatch::dispatch(input, session);
    session.compiler.solver_mut().bind(Callback::default());
    // A solver failure invalidates its terms and buffered transport state.
    if result
        .as_ref()
        .is_err_and(|e| matches!(e.kind, "solver" | "internal" | "unconfirmed_counterexample"))
    {
        state.session = None;
    }
    result
}
