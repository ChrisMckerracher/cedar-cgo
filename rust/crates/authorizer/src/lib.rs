//! Cedar operations share explicit native state across caller threads.

mod applicability;
mod authorize;
mod batched;
mod entity_store;
mod expressions;
mod format;
mod literals;
mod partial;
mod policies;
mod queries;
mod schemas;
mod slicing;
mod source_tokens;
mod state;
mod templates;
mod utilities;
mod validation;

use authorize::{AuthorizeInput, AuthorizeOutput, PolicyMessage, entity_uid};
use cgw_abi::{Callback, OpError};
use serde::Serialize;
use serde_json::Value;
pub use state::State;
use state::parse_entities;

fn project<T: Serialize>(result: Result<T, OpError>) -> Result<Value, OpError> {
    serde_json::to_value(result?).map_err(|e| OpError::msg("internal", e.to_string()))
}

/// Executes JSON operations using the supplied state and call-local callback.
pub fn execute(
    state: &mut State,
    operation: &str,
    bytes: &[u8],
    callback: Callback,
) -> Result<Value, OpError> {
    match operation.strip_prefix("cgw_").unwrap_or(operation) {
        "load" => project(state::load(state, bytes)),
        "authorize" => project(authorize::authorize(state, bytes)),
        "authorize_batched" => project(batched::authorize(state, bytes, callback)),
        "partial_authorize" => project(partial::partial_authorize(state, bytes)),
        "reauthorize" => project(partial::reauthorize(state, bytes)),
        "import_partial" => project(partial::import_partial(state, bytes)),
        "queries" => queries::execute(state, bytes),
        "entity_store" => entity_store::execute(bytes),
        "validate" => project(validation::validate(bytes)),
        "schema_warnings" => validation::schema_warnings(bytes),
        "policies" => project(policies::execute(bytes)),
        "expressions" => expressions::execute(bytes),
        "literals" => literals::execute(bytes),
        "applicability" => applicability::execute(bytes),
        "schemas" => schemas::execute(bytes),
        "utilities" => utilities::execute(bytes),
        "source_tokens" => source_tokens::execute(bytes),
        "templates" => project(templates::operate(bytes)),
        "format" => project(format::format(bytes)),
        "slice_entities" => project(slicing::slice(bytes)),
        _ => Err(OpError::msg("operation", "unknown authorizer operation")),
    }
}
