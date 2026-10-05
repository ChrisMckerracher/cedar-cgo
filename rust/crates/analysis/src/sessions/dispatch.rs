use super::{Input, Session};
use cgw_abi::OpError;
use serde_json::{Value, json};

pub(super) fn dispatch(input: Input, session: &mut Session) -> Result<Value, OpError> {
    match input.operation.as_str() {
        "compile" => super::compile::compile(session, input.policies),
        "release" => {
            let handle = input
                .handle
                .ok_or_else(|| OpError::msg("input", "missing handle"))?;
            session
                .entries
                .remove(&handle)
                .ok_or_else(|| OpError::msg("handle", "unknown or released handle"))?;
            Ok(json!({"released":true}))
        }
        "check" => {
            let query = input
                .query
                .ok_or_else(|| OpError::msg("input", "missing query"))?;
            let first = input
                .first
                .ok_or_else(|| OpError::msg("input", "missing first handle"))?;
            let second = input
                .second
                .ok_or_else(|| OpError::msg("input", "missing second handle"))?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(|e| OpError::msg("internal", e.to_string()))?;
            let report = runtime.block_on(super::check::check(session, query, first, second))?;
            Ok(json!({"report":report}))
        }
        _ => Err(OpError::msg("input", "unknown compiled session operation")),
    }
}
