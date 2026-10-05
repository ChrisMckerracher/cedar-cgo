use super::{Entry, MAX_HANDLES, Session};
use crate::queries::CompiledInput;
use cedar_policy_symcc::CompiledPolicySet;
use cgw_abi::{OpError, Source, parse_policies};
use serde_json::{Value, json};

pub(super) fn compile(session: &mut Session, source: Option<Source>) -> Result<Value, OpError> {
    if session.entries.len() >= MAX_HANDLES {
        return Err(OpError::msg(
            "handle_limit",
            "compiled session has 128 active handles",
        ));
    }
    let original =
        parse_policies(&source.ok_or_else(|| OpError::msg("input", "missing policies"))?)?;
    if original.templates().next().is_some() {
        return Err(OpError::msg(
            "compile_a",
            "compiled policy sets cannot contain templates",
        ));
    }
    let compiled = session
        .environments
        .iter()
        .zip(&session.symbolic_environments)
        .map(|(env, symbolic)| {
            // CompiledSchema creates the default terms for this exact schema and environment.
            CompiledPolicySet::compile_with_custom_symenv(
                &original,
                env,
                &session.schema,
                symbolic.clone(),
            )
            .map(CompiledInput::Set)
            .map_err(|e| OpError::new("compile_a", &e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let handle = session.next_handle;
    let next = handle
        .checked_add(1)
        .ok_or_else(|| OpError::msg("handle_limit", "native handle IDs exhausted"))?;
    session.entries.insert(handle, Entry { original, compiled });
    session.next_handle = next;
    Ok(json!({"handle":handle}))
}
