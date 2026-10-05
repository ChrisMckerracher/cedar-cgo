use super::{Input, Session, environment::selected_environments};
use crate::{State, counterexample::Uid, solver::HostSolver};
use cedar_policy_symcc::{CedarSymCompiler, CompiledSchema};
use cgw_abi::{Callback, OpError, parse_schema};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn open(state: &mut State, input: Input) -> Result<Value, OpError> {
    if state.session.is_some() {
        return Err(OpError::msg("input", "compiled session is already open"));
    }
    let schema = parse_schema(
        &input
            .schema
            .ok_or_else(|| OpError::msg("input", "missing session schema"))?,
    )?;
    let environments = selected_environments(&schema, input.environments)?;
    let compiled_schema = CompiledSchema::new(&schema).map_err(|e| OpError::new("schema", &e))?;
    let symbolic_environments = environments
        .iter()
        .map(|env| {
            compiled_schema
                .sym_env(env)
                .map_err(|e| OpError::new("schema", &e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let projected:Vec<_>=environments.iter().map(|env|json!({"principal_type":env.principal().to_string(),"action":Uid::from(env.action()),"resource_type":env.resource().to_string()})).collect();
    let compiler = CedarSymCompiler::new(HostSolver::new(Callback::default()))
        .map_err(|e| OpError::new("solver", &e))?;
    state.session = Some(Session {
        schema,
        environments,
        symbolic_environments,
        compiler,
        entries: BTreeMap::new(),
        next_handle: 1,
    });
    Ok(json!({"environments":projected}))
}
