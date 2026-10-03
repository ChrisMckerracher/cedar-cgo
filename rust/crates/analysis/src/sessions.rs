use super::{
    AnalyzeOutput, CompiledInput, EnvResult, HostSolver, Query, Uid, confirm, query_counterexample,
};
use cedar_policy::{EntityUid, PolicySet, RequestEnv, Schema};
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicySet, CompiledSchema, SymEnv};
use cgw_abi::{OpError, Source, parse_input, parse_policies, parse_schema};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

const MAX_HANDLES: usize = 128;

struct Entry {
    original: PolicySet,
    compiled: Vec<CompiledInput>,
}

struct Session {
    schema: Schema,
    environments: Vec<RequestEnv>,
    symbolic_environments: Vec<SymEnv>,
    compiler: CedarSymCompiler<HostSolver>,
    entries: BTreeMap<u64, Entry>,
    next_handle: u64,
}

thread_local! {
    static STATE: RefCell<Option<Session>> = const { RefCell::new(None) };
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

fn selected_environments(
    schema: &Schema,
    selection: Option<Vec<Environment>>,
) -> Result<Vec<RequestEnv>, OpError> {
    let mut available: Vec<_> = schema.request_envs().collect();
    available.sort_by_key(|env| {
        (
            env.principal().to_string(),
            env.action().clone(),
            env.resource().to_string(),
        )
    });
    let Some(selection) = selection else {
        return Ok(available);
    };
    let mut seen = BTreeSet::new();
    selection
        .into_iter()
        .map(|selected| {
            let action =
                EntityUid::from_json(selected.action).map_err(|e| OpError::new("input", &e))?;
            let key = (
                selected.principal_type.clone(),
                action.clone(),
                selected.resource_type.clone(),
            );
            if !seen.insert(key) {
                return Err(OpError::msg("input", "duplicate request environment"));
            }
            available
                .iter()
                .find(|env| {
                    env.principal().to_string() == selected.principal_type
                        && env.action() == &action
                        && env.resource().to_string() == selected.resource_type
                })
                .cloned()
                .ok_or_else(|| OpError::msg("input", "unknown request environment"))
        })
        .collect()
}

fn open(input: Input) -> Result<Value, OpError> {
    if STATE.with(|state| state.borrow().is_some()) {
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
    let compiler =
        CedarSymCompiler::new(HostSolver::new()).map_err(|e| OpError::new("solver", &e))?;
    STATE.with(|state| {
        *state.borrow_mut() = Some(Session {
            schema,
            environments,
            symbolic_environments,
            compiler,
            entries: BTreeMap::new(),
            next_handle: 1,
        })
    });
    Ok(json!({"environments":projected}))
}

fn compile(session: &mut Session, source: Option<Source>) -> Result<Value, OpError> {
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

async fn check(
    session: &mut Session,
    query: Query,
    first: u64,
    second: u64,
) -> Result<AnalyzeOutput, OpError> {
    if !matches!(query, Query::Implies | Query::Equivalent | Query::Disjoint) {
        return Err(OpError::msg(
            "input",
            "compiled sessions support implication, equivalence, and disjointness",
        ));
    }
    let first = session
        .entries
        .get(&first)
        .ok_or_else(|| OpError::msg("handle", "unknown or released first handle"))?;
    let second = session
        .entries
        .get(&second)
        .ok_or_else(|| OpError::msg("handle", "unknown or released second handle"))?;
    let mut results = Vec::new();
    for (index, env) in session.environments.iter().enumerate() {
        let cex = query_counterexample(
            &mut session.compiler,
            query,
            &first.compiled[index],
            Some(&second.compiled[index]),
        )
        .await?;
        let counterexample = cex
            .as_ref()
            .map(|env| confirm(query, env, &first.original, &second.original))
            .transpose()?;
        results.push(EnvResult {
            principal_type: env.principal().to_string(),
            action: Uid::from(env.action()),
            resource_type: env.resource().to_string(),
            holds: counterexample.is_none(),
            counterexample,
        });
    }
    Ok(AnalyzeOutput { results })
}

fn dispatch(input: Input, session: &mut Session) -> Result<Value, OpError> {
    match input.operation.as_str() {
        "compile" => compile(session, input.policies),
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
            let report = runtime.block_on(check(session, query, first, second))?;
            Ok(json!({"report":report}))
        }
        _ => Err(OpError::msg("input", "unknown compiled session operation")),
    }
}

pub fn execute(bytes: &[u8]) -> Result<Value, OpError> {
    let input: Input = parse_input(bytes)?;
    if input.operation == "open" {
        return open(input);
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let result = dispatch(
            input,
            state
                .as_mut()
                .ok_or_else(|| OpError::msg("session_closed", "compiled session is not open"))?,
        );
        // Failed solver state cannot safely serve another reusable query.
        if result
            .as_ref()
            .is_err_and(|e| matches!(e.kind, "solver" | "internal" | "unconfirmed_counterexample"))
        {
            *state = None;
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(value: Value) -> Result<Value, OpError> {
        execute(&serde_json::to_vec(&value).unwrap())
    }
    fn open_session() {
        operation(json!({"operation":"open","schema":{"format":"cedar","text":"entity User; entity Doc; action view appliesTo { principal: User, resource: Doc, context: {} };"}})).unwrap();
    }
    fn compile_policy(text: &str) -> u64 {
        operation(json!({"operation":"compile","policies":{"format":"cedar","text":text}})).unwrap()
            ["handle"]
            .as_u64()
            .unwrap()
    }

    #[test]
    fn handles_are_monotonic_and_released() {
        open_session();
        STATE.with(|state| {
            let state = state.borrow();
            let session = state.as_ref().unwrap();
            assert_eq!(
                session.symbolic_environments[0],
                SymEnv::new(&session.schema, &session.environments[0]).unwrap()
            );
        });
        let first = compile_policy("permit(principal,action,resource);");
        operation(json!({"operation":"release","handle":first})).unwrap();
        assert_eq!(
            operation(json!({"operation":"release","handle":first}))
                .unwrap_err()
                .kind,
            "handle"
        );
        let second = compile_policy("permit(principal,action,resource);");
        assert!(second > first);
        assert_eq!(
            operation(
                json!({"operation":"check","query":"equivalent","first":first,"second":second})
            )
            .unwrap_err()
            .kind,
            "handle"
        );
        assert_eq!(operation(json!({"operation":"compile","policies":{"format":"cedar","text":"permit(principal == ?principal,action,resource);"}})).unwrap_err().kind,"compile_a");
        STATE.with(|state| assert_eq!(state.borrow().as_ref().unwrap().entries.len(), 1));
    }

    #[test]
    fn selection_rejects_unknown_and_duplicate_environments() {
        let schema = json!({"format":"cedar","text":"entity User; entity Doc; action view appliesTo { principal: User, resource: Doc, context: {} };"});
        let env = json!({"principal_type":"User","action":{"type":"Action","id":"view"},"resource_type":"Doc"});
        assert_eq!(
            operation(json!({"operation":"open","schema":schema,"environments":[env,env]}))
                .unwrap_err()
                .kind,
            "input"
        );
        let env = json!({"principal_type":"User","action":{"type":"Action","id":"missing"},"resource_type":"Doc"});
        assert_eq!(
            operation(json!({"operation":"open","schema":schema,"environments":[env]}))
                .unwrap_err()
                .kind,
            "input"
        );
    }

    #[test]
    fn handle_limit_recovers_after_release() {
        open_session();
        let mut first = 0;
        for index in 0..MAX_HANDLES {
            let handle = compile_policy("permit(principal,action,resource);");
            if index == 0 {
                first = handle;
            }
        }
        assert_eq!(operation(json!({"operation":"compile","policies":{"format":"cedar","text":"permit(principal,action,resource);"}})).unwrap_err().kind,"handle_limit");
        operation(json!({"operation":"release","handle":first})).unwrap();
        let next = compile_policy("permit(principal,action,resource);");
        assert!(next > MAX_HANDLES as u64);
    }

    #[test]
    fn repeated_queries_reuse_entries_and_solver_fault_invalidates() {
        operation(json!({"operation":"open","schema":{"format":"cedar","text":"entity User; entity Doc; action view appliesTo { principal: User, resource: Doc, context: {n: Long} };"}})).unwrap();
        let handle = compile_policy("permit(principal,action,resource) when {context.n < 0};");
        let different = compile_policy("permit(principal,action,resource) when {context.n <= -1};");
        super::super::test_solver::set_unsat(true);
        for _ in 0..3 {
            let response = operation(
                json!({"operation":"check","query":"equivalent","first":handle,"second":different}),
            )
            .unwrap();
            assert!(response["report"]["results"][0]["holds"].as_bool().unwrap());
        }
        STATE.with(|state| assert_eq!(state.borrow().as_ref().unwrap().entries.len(), 2));
        super::super::test_solver::set_unsat(false);
        assert_eq!(
            operation(
                json!({"operation":"check","query":"equivalent","first":handle,"second":different})
            )
            .unwrap_err()
            .kind,
            "solver"
        );
        assert_eq!(
            operation(json!({"operation":"release","handle":handle}))
                .unwrap_err()
                .kind,
            "session_closed"
        );
    }
}
