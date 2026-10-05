use crate::{
    confirm::confirm,
    counterexample::{AnalyzeOutput, EnvResult, Uid},
    queries::{Query, compile_input, query_counterexample},
    solver::HostSolver,
};
use cedar_policy::{PolicySet, Schema};
use cedar_policy_symcc::CedarSymCompiler;
use cgw_abi::{Callback, OpError, Source, parse_input, parse_policies, parse_schema};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyzeInput {
    schema: Source,
    a: Source,
    b: Source,
    query: Query,
}

async fn analyze_async(
    input: &AnalyzeInput,
    schema: &Schema,
    a: &PolicySet,
    b: &PolicySet,
    callback: Callback,
) -> Result<AnalyzeOutput, OpError> {
    let solver_err = |e: cedar_policy_symcc::err::Error| OpError::new("solver", &e);
    let mut compiler = CedarSymCompiler::new(HostSolver::new(callback)).map_err(solver_err)?;
    let mut results = Vec::new();
    for env in schema.request_envs() {
        let ca = compile_input(a, &env, schema, input.query.singleton(), "compile_a")?;
        let cb = if input.query.unary() {
            None
        } else {
            Some(compile_input(
                b,
                &env,
                schema,
                input.query.singleton(),
                "compile_b",
            )?)
        };
        let cex = query_counterexample(&mut compiler, input.query, &ca, cb.as_ref()).await?;
        let counterexample = cex
            .as_ref()
            .map(|env| confirm(input.query, env, a, b))
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

pub(crate) fn analyze(bytes: &[u8], callback: Callback) -> Result<AnalyzeOutput, OpError> {
    let input: AnalyzeInput = parse_input(bytes)?;
    let schema = parse_schema(&input.schema)?;
    let a = parse_policies(&input.a)?;
    let b = parse_policies(&input.b)?;
    // Input contracts also apply when the schema has no request environments.
    for (set, kind) in [(&a, "compile_a"), (&b, "compile_b")] {
        if input.query.unary() && kind == "compile_b" {
            continue;
        }
        if set.templates().next().is_some() {
            return Err(OpError::msg(
                kind,
                "symbolic queries require static policies and no templates",
            ));
        }
        if input.query.singleton() && set.policies().count() != 1 {
            return Err(OpError::msg(
                kind,
                "matching and error queries require one policy and no templates",
            ));
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| OpError::msg("internal", e.to_string()))?;
    runtime.block_on(analyze_async(&input, &schema, &a, &b, callback))
}
