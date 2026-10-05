use super::Session;
use crate::{
    confirm::confirm,
    counterexample::{AnalyzeOutput, EnvResult, Uid},
    queries::{Query, query_counterexample},
};
use cgw_abi::OpError;

pub(super) async fn check(
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
