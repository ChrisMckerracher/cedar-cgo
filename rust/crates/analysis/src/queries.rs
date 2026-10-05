use crate::solver::HostSolver;
use cedar_policy::{PolicySet, Schema};
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicy, CompiledPolicySet, Env};
use cgw_abi::OpError;
use serde::Deserialize;

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Query {
    /// Every request that `a` allows, `b` allows too.
    Implies,
    /// `a` and `b` give the same decision on every request.
    Equivalent,
    Disjoint,
    NeverErrors,
    AlwaysMatches,
    NeverMatches,
    MatchesEquivalent,
    MatchesImplies,
    MatchesDisjoint,
}

impl Query {
    pub(crate) fn singleton(self) -> bool {
        matches!(
            self,
            Self::NeverErrors
                | Self::AlwaysMatches
                | Self::NeverMatches
                | Self::MatchesEquivalent
                | Self::MatchesImplies
                | Self::MatchesDisjoint
        )
    }
    pub(crate) fn unary(self) -> bool {
        matches!(
            self,
            Self::NeverErrors | Self::AlwaysMatches | Self::NeverMatches
        )
    }
}

// Compiled values own their native terms; query selection stays separate from compilation.
pub(crate) enum CompiledInput {
    Policy(CompiledPolicy),
    Set(CompiledPolicySet),
}

pub(crate) fn compile_input(
    set: &PolicySet,
    env: &cedar_policy::RequestEnv,
    schema: &Schema,
    singleton: bool,
    kind: &'static str,
) -> Result<CompiledInput, OpError> {
    if singleton {
        if set.templates().next().is_some() || set.policies().count() != 1 {
            return Err(OpError::msg(
                kind,
                "matching and error queries require one policy and no templates",
            ));
        }
        let policy = set
            .policies()
            .next()
            .ok_or_else(|| OpError::msg(kind, "missing policy"))?;
        CompiledPolicy::compile(policy, env, schema)
            .map(CompiledInput::Policy)
            .map_err(|e| OpError::new(kind, &e))
    } else {
        CompiledPolicySet::compile(set, env, schema)
            .map(CompiledInput::Set)
            .map_err(|e| OpError::new(kind, &e))
    }
}

pub(crate) async fn query_counterexample(
    compiler: &mut CedarSymCompiler<HostSolver>,
    query: Query,
    a: &CompiledInput,
    b: Option<&CompiledInput>,
) -> Result<Option<Env>, OpError> {
    use Query as Q;
    let result = match (query, a, b) {
        (Q::Implies, CompiledInput::Set(a), Some(CompiledInput::Set(b))) => {
            compiler.check_implies_with_counterexample_opt(a, b).await
        }
        (Q::Equivalent, CompiledInput::Set(a), Some(CompiledInput::Set(b))) => {
            compiler
                .check_equivalent_with_counterexample_opt(a, b)
                .await
        }
        (Q::Disjoint, CompiledInput::Set(a), Some(CompiledInput::Set(b))) => {
            compiler.check_disjoint_with_counterexample_opt(a, b).await
        }
        (Q::NeverErrors, CompiledInput::Policy(a), None) => {
            compiler.check_never_errors_with_counterexample_opt(a).await
        }
        (Q::AlwaysMatches, CompiledInput::Policy(a), None) => {
            compiler
                .check_always_matches_with_counterexample_opt(a)
                .await
        }
        (Q::NeverMatches, CompiledInput::Policy(a), None) => {
            compiler
                .check_never_matches_with_counterexample_opt(a)
                .await
        }
        (Q::MatchesEquivalent, CompiledInput::Policy(a), Some(CompiledInput::Policy(b))) => {
            compiler
                .check_matches_equivalent_with_counterexample_opt(a, b)
                .await
        }
        (Q::MatchesImplies, CompiledInput::Policy(a), Some(CompiledInput::Policy(b))) => {
            compiler
                .check_matches_implies_with_counterexample_opt(a, b)
                .await
        }
        (Q::MatchesDisjoint, CompiledInput::Policy(a), Some(CompiledInput::Policy(b))) => {
            compiler
                .check_matches_disjoint_with_counterexample_opt(a, b)
                .await
        }
        _ => {
            return Err(OpError::msg(
                "input",
                "compiled inputs do not match the query",
            ));
        }
    };
    result.map_err(|e| OpError::new("solver", &e))
}
