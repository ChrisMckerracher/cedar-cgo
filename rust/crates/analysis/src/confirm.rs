use crate::{counterexample::*, queries::Query};
use cedar_policy::{Authorizer, Decision, PolicySet};
use cedar_policy_symcc::Env;
use cgw_abi::OpError;

// For one original policy, a determining reason identifies a native match for either effect.
fn policy_evaluation(response: &cedar_policy::Response) -> PolicyEvaluation {
    let matched = response.diagnostics().reason().next().is_some();
    let errors = response
        .diagnostics()
        .errors()
        .map(|error| match error {
            cedar_policy::AuthorizationError::PolicyEvaluationError(error) => EvaluationError {
                policy_id: AsRef::<str>::as_ref(error.policy_id()).to_owned(),
                message: cgw_abi::diagnostics::render(error.inner()),
            },
        })
        .collect();
    PolicyEvaluation { matched, errors }
}

fn decision_name(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

/// Reject solver counterexamples that Cedar's concrete authorizer cannot reproduce.
pub(crate) fn confirm(
    query: Query,
    env: &Env,
    a: &PolicySet,
    b: &PolicySet,
) -> Result<Counterexample, OpError> {
    let authorizer = Authorizer::new();
    let first = authorizer.is_authorized(&env.request, a, &env.entities);
    let second = authorizer.is_authorized(&env.request, b, &env.entities);
    let da = first.decision();
    let db = second.decision();
    let ea = policy_evaluation(&first);
    let eb = policy_evaluation(&second);
    let genuine = match query {
        Query::Implies => da == Decision::Allow && db == Decision::Deny,
        Query::Equivalent => da != db,
        Query::Disjoint => da == Decision::Allow && db == Decision::Allow,
        Query::NeverErrors => !ea.errors.is_empty(),
        Query::AlwaysMatches => !ea.matched,
        Query::NeverMatches => ea.matched,
        Query::MatchesEquivalent => ea.matched != eb.matched,
        Query::MatchesImplies => ea.matched && !eb.matched,
        Query::MatchesDisjoint => ea.matched && eb.matched,
    };
    if !genuine {
        return Err(OpError::msg(
            "unconfirmed_counterexample",
            format!(
                "Cedar's authorizer does not confirm the solver's counterexample \
                 (a: {}, b: {}): {}",
                decision_name(da),
                decision_name(db),
                env.request
            ),
        ));
    }
    Ok(Counterexample {
        request: serialize_request(&env.request)?,
        entities: serialize_entities(&env.entities)?,
        text: env.request.to_string(),
        a_decision: decision_name(da),
        b_decision: decision_name(db),
        a_evaluation: query.singleton().then_some(ea),
        b_evaluation: (query.singleton() && !query.unary()).then_some(eb),
    })
}
