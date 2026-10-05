//! Direct native optimized SymCC queries and property-specific concrete replay.
use cedar_policy::{Authorizer, Decision, PolicySet, Schema};
use cedar_policy_symcc::{
    CedarSymCompiler, CompiledPolicy, CompiledPolicySet, solver::LocalSolver,
};
use serde_json::{Value, json};
use std::io::{self, Read};

fn policy_source(case: &Value, field: &str) -> PolicySet {
    let source = case[field].as_str().unwrap();
    if case[format!("{field}_format")] == "json" {
        PolicySet::from_json_str(source).unwrap()
    } else {
        source.parse().unwrap()
    }
}

fn evaluation(response: &cedar_policy::Response) -> Value {
    let errors: Vec<_> = response
        .diagnostics()
        .errors()
        .map(|error| match error {
            cedar_policy::AuthorizationError::PolicyEvaluationError(error) => json!({
                "policy_id": AsRef::<str>::as_ref(error.policy_id()),
                "message": error.inner().to_string(),
            }),
        })
        .collect();
    json!({"matched":response.diagnostics().reason().next().is_some(),"errors":errors})
}

mod proof;

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let input: Value = serde_json::from_str(&text).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let results = runtime.block_on(async {
        let mut results = Vec::new();
        for case in input.as_array().unwrap() {
            results.push(proof::fixture(case).await);
        }
        results
    });
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
