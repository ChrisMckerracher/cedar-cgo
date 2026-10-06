use super::{Result, inputs::Loaded};
use cedar_policy::{Decision, Request, Response};
use std::hint::black_box;

fn check(response: &Response) {
    assert_eq!(response.decision(), Decision::Allow);
    assert_eq!(response.diagnostics().errors().count(), 0);
    let reasons: Vec<_> = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    assert_eq!(reasons, ["policy1"]);
}

pub(super) fn decision(loaded: &Loaded, request: &Request) -> Result<()> {
    let response = loaded
        .authorizer
        .is_authorized(request, &loaded.policies, &loaded.entities);
    check(&response);
    black_box(response);
    Ok(())
}

pub(super) fn authorize(loaded: &Loaded, request: &Request) -> Result<()> {
    let response = loaded
        .authorizer
        .is_authorized(request, &loaded.policies, &loaded.entities);
    check(&response);
    let mut reasons: Vec<_> = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    reasons.sort_unstable();
    black_box(serde_json::to_vec(&serde_json::json!({
        "decision": "allow", "reasons": reasons, "errors": []
    }))?);
    Ok(())
}
