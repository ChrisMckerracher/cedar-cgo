use super::policy_error;
use cedar_policy::{Policy, PolicySet};
use cgw_abi::OpError;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub(super) struct PolicyOutput {
    id: String,
    effect: String,
    annotations: BTreeMap<String, String>,
    has_non_scope_constraint: bool,
    template_id: Option<String>,
    cedar: Option<String>,
    json: Value,
}

pub(super) fn policy_output(p: &Policy) -> Result<PolicyOutput, OpError> {
    Ok(PolicyOutput {
        id: AsRef::<str>::as_ref(p.id()).to_owned(),
        effect: p.effect().to_string(),
        annotations: p.annotations().map(|(k, v)| (k.into(), v.into())).collect(),
        has_non_scope_constraint: p.has_non_scope_constraint(),
        template_id: p
            .template_id()
            .map(|id| AsRef::<str>::as_ref(id).to_owned()),
        // Cedar text cannot preserve links, even when upstream renders a materialized body.
        cedar: if p.is_static() { p.to_cedar() } else { None },
        json: p.to_json().map_err(|e| policy_error(&e))?,
    })
}

#[derive(Serialize)]
pub(super) struct SetOutput {
    json: Value,
    cedar: Option<String>,
    policies: Vec<PolicyOutput>,
}

pub(super) fn set_output(set: PolicySet) -> Result<SetOutput, OpError> {
    let mut policies = set
        .policies()
        .map(policy_output)
        .collect::<Result<Vec<_>, _>>()?;
    policies.sort_by(|a, b| a.id.cmp(&b.id));
    // JSON-backed linked policies may render materialized bodies upstream; retain the link contract.
    let cedar = if policies.iter().any(|p| p.template_id.is_some()) {
        None
    } else {
        set.to_cedar()
    };
    Ok(SetOutput {
        json: set.to_json().map_err(|e| policy_error(&e))?,
        cedar,
        policies,
    })
}
