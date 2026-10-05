use super::{
    policy_error,
    syntax::{Action, Scope, Syntax, action, principal, resource},
};
use cedar_policy::{Policy, PolicySet};
use cedar_policy_core::est;
use cgw_abi::OpError;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub(super) struct PolicyOutput {
    id: String,
    effect: String,
    annotations: BTreeMap<String, String>,
    principal: Scope,
    action: Action,
    resource: Scope,
    has_non_scope_constraint: bool,
    template_id: Option<String>,
    cedar: Option<String>,
    json: Value,
    syntax: Option<Syntax>,
}

pub(super) fn policy_output(p: &Policy) -> Result<PolicyOutput, OpError> {
    let syntax = if p.is_static() {
        let tree = p.to_pst().map_err(|e| policy_error(&e))?;
        let conditions = tree
            .body()
            .clauses()
            .iter()
            .cloned()
            .map(est::Clause::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| policy_error(&e))?;
        Some(Syntax {
            id: AsRef::<str>::as_ref(p.id()).to_owned(),
            effect: p.effect().to_string(),
            annotations: p.annotations().map(|(k, v)| (k.into(), v.into())).collect(),
            principal: principal(p),
            action: action(p),
            resource: resource(p),
            conditions,
        })
    } else {
        None
    };
    Ok(PolicyOutput {
        id: AsRef::<str>::as_ref(p.id()).to_owned(),
        effect: p.effect().to_string(),
        annotations: p.annotations().map(|(k, v)| (k.into(), v.into())).collect(),
        principal: principal(p),
        action: action(p),
        resource: resource(p),
        has_non_scope_constraint: p.has_non_scope_constraint(),
        template_id: p
            .template_id()
            .map(|id| AsRef::<str>::as_ref(id).to_owned()),
        // Cedar text cannot preserve links, even when upstream renders a materialized body.
        cedar: if p.is_static() { p.to_cedar() } else { None },
        json: p.to_json().map_err(|e| policy_error(&e))?,
        syntax,
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
