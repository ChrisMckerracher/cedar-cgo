use cedar_policy::RequestEnv;
use cgw_abi::{OpError, Source, parse_input, parse_policies, parse_schema};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema: Source,
    policies: Source,
}

#[derive(Serialize)]
struct Environment {
    principal_type: String,
    action: Value,
    resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal_slot_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_slot_type: Option<String>,
}

fn environments(envs: impl Iterator<Item = RequestEnv>) -> Vec<Environment> {
    // Native ordering compares name components; sorting rendered names changes namespace order.
    envs.map(|env| Environment {
        principal_type: env.principal().to_string(),
        action: json!({"type":env.action().type_name().to_string(),"id":env.action().id().unescaped()}),
        resource_type: env.resource().to_string(),
        principal_slot_type: env.principal_slot().map(ToString::to_string),
        resource_slot_type: env.resource_slot().map(ToString::to_string),
    }).collect()
}

pub fn execute(bytes: &[u8]) -> Result<Value, OpError> {
    let input: Input = parse_input(bytes)?;
    let schema = parse_schema(&input.schema)?;
    let set = parse_policies(&input.policies)?;
    let policies: BTreeMap<_, _> = set
        .policies()
        .map(|p| {
            (
                p.id().to_string(),
                environments(p.get_valid_request_envs(&schema)),
            )
        })
        .collect();
    let templates: BTreeMap<_, _> = set
        .templates()
        .map(|t| {
            (
                t.id().to_string(),
                environments(t.get_valid_request_envs(&schema)),
            )
        })
        .collect();
    Ok(json!({"applicability":{"policies":policies,"templates":templates}}))
}
