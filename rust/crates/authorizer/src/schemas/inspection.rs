use cedar_policy::{EntityUid, Schema, SchemaFragment};
use cedar_policy_core::validator::{RawName, ValidatorSchema, json_schema};
use cgw_abi::OpError;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn uid(value: &EntityUid) -> Value {
    json!({"type":value.type_name().to_string(),"id":value.id().unescaped()})
}

fn sorted_uids(values: impl Iterator<Item = EntityUid>) -> Vec<Value> {
    let mut values: Vec<_> = values.collect();
    values.sort();
    values.into_iter().map(|value| uid(&value)).collect()
}

fn resolved(value: Value) -> Result<Value, OpError> {
    let fragment: json_schema::Fragment<RawName> =
        json_schema::Fragment::from_json_value(value).map_err(|e| OpError::new("schema", &e))?;
    let resolved = fragment
        .to_internal_name_fragment_with_resolved_types()
        .map_err(|e| OpError::new("schema", &e))?;
    serde_json::to_value(resolved).map_err(|e| OpError::msg("internal", e.to_string()))
}

pub(super) fn inspection(schema: &Schema, source: SchemaFragment) -> Result<Value, OpError> {
    let core: &ValidatorSchema = schema.as_ref();
    let expanded = core
        .to_json_schema()
        .map_err(|e| OpError::msg("schema", e))?;
    let declarations = source
        .to_json_value()
        .map_err(|e| OpError::new("schema", &e))?;
    let ancestors: BTreeMap<_, _> = schema
        .entity_types()
        .map(|entity_type| {
            let mut ancestors: Vec<_> = schema
                .ancestors(entity_type)
                .into_iter()
                .flatten()
                .map(ToString::to_string)
                .collect();
            ancestors.sort();
            (entity_type.to_string(), ancestors)
        })
        .collect();
    let mut environments: Vec<_> = schema
        .request_envs()
        .map(|env| {
            (
                env.principal().to_string(),
                env.action().clone(),
                env.resource().to_string(),
            )
        })
        .collect();
    environments.sort();
    let environments: Vec<_> = environments
        .into_iter()
        .map(|(principal, action, resource)| {
            json!({"principal_type":principal,"action":uid(&action),"resource_type":resource})
        })
        .collect();
    Ok(json!({
        "resolved_schema":resolved(declarations)?,
        "expanded_schema":expanded,
        "ancestors":ancestors,
        "actions":sorted_uids(schema.actions().cloned()),
        "action_groups":sorted_uids(schema.action_groups().cloned()),
        "environments":environments,
    }))
}
