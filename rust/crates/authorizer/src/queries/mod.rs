//! Permission queries use native TPE and schema enumeration; no Go candidate loop is involved.
use crate::{
    State, authorize::request_context, entity_uid, partial::parse_partial_entities,
    state::merged_entities,
};
use cedar_policy::{
    ActionQueryRequest, Decision, EntityUid, PrincipalQueryRequest, ResourceQueryRequest,
};
use cgw_abi::OpError;
use serde_json::{Value, json};
mod input;
use input::{ActionInput, Input, PrincipalInput, ResourceInput, input};

fn uid(value: EntityUid) -> Value {
    json!({"type":value.type_name().to_string(),"id":value.id().unescaped()})
}
fn sorted(values: impl Iterator<Item = EntityUid>) -> Vec<Value> {
    let mut values: Vec<_> = values.collect();
    values.sort();
    values.into_iter().map(uid).collect()
}

pub fn execute(state: &State, bytes: &[u8]) -> Result<Value, OpError> {
    let input = input(bytes)?;
    let loaded = state
        .loaded
        .as_ref()
        .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
    let schema = loaded
        .schema
        .as_ref()
        .ok_or_else(|| OpError::msg("schema", "permission queries require a schema"))?;
    match input {
        Input::Resource(ResourceInput {
            principal,
            action,
            resource_type,
            context,
            entities,
            ..
        }) => {
            let action = entity_uid(action, "action")?;
            let context = request_context(Some(&context), Some((schema, &action)))?;
            let request = ResourceQueryRequest::new(
                entity_uid(principal, "principal")?,
                action,
                resource_type
                    .parse()
                    .map_err(|e| OpError::new("resource", &e))?,
                context,
                schema,
            )
            .map_err(|e| OpError::new("request", &e))?;
            let entities = merged_entities(loaded, entities.as_deref())?;
            let allowed = loaded
                .policies
                .query_resource(&request, &entities, schema)
                .map_err(|e| OpError::msg("policies", e.to_string()))?;
            Ok(json!({"allowed":sorted(allowed)}))
        }
        Input::Principal(PrincipalInput {
            principal_type,
            action,
            resource,
            context,
            entities,
            ..
        }) => {
            let action = entity_uid(action, "action")?;
            let context = request_context(Some(&context), Some((schema, &action)))?;
            let request = PrincipalQueryRequest::new(
                principal_type
                    .parse()
                    .map_err(|e| OpError::new("principal", &e))?,
                action,
                entity_uid(resource, "resource")?,
                context,
                schema,
            )
            .map_err(|e| OpError::new("request", &e))?;
            let entities = merged_entities(loaded, entities.as_deref())?;
            let allowed = loaded
                .policies
                .query_principal(&request, &entities, schema)
                .map_err(|e| OpError::msg("policies", e.to_string()))?;
            Ok(json!({"allowed":sorted(allowed)}))
        }
        Input::Action(ActionInput {
            principal,
            resource,
            context,
            entities,
            ..
        }) => {
            let entities = parse_partial_entities(entities.as_deref(), &loaded.entities, schema)?;
            let context = context
                .as_deref()
                .map(|c| request_context(Some(c), None))
                .transpose()?;
            let request = ActionQueryRequest::new(
                principal.parse("principal")?,
                resource.parse("resource")?,
                context,
                schema.clone(),
            )
            .map_err(|e| OpError::new("request", &e))?;
            let mut allowed = Vec::new();
            let mut undecided = Vec::new();
            for (action, decision) in loaded
                .policies
                .query_action(&request, &entities)
                .map_err(|e| OpError::msg("policies", e.to_string()))?
            {
                match decision {
                    Some(Decision::Allow) => allowed.push(action.clone()),
                    None => undecided.push(action.clone()),
                    Some(Decision::Deny) => {
                        return Err(OpError::msg(
                            "internal",
                            "native query returned a denied action",
                        ));
                    }
                }
            }
            Ok(
                json!({"allowed":sorted(allowed.into_iter()),"undecided":sorted(undecided.into_iter())}),
            )
        }
    }
}

#[cfg(test)]
mod tests;
