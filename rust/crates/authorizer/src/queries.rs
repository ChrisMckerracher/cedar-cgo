//! Permission queries use native TPE and schema enumeration; no Go candidate loop is involved.
use crate::{
    STATE, entity_uid,
    partial::{PartialUidInput, parse_partial_entities},
};
use cedar_policy::{
    ActionQueryRequest, Context, Decision, EntityUid, PrincipalQueryRequest, ResourceQueryRequest,
};
use cgw_abi::{OpError, parse_input};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Resource,
    Principal,
    Action,
}

#[derive(Deserialize)]
struct Envelope {
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceInput {
    #[serde(rename = "operation")]
    _operation: Operation,
    principal: Value,
    action: Value,
    resource_type: String,
    context: Box<RawValue>,
    entities: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalInput {
    #[serde(rename = "operation")]
    _operation: Operation,
    principal_type: String,
    action: Value,
    resource: Value,
    context: Box<RawValue>,
    entities: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionInput {
    #[serde(rename = "operation")]
    _operation: Operation,
    principal: PartialUidInput,
    resource: PartialUidInput,
    context: Option<Box<RawValue>>,
    entities: Option<Box<RawValue>>,
}

enum Input {
    Resource(ResourceInput),
    Principal(PrincipalInput),
    Action(ActionInput),
}

fn input(bytes: &[u8]) -> Result<Input, OpError> {
    // Tagged enum buffering loses RawValue; parse each request from the original bytes.
    match parse_input::<Envelope>(bytes)?.operation {
        Operation::Resource => parse_input(bytes).map(Input::Resource),
        Operation::Principal => parse_input(bytes).map(Input::Principal),
        Operation::Action => parse_input(bytes).map(Input::Action),
    }
}

fn uid(value: EntityUid) -> Value {
    json!({"type":value.type_name().to_string(),"id":value.id().unescaped()})
}
fn sorted(values: impl Iterator<Item = EntityUid>) -> Vec<Value> {
    let mut values: Vec<_> = values.collect();
    values.sort();
    values.into_iter().map(uid).collect()
}

pub fn execute(bytes: &[u8]) -> Result<Value, OpError> {
    let input = input(bytes)?;
    STATE.with(|s| {
        let state=s.borrow();
        let loaded=state.as_ref().ok_or_else(|| OpError::msg("not_loaded","no policy set is loaded"))?;
        let schema=loaded.schema.as_ref().ok_or_else(|| OpError::msg("schema","permission queries require a schema"))?;
        match input {
            Input::Resource(ResourceInput{principal,action,resource_type,context,entities,..})=> {
                let action=entity_uid(action,"action")?;
                let context=Context::from_json_str(context.get(),Some((schema,&action))).map_err(|e| OpError::new("context",&e))?;
                let request=ResourceQueryRequest::new(entity_uid(principal,"principal")?,action,resource_type.parse().map_err(|e| OpError::new("resource",&e))?,context,schema).map_err(|e| OpError::new("request",&e))?;
                let entities=match entities {Some(e)=>loaded.entities.clone().add_entities_from_json_str(e.get(),Some(schema)).map_err(|e|OpError::new("entities",&e))?,None=>loaded.entities.clone()};
                let allowed=loaded.policies.query_resource(&request,&entities,schema).map_err(|e|OpError::msg("policies",e.to_string()))?;
                Ok(json!({"allowed":sorted(allowed)}))
            },
            Input::Principal(PrincipalInput{principal_type,action,resource,context,entities,..})=> {
                let action=entity_uid(action,"action")?;
                let context=Context::from_json_str(context.get(),Some((schema,&action))).map_err(|e| OpError::new("context",&e))?;
                let request=PrincipalQueryRequest::new(principal_type.parse().map_err(|e| OpError::new("principal",&e))?,action,entity_uid(resource,"resource")?,context,schema).map_err(|e| OpError::new("request",&e))?;
                let entities=match entities {Some(e)=>loaded.entities.clone().add_entities_from_json_str(e.get(),Some(schema)).map_err(|e|OpError::new("entities",&e))?,None=>loaded.entities.clone()};
                let allowed=loaded.policies.query_principal(&request,&entities,schema).map_err(|e|OpError::msg("policies",e.to_string()))?;
                Ok(json!({"allowed":sorted(allowed)}))
            },
            Input::Action(ActionInput{principal,resource,context,entities,..})=> {
                let entities=parse_partial_entities(entities.as_deref(),&loaded.entities,schema)?;
                let context=context.as_deref().map(|c|Context::from_json_str(c.get(),None).map_err(|e|OpError::new("context",&e))).transpose()?;
                let request=ActionQueryRequest::new(principal.parse("principal")?,resource.parse("resource")?,context,schema.clone()).map_err(|e|OpError::new("request",&e))?;
                let mut allowed=Vec::new();let mut undecided=Vec::new();
                for (action,decision) in loaded.policies.query_action(&request,&entities).map_err(|e|OpError::msg("policies",e.to_string()))? {
                    match decision {Some(Decision::Allow)=>allowed.push(action.clone()),None=>undecided.push(action.clone()),Some(Decision::Deny)=>return Err(OpError::msg("internal","native query returned a denied action"))}
                }
                Ok(json!({"allowed":sorted(allowed.into_iter()),"undecided":sorted(undecided.into_iter())}))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{Input, input};

    const CONTEXT: &str = r#"{"max":9223372036854775807,"min":-9223372036854775808,"exact":9007199254740993,"label":"\u96ea"}"#;
    const ENTITIES: &str =
        r#"[{"uid":{"type":"User","id":"new"},"attrs":{"max":9223372036854775807},"parents":[]}]"#;

    #[test]
    fn abi_requests_preserve_raw_context_and_entities() {
        for operation in ["resource", "principal", "action"] {
            let request = match operation {
                "resource" => format!(
                    r#"{{"operation":"resource","principal":{{"type":"User","id":"alice"}},"action":{{"type":"Action","id":"view"}},"resource_type":"Photo","context":{CONTEXT},"entities":{ENTITIES}}}"#
                ),
                "principal" => format!(
                    r#"{{"operation":"principal","principal_type":"User","action":{{"type":"Action","id":"view"}},"resource":{{"type":"Photo","id":"one"}},"context":{CONTEXT},"entities":{ENTITIES}}}"#
                ),
                "action" => format!(
                    r#"{{"operation":"action","principal":{{"type":"User"}},"resource":{{"type":"Photo"}},"context":{CONTEXT},"entities":{ENTITIES}}}"#
                ),
                _ => unreachable!(),
            };
            let (context, entities) = match input(request.as_bytes()).unwrap() {
                Input::Resource(request) => (Some(request.context), request.entities),
                Input::Principal(request) => (Some(request.context), request.entities),
                Input::Action(request) => (request.context, request.entities),
            };
            assert_eq!(context.unwrap().get(), CONTEXT);
            assert_eq!(entities.unwrap().get(), ENTITIES);
        }
    }

    #[test]
    fn abi_action_request_retains_unknown_context() {
        for context in ["", r#", "context":null"#] {
            let request = format!(
                r#"{{"operation":"action","principal":{{"type":"User"}},"resource":{{"type":"Photo"}}{context}}}"#
            );
            let Input::Action(request) = input(request.as_bytes()).unwrap() else {
                panic!("unexpected operation");
            };
            assert!(request.context.is_none());
            assert!(request.entities.is_none());
        }
    }

    #[test]
    fn abi_requests_reject_missing_and_unrelated_fields() {
        for request in [
            r#"{"operation":"resource","principal":{},"action":{},"resource_type":"Photo"}"#,
            r#"{"operation":"principal","action":{},"resource":{},"context":{}}"#,
            r#"{"operation":"action","principal":{"type":"User"}}"#,
            r#"{"operation":"action","principal":{"type":"User"},"resource":{"type":"Photo"},"resource_type":"Photo"}"#,
            r#"{"operation":"unknown"}"#,
            r#"{"operation":"action","operation":"principal","principal":{"type":"User"},"resource":{"type":"Photo"}}"#,
        ] {
            assert!(input(request.as_bytes()).is_err(), "{request}");
        }
    }
}
