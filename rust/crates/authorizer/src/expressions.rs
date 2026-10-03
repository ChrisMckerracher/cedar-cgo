use cedar_policy::{Context, Entities, EvalResult, Expression, Request, RestrictedExpression};
use cedar_policy_core::ast::{EntityUIDEntry, Request as CoreRequest};
use cgw_abi::{Format, OpError, Source, parse_input};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    principal: Option<Value>,
    action: Option<Value>,
    resource: Option<Value>,
    context: Box<RawValue>,
    entities: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    operation: String,
    expression: Source,
    restricted: bool,
    environment: Option<Environment>,
}

pub fn project(result: EvalResult) -> Value {
    match result {
        EvalResult::Bool(v) => json!({"bool": v}),
        EvalResult::Long(v) => json!({"long": v}),
        EvalResult::String(v) => json!({"string": v}),
        EvalResult::EntityUid(v) => {
            json!({"entity_uid": {"type": v.type_name().to_string(), "id": v.id().unescaped().to_string()}})
        }
        EvalResult::ExtensionValue(v) => json!({"extension": v}),
        EvalResult::Set(v) => json!({"set": v.iter().cloned().map(project).collect::<Vec<_>>()}),
        EvalResult::Record(v) => {
            json!({"record": v.iter().map(|(k, v)| (k.clone(), project(v.clone()))).collect::<BTreeMap<_, _>>()})
        }
    }
}

pub fn execute(bytes: &[u8]) -> Result<Value, OpError> {
    let input: Input = parse_input(bytes)?;
    if !matches!(input.expression.format, Format::Cedar) {
        return Err(OpError::msg("input", "expressions require Cedar syntax"));
    }
    if input.restricted {
        input
            .expression
            .text
            .parse::<RestrictedExpression>()
            .map_err(|e| OpError::new("expression", &e))?;
    }
    let expr: Expression = input
        .expression
        .text
        .parse()
        .map_err(|e| OpError::new("expression", &e))?;
    match input.operation.as_str() {
        "parse" => Ok(json!({"expression": expr.to_string()})),
        "evaluate" => {
            let env = input
                .environment
                .ok_or_else(|| OpError::msg("input", "missing expression environment"))?;
            let principal = env
                .principal
                .map(|v| super::entity_uid(v, "principal"))
                .transpose()?;
            let action = env
                .action
                .map(|v| super::entity_uid(v, "action"))
                .transpose()?;
            let resource = env
                .resource
                .map(|v| super::entity_uid(v, "resource"))
                .transpose()?;
            let context = Context::from_json_str(env.context.get(), None)
                .map_err(|e| OpError::new("context", &e))?;
            let entry = |uid: Option<cedar_policy::EntityUid>| {
                uid.map_or_else(EntityUIDEntry::unknown, |uid| {
                    EntityUIDEntry::known(uid.into(), None)
                })
            };
            let core_context: &cedar_policy_core::ast::Context = context.as_ref();
            // No schema applies here; omitted variables remain unknown.
            let request = Request::from(CoreRequest::new_unchecked(
                entry(principal),
                entry(action),
                entry(resource),
                Some(core_context.clone()),
            ));
            let entities = Entities::from_json_str(env.entities.get(), None)
                .map_err(|e| OpError::new("entities", &e))?;
            let result = cedar_policy::eval_expression(&request, &entities, &expr)
                .map_err(|e| OpError::new("expression", &e))?;
            Ok(json!({"result": project(result)}))
        }
        _ => Err(OpError::msg("input", "unknown expression operation")),
    }
}
