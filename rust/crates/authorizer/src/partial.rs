//! Experimental type-aware partial evaluation; continuations replay bounded inputs.

use crate::{AuthorizeInput, AuthorizeOutput, PolicyMessage, STATE, entity_uid};
use cedar_policy::{
    Context, Decision, Effect, Entities, PartialEntities, PartialEntityUid, PartialRequest,
    Request, Schema, TpeResponse,
};
use cgw_abi::{OpError, parse_input, run, take_input};
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use std::collections::HashSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartialUidInput {
    pub(crate) r#type: String,
    pub(crate) id: Option<String>,
}

impl PartialUidInput {
    pub(crate) fn parse(self, kind: &'static str) -> Result<PartialEntityUid, OpError> {
        Ok(PartialEntityUid::new(
            self.r#type.parse().map_err(|e| OpError::new(kind, &e))?,
            self.id.map(|id| cedar_policy::EntityId::new(&id)),
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartialInput {
    principal: PartialUidInput,
    action: Value,
    resource: PartialUidInput,
    context: Option<Box<RawValue>>,
    entities: Option<Box<RawValue>>,
}

impl PartialInput {
    pub(crate) fn request(self, schema: &Schema) -> Result<PartialRequest, OpError> {
        let action = entity_uid(self.action, "action")?;
        let context = self
            .context
            .as_deref()
            .map(|json| {
                Context::from_json_str(json.get(), Some((schema, &action)))
                    .map_err(|e| OpError::new("context", &e))
            })
            .transpose()?;
        PartialRequest::new(
            self.principal.parse("principal")?,
            action,
            self.resource.parse("resource")?,
            context,
            schema,
        )
        .map_err(|e| OpError::new("request", &e))
    }
}

pub(crate) fn parse_partial_entities(
    input: Option<&RawValue>,
    loaded: &Entities,
    schema: &Schema,
) -> Result<PartialEntities, OpError> {
    let mut entities = Vec::new();
    for entity in loaded.iter() {
        // TPE JSON excludes actions; its constructor inserts them from the schema.
        if entity.uid().type_name().basename() == "Action" {
            continue;
        }
        let mut json = entity
            .to_json_value()
            .map_err(|e| OpError::new("entities", &e))?;
        // Concrete JSON omits empty tags, while TPE interprets omission as unknown.
        if json.get("tags").is_none() {
            json["tags"] = serde_json::json!({});
        }
        entities.push(json);
    }
    if let Some(input) = input {
        let extra: Vec<Value> = serde_json::from_str(input.get())
            .map_err(|e| OpError::msg("entities", e.to_string()))?;
        entities.extend(extra);
    }
    PartialEntities::from_json_value(Value::Array(entities), schema)
        .map_err(|e| OpError::new("entities", &e))
}

#[derive(Serialize)]
pub(crate) struct ResidualOutput {
    policy_id: String,
    effect: &'static str,
    state: &'static str,
    cedar: String,
}

#[derive(Serialize)]
pub(crate) struct PartialOutput {
    decision: &'static str,
    reasons: Vec<String>,
    residuals: Vec<ResidualOutput>,
}

pub(crate) fn summarize(response: &TpeResponse<'_>) -> PartialOutput {
    let trues: HashSet<_> = response
        .true_permits()
        .chain(response.true_forbids())
        .collect();
    let falses: HashSet<_> = response
        .false_permits()
        .chain(response.false_forbids())
        .collect();
    let errors: HashSet<_> = response
        .error_permits()
        .chain(response.error_forbids())
        .collect();
    let mut residuals: Vec<_> = response
        .policies()
        .map(|p| ResidualOutput {
            policy_id: p.id().to_string(),
            effect: match p.effect() {
                Effect::Permit => "permit",
                Effect::Forbid => "forbid",
            },
            state: if trues.contains(p.id()) {
                "true"
            } else if falses.contains(p.id()) {
                "false"
            } else if errors.contains(p.id()) {
                "error"
            } else {
                "residual"
            },
            cedar: p.to_string(),
        })
        .collect();
    residuals.sort_unstable_by(|a, b| a.policy_id.cmp(&b.policy_id));
    let mut reasons: Vec<_> = response
        .reason()
        .into_iter()
        .flatten()
        .map(ToString::to_string)
        .collect();
    reasons.sort_unstable();
    PartialOutput {
        decision: match response.decision() {
            Some(Decision::Allow) => "allow",
            Some(Decision::Deny) => "deny",
            None => "undecided",
        },
        reasons,
        residuals,
    }
}

fn partial_authorize(bytes: &[u8]) -> Result<PartialOutput, OpError> {
    let input: PartialInput = parse_input(bytes)?;
    STATE.with(|s| {
        let state = s.borrow();
        let loaded = state
            .as_ref()
            .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
        let schema = loaded
            .schema
            .as_ref()
            .ok_or_else(|| OpError::msg("schema", "partial evaluation requires a schema"))?;
        let entities = parse_partial_entities(input.entities.as_deref(), &loaded.entities, schema)?;
        let request = input.request(schema)?;
        let response = loaded
            .policies
            .tpe(&request, &entities, schema)
            .map_err(|e| OpError::new("policies", &e))?;
        Ok(summarize(&response))
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthorizeInput {
    partial: PartialInput,
    request: AuthorizeInput,
}

fn reauthorize(bytes: &[u8]) -> Result<AuthorizeOutput, OpError> {
    let input: ReauthorizeInput = parse_input(bytes)?;
    STATE.with(|s| {
        let state = s.borrow();
        let loaded = state
            .as_ref()
            .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
        let schema = loaded
            .schema
            .as_ref()
            .ok_or_else(|| OpError::msg("schema", "partial evaluation requires a schema"))?;
        let partial_entities =
            parse_partial_entities(input.partial.entities.as_deref(), &loaded.entities, schema)?;
        let partial_request = input.partial.request(schema)?;
        let response = loaded
            .policies
            .tpe(&partial_request, &partial_entities, schema)
            .map_err(|e| OpError::new("policies", &e))?;
        let concrete = input.request;
        let action = entity_uid(concrete.action, "action")?;
        let context = Context::from_json_str(
            concrete.context.as_deref().map_or("{}", RawValue::get),
            Some((schema, &action)),
        )
        .map_err(|e| OpError::new("context", &e))?;
        let request = Request::new(
            entity_uid(concrete.principal, "principal")?,
            action,
            entity_uid(concrete.resource, "resource")?,
            context,
            Some(schema),
        )
        .map_err(|e| OpError::new("request", &e))?;
        let entities = match concrete.entities.as_deref() {
            Some(json) => loaded
                .entities
                .clone()
                .add_entities_from_json_str(json.get(), Some(schema))
                .map_err(|e| OpError::new("entities", &e))?,
            None => loaded.entities.clone(),
        };
        // Native reauthorization enforces consistency with all previously known data.
        let result = response
            .reauthorize(&request, &entities)
            .map_err(|e| OpError::msg("request", e.to_string()))?;
        let mut reasons: Vec<_> = result
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        reasons.sort_unstable();
        let mut errors: Vec<_> = result
            .diagnostics()
            .errors()
            .map(|e| match e {
                cedar_policy::AuthorizationError::PolicyEvaluationError(pe) => PolicyMessage {
                    policy_id: pe.policy_id().to_string(),
                    message: cgw_abi::diagnostics::render(pe.inner()),
                },
            })
            .collect();
        errors.sort_unstable_by(|a, b| a.policy_id.cmp(&b.policy_id));
        Ok(AuthorizeOutput {
            decision: match result.decision() {
                Decision::Allow => "allow",
                Decision::Deny => "deny",
            },
            reasons,
            errors,
        })
    })
}

/// Partially evaluates a request against loaded policies and schema.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_partial_authorize(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, partial_authorize)
}

/// Resumes a partial evaluation with consistent concrete data.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_reauthorize(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, reauthorize)
}
