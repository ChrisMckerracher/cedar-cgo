//! Cedar authorization and strict validation, exported to the Go host.
//!
//! Exports, besides `cgw_abi_version`, `cgw_alloc` and `cgw_free`:
//!
//! - `cgw_load`: parses a schema, a policy set and entities, and keeps them
//!   in this instance for later `cgw_authorize` calls.
//! - `cgw_authorize`: evaluates one request against the loaded state.
//! - `cgw_validate`: validates a policy set against a schema in strict mode.
//!
//! All logic is in `cedar-policy`. This crate only moves JSON in and out.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use cgw_abi::{OpError, Source, parse_input, parse_policies, parse_schema, run, take_input};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::cell::RefCell;

cgw_abi::export_memory_functions!();

/// The state that `cgw_load` installs.
struct Loaded {
    schema: Option<Schema>,
    policies: PolicySet,
    entities: Entities,
    authorizer: Authorizer,
}

thread_local! {
    static STATE: RefCell<Option<Loaded>> = const { RefCell::new(None) };
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadInput {
    schema: Option<Source>,
    policies: Source,
    entities: Option<Box<RawValue>>,
}

#[derive(Serialize)]
struct LoadOutput {
    policies: usize,
}

/// Parses entities in Cedar's entity JSON format. With a schema, Cedar checks
/// the entities against it and adds the schema's action entities.
fn parse_entities(json: Option<&RawValue>, schema: Option<&Schema>) -> Result<Entities, OpError> {
    let text = json.map_or("[]", RawValue::get);
    Entities::from_json_str(text, schema).map_err(|e| OpError::new("entities", &e))
}

fn load(bytes: &[u8]) -> Result<LoadOutput, OpError> {
    let input: LoadInput = parse_input(bytes)?;
    let schema = input.schema.as_ref().map(parse_schema).transpose()?;
    let policies = parse_policies(&input.policies)?;
    let entities = parse_entities(input.entities.as_deref(), schema.as_ref())?;
    let out = LoadOutput {
        policies: policies.policies().count(),
    };
    STATE.with(|s| {
        *s.borrow_mut() = Some(Loaded {
            schema,
            policies,
            entities,
            authorizer: Authorizer::new(),
        })
    });
    Ok(out)
}

/// Loads a schema, a policy set and entities into this instance.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_load(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, load)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeInput {
    principal: serde_json::Value,
    action: serde_json::Value,
    resource: serde_json::Value,
    context: Option<Box<RawValue>>,
    entities: Option<Box<RawValue>>,
}

#[derive(Serialize)]
struct PolicyMessage {
    policy_id: String,
    message: String,
}

#[derive(Serialize)]
struct AuthorizeOutput {
    decision: &'static str,
    reasons: Vec<String>,
    errors: Vec<PolicyMessage>,
}

fn entity_uid(v: serde_json::Value, kind: &'static str) -> Result<EntityUid, OpError> {
    EntityUid::from_json(v).map_err(|e| OpError::new(kind, &e))
}

fn authorize(bytes: &[u8]) -> Result<AuthorizeOutput, OpError> {
    let input: AuthorizeInput = parse_input(bytes)?;
    STATE.with(|s| {
        let state = s.borrow();
        let loaded = state
            .as_ref()
            .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
        let schema = loaded.schema.as_ref();
        let principal = entity_uid(input.principal, "principal")?;
        let action = entity_uid(input.action, "action")?;
        let resource = entity_uid(input.resource, "resource")?;
        let context_json = input.context.as_deref().map_or("{}", RawValue::get);
        let context = Context::from_json_str(context_json, schema.map(|s| (s, &action)))
            .map_err(|e| OpError::new("context", &e))?;
        let request = Request::new(principal, action, resource, context, schema)
            .map_err(|e| OpError::new("request", &e))?;
        let extra;
        let entities = match input.entities.as_deref() {
            None => &loaded.entities,
            Some(json) => {
                extra = loaded
                    .entities
                    .clone()
                    .add_entities_from_json_str(json.get(), schema)
                    .map_err(|e| OpError::new("entities", &e))?;
                &extra
            }
        };
        let response = loaded
            .authorizer
            .is_authorized(&request, &loaded.policies, entities);
        let diagnostics = response.diagnostics();
        let mut reasons: Vec<String> = diagnostics.reason().map(ToString::to_string).collect();
        reasons.sort_unstable();
        let mut errors: Vec<PolicyMessage> = diagnostics
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
            decision: match response.decision() {
                Decision::Allow => "allow",
                Decision::Deny => "deny",
            },
            reasons,
            errors,
        })
    })
}

/// Evaluates one request against the loaded state.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_authorize(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, authorize)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateInput {
    schema: Source,
    policies: Source,
}

#[derive(Serialize)]
struct ValidateOutput {
    passed: bool,
    errors: Vec<PolicyMessage>,
    warnings: Vec<PolicyMessage>,
}

fn validate(bytes: &[u8]) -> Result<ValidateOutput, OpError> {
    let input: ValidateInput = parse_input(bytes)?;
    let schema = parse_schema(&input.schema)?;
    let policies = parse_policies(&input.policies)?;
    let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
    Ok(ValidateOutput {
        passed: result.validation_passed(),
        errors: result
            .validation_errors()
            .map(|e| PolicyMessage {
                policy_id: e.policy_id().to_string(),
                message: cgw_abi::diagnostics::render(e),
            })
            .collect(),
        warnings: result
            .validation_warnings()
            .map(|w| PolicyMessage {
                policy_id: w.policy_id().to_string(),
                message: cgw_abi::diagnostics::render(w),
            })
            .collect(),
    })
}

/// Validates a policy set against a schema in strict mode.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_validate(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, validate)
}
