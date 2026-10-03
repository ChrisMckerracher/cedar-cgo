//! Authorization and strict validation delegate to `cedar-policy` so the Go
//! boundary shares the reference implementation's semantics.

mod partial;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use cgw_abi::{OpError, Source, parse_input, parse_policies, parse_schema, run, take_input};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::cell::RefCell;

mod applicability;
mod batched;
mod entity_store;
mod expressions;
mod format;
mod literals;
mod policies;
mod queries;
mod schemas;
mod slicing;
mod templates;
mod utilities;

cgw_abi::export_memory_functions!();

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

/// A schema also validates entity data and supplies action entities.
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

/// Reads or updates an immutable native entity snapshot.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_entity_store(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, entity_store::execute)
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
        let mut reasons: Vec<String> = diagnostics
            .reason()
            .map(|id| AsRef::<str>::as_ref(id).to_owned())
            .collect();
        reasons.sort_unstable();
        let mut errors: Vec<PolicyMessage> = diagnostics
            .errors()
            .map(|e| match e {
                cedar_policy::AuthorizationError::PolicyEvaluationError(pe) => PolicyMessage {
                    policy_id: AsRef::<str>::as_ref(pe.policy_id()).to_owned(),
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
    max_dereference_level: Option<u32>,
}

#[derive(Serialize)]
struct ValidateOutput {
    passed: bool,
    errors: Vec<cgw_abi::structured::PolicyMessage>,
    warnings: Vec<cgw_abi::structured::PolicyMessage>,
    schema_warnings: Vec<cgw_abi::structured::Message>,
}

fn validate(bytes: &[u8]) -> Result<ValidateOutput, OpError> {
    let input: ValidateInput = parse_input(bytes)?;
    let (schema, schema_warnings) = cgw_abi::parse_schema_with_warnings(&input.schema)?;
    let policies = parse_policies(&input.policies)?;
    let json_policies = matches!(input.policies.format, cgw_abi::Format::Json);
    let project = |message: cgw_abi::structured::PolicyMessage| {
        if json_policies {
            message.without_spans()
        } else {
            message
        }
    };
    let validator = Validator::new(schema);
    let result = match input.max_dereference_level {
        Some(level) => validator.validate_with_level(&policies, ValidationMode::Strict, level),
        None => validator.validate(&policies, ValidationMode::Strict),
    };
    Ok(ValidateOutput {
        passed: result.validation_passed(),
        errors: result
            .validation_errors()
            .map(cgw_abi::structured::validation_error)
            .map(project)
            .collect(),
        warnings: result
            .validation_warnings()
            .map(cgw_abi::structured::validation_warning)
            .map(project)
            .collect(),
        schema_warnings,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaWarningsInput {
    schema: Source,
}

fn schema_warnings(bytes: &[u8]) -> Result<serde_json::Value, OpError> {
    let input: SchemaWarningsInput = parse_input(bytes)?;
    let (_, warnings) = cgw_abi::parse_schema_with_warnings(&input.schema)?;
    Ok(serde_json::json!({"warnings":warnings}))
}

/// Returns schema warnings with native source spans.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_schema_warnings(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, schema_warnings)
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

/// Parses, inspects and edits policy sets with the upstream policy API.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_policies(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, policies::execute)
}

/// Parses and evaluates standalone Cedar expressions.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_expressions(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, expressions::execute)
}

/// Inspects and substitutes entity literals through native Cedar operations.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_literals(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, literals::execute)
}

/// Enumerates potential request environments for policies and templates.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_applicability(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, applicability::execute)
}

/// Converts, composes, and inspects native Cedar schemas.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_schemas(ptr: u32, len: u32) -> u64 {
    // SAFETY: the caller transfers the allocated input buffer.
    run(unsafe { take_input(ptr, len) }, schemas::execute)
}

/// Runs native context, request, UID, and language utilities.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_utilities(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, utilities::execute)
}

/// Runs a native TPE permission query against loaded state.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_queries(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, queries::execute)
}
