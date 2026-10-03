//! Experimental type-aware partial evaluation; continuations replay bounded inputs.

use crate::{AuthorizeInput, AuthorizeOutput, PolicyMessage, STATE, entity_uid};
use cedar_policy::{
    Context, Decision, Effect, Entities, PartialEntities, PartialEntityUid, PartialRequest,
    Request, Schema, TpeResponse,
};
use cgw_abi::{OpError, parse_input, run, take_input};
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use std::collections::{BTreeMap, HashSet};

const RESIDUAL_VERSION: u32 = 1;
const CEDAR_VERSION: &str = "4.13.0";

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidualProjection {
    version: u32,
    cedar_version: String,
    policies: BTreeMap<String, Value>,
}

fn projection(response: &TpeResponse<'_>) -> Result<ResidualProjection, OpError> {
    let native = response
        .policy_set()
        .to_pst()
        .map_err(|e| OpError::new("policies", &e))?;
    let policies = native
        .policies
        .into_iter()
        .map(|(id, policy)| {
            let est: cedar_policy_core::est::Policy = policy
                .body()
                .clone()
                .try_into()
                .map_err(|e| OpError::new("policies", &e))?;
            let json =
                serde_json::to_value(est).map_err(|e| OpError::msg("internal", e.to_string()))?;
            Ok((id.0.to_string(), json))
        })
        .collect::<Result<_, OpError>>()?;
    Ok(ResidualProjection {
        version: RESIDUAL_VERSION,
        cedar_version: CEDAR_VERSION.to_owned(),
        policies,
    })
}

fn import_projection(
    imported: &ResidualProjection,
    response: &TpeResponse<'_>,
) -> Result<cedar_policy::PolicySet, OpError> {
    if imported.version != RESIDUAL_VERSION || imported.cedar_version != CEDAR_VERSION {
        return Err(OpError::msg(
            "input",
            "unsupported residual representation or Cedar version",
        ));
    }
    if projection(response)? != *imported {
        return Err(OpError::msg(
            "input",
            "residual export does not match native partial evaluation",
        ));
    }
    // Ordinary EST parsing excludes residual errors; exact projection equality permits native PST reconstruction.
    let native = response
        .policy_set()
        .to_pst()
        .map_err(|e| OpError::new("input", &e))?;
    cedar_policy::PolicySet::from_pst(native).map_err(|e| OpError::new("input", &e))
}

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
    projection: ResidualProjection,
}

pub(crate) fn summarize(response: &TpeResponse<'_>) -> Result<PartialOutput, OpError> {
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
            policy_id: AsRef::<str>::as_ref(p.id()).to_owned(),
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
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort_unstable();
    Ok(PartialOutput {
        decision: match response.decision() {
            Some(Decision::Allow) => "allow",
            Some(Decision::Deny) => "deny",
            None => "undecided",
        },
        reasons,
        residuals,
        projection: projection(response)?,
    })
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
        summarize(&response)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportPartialInput {
    version: u32,
    cedar_version: String,
    partial: PartialInput,
    projection: ResidualProjection,
}

fn import_partial(bytes: &[u8]) -> Result<PartialOutput, OpError> {
    let input: ImportPartialInput = parse_input(bytes)?;
    if input.version != RESIDUAL_VERSION || input.cedar_version != CEDAR_VERSION {
        return Err(OpError::msg(
            "input",
            "unsupported partial export or Cedar version",
        ));
    }
    STATE.with(|s| {
        let state = s.borrow();
        let loaded = state
            .as_ref()
            .ok_or_else(|| OpError::msg("not_loaded", "no policy set is loaded"))?;
        let schema = loaded
            .schema
            .as_ref()
            .ok_or_else(|| OpError::msg("schema", "partial evaluation requires a schema"))?;
        let entities =
            parse_partial_entities(input.partial.entities.as_deref(), &loaded.entities, schema)?;
        let request = input.partial.request(schema)?;
        let response = loaded
            .policies
            .tpe(&request, &entities, schema)
            .map_err(|e| OpError::new("policies", &e))?;
        let output = summarize(&response)?;
        let imported = import_projection(&input.projection, &response)?;
        if imported.policies().count() != output.residuals.len() {
            return Err(OpError::msg(
                "input",
                "residual export does not match native partial evaluation",
            ));
        }
        Ok(output)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthorizeInput {
    partial: PartialInput,
    request: AuthorizeInput,
    projection: Option<ResidualProjection>,
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
        let checked = response
            .reauthorize(&request, &entities)
            .map_err(|e| OpError::msg("request", e.to_string()))?;
        let result = if let Some(imported) = input.projection {
            let policies = import_projection(&imported, &response)?;
            // Reuse the imported native PST only after Cedar checks the original known data.
            cedar_policy::Authorizer::new().is_authorized(&request, &policies, &entities)
        } else {
            checked
        };
        let mut reasons: Vec<_> = result
            .diagnostics()
            .reason()
            .map(|id| AsRef::<str>::as_ref(id).to_owned())
            .collect();
        reasons.sort_unstable();
        let mut errors: Vec<_> = result
            .diagnostics()
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

/// Imports a versioned residual export after native parsing and replay checks.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_import_partial(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, import_partial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::{Authorizer, Policy, PolicyId, PolicySet, Response};
    use serde_json::json;

    fn input(id: &str) -> (Schema, PolicySet, Entities) {
        let schema = Schema::from_cedarschema_str(
            "entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {mfa: Bool}};",
        )
        .unwrap()
        .0;
        let mut policies = PolicySet::new();
        policies
            .add(
                Policy::parse(
                    Some(PolicyId::new(id)),
                    "@note(\"雪\") permit(principal, action, resource) when { context.mfa || 9223372036854775807 + 1 > 0 };",
                )
                .unwrap(),
            )
            .unwrap();
        let entities = Entities::from_json_str("[]", Some(&schema)).unwrap();
        (schema, policies, entities)
    }

    fn partial_request(schema: &Schema) -> PartialRequest {
        PartialRequest::new(
            PartialEntityUid::new("User".parse().unwrap(), None),
            "Action::\"view\"".parse().unwrap(),
            PartialEntityUid::new("Photo".parse().unwrap(), None),
            None,
            schema,
        )
        .unwrap()
    }

    fn observation(response: &Response) -> (Decision, Vec<String>, Vec<(String, String)>) {
        let mut reasons: Vec<_> = response
            .diagnostics()
            .reason()
            .map(|id| AsRef::<str>::as_ref(id).to_owned())
            .collect();
        reasons.sort();
        let mut errors: Vec<_> = response
            .diagnostics()
            .errors()
            .map(|error| match error {
                cedar_policy::AuthorizationError::PolicyEvaluationError(error) => (
                    AsRef::<str>::as_ref(error.policy_id()).to_owned(),
                    error.to_string(),
                ),
            })
            .collect();
        errors.sort();
        (response.decision(), reasons, errors)
    }

    #[test]
    fn structured_import_preserves_nested_errors_and_raw_ids() {
        for id in ["", "policy\"\n\\\0", "ordinary"] {
            let (schema, policies, entities) = input(id);
            let partial_entities =
                PartialEntities::from_concrete(entities.clone(), &schema).unwrap();
            let request = partial_request(&schema);
            let response = policies.tpe(&request, &partial_entities, &schema).unwrap();
            let wire = serde_json::to_vec(&projection(&response).unwrap()).unwrap();
            let imported: ResidualProjection = serde_json::from_slice(&wire).unwrap();
            assert!(imported.policies[id].to_string().contains("\"error\":[]"));
            let reconstructed = import_projection(&imported, &response).unwrap();
            assert_eq!(
                reconstructed.to_pst().unwrap(),
                response.policy_set().to_pst().unwrap()
            );
            for mfa in [true, false] {
                let context = Context::from_json_value(json!({"mfa":mfa}), None).unwrap();
                let concrete = Request::new(
                    "User::\"alice\"".parse().unwrap(),
                    "Action::\"view\"".parse().unwrap(),
                    "Photo::\"one\"".parse().unwrap(),
                    context,
                    Some(&schema),
                )
                .unwrap();
                let expected = observation(&response.reauthorize(&concrete, &entities).unwrap());
                let actual = observation(&Authorizer::new().is_authorized(
                    &concrete,
                    &reconstructed,
                    &entities,
                ));
                assert_eq!(actual, expected);
                let direct =
                    observation(&Authorizer::new().is_authorized(&concrete, &policies, &entities));
                assert_eq!((actual.0, &actual.1), (direct.0, &direct.1));
                assert_eq!(
                    actual.2.iter().map(|e| &e.0).collect::<Vec<_>>(),
                    direct.2.iter().map(|e| &e.0).collect::<Vec<_>>()
                );
                if mfa {
                    assert_eq!(actual.0, Decision::Allow);
                    assert!(actual.2.is_empty());
                    assert_eq!(actual.1, vec![id.to_owned()]);
                } else {
                    assert_eq!(actual.0, Decision::Deny);
                    assert_eq!(actual.2.len(), 1);
                    assert_eq!(actual.2[0].0, id);
                    assert!(!actual.2[0].1.is_empty());
                }
            }
        }
    }

    #[test]
    fn structured_import_rejects_changed_projections() {
        let (schema, policies, entities) = input("policy");
        let partial_entities = PartialEntities::from_concrete(entities, &schema).unwrap();
        let request = partial_request(&schema);
        let response = policies.tpe(&request, &partial_entities, &schema).unwrap();
        let wire = serde_json::to_vec(&projection(&response).unwrap()).unwrap();
        for change in 0..5 {
            let mut imported: ResidualProjection = serde_json::from_slice(&wire).unwrap();
            match change {
                0 => imported.version += 1,
                1 => imported.cedar_version = "0.0.0".into(),
                2 => imported.policies.get_mut("policy").unwrap()["effect"] = json!("forbid"),
                3 => imported.policies.get_mut("policy").unwrap()["conditions"] = json!([]),
                _ => {
                    imported.policies.remove("policy");
                }
            }
            assert_eq!(
                import_projection(&imported, &response).unwrap_err().kind,
                "input"
            );
        }
    }
}
