use cedar_policy::{EntityUid, Template};
use cgw_abi::{OpError, Source, parse_input, parse_policies, parse_schema};
use serde::Deserialize;
use serde_json::{Value, json};
mod context;
pub(crate) use context::execute;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    ParseUid {
        text: String,
    },
    RenderUid {
        uid: Value,
    },
    ScopeValidate {
        principal: Value,
        action: Value,
        resource: Value,
        schema: Source,
    },
    Confusables {
        policies: Source,
    },
    LanguageVersion,
}

fn uid(value: Value) -> Result<EntityUid, OpError> {
    super::entity_uid(value, "entity_uid")
}

fn execute_other(bytes: &[u8]) -> Result<Value, OpError> {
    match parse_input(bytes)? {
        Input::ParseUid { text } => {
            let uid: EntityUid = text.parse().map_err(|e| OpError::new("entity_uid", &e))?;
            Ok(json!({"uid": {"type": uid.type_name().to_string(), "id": uid.id().unescaped()}}))
        }
        Input::RenderUid { uid: value } => Ok(json!({"text": uid(value)?.to_string()})),
        Input::ScopeValidate {
            principal,
            action,
            resource,
            schema,
        } => {
            let schema = parse_schema(&schema)?;
            cedar_policy::validate_scope_variables(
                &super::entity_uid(principal, "principal")?,
                &super::entity_uid(action, "action")?,
                &super::entity_uid(resource, "resource")?,
                &schema,
            )
            .map_err(|e| OpError::new("request", &e))?;
            Ok(json!({"valid": true}))
        }
        Input::Confusables { policies } => {
            let json_policies = matches!(policies.format, cgw_abi::Format::Json);
            let policies = parse_policies(&policies)?;
            // Static policies are templates without slots; linked policies share their template text.
            let static_templates: Vec<_> = policies
                .policies()
                .filter(|p| p.template_id().is_none())
                .map(|p| {
                    let ast: &cedar_policy_core::ast::Policy = p.as_ref();
                    Template::from(ast.template().clone())
                })
                .collect();
            let mut warnings: Vec<_> = cedar_policy::confusable_string_checker(
                policies.templates().chain(static_templates.iter()),
            )
            .map(|w| {
                let warning = cgw_abi::structured::validation_warning(&w);
                let warning = if json_policies {
                    warning.without_spans()
                } else {
                    warning
                };
                serde_json::to_value(warning).map_err(|e| OpError::msg("policies", e.to_string()))
            })
            .collect::<Result<Vec<_>, OpError>>()?;
            warnings.sort_by_key(Value::to_string);
            Ok(json!({"warnings": warnings}))
        }
        Input::LanguageVersion => {
            Ok(json!({"version": cedar_policy::get_lang_version().to_string()}))
        }
    }
}
