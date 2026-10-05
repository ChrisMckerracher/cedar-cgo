use cedar_policy::{ValidationMode, Validator};
use cgw_abi::{OpError, Source, parse_input, parse_policies};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateInput {
    schema: Source,
    policies: Source,
    max_dereference_level: Option<u32>,
}

#[derive(Serialize)]
pub(crate) struct ValidateOutput {
    passed: bool,
    errors: Vec<cgw_abi::structured::PolicyMessage>,
    warnings: Vec<cgw_abi::structured::PolicyMessage>,
    schema_warnings: Vec<cgw_abi::structured::Message>,
}

pub(crate) fn validate(bytes: &[u8]) -> Result<ValidateOutput, OpError> {
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

pub(crate) fn schema_warnings(bytes: &[u8]) -> Result<serde_json::Value, OpError> {
    let input: SchemaWarningsInput = parse_input(bytes)?;
    let (_, warnings) = cgw_abi::parse_schema_with_warnings(&input.schema)?;
    Ok(serde_json::json!({"warnings":warnings}))
}
