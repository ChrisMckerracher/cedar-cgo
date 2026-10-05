//! Native Cedar oracle for validation with a maximum entity dereference level.
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use serde_json::{Value, json};
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let input: Value = serde_json::from_str(&input).unwrap();
    let (schema, schema_warnings) =
        Schema::from_cedarschema_str(input["schema"].as_str().unwrap()).unwrap();
    let schema_warnings: Vec<_> = schema_warnings
        .map(|w| cgw_abi::structured::schema_warning(&w))
        .collect();
    let validator = Validator::new(schema);
    let results: Vec<_> = input["cases"].as_array().unwrap().iter().map(|case| {
        let policies: PolicySet = case["policies"].as_str().unwrap().parse().unwrap();
        let result = match case["level"].as_u64() {
            Some(level) => validator.validate_with_level(&policies, ValidationMode::Strict, u32::try_from(level).unwrap()),
            None => validator.validate(&policies, ValidationMode::Strict),
        };
        let mut errors: Vec<_> = result.validation_errors().map(|error| serde_json::to_value(cgw_abi::structured::validation_error(error)).unwrap()).collect();
        errors.sort_by_key(|error| error["policy_id"].to_string());
        let mut warnings: Vec<_> = result.validation_warnings().map(|warning| serde_json::to_value(cgw_abi::structured::validation_warning(warning)).unwrap()).collect();
        warnings.sort_by_key(|warning| warning["policy_id"].to_string());
        json!({"name": case["name"], "passed": result.validation_passed(), "errors": errors, "warnings": warnings,"schema_warnings":schema_warnings})
    }).collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
