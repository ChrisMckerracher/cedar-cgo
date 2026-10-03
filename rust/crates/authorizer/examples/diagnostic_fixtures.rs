//! Direct native Cedar validation oracle with structured diagnostic projection.
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use serde_json::{Value, json};
use std::io::{self, Read};
fn stable(value: impl serde::Serialize) -> Value {
    let mut value = serde_json::to_value(value).unwrap();
    if let Some(message) = value["message"].as_str() {
        value["message"] = json!(message.split(" (help: did you mean").next().unwrap());
    }
    value
}
fn main() {
    let mut source = String::new();
    io::stdin().read_to_string(&mut source).unwrap();
    let input: Vec<Value> = serde_json::from_str(&source).unwrap();
    let output:Vec<_>=input.iter().map(|case| {
        let (schema,warnings)=Schema::from_cedarschema_str(case["schema"].as_str().unwrap()).unwrap();
        let schema_warnings:Vec<_>=warnings.map(|w| cgw_abi::structured::schema_warning(&w)).collect();
        let json_policies = case.get("policies_json").is_some();
        let policies: PolicySet = if json_policies {
            PolicySet::from_json_value(case["policies_json"].clone()).unwrap()
        } else {
            case["policies"].as_str().unwrap().parse().unwrap()
        };
        let project = |message: cgw_abi::structured::PolicyMessage| {
            if json_policies {
                message.without_spans()
            } else {
                message
            }
        };
        let result=Validator::new(schema).validate(&policies,ValidationMode::Strict);
        let mut errors:Vec<_>=result.validation_errors().map(|e| stable(project(cgw_abi::structured::validation_error(e)))).collect();
        let mut warnings:Vec<_>=result.validation_warnings().map(|w| stable(project(cgw_abi::structured::validation_warning(w)))).collect();
        // Native hash iteration does not define diagnostic order.
        errors.sort_by_key(Value::to_string);
        warnings.sort_by_key(Value::to_string);
        json!({"name":case["name"],"passed":result.validation_passed(),"errors":errors,"warnings":warnings,"schema_warnings":schema_warnings})
    }).collect();
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
