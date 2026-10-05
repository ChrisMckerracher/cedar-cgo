//! Direct native permission-query oracle, including schema-driven action enumeration.
use cedar_policy::{
    ActionQueryRequest, Context, Decision, Entities, EntityId, EntityUid, PartialEntities,
    PartialEntity, PartialEntityUid, PolicySet, PrincipalQueryRequest, ResourceQueryRequest,
    Schema,
};
use serde_json::{Value, json};
use std::io::{self, Read};
mod evaluate;
mod inputs;
use inputs::*;

fn main() {
    let mut source = String::new();
    io::stdin().read_to_string(&mut source).unwrap();
    let input: Value = serde_json::from_str(&source).unwrap();
    let schema = Schema::from_cedarschema_str(input["schema"].as_str().unwrap())
        .unwrap()
        .0;
    let results: Vec<_> = input["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let mut result = match evaluate::query(case, &input, &schema) {
                Ok(value) => value,
                Err(kind) => json!({"error_kind":kind}),
            };
            result["name"] = case["name"].clone();
            if case.get("additions").is_some() {
                let mut without = case.clone();
                without.as_object_mut().unwrap().remove("additions");
                result["without_additions"] = evaluate::query(&without, &input, &schema).unwrap();
            }
            result
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
