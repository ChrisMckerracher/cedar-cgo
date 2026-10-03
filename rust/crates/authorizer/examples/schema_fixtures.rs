//! Direct native Cedar oracle for schema fragments, resolution, and action entities.
use cedar_policy::{EntityUid, PolicySet, Schema, SchemaFragment, ValidationMode, Validator};
use cedar_policy_core::validator::{RawName, ValidatorSchema, json_schema};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, Read};

fn uid(value: &EntityUid) -> Value {
    json!({"type":value.type_name().to_string(),"id":value.id().unescaped()})
}

fn uids(values: impl Iterator<Item = EntityUid>) -> Vec<Value> {
    let mut values: Vec<_> = values.collect();
    values.sort();
    values.into_iter().map(|value| uid(&value)).collect()
}

fn inspect(schema: &Schema, fragment: SchemaFragment) -> Value {
    let core: &ValidatorSchema = schema.as_ref();
    let declarations = fragment.to_json_value().unwrap();
    let fragment: json_schema::Fragment<RawName> =
        json_schema::Fragment::from_json_value(declarations).unwrap();
    let resolved = fragment
        .to_internal_name_fragment_with_resolved_types()
        .unwrap();
    let ancestors: BTreeMap<_, _> = schema
        .entity_types()
        .map(|name| {
            let mut ancestors: Vec<_> = schema
                .ancestors(name)
                .unwrap()
                .map(ToString::to_string)
                .collect();
            ancestors.sort();
            (name.to_string(), ancestors)
        })
        .collect();
    let mut envs: Vec<_> = schema
        .request_envs()
        .map(|env| {
            (
                env.principal().to_string(),
                env.action().clone(),
                env.resource().to_string(),
            )
        })
        .collect();
    envs.sort();
    let envs: Vec<_> = envs.into_iter().map(|(principal, action, resource)| json!({"principal_type":principal,"action":uid(&action),"resource_type":resource})).collect();
    json!({
        "resolved_schema": resolved,
        "expanded_schema": core.to_json_schema().unwrap(),
        "ancestors": ancestors,
        "actions": uids(schema.actions().cloned()),
        "action_groups": uids(schema.action_groups().cloned()),
        "environments": envs
    })
}

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let cases: Value = serde_json::from_str(&text).unwrap();
    let results: Vec<_> = cases.as_array().unwrap().iter().map(|case| {
        let fragments: Vec<_> = case["fragments"].as_array().unwrap().iter().map(|source| {
            match source["format"].as_str().unwrap() {
                "cedar" => SchemaFragment::from_cedarschema_str(source["text"].as_str().unwrap()).unwrap().0,
                "json" => SchemaFragment::from_json_str(source["text"].as_str().unwrap()).unwrap(),
                _ => unreachable!(),
            }
        }).collect();
        if case["error"].as_bool() == Some(true) {
            assert!(Schema::from_schema_fragments(fragments).is_err(), "{}", case["name"]);
            return json!({"name":case["name"],"error":true});
        }
        let schema = Schema::from_schema_fragments(fragments.clone()).unwrap();
        let conversions: Vec<_> = fragments.iter().enumerate().map(|(index, fragment)| {
            let cedar = fragment.to_cedarschema().unwrap();
            let json = fragment.clone().to_json_value().unwrap();
            let reparsed = SchemaFragment::from_cedarschema_str(&cedar).unwrap().0;
            let mut roundtrip_fragments = fragments.clone();
            roundtrip_fragments[index] = reparsed;
            let roundtrip = Schema::from_schema_fragments(roundtrip_fragments).unwrap();
            let original: &ValidatorSchema = schema.as_ref();
            let roundtrip: &ValidatorSchema = roundtrip.as_ref();
            assert_eq!(serde_json::to_value(original.to_json_schema().unwrap()).unwrap(), serde_json::to_value(roundtrip.to_json_schema().unwrap()).unwrap());
            json!({"json":json,"cedar":cedar})
        }).collect();
        let complete = if case["schema_json"].is_null() {
            SchemaFragment::from_cedarschema_str(case["schema"].as_str().unwrap()).unwrap().0
        } else {
            SchemaFragment::from_json_value(case["schema_json"].clone()).unwrap()
        };
        let complete_schema: Schema = complete.clone().try_into().unwrap();
        assert_eq!(inspect(&schema, complete.clone()), inspect(&complete_schema, complete.clone()));
        let entities = schema.action_entities().unwrap();
        let mut entities = entities.to_json_value().unwrap().as_array().unwrap().clone();
            entities.sort_by_key(|entity| (
                entity["uid"]["type"].as_str().unwrap().to_owned(),
                entity["uid"]["id"].as_str().unwrap().to_owned(),
            ));
        let policies: PolicySet = case["policies"].as_str().unwrap().parse().unwrap();
        let valid = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict).validation_passed();
        json!({"name":case["name"],"conversions":conversions,"inspection":inspect(&schema,complete),"action_entities":entities,"valid":valid})
    }).collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
