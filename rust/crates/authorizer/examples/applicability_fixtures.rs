//! Direct native Cedar oracle for policy and template request environments.
use cedar_policy::{EntityUid, PolicyId, PolicySet, RequestEnv, Schema, SlotId};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read};

fn envs(values: impl Iterator<Item = RequestEnv>) -> Vec<Value> {
    values.map(|env| {
        let mut value=json!({"principal_type":env.principal().to_string(),"action":{"type":env.action().type_name().to_string(),"id":env.action().id().unescaped()},"resource_type":env.resource().to_string()});
        if let Some(slot)=env.principal_slot() {value["principal_slot_type"]=json!(slot.to_string());}
        if let Some(slot)=env.resource_slot() {value["resource_slot_type"]=json!(slot.to_string());}
        value
    }).collect()
}

fn main() {
    let mut source = String::new();
    io::stdin().read_to_string(&mut source).unwrap();
    let input: Value = serde_json::from_str(&source).unwrap();
    let (default_schema, _) =
        Schema::from_cedarschema_str(input["schema"].as_str().unwrap()).unwrap();
    let cases: Vec<_> = input["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let case_schema = case.get("schema").map(|value| {
                Schema::from_cedarschema_str(value.as_str().unwrap())
                    .unwrap()
                    .0
            });
            let schema = case_schema.as_ref().unwrap_or(&default_schema);
            let mut policies: PolicySet = if case["format"].as_str() == Some("json") {
                PolicySet::from_json_value(case["policies"].clone()).unwrap()
            } else {
                case["policies"].as_str().unwrap().parse().unwrap()
            };
            if let Some(link) = case.get("link") {
                policies
                    .link(
                        PolicyId::new(link["template_id"].as_str().unwrap()),
                        PolicyId::new(link["id"].as_str().unwrap()),
                        HashMap::from([
                            (
                                SlotId::principal(),
                                EntityUid::from_json(link["principal"].clone()).unwrap(),
                            ),
                            (
                                SlotId::resource(),
                                EntityUid::from_json(link["resource"].clone()).unwrap(),
                            ),
                        ]),
                    )
                    .unwrap();
            }
            let results: BTreeMap<_, _> = policies
                .policies()
                .map(|p| {
                    (
                        AsRef::<str>::as_ref(p.id()).to_owned(),
                        envs(p.get_valid_request_envs(schema)),
                    )
                })
                .collect();
            let templates: BTreeMap<_, _> = policies
                .templates()
                .map(|t| {
                    (
                        AsRef::<str>::as_ref(t.id()).to_owned(),
                        envs(t.get_valid_request_envs(schema)),
                    )
                })
                .collect();
            json!({"name":case["name"],"applicability":{"policies":results,"templates":templates}})
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&cases).unwrap());
}
