//! Independent native Cedar oracle; never calls the Wasm guest or its transport.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityLoader, EntityUid, PolicySet, Request,
    Schema, TestEntityLoader,
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

struct Trace<'a> {
    native: TestEntityLoader<'a>,
    batches: Vec<Vec<EntityUid>>,
    fetched: HashMap<EntityUid, Entity>,
}

impl EntityLoader for Trace<'_> {
    fn load_entities(&mut self, uids: &HashSet<EntityUid>) -> HashMap<EntityUid, Option<Entity>> {
        let mut batch: Vec<_> = uids.iter().cloned().collect();
        batch.sort();
        self.batches.push(batch);
        let result = self.native.load_entities(uids);
        self.fetched.extend(
            result
                .iter()
                .filter_map(|(uid, entity)| entity.clone().map(|e| (uid.clone(), e))),
        );
        result
    }
}

// Cedar sets and parent collections have no semantic ordering.
fn canonical(value: &mut Value) {
    match value {
        Value::Array(items) => {
            items.iter_mut().for_each(canonical);
            items.sort_by_key(Value::to_string);
        }
        Value::Object(fields) => {
            fields.values_mut().for_each(canonical);
            fields.sort_keys();
        }
        _ => (),
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: slicing-fixtures cases.json");
    let cases: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let output: Vec<_> = cases
        .iter()
        .map(|case| {
            let schema = if case["schema"].is_string() {
                Schema::from_str(case["schema"].as_str().unwrap()).unwrap()
            } else {
                Schema::from_json_value(case["schema"].clone()).unwrap()
            };
            let policies = PolicySet::from_str(case["policies"].as_str().unwrap()).unwrap();
            let source =
                Entities::from_json_value(case["entities"].clone(), Some(&schema)).unwrap();
            let input = &case["request"];
            let action = EntityUid::from_json(input["action"].clone()).unwrap();
            let request = Request::new(
                EntityUid::from_json(input["principal"].clone()).unwrap(),
                action.clone(),
                EntityUid::from_json(input["resource"].clone()).unwrap(),
                Context::from_json_value(input["context"].clone(), Some((&schema, &action)))
                    .unwrap(),
                Some(&schema),
            )
            .unwrap();
            let full = Authorizer::new().is_authorized(&request, &policies, &source);
            let mut loader = Trace {
                native: TestEntityLoader::new(&source),
                batches: Vec::new(),
                fetched: HashMap::new(),
            };
            let decision = policies
                .is_authorized_batched(&request, &schema, &mut loader, 32)
                .unwrap();
            assert_eq!(full.decision(), decision, "{} full vs loader", case["name"]);
            let mut slice = Value::Array(
                loader
                    .fetched
                    .values()
                    .map(|e| e.to_json_value().unwrap())
                    .collect(),
            );
            canonical(&mut slice);
            let reduced = Entities::from_json_value(slice.clone(), Some(&schema)).unwrap();
            assert_eq!(
                decision,
                Authorizer::new()
                    .is_authorized(&request, &policies, &reduced)
                    .decision(),
                "{} full vs reduced",
                case["name"]
            );
            let batches: Vec<Vec<_>> = loader
                .batches
                .iter()
                .map(|batch| {
                    batch
                        .iter()
                        .map(|uid| uid.to_json_value().unwrap())
                        .collect()
                })
                .collect();
            json!({
                "name": case["name"],
                "decision": match decision { Decision::Allow => "allow", Decision::Deny => "deny" },
                "entities": slice,
                "batches": batches,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
