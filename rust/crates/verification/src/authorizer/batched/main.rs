//! Direct upstream oracle; deliberately independent of the guest bridge and wire helpers.
use cedar_policy::{
    Context, Decision, Entity, EntityLoader, EntityUid, PolicySet, Request, Schema,
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::str::FromStr;

struct Loader<'a> {
    schema: &'a Schema,
    batches: &'a [Value],
    calls: Vec<Vec<Value>>,
}

impl EntityLoader for Loader<'_> {
    fn load_entities(&mut self, ids: &HashSet<EntityUid>) -> HashMap<EntityUid, Option<Entity>> {
        let mut ids: Vec<_> = ids.iter().collect();
        ids.sort_unstable();
        let batch = self.batches.get(self.calls.len());
        self.calls
            .push(ids.iter().map(|id| serde_json::json!({"type": id.type_name().to_string(), "id": id.id().unescaped()})).collect());
        let mut result = HashMap::new();
        if let Some(batch) = batch {
            for entity in batch["entities"].as_array().unwrap() {
                let entity = Entity::from_json_value(entity.clone(), Some(self.schema)).unwrap();
                result.insert(entity.uid(), Some(entity));
            }
            for uid in batch["missing"].as_array().unwrap() {
                result.insert(EntityUid::from_json(uid.clone()).unwrap(), None);
            }
        }
        result
    }
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let cases: Vec<Value> = serde_json::from_str(&input).unwrap();
    let mut out = Vec::new();
    for case in cases {
        let (schema, _) = Schema::from_cedarschema_str(case["schema"].as_str().unwrap()).unwrap();
        let policies = PolicySet::from_str(case["policies"].as_str().unwrap()).unwrap();
        let req = &case["request"];
        let action = EntityUid::from_json(req["action"].clone()).unwrap();
        let context =
            Context::from_json_value(req["context"].clone(), Some((&schema, &action))).unwrap();
        let request = Request::new(
            EntityUid::from_json(req["principal"].clone()).unwrap(),
            action,
            EntityUid::from_json(req["resource"].clone()).unwrap(),
            context,
            Some(&schema),
        )
        .unwrap();
        let mut loader = Loader {
            schema: &schema,
            batches: case["batches"].as_array().unwrap(),
            calls: Vec::new(),
        };
        let result = policies.is_authorized_batched(
            &request,
            &schema,
            &mut loader,
            u32::try_from(case["max_iterations"].as_u64().unwrap()).unwrap(),
        );
        let (decision, error) = match result {
            Ok(Decision::Allow) => ("allow", None),
            Ok(Decision::Deny) => ("deny", None),
            Err(error) => ("deny", Some(error.to_string())),
        };
        out.push(
            json!({"name":case["name"],"decision":decision,"error":error,"calls":loader.calls}),
        );
    }
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
