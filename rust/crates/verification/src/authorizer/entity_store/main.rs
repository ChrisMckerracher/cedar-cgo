//! Direct native entity-store oracle, retaining direct parents across mutation sequences.
use cedar_policy::{Entities, Entity, EntityUid, Schema};
use cedar_policy_core::ast;
use serde_json::{Value, json};
use std::io::{self, Read};

fn canonical(value: &mut Value) {
    match value {
        Value::Array(values) => {
            values.iter_mut().for_each(canonical);
            values.sort_by_cached_key(Value::to_string);
        }
        Value::Object(values) => {
            values.values_mut().for_each(canonical);
            values.sort_keys();
        }
        _ => (),
    }
}

fn uid_value(uid: EntityUid) -> Value {
    json!({"type":uid.type_name().to_string(),"id":uid.id().unescaped()})
}

fn stage(entities: &Entities, uid: &EntityUid, ancestor: &EntityUid) -> Value {
    let mut normalized = entities.to_json_value().unwrap();
    canonical(&mut normalized);
    let mut entity = entities
        .get(uid)
        .map(|entity| entity.to_json_value().unwrap())
        .unwrap_or(Value::Null);
    canonical(&mut entity);
    let parents = entities.get(uid).map(|entity| {
        let native: &ast::Entity = entity.as_ref();
        let mut parents: Vec<_> = native.parents().cloned().collect();
        parents.sort();
        parents
            .into_iter()
            .map(EntityUid::from)
            .map(uid_value)
            .collect::<Vec<_>>()
    });
    let ancestors = entities.ancestors(uid).map(|values| {
        let mut values: Vec<_> = values.cloned().collect();
        values.sort();
        values.into_iter().map(uid_value).collect::<Vec<_>>()
    });
    let reparsed = Entities::from_json_value(normalized.clone(), None).unwrap();
    json!({"normalized":normalized,"entity":entity,"parents":parents,"ancestors":ancestors,"is_ancestor":entities.is_ancestor_of(ancestor,uid),"normalized_deep_equal":entities.deep_eq(&reparsed)})
}

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let input: Value = serde_json::from_str(&text).unwrap();
    let expected: Vec<_> = input
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let schema = case["schema"]
                .as_str()
                .map(|schema| Schema::from_cedarschema_str(schema).unwrap().0);
            let mut entities =
                Entities::from_json_value(case["entities"].clone(), schema.as_ref()).unwrap();
            let uid = EntityUid::from_json(case["uid"].clone()).unwrap();
            let ancestor = EntityUid::from_json(case["ancestor"].clone()).unwrap();
            let mut stages = vec![json!({"result":stage(&entities,&uid,&ancestor)})];
            for step in case["steps"].as_array().unwrap() {
                let result = match step["operation"].as_str().unwrap() {
                    "remove" => entities
                        .clone()
                        .remove_entities(
                            step["uids"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .cloned()
                                .map(|u| EntityUid::from_json(u).unwrap())
                                .collect::<Vec<_>>(),
                        )
                        .map_err(|e| e.to_string()),
                    "upsert" => {
                        let additions = step["entities"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .cloned()
                            .map(|v| {
                                Entity::from_json_value(v, schema.as_ref())
                                    .map_err(|e| e.to_string())
                            })
                            .collect::<Result<Vec<_>, _>>();
                        match additions {
                            Ok(additions) => entities
                                .clone()
                                .upsert_entities(additions, schema.as_ref())
                                .map_err(|e| e.to_string()),
                            Err(error) => Err(error.to_string()),
                        }
                    }
                    _ => panic!("unknown fixture operation"),
                };
                match result {
                    Ok(changed) => {
                        entities = changed;
                        stages.push(json!({"result":stage(&entities,&uid,&ancestor)}));
                    }
                    Err(_) => stages.push(
                        json!({"error_kind":"entities","result":stage(&entities,&uid,&ancestor)}),
                    ),
                }
            }
            json!({"name":case["name"],"stages":stages})
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&expected).unwrap());
}
