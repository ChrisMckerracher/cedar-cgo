//! Direct native permission-query oracle, including schema-driven action enumeration.
use cedar_policy::{
    ActionQueryRequest, Context, Decision, Entities, EntityId, EntityUid, PartialEntities,
    PartialEntity, PartialEntityUid, PolicySet, PrincipalQueryRequest, ResourceQueryRequest,
    Schema,
};
use serde_json::{Value, json};
use std::io::{self, Read};
fn uid(value: &Value) -> EntityUid {
    EntityUid::from_json(value.clone()).unwrap()
}
fn partial(value: &Value) -> PartialEntityUid {
    PartialEntityUid::new(
        value["type"].as_str().unwrap().parse().unwrap(),
        value["id"].as_str().map(EntityId::new),
    )
}
fn sorted(values: impl Iterator<Item = EntityUid>) -> Vec<Value> {
    let mut values: Vec<_> = values.collect();
    values.sort();
    values
        .into_iter()
        .map(|u| json!({"type":u.type_name().to_string(),"id":u.id().unescaped()}))
        .collect()
}
fn partial_entities(
    loaded: Entities,
    additions: Option<&Value>,
    schema: &Schema,
) -> Result<PartialEntities, &'static str> {
    // Native conversion fixes all loaded fields before partial query additions are parsed.
    let loaded = PartialEntities::from_concrete(loaded, schema).map_err(|_| "entities")?;
    let Some(additions) = additions else {
        return Ok(loaded);
    };
    let core: &cedar_policy_core::tpe::entities::PartialEntities = loaded.as_ref();
    let mut values: Vec<_> = core
        .entities()
        .filter(|entity| !entity.uid().is_action())
        .cloned()
        .collect();
    for addition in additions.as_array().unwrap() {
        values.push(
            cedar_policy_core::tpe::entities::parse_ejson(
                serde_json::from_value(addition.clone()).unwrap(),
                schema.as_ref(),
            )
            .map_err(|_| "entities")?,
        );
    }
    let values = values
        .into_iter()
        .map(|entity| {
            let attrs = entity.attrs().map(|values| {
                values
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            cedar_policy_core::ast::RestrictedExpr::from(value.clone()).into(),
                        )
                    })
                    .collect()
            });
            let tags = entity.tags().map(|values| {
                values
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            cedar_policy_core::ast::RestrictedExpr::from(value.clone()).into(),
                        )
                    })
                    .collect()
            });
            let ancestors = entity
                .ancestors()
                .map(|values| values.iter().cloned().map(EntityUid::from).collect());
            PartialEntity::new(entity.uid().clone().into(), attrs, ancestors, tags, schema)
                .map_err(|_| "entities")
        })
        .collect::<Result<Vec<_>, _>>()?;
    PartialEntities::from_partial_entities(values, schema).map_err(|_| "entities")
}

fn query(case: &Value, input: &Value, schema: &Schema) -> Result<Value, &'static str> {
    let policies: PolicySet = case
        .get("policies")
        .unwrap_or(&input["policies"])
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let loaded = Entities::from_json_value(
        case.get("entities").unwrap_or(&input["entities"]).clone(),
        Some(schema),
    )
    .unwrap();
    match case["operation"].as_str().unwrap() {
        "resource" => {
            let entities = match case.get("additions") {
                Some(additions) => loaded
                    .add_entities_from_json_value(additions.clone(), Some(schema))
                    .map_err(|_| "entities")?,
                None => loaded,
            };
            let action = uid(&case["action"]);
            let context =
                Context::from_json_value(case["context"].clone(), Some((schema, &action))).unwrap();
            let request = ResourceQueryRequest::new(
                uid(&case["principal"]),
                action,
                case["resource_type"].as_str().unwrap().parse().unwrap(),
                context,
                schema,
            )
            .unwrap();
            Ok(
                json!({"allowed":sorted(policies.query_resource(&request,&entities,schema).unwrap())}),
            )
        }
        "principal" => {
            let entities = match case.get("additions") {
                Some(additions) => loaded
                    .add_entities_from_json_value(additions.clone(), Some(schema))
                    .map_err(|_| "entities")?,
                None => loaded,
            };
            let action = uid(&case["action"]);
            let context =
                Context::from_json_value(case["context"].clone(), Some((schema, &action))).unwrap();
            let request = PrincipalQueryRequest::new(
                case["principal_type"].as_str().unwrap().parse().unwrap(),
                action,
                uid(&case["resource"]),
                context,
                schema,
            )
            .unwrap();
            Ok(
                json!({"allowed":sorted(policies.query_principal(&request,&entities,schema).unwrap())}),
            )
        }
        "action" => {
            let entities = partial_entities(loaded, case.get("additions"), schema)?;
            let context = if case["context"].is_null() {
                None
            } else {
                Some(Context::from_json_value(case["context"].clone(), None).unwrap())
            };
            let request = ActionQueryRequest::new(
                partial(&case["principal"]),
                partial(&case["resource"]),
                context,
                schema.clone(),
            )
            .unwrap();
            let mut allowed = Vec::new();
            let mut undecided = Vec::new();
            for (uid, decision) in policies.query_action(&request, &entities).unwrap() {
                match decision {
                    Some(Decision::Allow) => allowed.push(uid.clone()),
                    None => undecided.push(uid.clone()),
                    Some(Decision::Deny) => panic!("native query returned deny"),
                }
            }
            Ok(
                json!({"allowed":sorted(allowed.into_iter()),"undecided":sorted(undecided.into_iter())}),
            )
        }
        _ => panic!("unknown fixture operation"),
    }
}

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
            let mut result = match query(case, &input, &schema) {
                Ok(value) => value,
                Err(kind) => json!({"error_kind":kind}),
            };
            result["name"] = case["name"].clone();
            if case.get("additions").is_some() {
                let mut without = case.clone();
                without.as_object_mut().unwrap().remove("additions");
                result["without_additions"] = query(&without, &input, &schema).unwrap();
            }
            result
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
