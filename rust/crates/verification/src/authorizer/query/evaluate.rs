use super::*;

pub(super) fn query(case: &Value, input: &Value, schema: &Schema) -> Result<Value, &'static str> {
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
