use super::*;

pub(super) fn case(v: &Value, schema: &Schema) -> Result<Value> {
    let named = v["policies_json"]["staticPolicies"].as_object();
    let policies = if let Some(named) = named {
        let mut policies = PolicySet::new();
        for (id, policy) in named {
            policies.add(Policy::from_json(Some(PolicyId::new(id)), policy.clone())?)?;
        }
        policies
    } else {
        v["policies"].as_str().ok_or("missing policies")?.parse()?
    };
    let loaded = Entities::from_json_value(v["loaded"].clone(), Some(schema))?;
    let p = &v["partial"];
    let mut json_entities = v["loaded"].as_array().ok_or("loaded array")?.clone();
    for e in &mut json_entities {
        if e.get("tags").is_none() {
            e["tags"] = json!({});
        }
    }
    json_entities.extend(
        p["entities"]
            .as_array()
            .ok_or("entity array")?
            .iter()
            .cloned(),
    );
    let parsed_entities = if p["entities"].as_array().ok_or("entity array")?.is_empty() {
        PartialEntities::from_concrete(loaded.clone(), schema)
    } else {
        PartialEntities::from_json_value(json!(json_entities), schema)
    };
    let entities = match parsed_entities {
        Ok(e) => e,
        Err(_) => return Ok(json!({"error_stage":"entities"})),
    };
    let action = uid(&p["action"])?;
    let context = if p["context"].is_null() {
        None
    } else {
        match Context::from_json_value(p["context"].clone(), Some((schema, &action))) {
            Ok(c) => Some(c),
            Err(_) => return Ok(json!({"error_stage":"context"})),
        }
    };
    let request = match PartialRequest::new(
        partial_uid(&p["principal"])?,
        action,
        partial_uid(&p["resource"])?,
        context,
        schema,
    ) {
        Ok(r) => r,
        Err(_) => return Ok(json!({"error_stage":"request"})),
    };
    let response = match policies.tpe(&request, &entities, schema) {
        Ok(r) => r,
        Err(_) => return Ok(json!({"error_stage":"policies"})),
    };
    let projection::Projection {
        reasons,
        residuals,
        projected,
        nested_errors,
        rebuilt,
    } = projection::project(&response)?;
    let mut completions = Vec::new();
    for c in v["completions"].as_array().ok_or("completions array")? {
        let (req, entities) = completion(c, schema, &loaded)?;
        completions.push(match response.reauthorize(&req, &entities) {
            Ok(res) => {
                let direct = Authorizer::new().is_authorized(&req, &policies, &entities);
                let actual = response_json(&res);
                let replay = Authorizer::new().is_authorized(&req, &rebuilt, &entities);
                assert_eq!(
                    actual,
                    response_json(&replay),
                    "native PST residual replay differs"
                );
                assert_eq!(
                    actual,
                    response_json(&direct),
                    "TPE/ordinary native disagreement: {}",
                    v["name"]
                );
                actual
            }
            Err(_) => json!({"error_stage":"request"}),
        });
    }
    let output = json!({"decision":response.decision().map(decision).unwrap_or("undecided"), "reasons":reasons, "residuals":residuals, "completions":completions,
        "projection":{"version":1,"cedar_version":"4.13.0","policies":projected},"nested_error_policies":nested_errors});
    if let Some(named) = named {
        // Anchor the oracle to input keys so two escaped Display projections cannot agree unnoticed.
        let mut expected: Vec<_> = named.keys().map(String::as_str).collect();
        expected.sort_unstable();
        let actual: Vec<_> = output["residuals"]
            .as_array()
            .ok_or("residuals")?
            .iter()
            .map(|p| p["policy_id"].as_str().expect("policy id string"))
            .collect();
        assert_eq!(
            actual, expected,
            "native residual identities must match input keys"
        );
        for response in
            std::iter::once(&output).chain(output["completions"].as_array().ok_or("completions")?)
        {
            for field in ["reasons", "error_policies"] {
                if let Some(ids) = response[field].as_array() {
                    for id in ids {
                        assert!(
                            named.contains_key(id.as_str().expect("policy id string")),
                            "native {field} ID {id:?} is not an original input key"
                        );
                    }
                }
            }
        }
    }
    Ok(output)
}
