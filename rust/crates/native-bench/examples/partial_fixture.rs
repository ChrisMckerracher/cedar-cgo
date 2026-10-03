//! Independent native Cedar oracle for testdata/parity/partial; no guest helpers.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityUid, PartialEntities,
    PartialEntityUid, PartialRequest, Policy, PolicyId, PolicySet, Request, Schema,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, error::Error, io::Read};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn uid(v: &Value) -> Result<EntityUid> {
    Ok(EntityUid::from_json(v.clone())?)
}

fn partial_uid(v: &Value) -> Result<PartialEntityUid> {
    Ok(PartialEntityUid::new(
        v["type"].as_str().ok_or("missing type")?.parse()?,
        v["id"].as_str().map(EntityId::new),
    ))
}

fn response_json(response: &cedar_policy::Response) -> Value {
    let mut reasons: Vec<_> = response
        .diagnostics()
        .reason()
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort();
    let mut errors: Vec<_> = response
        .diagnostics()
        .errors()
        .map(|e| match e {
            cedar_policy::AuthorizationError::PolicyEvaluationError(e) => {
                AsRef::<str>::as_ref(e.policy_id()).to_owned()
            }
        })
        .collect();
    errors.sort();
    json!({"decision": decision(response.decision()), "reasons": reasons, "error_policies": errors})
}

fn decision(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

fn completion(v: &Value, schema: &Schema, loaded: &Entities) -> Result<(Request, Entities)> {
    let action = uid(&v["action"])?;
    let context = Context::from_json_value(v["context"].clone(), Some((schema, &action)))?;
    let request = Request::new(
        uid(&v["principal"])?,
        action,
        uid(&v["resource"])?,
        context,
        Some(schema),
    )?;
    let entities = loaded
        .clone()
        .add_entities_from_json_value(v["entities"].clone(), Some(schema))?;
    Ok((request, entities))
}

fn case(v: &Value, schema: &Schema) -> Result<Value> {
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
    let mut reasons: Vec<_> = response
        .reason()
        .into_iter()
        .flatten()
        .map(|id| AsRef::<str>::as_ref(id).to_owned())
        .collect();
    reasons.sort();
    let mut residuals: Vec<_> = response.policies().map(|policy| {
        let id = policy.id();
        let state = if response.true_permits().chain(response.true_forbids()).any(|p| p == id) { "true" }
            else if response.false_permits().chain(response.false_forbids()).any(|p| p == id) { "false" }
            else if response.error_permits().chain(response.error_forbids()).any(|p| p == id) { "error" }
            else { "residual" };
        json!({"policy_id":AsRef::<str>::as_ref(id).to_owned(), "effect":policy.effect().to_string(), "state":state, "cedar":policy.to_string()})
    }).collect();
    residuals.sort_by(|a, b| a["policy_id"].as_str().cmp(&b["policy_id"].as_str()));
    let residual_set = response.policy_set();
    let mut projected = BTreeMap::new();
    for policy in response.policies() {
        let canonical = Policy::from_pst(policy.to_pst()?)?;
        let json = canonical.to_json()?;
        let stored = residual_set
            .policy(policy.id())
            .ok_or("missing residual policy")?;
        assert_eq!(json, Policy::from_pst(stored.to_pst()?)?.to_json()?);
        projected.insert(AsRef::<str>::as_ref(policy.id()).to_owned(), json);
    }
    let mut nested_errors = Vec::new();
    for policy in response.residual_policies() {
        let pst = policy.to_pst()?;
        if pst.body().clauses().iter().any(|clause| match clause {
            cedar_policy::pst::Clause::When(expr) | cedar_policy::pst::Clause::Unless(expr) => {
                expr.has_error()
            }
        }) {
            nested_errors.push(AsRef::<str>::as_ref(policy.id()).to_owned());
        }
        assert!(projected.contains_key(AsRef::<str>::as_ref(policy.id())));
    }
    nested_errors.sort();
    let rebuilt = PolicySet::from_pst(residual_set.to_pst()?)?;
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

fn main() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let input: Value = serde_json::from_str(&input)?;
    let schema = Schema::from_cedarschema_str(input["schema"].as_str().ok_or("schema")?)?.0;
    let outputs = input["cases"]
        .as_array()
        .ok_or("cases array")?
        .iter()
        .map(|v| Ok(json!({"name":v["name"], "result":case(v, &schema)?})))
        .collect::<Result<Vec<_>>>()?;
    println!("{}", serde_json::to_string_pretty(&outputs)?);
    Ok(())
}
