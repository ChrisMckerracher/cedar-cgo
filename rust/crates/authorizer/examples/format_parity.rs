//! Direct native upstream oracle; deliberately independent of the guest operation.

use cedar_policy::{
    AuthorizationError, Authorizer, Context, Decision, Entities, EntityUid, PolicyId, PolicySet,
    Request, SlotId,
};
use cedar_policy_formatter::{Config, policies_str_to_pretty};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Deserialize)]
struct Case {
    name: String,
    input: String,
    line_width: u32,
    indent_width: i32,
    valid: bool,
    contexts: Vec<serde_json::Value>,
}

#[derive(Debug, PartialEq, Serialize)]
struct Outcome {
    decision: &'static str,
    reasons: Vec<String>,
    error_ids: Vec<String>,
}

#[derive(Serialize)]
struct Expected {
    name: String,
    formatted: Option<String>,
    outcomes: Vec<Outcome>,
}

fn uid(ty: &str, id: &str) -> EntityUid {
    EntityUid::from_json(serde_json::json!({"type": ty, "id": id})).unwrap()
}

fn evaluate(set: &PolicySet, contexts: &[serde_json::Value]) -> Vec<Outcome> {
    contexts
        .iter()
        .map(|context| {
            let request = Request::new(
                uid("User", "alice"),
                uid("Action", "view"),
                uid("Photo", "p1"),
                Context::from_json_value(context.clone(), None).unwrap(),
                None,
            )
            .unwrap();
            let response = Authorizer::new().is_authorized(&request, set, &Entities::empty());
            let mut reasons = response
                .diagnostics()
                .reason()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            reasons.sort();
            let mut error_ids = response
                .diagnostics()
                .errors()
                .map(|error| match error {
                    AuthorizationError::PolicyEvaluationError(error) => {
                        error.policy_id().to_string()
                    }
                })
                .collect::<Vec<_>>();
            error_ids.sort();
            Outcome {
                decision: match response.decision() {
                    Decision::Allow => "allow",
                    Decision::Deny => "deny",
                },
                reasons,
                error_ids,
            }
        })
        .collect()
}

fn link_templates(set: &mut PolicySet) {
    let links = set
        .templates()
        .map(|template| {
            let slots = template
                .slots()
                .map(|slot| {
                    let value = if *slot == SlotId::principal() {
                        uid("User", "alice")
                    } else {
                        uid("Photo", "p1")
                    };
                    (slot.clone(), value)
                })
                .collect::<HashMap<_, _>>();
            (template.id().clone(), slots)
        })
        .collect::<Vec<_>>();
    for (id, slots) in links {
        let linked_id = PolicyId::from_str(&format!("linked_{id}")).unwrap();
        set.link(id, linked_id, slots).unwrap();
    }
}

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/parity/format");
    let cases: Vec<Case> =
        serde_json::from_str(&std::fs::read_to_string(dir.join("cases.json")).unwrap()).unwrap();
    let mut expected = Vec::new();
    for case in cases {
        let config = Config {
            line_width: case.line_width as usize,
            indent_width: case.indent_width as isize,
        };
        let result = policies_str_to_pretty(&case.input, &config);
        assert_eq!(
            result.is_ok(),
            case.valid,
            "{}: unexpected formatting result: {result:?}",
            case.name
        );
        let (formatted, outcomes) = match result {
            Ok(formatted) => {
                assert_eq!(
                    formatted,
                    policies_str_to_pretty(&formatted, &config).unwrap(),
                    "{}: idempotence",
                    case.name
                );
                let mut before = PolicySet::from_str(&case.input).unwrap();
                let mut after = PolicySet::from_str(&formatted).unwrap();
                // EST equality covers templates and annotations as well as static policies.
                assert_eq!(
                    before.clone().to_json().unwrap(),
                    after.clone().to_json().unwrap(),
                    "{}: policy/template EST changed",
                    case.name
                );
                let outcomes = evaluate(&before, &case.contexts);
                assert_eq!(outcomes, evaluate(&after, &case.contexts), "{}", case.name);
                link_templates(&mut before);
                link_templates(&mut after);
                assert_eq!(
                    evaluate(&before, &case.contexts),
                    evaluate(&after, &case.contexts),
                    "{}: linked template decisions changed",
                    case.name
                );
                (Some(formatted), outcomes)
            }
            Err(err) => {
                assert!(
                    PolicySet::from_str(&case.input).is_err(),
                    "{}: formatter rejected valid Cedar: {err:#}",
                    case.name
                );
                (None, Vec::new())
            }
        };
        expected.push(Expected {
            name: case.name,
            formatted,
            outcomes,
        });
    }
    let actual = serde_json::to_string_pretty(&expected).unwrap() + "\n";
    let path = dir.join("expected.json");
    match std::env::args().nth(1).as_deref() {
        Some("--write") => std::fs::write(path, actual).unwrap(),
        Some("--check") => assert_eq!(
            actual,
            std::fs::read_to_string(path).unwrap(),
            "native formatting fixtures changed; regenerate and review"
        ),
        _ => panic!("expected --check or --write"),
    }
    println!("{} native formatting cases checked", expected.len());
}
