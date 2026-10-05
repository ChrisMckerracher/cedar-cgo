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

mod observations;
use observations::*;

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
