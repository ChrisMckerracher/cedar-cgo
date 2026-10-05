use super::*;

#[derive(Deserialize)]
pub(super) struct Case {
    pub(super) name: String,
    pub(super) input: String,
    pub(super) line_width: u32,
    pub(super) indent_width: i32,
    pub(super) valid: bool,
    pub(super) contexts: Vec<serde_json::Value>,
}

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct Outcome {
    pub(super) decision: &'static str,
    pub(super) reasons: Vec<String>,
    pub(super) error_ids: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct Expected {
    pub(super) name: String,
    pub(super) formatted: Option<String>,
    pub(super) outcomes: Vec<Outcome>,
}

pub(super) fn uid(ty: &str, id: &str) -> EntityUid {
    EntityUid::from_json(serde_json::json!({"type": ty, "id": id})).unwrap()
}

pub(super) fn evaluate(set: &PolicySet, contexts: &[serde_json::Value]) -> Vec<Outcome> {
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

pub(super) fn link_templates(set: &mut PolicySet) {
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
