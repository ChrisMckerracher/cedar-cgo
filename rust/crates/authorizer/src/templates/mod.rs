//! Immutable host snapshots keep template edits independent of loaded authorizers.

use cedar_policy::{EntityUid, PolicyId, PolicySet, SlotId, Template};
use cgw_abi::{Format, OpError, Source, parse_input, parse_policies};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
mod listing;
mod records;
pub(crate) use records::Output;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    policies: Source,
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Operation {
    Add {
        id: String,
        template: Source,
    },
    Link {
        template_id: String,
        policy_id: String,
        bindings: BTreeMap<String, Value>,
    },
    Unlink {
        policy_id: String,
    },
    Remove {
        template_id: String,
    },
    Templates {},
    Links {},
}

fn policy_error(e: &dyn cgw_abi::diagnostics::Diagnostic) -> OpError {
    let mut error = OpError::new("policies", e);
    // Cedar's outer linking error omits the cause from Display.
    let mut source = e.source();
    while let Some(cause) = source {
        let detail = cause.to_string();
        if !detail.is_empty() && !error.message.contains(&detail) {
            error.message.push_str("; ");
            error.message.push_str(&detail);
        }
        source = cause.source();
    }
    error
}

fn add(set: &mut PolicySet, id: String, source: Source) -> Result<(), OpError> {
    let id = Some(PolicyId::new(id));
    let template = match source.format {
        Format::Cedar => Template::parse(id, source.text).map_err(|e| policy_error(&e))?,
        Format::Json => {
            let json = serde_json::from_str(&source.text)
                .map_err(|e| OpError::msg("policies", e.to_string()))?;
            Template::from_json(id, json).map_err(|e| policy_error(&e))?
        }
    };
    set.add_template(template).map_err(|e| policy_error(&e))
}

pub(crate) fn operate(bytes: &[u8]) -> Result<Output, OpError> {
    let input: Input = parse_input(bytes)?;
    let mut set = parse_policies(&input.policies)?;
    match input.operation {
        Operation::Add { id, template } => add(&mut set, id, template)?,
        Operation::Link {
            template_id,
            policy_id,
            bindings,
        } => {
            let bindings: HashMap<SlotId, EntityUid> = bindings
                .into_iter()
                .map(|(slot, uid)| {
                    let slot = serde_json::from_value(Value::String(slot))
                        .map_err(|e| OpError::msg("policies", e.to_string()))?;
                    let uid = EntityUid::from_json(uid).map_err(|e| policy_error(&e))?;
                    Ok((slot, uid))
                })
                .collect::<Result<_, OpError>>()?;
            set.link(
                PolicyId::new(template_id),
                PolicyId::new(policy_id),
                bindings,
            )
            .map_err(|e| policy_error(&e))?;
        }
        Operation::Unlink { policy_id } => {
            set.unlink(PolicyId::new(policy_id))
                .map_err(|e| policy_error(&e))?;
        }
        Operation::Remove { template_id } => {
            set.remove_template(PolicyId::new(template_id))
                .map_err(|e| policy_error(&e))?;
        }
        Operation::Templates {} => return listing::templates(&set),
        Operation::Links {} => return Ok(listing::links(&set)),
    }
    Ok(Output::Policies {
        policies: set.to_json().map_err(|e| policy_error(&e))?,
    })
}
