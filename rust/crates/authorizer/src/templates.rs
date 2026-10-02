//! Immutable host snapshots keep template edits independent of loaded authorizers.

use cedar_policy::{EntityUid, PolicyId, PolicySet, SlotId, Template};
use cgw_abi::{Format, OpError, Source, parse_input, parse_policies, run, take_input};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

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

#[derive(Serialize)]
#[serde(untagged)]
enum Output {
    Policies { policies: Value },
    Templates { templates: Vec<TemplateInfo> },
    Links { links: Vec<LinkInfo> },
}

#[derive(Serialize)]
struct TemplateInfo {
    id: String,
    cedar: String,
    json: Value,
    slots: Vec<String>,
    annotations: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Uid {
    r#type: String,
    id: String,
}

#[derive(Serialize)]
struct LinkInfo {
    policy_id: String,
    template_id: String,
    bindings: BTreeMap<String, Uid>,
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

fn operate(bytes: &[u8]) -> Result<Output, OpError> {
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
        Operation::Templates {} => {
            let mut templates = set
                .templates()
                .map(|t| {
                    let mut slots: Vec<_> = t.slots().map(ToString::to_string).collect();
                    slots.sort_unstable();
                    Ok(TemplateInfo {
                        id: AsRef::<str>::as_ref(t.id()).to_owned(),
                        cedar: t.to_cedar(),
                        json: t.to_json().map_err(|e| policy_error(&e))?,
                        slots,
                        annotations: t
                            .annotations()
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect(),
                    })
                })
                .collect::<Result<Vec<_>, OpError>>()?;
            templates.sort_unstable_by(|a, b| a.id.cmp(&b.id));
            return Ok(Output::Templates { templates });
        }
        Operation::Links {} => {
            let mut links: Vec<_> = set
                .policies()
                .filter_map(|p| {
                    Some(LinkInfo {
                        policy_id: AsRef::<str>::as_ref(p.id()).to_owned(),
                        template_id: AsRef::<str>::as_ref(p.template_id()?).to_owned(),
                        bindings: p
                            .template_links()?
                            .into_iter()
                            .map(|(slot, uid)| {
                                (
                                    slot.to_string(),
                                    Uid {
                                        r#type: uid.type_name().to_string(),
                                        id: uid.id().unescaped().to_owned(),
                                    },
                                )
                            })
                            .collect(),
                    })
                })
                .collect();
            links.sort_unstable_by(|a, b| a.policy_id.cmp(&b.policy_id));
            return Ok(Output::Links { links });
        }
    }
    Ok(Output::Policies {
        policies: set.to_json().map_err(|e| policy_error(&e))?,
    })
}

/// Inspects or edits templates using Cedar's PolicySet operations.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_templates(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, operate)
}
