use cedar_policy::{Policy, PolicyId};
use cgw_abi::{OpError, parse_input, parse_policies};
use serde::Serialize;
use std::collections::BTreeMap;
mod input;
mod output;
use input::Input;
use output::{PolicyOutput, SetOutput, policy_output, set_output};

fn policy_error(e: &(dyn cgw_abi::diagnostics::Diagnostic + '_)) -> OpError {
    OpError::new("policies", e)
}

#[derive(Serialize)]
pub(super) struct Output {
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<PolicyOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set: Option<SetOutput>,
    renames: BTreeMap<String, String>,
}

pub(super) fn execute(bytes: &[u8]) -> Result<Output, OpError> {
    let input: Input = parse_input(bytes)?;
    let mut out = Output {
        policy: None,
        set: None,
        renames: BTreeMap::new(),
    };
    match input {
        Input::Parse { id, source } => {
            let id = Some(PolicyId::new(id));
            let policy = match source.format {
                cgw_abi::Format::Cedar => {
                    Policy::parse(id, source.text).map_err(|e| policy_error(&e))?
                }
                cgw_abi::Format::Json => Policy::from_json(
                    id,
                    serde_json::from_str(&source.text)
                        .map_err(|e| OpError::msg("policies", e.to_string()))?,
                )
                .map_err(|e| policy_error(&e))?,
            };
            out.policy = Some(policy_output(&policy)?);
        }
        Input::Inspect { set } => out.set = Some(set_output(parse_policies(&set)?)?),
        Input::Add { set, id, policy } => {
            let mut set = parse_policies(&set)?;
            set.add(
                Policy::from_json(Some(PolicyId::new(id)), policy).map_err(|e| policy_error(&e))?,
            )
            .map_err(|e| policy_error(&e))?;
            out.set = Some(set_output(set)?);
        }
        Input::Remove { set, id } => {
            let mut set = parse_policies(&set)?;
            set.remove_static(PolicyId::new(id))
                .map_err(|e| policy_error(&e))?;
            out.set = Some(set_output(set)?);
        }
        Input::Merge {
            set,
            other,
            rename_duplicates,
        } => {
            let mut set = parse_policies(&set)?;
            let renames = set
                .merge(&parse_policies(&other)?, rename_duplicates)
                .map_err(|e| policy_error(&e))?;
            out.renames = renames
                .into_iter()
                .map(|(k, v)| {
                    (
                        AsRef::<str>::as_ref(&k).to_owned(),
                        AsRef::<str>::as_ref(&v).to_owned(),
                    )
                })
                .collect();
            out.set = Some(set_output(set)?);
        }
    }
    Ok(out)
}
