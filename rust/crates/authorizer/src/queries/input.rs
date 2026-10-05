use crate::partial::PartialUidInput;
use cgw_abi::{OpError, parse_input};
use serde::Deserialize;
use serde_json::{Value, value::RawValue};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Resource,
    Principal,
    Action,
}

#[derive(Deserialize)]
struct Envelope {
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResourceInput {
    #[serde(rename = "operation")]
    _operation: Operation,
    pub(super) principal: Value,
    pub(super) action: Value,
    pub(super) resource_type: String,
    pub(super) context: Box<RawValue>,
    pub(super) entities: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrincipalInput {
    #[serde(rename = "operation")]
    _operation: Operation,
    pub(super) principal_type: String,
    pub(super) action: Value,
    pub(super) resource: Value,
    pub(super) context: Box<RawValue>,
    pub(super) entities: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionInput {
    #[serde(rename = "operation")]
    _operation: Operation,
    pub(super) principal: PartialUidInput,
    pub(super) resource: PartialUidInput,
    pub(super) context: Option<Box<RawValue>>,
    pub(super) entities: Option<Box<RawValue>>,
}

pub(super) enum Input {
    Resource(ResourceInput),
    Principal(PrincipalInput),
    Action(ActionInput),
}

pub(super) fn input(bytes: &[u8]) -> Result<Input, OpError> {
    // Tagged enum buffering loses RawValue; parse each request from the original bytes.
    match parse_input::<Envelope>(bytes)?.operation {
        Operation::Resource => parse_input(bytes).map(Input::Resource),
        Operation::Principal => parse_input(bytes).map(Input::Principal),
        Operation::Action => parse_input(bytes).map(Input::Action),
    }
}
