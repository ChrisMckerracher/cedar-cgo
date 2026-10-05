//! Independent native Cedar oracle for testdata/parity/partial; no guest helpers.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityUid, PartialEntities,
    PartialEntityUid, PartialRequest, Policy, PolicyId, PolicySet, Request, Schema,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, error::Error, io::Read};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

mod evaluate;
mod inputs;
mod projection;
use inputs::*;

fn main() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let input: Value = serde_json::from_str(&input)?;
    let schema = Schema::from_cedarschema_str(input["schema"].as_str().ok_or("schema")?)?.0;
    let outputs = input["cases"]
        .as_array()
        .ok_or("cases array")?
        .iter()
        .map(|v| Ok(json!({"name":v["name"], "result":evaluate::case(v, &schema)?})))
        .collect::<Result<Vec<_>>>()?;
    println!("{}", serde_json::to_string_pretty(&outputs)?);
    Ok(())
}
