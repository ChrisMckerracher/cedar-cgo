//! Native timing of cedar-policy on the joy data set, as a baseline for the
//! wazero benchmarks in the Go package.
//!
//! Usage: cargo run --release -p cgw-native-bench -- ../testdata/joy
//!
//! It prints two numbers. "decision" times `Authorizer::is_authorized` on a
//! prebuilt request. "end-to-end" also parses the request and its context
//! from JSON, as the authorization module does on every call.

use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request, Schema};
use std::hint::black_box;
use std::str::FromStr;
use std::time::Instant;

const CONTEXT: &str = r#"{"deviceLevel":1,"platform":{"os":"ios","model":"iPhone17,1","securityLevel":3},"sessionId":"s1","now":{"__extn":{"fn":"datetime","arg":"2026-10-01T12:00:00Z"}},"machineAttested":true,"sourceIp":{"__extn":{"fn":"ip","arg":"10.1.2.3"}}}"#;

fn uid(t: &str, id: &str) -> serde_json::Value {
    serde_json::json!({"type": t, "id": id})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../testdata/joy".into());
    let (schema, _) =
        Schema::from_cedarschema_str(&std::fs::read_to_string(format!("{dir}/joy.cedarschema"))?)?;
    let policies = PolicySet::from_str(&std::fs::read_to_string(format!("{dir}/old.cedar"))?)?;
    let entities = Entities::from_json_str(
        &std::fs::read_to_string(format!("{dir}/entities.json"))?,
        Some(&schema),
    )?;
    let authorizer = Authorizer::new();

    let build = || -> Result<Request, Box<dyn std::error::Error>> {
        let action = EntityUid::from_json(uid("Joy::Action", "session.write"))?;
        let context = Context::from_json_str(CONTEXT, Some((&schema, &action)))?;
        Ok(Request::new(
            EntityUid::from_json(uid("Joy::Device", "phone1"))?,
            action,
            EntityUid::from_json(uid("Joy::Session", "s1"))?,
            context,
            Some(&schema),
        )?)
    };

    let request = build()?;
    let n = 20_000;
    let start = Instant::now();
    for _ in 0..n {
        black_box(authorizer.is_authorized(&request, &policies, &entities));
    }
    let decision = start.elapsed().as_nanos() as f64 / f64::from(n) / 1000.0;

    let start = Instant::now();
    for _ in 0..n {
        let request = build()?;
        let response = authorizer.is_authorized(&request, &policies, &entities);
        let mut reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        reasons.sort_unstable();
        black_box(serde_json::to_vec(&reasons)?);
    }
    let end_to_end = start.elapsed().as_nanos() as f64 / f64::from(n) / 1000.0;

    println!(
        "policies={} decision={decision:.1}us end-to-end={end_to_end:.1}us",
        policies.policies().count()
    );
    Ok(())
}
