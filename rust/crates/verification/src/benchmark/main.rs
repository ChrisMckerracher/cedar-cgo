//! Direct pinned Cedar timings use the same Joy inputs as production Go/cgo.
mod inputs;
mod workloads;

use std::hint::black_box;
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let directory = args.get(1).ok_or("provide the Joy fixture directory")?;
    let workload = args
        .get(2)
        .ok_or("provide decision, authorize, load, or validate")?;
    let iterations: u32 = args.get(3).ok_or("provide iteration count")?.parse()?;
    if iterations == 0 {
        return Err("iteration count must be positive".into());
    }
    let inputs = inputs::Inputs::read(directory)?;
    let loaded = inputs.load()?;
    let request = inputs.request(&loaded.schema)?;
    workloads::authorize(&loaded, &request)?;
    inputs.validate()?;

    let run = || -> Result<()> {
        match workload.as_str() {
            "decision" => workloads::decision(&loaded, &request),
            "authorize" => workloads::authorize(&loaded, &inputs.request(&loaded.schema)?),
            "load" => {
                black_box(inputs.load()?);
                Ok(())
            }
            "validate" => inputs.validate(),
            _ => Err("unknown workload".into()),
        }
    };
    run()?;
    let start = Instant::now();
    for _ in 0..iterations {
        run()?;
    }
    let elapsed = start.elapsed().as_nanos();
    println!(
        "{}",
        serde_json::json!({
            "workload": workload,
            "iterations": iterations,
            "elapsed_ns": elapsed,
            "ns_per_op": elapsed as f64 / f64::from(iterations),
            "expected_decision": "allow",
            "expected_reasons": ["policy1"],
            "policies": loaded.policies.policies().count(),
            "entities": loaded.entities.iter().count(),
        })
    );
    Ok(())
}
