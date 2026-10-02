//! SymCC uses a host-owned solver; Cedar's concrete authorizer rechecks every
//! counterexample before it crosses the Go boundary.

use cedar_policy::{Authorizer, Decision, Entities, EntityUid, PolicySet, Request, Schema};
use cedar_policy_core::ast::Context as CoreContext;
use cedar_policy_core::entities::json::CedarValueJson;
use cedar_policy_symcc::solver::{Decision as SatDecision, DecisionWithModel, Solver, SolverError};
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicySet, Env, SmtLibScript};
use cgw_abi::{OpError, Source, parse_input, parse_policies, parse_schema, run, take_input};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read};

cgw_abi::export_memory_functions!();

#[link(wasm_import_module = "cgw_host")]
unsafe extern "C" {
    /// Returns 0 on success or a negative value on error.
    fn solver_write(ptr: *const u8, len: u32) -> i32;
    /// Returns at most `cap` bytes, 0 at EOF, or a negative value on error.
    fn solver_read(ptr: *mut u8, cap: u32) -> i32;
}

struct HostReader;

impl Read for HostReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` is valid for `cap` bytes of writes.
        let n = unsafe { solver_read(buf.as_mut_ptr(), cap) };
        usize::try_from(n).map_err(|_| std::io::Error::other("host solver read failed"))
    }
}

/// Mirrors `LocalSolver`'s reply handling to keep the host transport compatible.
struct HostSolver {
    pending: Vec<u8>,
    output: BufReader<HostReader>,
}

impl HostSolver {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            output: BufReader::new(HostReader),
        }
    }

    fn flush(&mut self) -> Result<(), SolverError> {
        let len = u32::try_from(self.pending.len())
            .map_err(|_| SolverError::Solver("solver input exceeds 4 GiB".into()))?;
        // SAFETY: `pending` is valid for `len` bytes of reads.
        let rc = unsafe { solver_write(self.pending.as_ptr(), len) };
        self.pending.clear();
        if rc < 0 {
            return Err(std::io::Error::other("host solver write failed").into());
        }
        Ok(())
    }

    /// EOF means the solver exited before answering, not a completed reply.
    fn read_line(&mut self, buf: &mut String) -> Result<usize, SolverError> {
        let n = self.output.read_line(buf)?;
        if n == 0 {
            return Err(SolverError::Solver("solver closed its output".into()));
        }
        Ok(n)
    }

    fn error_from(line: &str) -> SolverError {
        match line
            .strip_prefix("(error \"")
            .and_then(|s| s.strip_suffix("\")"))
        {
            Some(e) => SolverError::Solver(e.to_string()),
            None => SolverError::UnrecognizedSolverOutput(line.to_string()),
        }
    }
}

impl Solver for HostSolver {
    fn smtlib_input(&mut self) -> &mut (dyn tokio::io::AsyncWrite + Unpin + Send) {
        &mut self.pending
    }

    async fn enable_models(&mut self) -> Result<(), SolverError> {
        self.smtlib_input()
            .set_option("produce-models", "true")
            .await
            .map_err(Into::into)
    }

    async fn check_sat(&mut self) -> Result<SatDecision, SolverError> {
        self.smtlib_input().check_sat().await?;
        self.flush()?;
        let mut line = String::new();
        self.read_line(&mut line)?;
        match line.trim() {
            "sat" => Ok(SatDecision::Sat),
            "unsat" => Ok(SatDecision::Unsat),
            "unknown" => Ok(SatDecision::Unknown),
            other => Err(Self::error_from(other)),
        }
    }

    async fn check_sat_with_model(&mut self) -> Result<DecisionWithModel, SolverError> {
        match self.check_sat().await? {
            SatDecision::Sat => {
                self.smtlib_input().get_model().await?;
                self.flush()?;
                let mut model = String::new();
                self.read_line(&mut model)?;
                if model.trim() != "(" {
                    return Err(Self::error_from(model.trim()));
                }
                loop {
                    let start = model.len();
                    self.read_line(&mut model)?;
                    if model.get(start..).is_some_and(|l| l.trim() == ")") {
                        break;
                    }
                }
                Ok(DecisionWithModel::Sat { model })
            }
            SatDecision::Unsat => Ok(DecisionWithModel::Unsat),
            SatDecision::Unknown => Ok(DecisionWithModel::Unknown),
        }
    }
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Query {
    /// Every request that `a` allows, `b` allows too.
    Implies,
    /// `a` and `b` give the same decision on every request.
    Equivalent,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyzeInput {
    schema: Source,
    a: Source,
    b: Source,
    query: Query,
}

#[derive(Serialize)]
struct Uid {
    #[serde(rename = "type")]
    type_name: String,
    id: String,
}

impl From<&EntityUid> for Uid {
    fn from(uid: &EntityUid) -> Self {
        Self {
            type_name: uid.type_name().to_string(),
            id: uid.id().unescaped().to_string(),
        }
    }
}

#[derive(Serialize)]
struct CexRequest {
    principal: Uid,
    action: Uid,
    resource: Uid,
    context: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct Counterexample {
    request: CexRequest,
    entities: serde_json::Value,
    text: String,
    a_decision: &'static str,
    b_decision: &'static str,
}

#[derive(Serialize)]
struct EnvResult {
    principal_type: String,
    action: Uid,
    resource_type: String,
    holds: bool,
    counterexample: Option<Counterexample>,
}

#[derive(Serialize)]
struct AnalyzeOutput {
    results: Vec<EnvResult>,
}

fn decision_name(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

fn request_part(uid: Option<&EntityUid>, what: &str) -> Result<Uid, OpError> {
    uid.map(Uid::from)
        .ok_or_else(|| OpError::msg("internal", format!("counterexample has no {what}")))
}

/// Reject solver counterexamples that Cedar's concrete authorizer cannot reproduce.
fn confirm(
    query: Query,
    env: &Env,
    a: &PolicySet,
    b: &PolicySet,
) -> Result<Counterexample, OpError> {
    let authorizer = Authorizer::new();
    let da = authorizer
        .is_authorized(&env.request, a, &env.entities)
        .decision();
    let db = authorizer
        .is_authorized(&env.request, b, &env.entities)
        .decision();
    let genuine = match query {
        Query::Implies => da == Decision::Allow && db == Decision::Deny,
        Query::Equivalent => da != db,
    };
    if !genuine {
        return Err(OpError::msg(
            "unconfirmed_counterexample",
            format!(
                "Cedar's authorizer does not confirm the solver's counterexample \
                 (a: {}, b: {}): {}",
                decision_name(da),
                decision_name(db),
                env.request
            ),
        ));
    }
    Ok(Counterexample {
        request: serialize_request(&env.request)?,
        entities: serialize_entities(&env.entities)?,
        text: env.request.to_string(),
        a_decision: decision_name(da),
        b_decision: decision_name(db),
    })
}

fn serialize_request(req: &Request) -> Result<CexRequest, OpError> {
    let mut context = serde_json::Map::new();
    match req.context().map(AsRef::<CoreContext>::as_ref) {
        Some(CoreContext::Value(attrs)) => {
            for (k, v) in attrs.iter() {
                let json = CedarValueJson::from_value(v.clone())
                    .map_err(|e| OpError::new("internal", &e))?;
                let json = serde_json::to_value(json)
                    .map_err(|e| OpError::msg("internal", e.to_string()))?;
                context.insert(k.to_string(), json);
            }
        }
        _ => {
            return Err(OpError::msg(
                "internal",
                "counterexample context is not concrete",
            ));
        }
    }
    Ok(CexRequest {
        principal: request_part(req.principal(), "principal")?,
        action: request_part(req.action(), "action")?,
        resource: request_part(req.resource(), "resource")?,
        context,
    })
}

fn serialize_entities(entities: &Entities) -> Result<serde_json::Value, OpError> {
    entities
        .to_json_value()
        .map_err(|e| OpError::new("internal", &e))
}

async fn analyze_async(
    input: &AnalyzeInput,
    schema: &Schema,
    a: &PolicySet,
    b: &PolicySet,
) -> Result<AnalyzeOutput, OpError> {
    let solver_err = |e: cedar_policy_symcc::err::Error| OpError::new("solver", &e);
    let mut compiler = CedarSymCompiler::new(HostSolver::new()).map_err(solver_err)?;
    let mut results = Vec::new();
    for env in schema.request_envs() {
        let ca = CompiledPolicySet::compile(a, &env, schema)
            .map_err(|e| OpError::new("compile_a", &e))?;
        let cb = CompiledPolicySet::compile(b, &env, schema)
            .map_err(|e| OpError::new("compile_b", &e))?;
        let cex = match input.query {
            Query::Implies => {
                compiler
                    .check_implies_with_counterexample_opt(&ca, &cb)
                    .await
            }
            Query::Equivalent => {
                compiler
                    .check_equivalent_with_counterexample_opt(&ca, &cb)
                    .await
            }
        }
        .map_err(solver_err)?;
        let counterexample = cex
            .as_ref()
            .map(|env| confirm(input.query, env, a, b))
            .transpose()?;
        results.push(EnvResult {
            principal_type: env.principal().to_string(),
            action: Uid::from(env.action()),
            resource_type: env.resource().to_string(),
            holds: counterexample.is_none(),
            counterexample,
        });
    }
    Ok(AnalyzeOutput { results })
}

fn analyze(bytes: &[u8]) -> Result<AnalyzeOutput, OpError> {
    let input: AnalyzeInput = parse_input(bytes)?;
    let schema = parse_schema(&input.schema)?;
    let a = parse_policies(&input.a)?;
    let b = parse_policies(&input.b)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| OpError::msg("internal", e.to_string()))?;
    runtime.block_on(analyze_async(&input, &schema, &a, &b))
}

/// Compares two policy sets under one schema.
///
/// # Safety
/// `ptr` and `len` must come from one `cgw_alloc(len)` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cgw_analyze(ptr: u32, len: u32) -> u64 {
    // SAFETY: the host passes a buffer from `cgw_alloc(len)`.
    run(unsafe { take_input(ptr, len) }, analyze)
}
