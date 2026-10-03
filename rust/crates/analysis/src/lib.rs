//! SymCC uses a host-owned solver; Cedar's concrete authorizer rechecks every
//! counterexample before it crosses the Go boundary.

use cedar_policy::{Authorizer, Decision, Entities, EntityUid, PolicySet, Request, Schema};
use cedar_policy_core::ast::Context as CoreContext;
use cedar_policy_core::entities::json::CedarValueJson;
use cedar_policy_symcc::solver::{Decision as SatDecision, DecisionWithModel, Solver, SolverError};
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicy, CompiledPolicySet, Env, SmtLibScript};
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
    Disjoint,
    NeverErrors,
    AlwaysMatches,
    NeverMatches,
    MatchesEquivalent,
    MatchesImplies,
    MatchesDisjoint,
}

impl Query {
    fn singleton(self) -> bool {
        matches!(
            self,
            Self::NeverErrors
                | Self::AlwaysMatches
                | Self::NeverMatches
                | Self::MatchesEquivalent
                | Self::MatchesImplies
                | Self::MatchesDisjoint
        )
    }
    fn unary(self) -> bool {
        matches!(
            self,
            Self::NeverErrors | Self::AlwaysMatches | Self::NeverMatches
        )
    }
}

// Compiled values own their native terms; query selection stays separate from compilation.
enum CompiledInput {
    Policy(CompiledPolicy),
    Set(CompiledPolicySet),
}

fn compile_input(
    set: &PolicySet,
    env: &cedar_policy::RequestEnv,
    schema: &Schema,
    singleton: bool,
    kind: &'static str,
) -> Result<CompiledInput, OpError> {
    if singleton {
        if set.templates().next().is_some() || set.policies().count() != 1 {
            return Err(OpError::msg(
                kind,
                "matching and error queries require one policy and no templates",
            ));
        }
        let policy = set
            .policies()
            .next()
            .ok_or_else(|| OpError::msg(kind, "missing policy"))?;
        CompiledPolicy::compile(policy, env, schema)
            .map(CompiledInput::Policy)
            .map_err(|e| OpError::new(kind, &e))
    } else {
        CompiledPolicySet::compile(set, env, schema)
            .map(CompiledInput::Set)
            .map_err(|e| OpError::new(kind, &e))
    }
}

async fn query_counterexample(
    compiler: &mut CedarSymCompiler<HostSolver>,
    query: Query,
    a: &CompiledInput,
    b: Option<&CompiledInput>,
) -> Result<Option<Env>, OpError> {
    use Query as Q;
    let result = match (query, a, b) {
        (Q::Implies, CompiledInput::Set(a), Some(CompiledInput::Set(b))) => {
            compiler.check_implies_with_counterexample_opt(a, b).await
        }
        (Q::Equivalent, CompiledInput::Set(a), Some(CompiledInput::Set(b))) => {
            compiler
                .check_equivalent_with_counterexample_opt(a, b)
                .await
        }
        (Q::Disjoint, CompiledInput::Set(a), Some(CompiledInput::Set(b))) => {
            compiler.check_disjoint_with_counterexample_opt(a, b).await
        }
        (Q::NeverErrors, CompiledInput::Policy(a), None) => {
            compiler.check_never_errors_with_counterexample_opt(a).await
        }
        (Q::AlwaysMatches, CompiledInput::Policy(a), None) => {
            compiler
                .check_always_matches_with_counterexample_opt(a)
                .await
        }
        (Q::NeverMatches, CompiledInput::Policy(a), None) => {
            compiler
                .check_never_matches_with_counterexample_opt(a)
                .await
        }
        (Q::MatchesEquivalent, CompiledInput::Policy(a), Some(CompiledInput::Policy(b))) => {
            compiler
                .check_matches_equivalent_with_counterexample_opt(a, b)
                .await
        }
        (Q::MatchesImplies, CompiledInput::Policy(a), Some(CompiledInput::Policy(b))) => {
            compiler
                .check_matches_implies_with_counterexample_opt(a, b)
                .await
        }
        (Q::MatchesDisjoint, CompiledInput::Policy(a), Some(CompiledInput::Policy(b))) => {
            compiler
                .check_matches_disjoint_with_counterexample_opt(a, b)
                .await
        }
        _ => {
            return Err(OpError::msg(
                "input",
                "compiled inputs do not match the query",
            ));
        }
    };
    result.map_err(|e| OpError::new("solver", &e))
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
    #[serde(skip_serializing_if = "Option::is_none")]
    a_evaluation: Option<PolicyEvaluation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b_evaluation: Option<PolicyEvaluation>,
}

#[derive(Serialize)]
struct EvaluationError {
    policy_id: String,
    message: String,
}

#[derive(Serialize)]
struct PolicyEvaluation {
    matched: bool,
    errors: Vec<EvaluationError>,
}

// For one original policy, a determining reason identifies a native match for either effect.
fn policy_evaluation(response: &cedar_policy::Response) -> PolicyEvaluation {
    let matched = response.diagnostics().reason().next().is_some();
    let errors = response
        .diagnostics()
        .errors()
        .map(|error| match error {
            cedar_policy::AuthorizationError::PolicyEvaluationError(error) => EvaluationError {
                policy_id: AsRef::<str>::as_ref(error.policy_id()).to_owned(),
                message: cgw_abi::diagnostics::render(error.inner()),
            },
        })
        .collect();
    PolicyEvaluation { matched, errors }
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
    let first = authorizer.is_authorized(&env.request, a, &env.entities);
    let second = authorizer.is_authorized(&env.request, b, &env.entities);
    let da = first.decision();
    let db = second.decision();
    let ea = policy_evaluation(&first);
    let eb = policy_evaluation(&second);
    let genuine = match query {
        Query::Implies => da == Decision::Allow && db == Decision::Deny,
        Query::Equivalent => da != db,
        Query::Disjoint => da == Decision::Allow && db == Decision::Allow,
        Query::NeverErrors => !ea.errors.is_empty(),
        Query::AlwaysMatches => !ea.matched,
        Query::NeverMatches => ea.matched,
        Query::MatchesEquivalent => ea.matched != eb.matched,
        Query::MatchesImplies => ea.matched && !eb.matched,
        Query::MatchesDisjoint => ea.matched && eb.matched,
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
        a_evaluation: query.singleton().then_some(ea),
        b_evaluation: (query.singleton() && !query.unary()).then_some(eb),
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
        let ca = compile_input(a, &env, schema, input.query.singleton(), "compile_a")?;
        let cb = if input.query.unary() {
            None
        } else {
            Some(compile_input(
                b,
                &env,
                schema,
                input.query.singleton(),
                "compile_b",
            )?)
        };
        let cex = query_counterexample(&mut compiler, input.query, &ca, cb.as_ref()).await?;
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
    // Input contracts also apply when the schema has no request environments.
    for (set, kind) in [(&a, "compile_a"), (&b, "compile_b")] {
        if input.query.unary() && kind == "compile_b" {
            continue;
        }
        if set.templates().next().is_some() {
            return Err(OpError::msg(
                kind,
                "symbolic queries require static policies and no templates",
            ));
        }
        if input.query.singleton() && set.policies().count() != 1 {
            return Err(OpError::msg(
                kind,
                "matching and error queries require one policy and no templates",
            ));
        }
    }
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
