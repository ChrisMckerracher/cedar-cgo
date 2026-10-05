use cedar_policy_symcc::{
    SmtLibScript,
    solver::{Decision as SatDecision, DecisionWithModel, Solver, SolverError},
};
use cgw_abi::Callback;
use std::io::{BufRead, BufReader, Read};

struct HostReader(Callback);

impl Read for HostReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = self.0.call(4, buf);
        let count = usize::try_from(result)
            .map_err(|_| std::io::Error::other("host solver read failed"))?;
        if count > buf.len() {
            return Err(std::io::Error::other(
                "host solver returned an invalid byte count",
            ));
        }
        Ok(count)
    }
}

/// Mirrors `LocalSolver`'s reply handling to keep the host transport compatible.
pub(crate) struct HostSolver {
    pending: Vec<u8>,
    output: BufReader<HostReader>,
}

impl HostSolver {
    pub(crate) fn new(callback: Callback) -> Self {
        Self {
            pending: Vec::new(),
            output: BufReader::new(HostReader(callback)),
        }
    }

    pub(crate) fn bind(&mut self, callback: Callback) {
        self.output.get_mut().0 = callback;
    }

    fn flush(&mut self) -> Result<(), SolverError> {
        let rc = self.output.get_ref().0.call(3, &mut self.pending);
        self.pending.clear();
        if rc != 0 {
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

#[cfg(test)]
pub(crate) mod test_solver;
