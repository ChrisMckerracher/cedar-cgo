use super::*;
use crate::solver::test_solver::TestSolver;
use serde_json::json;

#[derive(Default)]
struct Tester {
    state: State,
    solver: TestSolver,
}

impl Tester {
    fn operation(&mut self, value: Value) -> Result<Value, OpError> {
        execute(
            &mut self.state,
            &serde_json::to_vec(&value).unwrap(),
            self.solver.callback(),
        )
    }
    fn open_session(&mut self) {
        self.operation(json!({"operation":"open","schema":{"format":"cedar","text":"entity User; entity Doc; action view appliesTo { principal: User, resource: Doc, context: {} };"}})).unwrap();
    }
    fn compile_policy(&mut self, text: &str) -> u64 {
        self.operation(json!({"operation":"compile","policies":{"format":"cedar","text":text}}))
            .unwrap()["handle"]
            .as_u64()
            .unwrap()
    }
}

#[test]
fn handles_are_monotonic_and_released() {
    let mut test = Tester::default();
    test.open_session();
    {
        let session = test.state.session.as_ref().unwrap();
        assert_eq!(
            session.symbolic_environments[0],
            SymEnv::new(&session.schema, &session.environments[0]).unwrap()
        );
    }
    let first = test.compile_policy("permit(principal,action,resource);");
    test.operation(json!({"operation":"release","handle":first}))
        .unwrap();
    assert_eq!(
        test.operation(json!({"operation":"release","handle":first}))
            .unwrap_err()
            .kind,
        "handle"
    );
    let second = test.compile_policy("permit(principal,action,resource);");
    assert!(second > first);
    assert_eq!(
        test.operation(
            json!({"operation":"check","query":"equivalent","first":first,"second":second})
        )
        .unwrap_err()
        .kind,
        "handle"
    );
    assert_eq!(test.operation(json!({"operation":"compile","policies":{"format":"cedar","text":"permit(principal == ?principal,action,resource);"}})).unwrap_err().kind,"compile_a");
    assert_eq!(test.state.session.as_ref().unwrap().entries.len(), 1);
}

#[test]
fn selection_rejects_unknown_and_duplicate_environments() {
    let mut test = Tester::default();
    let schema = json!({"format":"cedar","text":"entity User; entity Doc; action view appliesTo { principal: User, resource: Doc, context: {} };"});
    let env = json!({"principal_type":"User","action":{"type":"Action","id":"view"},"resource_type":"Doc"});
    assert_eq!(
        test.operation(json!({"operation":"open","schema":schema,"environments":[env,env]}))
            .unwrap_err()
            .kind,
        "input"
    );
    let env = json!({"principal_type":"User","action":{"type":"Action","id":"missing"},"resource_type":"Doc"});
    assert_eq!(
        test.operation(json!({"operation":"open","schema":schema,"environments":[env]}))
            .unwrap_err()
            .kind,
        "input"
    );
}

#[test]
fn handle_limit_recovers_after_release() {
    let mut test = Tester::default();
    test.open_session();
    let mut first = 0;
    for index in 0..MAX_HANDLES {
        let handle = test.compile_policy("permit(principal,action,resource);");
        if index == 0 {
            first = handle;
        }
    }
    assert_eq!(test.operation(json!({"operation":"compile","policies":{"format":"cedar","text":"permit(principal,action,resource);"}})).unwrap_err().kind,"handle_limit");
    test.operation(json!({"operation":"release","handle":first}))
        .unwrap();
    let next = test.compile_policy("permit(principal,action,resource);");
    assert!(next > MAX_HANDLES as u64);
}

#[test]
fn repeated_queries_reuse_entries_and_solver_fault_invalidates() {
    let mut test = Tester::default();
    test.operation(json!({"operation":"open","schema":{"format":"cedar","text":"entity User; entity Doc; action view appliesTo { principal: User, resource: Doc, context: {n: Long} };"}})).unwrap();
    let handle = test.compile_policy("permit(principal,action,resource) when {context.n < 0};");
    let different =
        test.compile_policy("permit(principal,action,resource) when {context.n <= -1};");
    test.solver.enable(true);
    for _ in 0..3 {
        let response = test
            .operation(
                json!({"operation":"check","query":"equivalent","first":handle,"second":different}),
            )
            .unwrap();
        assert!(response["report"]["results"][0]["holds"].as_bool().unwrap());
    }
    assert_eq!(test.state.session.as_ref().unwrap().entries.len(), 2);
    test.solver.enable(false);
    assert_eq!(
        test.operation(
            json!({"operation":"check","query":"equivalent","first":handle,"second":different})
        )
        .unwrap_err()
        .kind,
        "solver"
    );
    assert_eq!(
        test.operation(json!({"operation":"release","handle":handle}))
            .unwrap_err()
            .kind,
        "session_closed"
    );
}

#[test]
fn handle_exhaustion_preserves_existing_entries() {
    let mut test = Tester::default();
    test.open_session();
    let retained = test.compile_policy("permit(principal,action,resource);");
    test.state.session.as_mut().unwrap().next_handle = u64::MAX;
    let error = test.operation(json!({"operation":"compile","policies":{"format":"cedar","text":"permit(principal,action,resource);"}})).unwrap_err();
    assert_eq!(error.kind, "handle_limit");
    assert!(
        test.state
            .session
            .as_ref()
            .unwrap()
            .entries
            .contains_key(&retained)
    );
    test.operation(json!({"operation":"release","handle":retained}))
        .unwrap();
}

#[test]
fn explicit_state_moves_between_threads_and_callbacks() {
    fn require_send<T: Send>() {}
    require_send::<State>();
    let mut test = Tester::default();
    test.open_session();
    let first = test.compile_policy("permit(principal,action,resource);");
    let second = test.compile_policy("permit(principal,action,resource);");
    let mut state = std::thread::spawn(move || {
        let mut solver = TestSolver::default();
        solver.enable(true);
        execute(
            &mut test.state,
            &serde_json::to_vec(
                &json!({"operation":"check","query":"equivalent","first":first,"second":second}),
            )
            .unwrap(),
            solver.callback(),
        )
        .unwrap();
        test.state
    })
    .join()
    .unwrap();
    let mut replacement = TestSolver::default();
    replacement.enable(true);
    let output = execute(
        &mut state,
        &serde_json::to_vec(
            &json!({"operation":"check","query":"equivalent","first":first,"second":second}),
        )
        .unwrap(),
        replacement.callback(),
    )
    .unwrap();
    assert!(output["report"]["results"][0]["holds"].as_bool().unwrap());
}
