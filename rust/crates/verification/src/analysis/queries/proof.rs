use super::*;

pub(super) async fn fixture(case: &Value) -> Value {
    let schema = Schema::from_cedarschema_str(case["schema"].as_str().unwrap())
        .unwrap()
        .0;
    let a = policy_source(case, "a");
    let b = policy_source(case, "b");
    let query = case["query"].as_str().unwrap();
    let set_query = matches!(query, "disjoint" | "equivalent" | "implies");
    let unary = matches!(query, "never_errors" | "always_matches" | "never_matches");
    for (set, kind) in [(&a, "compile_a"), (&b, "compile_b")] {
        if unary && kind == "compile_b" {
            continue;
        }
        if set.templates().next().is_some() {
            return json!({"name":case["name"],"error":{"kind":kind,"message":"symbolic queries require static policies and no templates"}});
        }
    }
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let mut results = Vec::new();
    for env in schema.request_envs() {
        let (holds, cex) = if set_query {
            let ca = CompiledPolicySet::compile(&a, &env, &schema).unwrap();
            let cb = CompiledPolicySet::compile(&b, &env, &schema).unwrap();
            match query {
                "disjoint" => (
                    compiler.check_disjoint_opt(&ca, &cb).await.unwrap(),
                    compiler
                        .check_disjoint_with_counterexample_opt(&ca, &cb)
                        .await
                        .unwrap(),
                ),
                "equivalent" => (
                    compiler.check_equivalent_opt(&ca, &cb).await.unwrap(),
                    compiler
                        .check_equivalent_with_counterexample_opt(&ca, &cb)
                        .await
                        .unwrap(),
                ),
                "implies" => (
                    compiler.check_implies_opt(&ca, &cb).await.unwrap(),
                    compiler
                        .check_implies_with_counterexample_opt(&ca, &cb)
                        .await
                        .unwrap(),
                ),
                _ => unreachable!(),
            }
        } else {
            let ca = CompiledPolicy::compile(a.policies().next().unwrap(), &env, &schema).unwrap();
            let cb = b
                .policies()
                .next()
                .map(|p| CompiledPolicy::compile(p, &env, &schema).unwrap());
            match query {
                "never_errors" => (
                    compiler.check_never_errors_opt(&ca).await.unwrap(),
                    compiler
                        .check_never_errors_with_counterexample_opt(&ca)
                        .await
                        .unwrap(),
                ),
                "always_matches" => (
                    compiler.check_always_matches_opt(&ca).await.unwrap(),
                    compiler
                        .check_always_matches_with_counterexample_opt(&ca)
                        .await
                        .unwrap(),
                ),
                "never_matches" => (
                    compiler.check_never_matches_opt(&ca).await.unwrap(),
                    compiler
                        .check_never_matches_with_counterexample_opt(&ca)
                        .await
                        .unwrap(),
                ),
                "matches_equivalent" => (
                    compiler
                        .check_matches_equivalent_opt(&ca, cb.as_ref().unwrap())
                        .await
                        .unwrap(),
                    compiler
                        .check_matches_equivalent_with_counterexample_opt(&ca, cb.as_ref().unwrap())
                        .await
                        .unwrap(),
                ),
                "matches_implies" => (
                    compiler
                        .check_matches_implies_opt(&ca, cb.as_ref().unwrap())
                        .await
                        .unwrap(),
                    compiler
                        .check_matches_implies_with_counterexample_opt(&ca, cb.as_ref().unwrap())
                        .await
                        .unwrap(),
                ),
                "matches_disjoint" => (
                    compiler
                        .check_matches_disjoint_opt(&ca, cb.as_ref().unwrap())
                        .await
                        .unwrap(),
                    compiler
                        .check_matches_disjoint_with_counterexample_opt(&ca, cb.as_ref().unwrap())
                        .await
                        .unwrap(),
                ),
                _ => panic!("unknown fixture query"),
            }
        };
        assert_eq!(holds, cex.is_none());
        let mut a_evaluation = None;
        let mut b_evaluation = None;
        let confirmed = cex.map(|env| {
            let authorizer = Authorizer::new();
            let first = authorizer.is_authorized(&env.request, &a, &env.entities);
            let second = authorizer.is_authorized(&env.request, &b, &env.entities);
            let ma = first.diagnostics().reason().next().is_some();
            let mb = second.diagnostics().reason().next().is_some();
            if !set_query {
                a_evaluation = Some(evaluation(&first));
                if query.starts_with("matches_") {
                    b_evaluation = Some(evaluation(&second));
                }
            }
            match query {
                "never_errors" => first.diagnostics().errors().next().is_some(),
                "always_matches" => !ma,
                "never_matches" => ma,
                "matches_equivalent" => ma != mb,
                "matches_implies" => ma && !mb,
                "matches_disjoint" => ma && mb,
                "disjoint" => {
                    first.decision() == Decision::Allow && second.decision() == Decision::Allow
                }
                "equivalent" => first.decision() != second.decision(),
                "implies" => {
                    first.decision() == Decision::Allow && second.decision() == Decision::Deny
                }
                _ => false,
            }
        });
        if let Some(confirmed) = confirmed {
            assert!(confirmed);
        }
        results.push(json!({"principal_type":env.principal().to_string(),"action":{"type":env.action().type_name().to_string(),"id":env.action().id().unescaped()},"resource_type":env.resource().to_string(),"holds":holds,"counterexample_confirmed":confirmed,"a_evaluation":a_evaluation,"b_evaluation":b_evaluation}));
    }
    json!({"name":case["name"],"results":results})
}
