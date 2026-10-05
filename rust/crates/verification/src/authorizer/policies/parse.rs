use super::*;

pub(super) fn cases() -> Vec<Value> {
    let mut parses = Vec::new();
    for (id, src) in [
        ("explicit/id", PERMIT),
        (
            "expressions",
            r#"permit(principal in Group::"staff", action in [Action::"view"], resource is Photo in Album::"all") when { if context has nested.key then context.nested.key like "a*\*" else [1,2,3].contains(2) && {x: 1}["x"] >= -1 } unless { decimal("1.0").lessThan(decimal("0.0")) || ip("192.0.2.1").isLoopback() || datetime("2026-10-01T00:00:00Z").offset(duration("1h")) < datetime("2026-10-01T00:00:00Z") };"#,
        ),
        ("", FORBID),
        ("bad", "permit(principal, action, resource) when { 1 + };"),
        ("slot", "permit(principal == ?principal, action, resource);"),
        (
            "twice",
            "permit(principal,action,resource); forbid(principal,action,resource);",
        ),
        (
            "overflow",
            "permit(principal,action,resource) when { 9223372036854775808 == 0 };",
        ),
        (
            "annotation",
            "@owner(\"one\") @owner(\"two\") permit(principal,action,resource);",
        ),
        (
            "escapes\n雪",
            r#"@empty @text("quote\" and \n") permit(principal == User::"a\"\n雪", action in [], resource is Photo);"#,
        ),
    ] {
        let result = Policy::parse(Some(PolicyId::new(id)), src);
        parses.push(match result {
            Ok(p) => {
                let pst_policy = Policy::from_pst(p.to_pst().unwrap()).unwrap();
                let cedar = pst_policy.to_cedar().unwrap();
                let rendered = Policy::parse(Some(p.id().clone()), &cedar).unwrap();
                assert_eq!(pst_policy, rendered, "Cedar round trip changed policy {id}");
                json!({"id":id,"source":src,"json":p.to_json().unwrap(),"pst_json":pst_policy.to_json().unwrap(),"pst_cedar":cedar,"rendered_json":rendered.to_json().unwrap(),"error":null})
            },
            Err(e) => json!({"id":id,"source":src,"json":null,"error":diagnostic(&e)}),
        });
    }
    parses
}
