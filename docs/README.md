# Documentation

[Project overview and example](../README.md)

| Guide | Use it to |
|---|---|
| [API](api.md) | Authorize requests, edit policies/templates, load/slice entities, validate, and format |
| [Partial evaluation](partial-evaluation.md) | Use unknown inputs and reauthorize residual policies |
| [Change analysis](analysis.md) | Compare policy sets with SymCC and cvc5 |
| [Security model](security.md) | Understand native ownership, resource limits, and failure behavior |
| [Verification](verification.md) | Review conformance, fuzzing, fault tests, and proof scope |
| [Performance](performance.md) | Review production measurements and their controls |
| [Maintenance](maintenance.md) | Upgrade Cedar, rebuild native archives, audit dependencies, and release |
| [Contributing](../CONTRIBUTING.md) | Navigate the source and run the development checks |

The Go reference is also available locally:

```bash
go doc ./cedar
go doc ./analysis
```

Read the [consumer migration lessons](migration/consumer.md), [native contract](migration/native-contract.md), and [verification report](migration/verification.md).
