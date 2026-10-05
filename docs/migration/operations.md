# Native operation inventory

Reference source: `a7083b5cb27dae4ec8be5f84d8f7b88b4a1fbcc6`.

The first native implementation preserves JSON envelopes and all 22 feature operation names.

| Rust operation | Domain | Migration task | Independent evidence |
|---|---|---|---|
| `cgw_load` | `authorization` | #52 | corpus and configuration tests |
| `cgw_authorize` | `authorization` | #52 | corpus, property tests, and request fuzzing |
| `cgw_validate` | `validation` | #52 | corpus, validation depth, and diagnostics fixtures |
| `cgw_schema_warnings` | `schema` | #53 | schema and diagnostics fixtures |
| `cgw_policies` | `policy` | #53 | policies and PST fixtures |
| `cgw_templates` | `policy/template` | #53 | direct template fixtures |
| `cgw_format` | `policy/format` | #53 | format fixtures and fuzzing |
| `cgw_expressions` | `expression` | #53 | expression fixtures and result fuzzing |
| `cgw_literals` | `policy` | #53 | literal substitution fixtures and fuzzing |
| `cgw_applicability` | `policy/applicability` | #53 | request environment fixtures |
| `cgw_schemas` | `schema` | #53 | schema fragments fixtures and fuzzing |
| `cgw_entity_store` | `entity` | #53 | entity store fixtures and mutation tests |
| `cgw_utilities` | `utility and entity/uid` | #53 | UID, scope, context, and confusable string fixtures |
| `cgw_source_tokens` | `policy/source` | #53 | source token fixtures and span fuzzing |
| `cgw_authorize_batched` | `authorization/batched` | #54 | callback trace fixtures and differential fuzzing |
| `cgw_slice_entities` | `entity/slicing` | #54 | slicing fixtures and ancestor closure properties |
| `cgw_partial_authorize` | `authorization/partial` | #55 | partial fixtures and unknown-input fuzzing |
| `cgw_reauthorize` | `authorization/partial` | #55 | partial fixtures and concrete replay |
| `cgw_import_partial` | `authorization/partial` | #55 | residual persistence fixtures and corruption fuzzing |
| `cgw_queries` | `authorization/partial` | #55 | permission query fixtures and concrete replay |
| `cgw_analyze` | `analysis` | #56 | nine direct SymCC queries and concrete replay |
| `cgw_compiled` | `analysis` | #56 | compiled lifetime, ownership, and real solver tests |

## Public declaration inventory

Each row identifies a public declaration at the reference commit.
Clients own feature operations. Pure records keep their domain responsibilities.
The native domain identifies the package that owns the current receiver or function.
`Report` and `PolicyEvaluation` remain public aliases in `analysis`.
Their methods are declared in `analysis/internal/report`.

| Reference file | Public declaration | Native domain |
|---|---|---|
| `cedar/applicability.go` | `env RequestEnvironment.MarshalJSON` | `cedar/schema` |
| `cedar/applicability.go` | `rt *Runtime.ApplicableEnvironments` | `cedar/policy/applicability` |
| `cedar/authorizer.go` | `a *Authorizer.Authorize` | `cedar/authorization` |
| `cedar/authorizer.go` | `a *Authorizer.Close` | `cedar/authorization` |
| `cedar/batched.go` | `f EntityLoaderFunc.LoadEntities` | `cedar/authorization/batched` |
| `cedar/batched.go` | `a *Authorizer.AuthorizeBatched` | `cedar/authorization/batched` |
| `cedar/context.go` | `NewContext` | `cedar/authorization/request` |
| `cedar/context.go` | `ContextFromJSON` | `cedar/authorization/request` |
| `cedar/context.go` | `c Context.MarshalJSON` | `cedar/authorization/request` |
| `cedar/diagnostics.go` | `s *SourceSpan.UnmarshalJSON` | `cedar/diagnostic` |
| `cedar/diagnostics.go` | `rt *Runtime.SchemaWarnings` | `cedar/schema` |
| `cedar/entities.go` | `NewEntityUID` | `cedar/entity/uid` |
| `cedar/entities.go` | `u EntityUID.String` | `cedar/entity/uid` |
| `cedar/entities.go` | `u EntityUID.MarshalJSON` | `cedar/entity/uid` |
| `cedar/entities.go` | `e Entity.MarshalJSON` | `cedar/entity` |
| `cedar/entities.go` | `NewEntities` | `cedar/entity` |
| `cedar/entities.go` | `EntitiesFromJSON` | `cedar/entity` |
| `cedar/entities.go` | `e Entities.IsZero` | `cedar/entity` |
| `cedar/entities.go` | `e Entities.MarshalJSON` | `cedar/entity` |
| `cedar/entity_store.go` | `e ParsedEntity.JSON` | `cedar/entity` |
| `cedar/entity_store.go` | `s ParsedEntityStore.Export` | `cedar/entity` |
| `cedar/entity_store.go` | `rt *Runtime.ParseEntityStore` | `cedar/entity` |
| `cedar/entity_store.go` | `s ParsedEntityStore.Get` | `cedar/entity` |
| `cedar/entity_store.go` | `s ParsedEntityStore.Ancestors` | `cedar/entity` |
| `cedar/entity_store.go` | `s ParsedEntityStore.IsAncestorOf` | `cedar/entity` |
| `cedar/entity_store.go` | `s ParsedEntityStore.DeepEqual` | `cedar/entity` |
| `cedar/entity_store.go` | `s ParsedEntityStore.Remove` | `cedar/entity` |
| `cedar/entity_store.go` | `s ParsedEntityStore.Upsert` | `cedar/entity` |
| `cedar/errors.go` | `e *Error.Error` | `cedar/diagnostic` |
| `cedar/errors.go` | `e *Error.Unwrap` | `cedar/diagnostic` |
| `cedar/errors.go` | `e *Error.Is` | `cedar/diagnostic` |
| `cedar/expressions.go` | `e Expression.Text` | `cedar/expression` |
| `cedar/expressions.go` | `e RestrictedExpression.Text` | `cedar/expression` |
| `cedar/expressions.go` | `e RestrictedExpression.Expression` | `cedar/expression` |
| `cedar/expressions.go` | `rt *Runtime.ParseExpression` | `cedar/expression` |
| `cedar/expressions.go` | `rt *Runtime.ParseRestrictedExpression` | `cedar/expression` |
| `cedar/expressions.go` | `rt *Runtime.EvalExpression` | `cedar/expression` |
| `cedar/format.go` | `WithFormatLineWidth` | `cedar/policy/format` |
| `cedar/format.go` | `WithFormatIndentWidth` | `cedar/policy/format` |
| `cedar/format.go` | `WithFormatMaxOutputBytes` | `cedar/policy/format` |
| `cedar/format.go` | `rt *Runtime.FormatPolicies` | `cedar/policy/format` |
| `cedar/literals.go` | `inventory EntityLiteralInventory.MarshalJSON` | `cedar/policy` |
| `cedar/literals.go` | `rt *Runtime.EntityLiterals` | `cedar/policy` |
| `cedar/literals.go` | `rt *Runtime.SubstituteEntityLiterals` | `cedar/policy` |
| `cedar/partial.go` | `d PartialDecision.String` | `cedar/authorization/partial` |
| `cedar/partial.go` | `u PartialEntityUID.MarshalJSON` | `cedar/authorization/partial` |
| `cedar/partial.go` | `UnknownEntityUID` | `cedar/authorization/partial` |
| `cedar/partial.go` | `KnownEntityUID` | `cedar/authorization/partial` |
| `cedar/partial.go` | `e PartialEntity.MarshalJSON` | `cedar/authorization/partial` |
| `cedar/partial.go` | `NewPartialEntities` | `cedar/authorization/partial` |
| `cedar/partial.go` | `PartialEntitiesFromJSON` | `cedar/authorization/partial` |
| `cedar/partial.go` | `e PartialEntities.MarshalJSON` | `cedar/authorization/partial` |
| `cedar/partial.go` | `r PartialResponse.Projection` | `cedar/authorization/partial` |
| `cedar/partial.go` | `r PartialResponse.Export` | `cedar/authorization/partial` |
| `cedar/partial.go` | `a *Authorizer.ImportPartialResponse` | `cedar/authorization/partial` |
| `cedar/partial.go` | `a *Authorizer.PartialAuthorize` | `cedar/authorization/partial` |
| `cedar/partial.go` | `r PartialResponse.Reauthorize` | `cedar/authorization/partial` |
| `cedar/policies.go` | `c ScopeConstraint.MarshalJSON` | `cedar/policy` |
| `cedar/policies.go` | `c *ScopeConstraint.UnmarshalJSON` | `cedar/policy` |
| `cedar/policies.go` | `c ActionConstraint.MarshalJSON` | `cedar/policy` |
| `cedar/policies.go` | `c *ActionConstraint.UnmarshalJSON` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.ID` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.Effect` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.IsStatic` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.TemplateID` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.HasNonScopeConstraint` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.Annotations` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.Annotation` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.PrincipalConstraint` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.ResourceConstraint` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.ActionConstraint` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.JSON` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.Cedar` | `cedar/policy` |
| `cedar/policies.go` | `p ParsedPolicy.Syntax` | `cedar/policy` |
| `cedar/policies.go` | `s ParsedPolicySet.JSON` | `cedar/policy` |
| `cedar/policies.go` | `s ParsedPolicySet.Source` | `cedar/policy` |
| `cedar/policies.go` | `s ParsedPolicySet.Policies` | `cedar/policy` |
| `cedar/policies.go` | `s ParsedPolicySet.Policy` | `cedar/policy` |
| `cedar/policies.go` | `s ParsedPolicySet.Cedar` | `cedar/policy` |
| `cedar/policies.go` | `rt *Runtime.ParsePolicy` | `cedar/policy` |
| `cedar/policies.go` | `rt *Runtime.PolicyFromJSON` | `cedar/policy` |
| `cedar/policies.go` | `rt *Runtime.PolicyFromSyntax` | `cedar/policy` |
| `cedar/policies.go` | `rt *Runtime.ParsePolicySet` | `cedar/policy` |
| `cedar/policies.go` | `rt *Runtime.AddPolicy` | `cedar/policy` |
| `cedar/policies.go` | `rt *Runtime.RemovePolicy` | `cedar/policy` |
| `cedar/policies.go` | `rt *Runtime.MergePolicySets` | `cedar/policy` |
| `cedar/pool.go` | `rt *Runtime.NewAuthorizer` | `cedar` |
| `cedar/pool.go` | `a *Authorizer.Stats` | `cedar/authorization` |
| `cedar/queries.go` | `r ActionQueryResult.MarshalJSON` | `cedar/authorization/partial` |
| `cedar/queries.go` | `a *Authorizer.QueryResources` | `cedar/authorization/partial` |
| `cedar/queries.go` | `a *Authorizer.QueryPrincipals` | `cedar/authorization/partial` |
| `cedar/queries.go` | `a *Authorizer.QueryActions` | `cedar/authorization/partial` |
| `cedar/request.go` | `d Decision.String` | `cedar/authorization/request` |
| `cedar/request.go` | `m *PolicyMessage.UnmarshalJSON` | `cedar/diagnostic` |
| `cedar/runtime.go` | `WithMemoryLimit` | Rejected: Wasm option |
| `cedar/runtime.go` | `WithCompilationCache` | Rejected: Wasm option |
| `cedar/runtime.go` | `WithMaxSourceBytes` | `cedar` |
| `cedar/runtime.go` | `NewRuntime` | `cedar` |
| `cedar/runtime.go` | `rt *Runtime.Close` | `cedar` |
| `cedar/runtime.go` | `ModuleSHA256` | Removed |
| `cedar/schemas.go` | `SchemaFragmentFromCedar` | `cedar/schema` |
| `cedar/schemas.go` | `SchemaFragmentFromJSON` | `cedar/schema` |
| `cedar/schemas.go` | `f SchemaFragment.Format` | `cedar/schema` |
| `cedar/schemas.go` | `f SchemaFragment.Text` | `cedar/schema` |
| `cedar/schemas.go` | `s SchemaInspection.MarshalJSON` | `cedar/schema` |
| `cedar/schemas.go` | `rt *Runtime.ConvertSchemaFragment` | `cedar/schema` |
| `cedar/schemas.go` | `rt *Runtime.ComposeSchema` | `cedar/schema` |
| `cedar/schemas.go` | `rt *Runtime.InspectSchema` | `cedar/schema` |
| `cedar/schemas.go` | `rt *Runtime.ActionEntities` | `cedar/schema` |
| `cedar/slicing.go` | `rt *Runtime.SliceEntities` | `cedar/entity/slicing` |
| `cedar/source.go` | `f Format.String` | `cedar/syntax` |
| `cedar/source.go` | `SchemaFromCedar` | `cedar/schema` |
| `cedar/source.go` | `SchemaFromJSON` | `cedar/schema` |
| `cedar/source.go` | `s Schema.Format` | `cedar/schema` |
| `cedar/source.go` | `s Schema.Text` | `cedar/schema` |
| `cedar/source.go` | `PoliciesFromCedar` | `cedar/policy` |
| `cedar/source.go` | `PoliciesFromJSON` | `cedar/policy` |
| `cedar/source.go` | `p PolicySet.Format` | `cedar/policy` |
| `cedar/source.go` | `p PolicySet.Text` | `cedar/policy` |
| `cedar/source_tokens.go` | `s *TokenSpan.UnmarshalJSON` | `cedar/policy/source` |
| `cedar/source_tokens.go` | `t *SourceToken.UnmarshalJSON` | `cedar/policy/source` |
| `cedar/source_tokens.go` | `c *sourceTokenComments.UnmarshalJSON` | `cedar/policy/source` |
| `cedar/source_tokens.go` | `rt *Runtime.TokenizePolicies` | `cedar/policy/source` |
| `cedar/templates.go` | `TemplateFromCedar` | `cedar/policy/template` |
| `cedar/templates.go` | `TemplateFromJSON` | `cedar/policy/template` |
| `cedar/templates.go` | `t Template.Format` | `cedar/policy/template` |
| `cedar/templates.go` | `t Template.Text` | `cedar/policy/template` |
| `cedar/templates.go` | `rt *Runtime.AddTemplate` | `cedar/policy/template` |
| `cedar/templates.go` | `rt *Runtime.LinkTemplate` | `cedar/policy/template` |
| `cedar/templates.go` | `rt *Runtime.UnlinkTemplate` | `cedar/policy/template` |
| `cedar/templates.go` | `rt *Runtime.RemoveTemplate` | `cedar/policy/template` |
| `cedar/templates.go` | `rt *Runtime.Templates` | `cedar/policy/template` |
| `cedar/templates.go` | `rt *Runtime.TemplateLinks` | `cedar/policy/template` |
| `cedar/utilities.go` | `rt *Runtime.ParseEntityUID` | `cedar/utility` |
| `cedar/utilities.go` | `u EntityUID.CedarText` | `cedar/entity/uid` |
| `cedar/utilities.go` | `c Context.Values` | `cedar/authorization/request` |
| `cedar/utilities.go` | `c Context.Get` | `cedar/authorization/request` |
| `cedar/utilities.go` | `c Context.Merge` | `cedar/authorization/request` |
| `cedar/utilities.go` | `c Context.Validate` | `cedar/authorization/request` |
| `cedar/utilities.go` | `rt *Runtime.ValidateScopeVariables` | `cedar/utility` |
| `cedar/utilities.go` | `rt *Runtime.ConfusableStrings` | `cedar/utility` |
| `cedar/utilities.go` | `rt *Runtime.LanguageVersion` | `cedar/utility` |
| `cedar/validation.go` | `rt *Runtime.Validate` | `cedar/validation` |
| `cedar/validation.go` | `rt *Runtime.ValidateWithLevel` | `cedar/validation` |
| `cedar/value.go` | `v Bool.MarshalJSON` | `cedar/value` |
| `cedar/value.go` | `v Long.MarshalJSON` | `cedar/value` |
| `cedar/value.go` | `v String.MarshalJSON` | `cedar/value` |
| `cedar/value.go` | `v Set.MarshalJSON` | `cedar/value` |
| `cedar/value.go` | `v Record.MarshalJSON` | `cedar/value` |
| `cedar/value.go` | `v Decimal.MarshalJSON` | `cedar/value` |
| `cedar/value.go` | `v IPAddr.MarshalJSON` | `cedar/value` |
| `cedar/value.go` | `v Datetime.MarshalJSON` | `cedar/value` |
| `cedar/value.go` | `v Duration.MarshalJSON` | `cedar/value` |
| `analysis/analyzer.go` | `New` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.Close` | `analysis` |
| `analysis/analyzer.go` | `ModuleSHA256` | Removed |
| `analysis/analyzer.go` | `a *Analyzer.NewlyPermitted` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.Equivalent` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.NeverErrors` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.AlwaysMatches` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.NeverMatches` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.MatchesEquivalent` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.MatchesImplies` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.MatchesDisjoint` | `analysis` |
| `analysis/analyzer.go` | `a *Analyzer.Disjoint` | `analysis` |
| `analysis/analyzer.go` | `e *Error.Error` | `analysis` |
| `analysis/compiled.go` | `env RequestEnvironment.MarshalJSON` | `analysis` |
| `analysis/compiled_construction.go` | `a *Analyzer.OpenCompiled` | `analysis` |
| `analysis/compiled_construction.go` | `s *CompiledSession.Environments` | `analysis` |
| `analysis/compiled_handles.go` | `s *CompiledSession.Compile` | `analysis` |
| `analysis/compiled_handles.go` | `s *CompiledSession.Release` | `analysis` |
| `analysis/compiled_lifecycle.go` | `s *CompiledSession.Close` | `analysis` |
| `analysis/compiled_queries.go` | `s *CompiledSession.Implies` | `analysis` |
| `analysis/compiled_queries.go` | `s *CompiledSession.Equivalent` | `analysis` |
| `analysis/compiled_queries.go` | `s *CompiledSession.Disjoint` | `analysis` |
| `analysis/options.go` | `WithTimeout` | `analysis` |
| `analysis/options.go` | `WithMemoryLimit` | Removed: Wasm option |
| `analysis/options.go` | `WithCompilationCache` | Removed: Wasm option |
| `analysis/options.go` | `WithMaxSourceBytes` | `analysis` |
| `analysis/options.go` | `WithMaxSolverOutput` | `analysis` |
| `analysis/report.go` | `r Report.Holds` | `analysis` |
| `analysis/report.go` | `p *PolicyEvaluation.UnmarshalJSON` | `analysis` |
| `analysis/solver.go` | `CVC5` | `analysis/solver` |
| `analysis/solver.go` | `c *Command.Start` | `analysis/solver` |
| `analysis/solver.go` | `p *process.Read` | `analysis/solver` |
| `analysis/solver.go` | `p *process.Write` | `analysis/solver` |
| `analysis/solver.go` | `p *process.Close` | `analysis/solver` |
| `analysis/solver.go` | `p *process.Stderr` | `analysis/solver` |

All 25 existing fuzz targets and saved inputs must remain present.
Expected fixtures remain read-only during verification.
Each fixture update requires its explicit update command and review.

Allocator exports and Wasm initialization are transport details. ABI version 2 replaces them with native allocation and lifetime rules.
