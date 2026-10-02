# Slicing differential fixtures

`cases.json` covers nested attributes, optional attributes, entity-reference
chains, transitive ancestors, ancestor attributes, schema action hierarchy,
conditional branches, missing entities, forbids, extensions, tags, and empty policies.
An unusual-ID case preserves quotes, newlines, backslashes, and Unicode through JSON.
Unused records and nested fields exercise whole-entity retention and reduction.

Run `scripts/slicing-fixtures.sh` to regenerate `expected.json`, or pass
`--check` to compare with committed output. The command uses locked, offline
Cargo dependencies. CI runs the check and lints the native binary as part of
`cgw-native-bench`.

The independent native binary calls pinned `cedar-policy` 4.13.0 directly:
ordinary `Authorizer::is_authorized` on the full store, upstream
`TestEntityLoader` through `PolicySet::is_authorized_batched`, then ordinary
authorization on the selected store. It asserts all three decisions agree.
It does not import the guest crate, call its wrapper, or invoke Wasm.

`TestSliceEntitiesNativeParity` compares the exported Go API and committed Wasm
with these native decisions, entity data, and loading rounds; it also authorizes
both full and reduced stores through Go. Entity/parent/set JSON ordering is
normalized; loading-round order is preserved. These are differential checks of
the listed cases, not a proof of general equivalence or minimality.

No new arithmetic or callback protocol is introduced by slicing. The existing
source-linked ABI cvc5 obligations still apply; Cedar owns dependency analysis
and iteration semantics. No additional solver claim is made for Cedar's evaluator.
