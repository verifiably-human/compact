---
COIPID: XXXX
Title: Machine-readable security-analysis output from the Compact compiler
Authors: Bob Blessing-Hartley <@bobblessing-hartley>
Status: Proposed
Category: Tooling
Created: 2026-06-10
Requires: None
Replaces: None
---

<!--
 This file is part of Compact.
 Copyright (C) 2026 contributors to Minokawa Compact
 SPDX-License-Identifier: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

## Abstract

This proposal surfaces the Compact compiler's existing witness data-flow analysis as a structured, machine-readable artifact emitted on every successful compile. A new file, `compiler/security-analysis.json`, is written alongside `compiler/contract-info.json` and records every explicit `disclose()` call in the contract together with the witness origin and the program path that produced the disclosed value. The proposal introduces no new analysis: it taps the `track-witness-data` pass (also known as the witness-protection program) that the compiler already runs on every build, and serialises its findings so that downstream tools — auditors, dashboards, CI gates, IDE extensions — can consume them without parsing compiler stderr or rerunning the analysis themselves.

## Motivation

The Compact compiler performs a substantial witness data-flow analysis on every compile. The `track-witness-data` pass in `compiler/analysis-passes.ss` propagates abstract values through every expression form, merges values across control flow, traces witness data through cross-circuit calls, and refuses to compile any contract that would expose a witness value outside an explicit `disclose()` carve-out. This analysis is the substantive privacy guarantee the compiler offers.

Today the analysis is invisible to anything other than the compiler itself. Three concrete consequences follow:

1. **No audit artifact.** A contract that compiles cleanly leaves no record of *which* witness values are intentionally disclosed and *where*. Reviewers re-read the source to reconstruct what the compiler already knew.
2. **No machine-readable input for tools.** External auditors, CI gates, and editors cannot ask the compiler "what does this contract disclose?" without re-running compile and scraping output, or reimplementing the analysis.
3. **The analysis lives only as compile errors.** Disclosures and leaks are surfaced only when the compiler refuses to compile (via `pending-errorf` in the leak path). Successful compiles carry no positive evidence that the analysis was run, or what it found.

This proposal addresses all three by writing a JSON artifact derived from data the compiler is already computing.

### Use Cases Enabled

**Audit trails.** Reviewers can ask "what does this contract intentionally disclose?" and get a structured answer with source locations, witness origins, and the full program path through which each value flows to its disclosure site.

**CI gates.** A CI workflow can fail if a contract introduces a new `disclose()` site without a corresponding review approval, or if the disclosure count exceeds a configured threshold.

**IDE integrations.** An editor extension can highlight every `disclose()` call and, on hover, show the witness origin and exposure summary, without re-running the compiler.

**Cross-version comparison.** Two builds of the same contract can be diffed at the disclosure level to detect privacy regressions introduced by refactoring.

## Specification

### Output file

On every successful compile the compiler writes `compiler/security-analysis.json` relative to the output directory, alongside the existing `compiler/contract-info.json`. The file is created via the same `with-target-ports` machinery; on a failed compile the dynamic-wind cleanup deletes it along with the rest of the output. The presence of the file therefore implies a successful compile.

### Schema

```
{
  "schema_version": "1.0.0",
  "status":          "clean" | "leaks-found",
  "witness_count":   <integer>,
  "leaks":           [ <leak>, ... ],
  "disclosures":     [ <disclosure>, ... ]
}
```

- `schema_version` — semver string. This proposal defines `"1.0.0"`. Future schema-breaking changes require a major-version bump.
- `status` — `"clean"` if `leaks` is empty, `"leaks-found"` otherwise. In practice every emitted file has status `"clean"` because the compiler refuses to compile a contract that has leaks; the field is retained for explicitness and to keep downstream code identical for the two cases if future revisions allow leak emission on failed compiles.
- `witness_count` — number of `witness` declarations in the contract.
- `leaks` — array of leak records.
- `disclosures` — array of disclosure records (sites of explicit `disclose()` calls).

Each `<leak>` record:
```
{
  "location":  <src-loc>,           // where the leak would occur (e.g. a ledger write)
  "what":      <string>,            // human-readable description of the leak site
  "witnesses": [ <witness>, ... ]   // which witness values flow to this site
}
```

Each `<disclosure>` record:
```
{
  "location":  <src-loc>,           // where the disclose() call appears
  "witnesses": [ <witness>, ... ]   // which witness values are being intentionally disclosed
}
```

Each `<witness>` record:
```
{
  "origin": <origin>,
  "paths":  [ <path>, ... ]         // alternative data-flow paths from origin to this site
}
```

Each `<origin>` record is one of:
```
{ "kind": "witness-return-value", "function": <string>,                       "location": <src-loc> }
{ "kind": "constructor-argument", "argument": <string>,                       "location": <src-loc> }
{ "kind": "circuit-argument",     "function": <string>, "argument": <string>, "location": <src-loc> }
```

Each `<path>` record:
```
{
  "points":          [ <point>, ... ],   // transformation steps in data-flow order
  "final_exposure":  <string>            // e.g. "the witness value", "a hash of the witness value"
}
```

The `points` array is ordered from the witness origin toward the exposure site. Index 0 is the step closest to the witness; the last index is the step closest to the disclosure or leak.

Each `<point>` record:
```
{
  "description": <string>,    // e.g. "the binding of sk", "the argument to persistentHash"
  "location":    <src-loc>,
  "exposure":    <string> | null
}
```

Each `<src-loc>` record:
```
{ "file": <string>, "line": <integer>, "column": <integer> }
```
or, when line/column resolution is unavailable:
```
{ "file": <string>, "character": <integer> }
```

### Compiler changes

A new library `(security-analysis-passes)` (`compiler/security-analysis-passes.ss`) defines two parameters and one helper:
- `security-leaks-json` — a parameter holding a vector of leak records or `#f`.
- `security-disclosures-json` — a parameter holding a vector of disclosure records or `#f`.
- `source-object->json` — utility for converting a Chez `source-object` to the `<src-loc>` shape.

The `track-witness-data` pass in `compiler/analysis-passes.ss` is extended to:
1. Record explicit `disclose()` sites in an internal hashtable.
2. Build JSON-shape records for both leaks (which the pass already records via `record-leak!`) and disclosures.
3. Populate the two parameters at the end of its `Program` clause.

No analysis logic changes. The pass still raises the same `pending-errorf` conditions on leak detection and the compiler still refuses to compile a leaky contract.

A new pass `save-security-analysis` (`compiler/save-contract-info-passes.ss`) reads the parameters, walks the IR to count witness declarations, and writes the JSON file. It is added to the existing `save-contract-info-passes` pipeline so it runs immediately after `save-contract-info`.

`compiler/passes.ss` is extended to declare `security-analysis.json` as a target port alongside `contract-info.json`.

## Rationale

### Why a derived artifact instead of new analysis

The compiler's witness-protection program is already a complete witness data-flow taint analysis. Building a parallel or simplified analyzer to produce the audit artifact would duplicate substantial logic, drift out of sync with the real analysis, and risk producing a different answer than the compiler enforces. Surfacing the existing analysis's findings keeps a single source of truth.

### Why JSON

JSON is the lingua franca of compiler output for downstream tooling and is already in use for `contract-info.json`. The file is intentionally not stable across compiler versions in the structural sense — `schema_version` is the contract — but the JSON shape is easy to consume from any language.

### Why emit on success only

The compiler refuses to compile a contract with unintended witness leaks. On a failed compile the output directory is wiped by the existing `with-exception-handler` cleanup in `passes.ss`; the security-analysis.json shares this fate. This means the JSON's existence is itself a positive signal: "the compiler accepted this contract." A future extension could preserve a partial JSON on failed compiles, but doing so would require carving the security-analysis file out of the cleanup path and is out of scope for this proposal.

### Why include leaks in the schema even though the file is only emitted on success

The schema is forward-compatible with a future change that emits the JSON on failed compiles as well. Downstream consumers can write code today that handles both shapes; current emission always has `"leaks": []` and `"status": "clean"`.

### Why a separate `(security-analysis-passes)` library

The library is the integration seam between the analyzer (`track-witness-data`) and the serialiser (`save-security-analysis`). Putting the parameters and the `source-object->json` helper in a small dedicated library keeps the dependency graph clean: `analysis-passes` writes, `save-contract-info-passes` reads, neither depends on the other.

### Alternatives considered

1. **Stream findings as compile-time warnings.** Easy to implement but loses structure (paths, origins) when serialised to stderr, and tools must parse free text.
2. **Re-run the analysis from a separate tool.** Duplicates logic, risks divergence from the compiler.
3. **Emit the findings into `contract-info.json`.** Conflates two concerns. `contract-info.json` describes the public surface (circuits, witnesses, contract refs); the security artifact describes the analysis result. Separating them lets tools subscribe to only what they need.

## Path to Active

### Acceptance Criteria

- The schema documented in this CoIP is finalised.
- The compiler emits `security-analysis.json` on every successful compile of every example contract in `examples/`.
- The output matches the schema and is independently validated against a JSON Schema document published alongside the CoIP (a future addition).
- The compiler's existing leak detection behaviour is unchanged: leaky contracts still fail to compile with the same error message.

### Implementation Plan

A reference implementation accompanies this proposal in the same pull request. It modifies four files:
- `compiler/security-analysis-passes.ss` (new, ~90 lines).
- `compiler/analysis-passes.ss` (modified: imports `(security-analysis-passes)`; adds disclose-site collection, JSON conversion helpers, and parameter population to `track-witness-data`).
- `compiler/save-contract-info-passes.ss` (modified: imports `(security-analysis-passes)`; adds `save-security-analysis` pass).
- `compiler/passes.ss` (modified: adds `security-analysis.json` to the `save-contract-info-passes` target-port set).

No changes to the language, the standard library, or the generated TypeScript output.

## Backwards Compatibility Assessment

- **Source compatibility:** None affected. No language change.
- **Generated-output compatibility:** A new file is created in the output directory. Tools that enumerate output files unconditionally (e.g. CI artifact uploaders that copy everything under `compiler/`) will pick it up automatically. Tools that whitelist `contract-info.json` specifically will continue to work and simply not consume the new file.
- **Compiler behaviour:** No change to which contracts compile, which fail, or what error messages are produced.
- **No hard fork required.**

## Security Considerations

The artifact discloses the same information the source code already discloses to anyone with read access to the contract. Specifically:
- The location of each explicit `disclose()` call (already visible in source).
- The witness declarations involved (already visible in source).
- The data-flow path the compiler computed (derivable from source by reading the code).

There is no new information leaked by emitting the JSON that was not already trivially derivable. The artifact does not contain witness values, private state, secret keys, or any runtime data — only static facts about which sources flow to which sinks.

Two operational notes:
1. **Distribution.** The JSON is part of compiler output. Projects that publish their contract artifacts should decide whether to publish the security-analysis.json alongside `contract.js` and `contract-info.json`. Publishing it is encouraged: it documents the privacy properties the compiler verified. Withholding it is harmless.
2. **Trust.** The JSON is generated by the compiler that compiled the contract. It is not an independent attestation. A reviewer who does not trust the compiler should re-compile from source.

## Implementation

This proposal touches only the compiler. No changes to:
- The Compact language or grammar.
- The standard library.
- The generated TypeScript runtime.
- ZKIR or any downstream artifact.
- The wallet, indexer, node, or any other Midnight component.

The reference implementation accompanies this CoIP. Dependencies: none beyond the existing compiler libraries.

## Testing

The accompanying implementation is verified against the example contracts in `examples/`:

- `examples/counter.compact` — no witnesses, no disclosures. Emits `{ status: "clean", witness_count: 0, leaks: [], disclosures: [] }`.
- `examples/tiny.compact` — one witness, three disclosure sites. Emits the disclosure structure for each, including the full data-flow path from the secret-key witness through the `public_key` circuit, through `persistentHash`, and out to the ledger write. Final exposure correctly rendered as "a hash of the witness value".
- `examples/election.compact` — seven witnesses, nine disclosure sites. Emits all nine.
- A negative test (contract that writes a witness value to the ledger without `disclose()`) — compile fails with the existing witness-disclosure error message, no JSON is written.

Acceptance tests added to the compiler test suite assert:
1. Every example contract emits a parsable `security-analysis.json` that conforms to `schema_version: "1.0.0"`.
2. `witness_count` matches the number of `witness` declarations in the source.
3. Every `disclose()` call in the source has a corresponding entry in `disclosures`.
4. Existing leak-detection behaviour is unchanged.

## References

- `compiler/analysis-passes.ss` — the `track-witness-data` pass and surrounding analysis machinery.
- `compiler/passes.ss` — the pass driver and target-port machinery.
- `compiler/save-contract-info-passes.ss` — the model for emitting per-compile JSON artifacts.

## Acknowledgements

Thanks to the authors of `track-witness-data` for building an analysis substantial enough to be worth surfacing.

## Copyright Waiver

All contributions (code and text) submitted in this CoIP must be licensed under the Apache License, Version 2.0. Submission requires agreement to the Compact Foundation Contributor License Agreement, which includes the assignment of copyright for your contributions to the Foundation.
