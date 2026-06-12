# Security Analysis in the Compact Security Analyzer

## Overview

This tool surfaces two streams of findings:

1. **Compiler analysis** — authoritative. Read from `compiler/security-analysis.json`, the artifact defined by the *Machine-readable security-analysis output from the Compact compiler* COIP (schema v1.0.0). No re-analysis: the compiler already ran a complete witness data-flow taint analysis on every compile; this tool consumes its output.
2. **Heuristic analysis** — supplement. Regex over the source for categories the compiler does not cover (access control, nullifier handling, etc.). Findings are tagged `[Heuristic]` and require manual verification.

The compiler is authoritative for privacy claims. Where both streams target the same circuit and the heuristic claim is a privacy leak, the heuristic finding is dropped to avoid duplication.

## Compiler Analysis

### Where it comes from

The compiler writes `compiler/security-analysis.json` on every successful compile, alongside `compiler/contract-info.json`. Presence of the file is the capability signal — there is no version-gate. If the file is absent, the compiler in use does not implement the COIP and only heuristic findings are reported.

### What the compiler is doing

The `track-witness-data` pass in `compiler/analysis-passes.ss` (the "witness-protection program") propagates abstract witness values through every expression form, merges them across control flow, traces them through cross-circuit calls, and refuses to compile any contract that would expose a witness outside an explicit `disclose()` carve-out. The `save-security-analysis` pass serialises the per-`disclose()` findings (and the empty leak list, since leaky contracts do not compile) into the JSON.

### Schema (v1.0.0)

```json
{
  "schema_version": "1.0.0",
  "status": "clean",
  "witness_count": 1,
  "leaks": [],
  "disclosures": [
    {
      "location": { "file": "examples/tiny.compact", "line": 126, "column": 10 },
      "witnesses": [
        {
          "origin": {
            "kind": "witness-return-value",
            "function": "private$secret_key",
            "location": { "file": "examples/tiny.compact", "line": 70, "column": 1 }
          },
          "paths": [
            {
              "points": [
                {
                  "description": "the argument to persistentHash",
                  "location": { "file": "examples/tiny.compact", "line": 126, "column": 19 },
                  "exposure": "a hash of"
                }
              ],
              "final_exposure": "a hash of the witness value"
            }
          ]
        }
      ]
    }
  ]
}
```

Key shapes:

- `<origin>` is one of `witness-return-value | constructor-argument | circuit-argument`.
- `<path>.points` is ordered origin → site; each point may carry an `exposure` annotation.
- `<path>.final_exposure` is a human-readable summary of what is published.
- `<leak>` records add `what` (description of the leak site, e.g. a ledger write).

Canonical schema definition lives in `coips/coip-xxxx-security-analysis-output.md`.

### Severity mapping

| Source            | `final_exposure`           | Severity |
|-------------------|----------------------------|----------|
| `leaks[]`         | (any)                      | critical |
| `disclosures[]`   | `"the witness value"`      | high     |
| `disclosures[]`   | anything else              | info     |

A leak in the JSON means the compiler would have rejected the contract; in practice the JSON is only emitted on success, so `leaks` is empty. The schema reserves the field for forward compatibility.

A `high`-severity disclosure is the compiler telling you, *this disclose() publishes the witness value verbatim — confirm that is what you want.* An `info` disclosure says, *a derived value is being published; privacy depends on whether the transform is hiding.*

### Example output

**Direct disclosure (high):**

```
[HIGH] Direct witness disclosure in public_key

Source: argument `v` of circuit `set` (examples/tiny.compact:82:13)
Site:   disclose() call at examples/tiny.compact:87:11
Result: the witness value

Data-flow path (origin → site):
  (direct — no intermediate transformations)
```

**Transformed disclosure (info):**

```
[INFO] Transformed witness disclosure in public_key (a hash of the witness value)

Source: witness function `private$secret_key` (declared at examples/tiny.compact:70:1)
Site:   disclose() call at examples/tiny.compact:126:10
Result: a hash of the witness value

Data-flow path (origin → site):
  1. the binding of sk @ examples/tiny.compact:56:9
  2. the argument to public_key @ examples/tiny.compact:57:15
  3. the argument to persistentHash @ examples/tiny.compact:126:19 [exposure: a hash of]
```

## Heuristic Analysis

### Coverage

- Access control patterns
- State mutation auditing
- Nullifier usage
- Taint propagation
- Side-channel detection
- Information flow

### Limitations

**False positives** — flags safe code:

```compact
disclose(persistentHash(private$secret()));  // ⚠️ heuristic sees "private$secret"
                                             // in disclose(); compiler analysis
                                             // correctly classifies this as a
                                             // hash disclosure (info).
```

**False negatives** — misses indirect cases:

```compact
function wrapper() { return private$secret(); }
disclose(wrapper());  // ✗ heuristic misses; compiler analysis tracks through the call.
```

The compiler analysis catches both. Heuristics remain for categories the compiler does not cover.

## Finding Annotations

- Compiler findings are reported without prefix. The description includes the data-flow trace.
- Heuristic findings are prefixed `[Heuristic]` and carry a manual-review note.

## Best Practices

### For users

1. **Trust compiler findings.** They are derived from the same analysis that gates compilation.
2. **Treat `high` disclosures as review items.** A raw witness disclosure is sometimes correct (e.g. revealing a previously-committed value) but is the most common privacy bug.
3. **Treat `info` disclosures as documentation.** They list every value the contract intentionally publishes — useful audit trail.
4. **Review heuristic findings.** They cover categories the compiler does not (yet) check.

### For developers integrating this reader

1. **Use file presence as the capability signal.** No version-gate. `readCompilerSecurityAnalysis(outputDir)` returns `null` if the file is absent or the schema major is unsupported.
2. **Compiler precedence.** `mergeSecurityFindings` drops heuristic privacy-leak findings that overlap with a circuit the compiler already covered.
3. **Preserve the trace.** When forwarding findings to other tools, keep the `paths[].points[]` ordering and `exposure` annotations — they are the audit trail.

## Wiring

```typescript
import {
  readCompilerSecurityAnalysis,
  convertCompilerFindings,
  mergeSecurityFindings,
} from './compiler-security-reader.js';
import { SecurityAnalyzer } from './security-analyzer.js';

const compilerAnalysis = readCompilerSecurityAnalysis(outputDir);
const compilerFindings = compilerAnalysis
  ? convertCompilerFindings(compilerAnalysis)
  : null;

const heuristicAnalyzer = new SecurityAnalyzer(contractPath);
const heuristicFindings = heuristicAnalyzer.analyze();

const findings = mergeSecurityFindings(compilerFindings, heuristicFindings);
```

## Technical Details

### Compiler side

- `compiler/security-analysis-passes.ss` — parameters and `source-object->json` helper.
- `compiler/analysis-passes.ss` — `track-witness-data` populates the parameters.
- `compiler/save-contract-info-passes.ss` — `save-security-analysis` writes the JSON.
- `compiler/passes.ss` — declares `security-analysis.json` as a target port.

### Reader side

- `src/compiler-security-reader.ts` — JSON I/O, schema-major check, conversion to `SecurityFinding`, merge with heuristic stream.
- `src/security-analyzer.ts` — regex heuristics (privacy-leak only when compiler analysis is unavailable; non-privacy categories always).
- `src/analyzer.ts` — orchestration. Compiles the contract, reads the JSON, runs heuristics, merges.

## Contract Profile and Value Inventory (phase 1)

The analyzer emits a Contract Profile at the top of the report. The profile classifies the contract by three orthogonal postures derived from the source: value posture, privacy posture, and authority model. The point is to give a reviewer the right lens before any individual finding — a critical disclosure in a `valuePosture: none` voting contract is a privacy finding; the same disclosure in a `valuePosture: mints` token contract is a value finding.

### Posture derivation

| Posture | Values | Inputs |
|---|---|---|
| Value | `none`, `receives`, `holds`, `mints`, `bridges` | Stdlib token primitives invoked (`mintShieldedToken`, `mintUnshieldedToken`, `sendShielded`, `sendUnshielded`, `receiveShielded`, `receiveUnshielded`); balance-like ledger field count; off-chain custody identifier matches. `bridges` = mints + sends + custody signals. |
| Privacy | `open`, `selective`, `strong-with-disclosures`, `strong` | Witness function count; `disclose()` count per circuit; whether each `disclose()` is on the same line as a protocol-required token-primitive call. |
| Authority | `permissionless`, `single-owner`, `multi-key`, `membership-proof`, `unclear` | Access-control findings from `SecurityAnalyzer` (missing or disabled guards on every exported circuit ⇒ `permissionless`); owner-like ledger field count; Merkle-root field presence. |

### Ledger surface classification

Ledger fields are classified by name and type:

- **Balance-like** — name matches `/balance/`, `/supply/`, `/^total[A-Z]/`, `/^reserves?$/`, `/vault/`.
- **Commitment-like** — name ends with `Commitment` or starts with `commitment*`.
- **Nullifier-like** — name ends with `Nullifier` or starts with `nullifier*`.
- **Counter-like** — type is `Counter` (and not otherwise classified).
- **Key-like** — name ends with `Key` or starts with `owner`/`authority`/`admin`.

### Value Inventory

Per-operation enumeration:

- `mintOperations`: every call to `mintShieldedToken`/`mintUnshieldedToken` with circuit + line + an `authorizedBy` tag (`owner-check` | `membership-proof` | `missing` | `unclear`) cross-referenced from access-control findings.
- `sendOperations` / `receiveOperations`: same shape, without `authorizedBy`.
- `balanceFields`: each balance-like field with the circuits that read/write it and an `overflowAssertionPresent` flag (is there an `assert` on the field within a writing circuit?).
- `commitmentNullifierPairs`: paired by stem (`fooCommitment` + `fooNullifier`).
- `maintenanceAuthorityRefs`: lines referencing `ContractMaintenanceAuthority`.
- `maxSupplyConstraints`: lines containing `assert(... max*upply ...)` or `MAX_SUPPLY`-style guards.
- `offChainCustodySignals`: identifier matches for `vault`, `reserve`, `custodian`, `escrow`, `treasury`, `solven*`.
- `valueAtRiskSummary`: synthesizes `estimatedClass` (enum), `isUnboundedMint` (mints present + missing auth + no max-supply assert), `isValueHolding` (balance fields or receives or commitment+nullifier pairs).

### Contract class enum

`estimatedClass` is one of:

`custodial-token`, `shielded-token`, `unshielded-token`, `nft`, `escrow`, `voting`, `auction`, `registry`, `amm`, `bridge`, `compute-only`, `unknown`.

The classifier is conservative: it only assigns a class when the structural signals are unambiguous. `unknown` is the default when no signal cluster matches.

## Nonce Hygiene (phase 2)

Nonces (per-event randomness, blinders, salts) underpin most privacy claims in shielded protocols. A constant or deterministic nonce defeats unlinkability without breaking the proof system — the compiler accepts the contract. The Nonce Hygiene analyzer surfaces two failure patterns. Two further patterns from the locked schema (`multi-call-binding`, `hash-without-blinder`) are deferred to phase 2b because of higher false-positive risk.

### `constant-return-witness`

Inspects the witness JS/TS implementation file (located by auto-search or `--witness-file <path>`) for functions whose name suggests a nonce role:

- `*nonce*`, `*salt*`, `*blinder*`, `*random*`, `*seed*`

For each such function, the analyzer:

1. Parses the function body via small bespoke patterns (object-property arrow, method shorthand, `function` declaration, `const`-arrow assignment).
2. Checks for a CSPRNG marker (`crypto.randomBytes`, `crypto.getRandomValues`, `crypto.subtle.generateKey`). If present → not flagged.
3. Otherwise checks for constant-return patterns:
   - `new Uint8Array(N)` with no fill (all-zero bytes)
   - `Buffer.alloc(N)` (all-zero bytes)
   - Hardcoded array literals (`new Uint8Array([0, 0, …])`)
   - `Buffer.from(<string-literal>)` (deterministic bytes)

Each finding records the witness implementation site **plus every circuit-call site** in the contract, so the reviewer can audit both the witness and its callers at once.

Severity: critical.

### `missing-counter-increment`

Source-only scan. For each ledger field typed `Counter` or named like a sequence/nonce/version/counter:

1. Find calls to `persistentHash<...>(...)` or `transientHash<...>(...)` whose argument list references the field.
2. Check every circuit body for an increment of the field — either `field.increment(...)` or direct assignment `field = (... + N ...)`.
3. If a hash-read exists and no circuit increments the field → finding.

Severity: high.

### Stable IDs

`nonce-<sha256-prefix-12>` derived from `(kind, witness-or-field-name, sorted-sites-with-line)`. Same finding produces the same ID across runs. CI can pin known IDs and alert only when new ones appear.

### Witness file resolution

When `--witness-file <path>` is not provided, the analyzer searches:

1. `<contract-dir>/<stem>-witnesses.{ts,js}`
2. `<contract-dir>/<stem>.witnesses.{ts,js}`
3. `<contract-dir>/witness.{ts,js}`, `<contract-dir>/witnesses.{ts,js}`
4. `<contract-dir>/witnesses/<stem>{-witnesses,}.{ts,js}`
5. `<contract-dir>/../witnesses/<stem>{-witnesses,}.{ts,js}`
6. `<contract-dir>/../deploy/witnesses/<stem>{-witnesses,}.{ts,js}`
7. `<contract-dir>/../../deploy/witnesses/...`
8. `<contract-dir>/../src/witnesses/...`

Each with progressively shorter hyphen-stems (`pattern7a-custodial` → `pattern7a` → ...). If no file is found, the constant-return check is skipped and `nonceAnalysis.witnessFileSkipped` is set to true.

## In-source audit annotations

The analyzer parses `// @<key>: <tag>` comments immediately above circuit declarations and uses them to downgrade or contextualise findings the contract author has marked as intentional.

### Format

```compact
// @<key>: <tag>
//
// <optional multi-line reason>
[export] circuit <name>(...): <ret> { ... }
```

- The `// @<key>: <tag>` line opens the annotation. The key is one of `access-control`, `disclose-intent`, `audit-ack`.
- Subsequent `//` comment lines are collected as the reason text. Blank `//` lines are allowed.
- The annotation block ends at the first non-comment, non-blank line.
- That non-comment line must be a `circuit` or `export circuit` declaration. If a different top-level form intervenes (witness, ledger, constructor) the annotation is orphaned (not bound to any circuit) and ignored.

### Recognised keys and tags

#### `@access-control: <tag>` — honoured today

Acknowledges the authorization posture of an exported circuit so the analyzer doesn't flag it as a missing guard. Tags:

| Tag | Meaning |
|---|---|
| `intentional-permissionless` | Anyone can call. Demo, public utility, KYC-gated, compliance-gated. |
| `witness-gated` | Authorization is enforced through witness assertions (private-key check inside the circuit). |
| `compliance-gated` | Authorization through a `runComplianceChecks`-style internal circuit that asserts KYC, sanctions, etc. |
| `read-only` | Circuit performs no real mutation despite syntactic appearance. |
| `documented` | The design intent is documented elsewhere in the contract; see the docstring. |

Effect: a `Missing authorization check: <circuit>` finding for the annotated circuit is replaced by a single `info`-severity `Access-control acknowledged: <circuit> (<tag>)` finding. The annotation reason is surfaced in the finding's description and persists into `security-profile.json`. CI gates pinned to critical/high don't fire on the downgraded finding.

#### `@disclose-intent: <tag>` — parsed today, honoured in phase 3

Forward-compatible. The parser accepts annotations of this shape today; the correlator analyzer (phase 3) will consume them to acknowledge intentional cross-circuit linkability anchors. Planned tags: `intentional-correlator`, `nullifier-emission`, `commitment-output`, `public-by-design`, `protocol-required`.

Adding these annotations today does no harm — they are parsed and stored; future analyzer versions will read them without requiring contract changes.

#### `@audit-ack: <finding-id>` — parsed today, honoured later

Forward-compatible. Annotation by stable finding ID for case-by-case acknowledgements after audit review.

### Unknown-tag behaviour

If the tag is not in the known enum for its key (e.g., `// @access-control: probably-fine`), the parser still records the annotation but the analyzer:

- Emits the finding at `low` severity (one notch above `info`) with a "tag not in known enum" note.
- Includes the unknown tag verbatim so a reviewer can correct it or you can extend the enum.

This is deliberate — silently honouring unknown tags would let typos disable findings.

### Binding rules

- The annotation block must immediately precede a circuit declaration. Multiple `// @key: tag` annotations on the same circuit are allowed; only the first of each key is honoured.
- Function-level annotations don't exist — the annotation is per-circuit only. This is intentional: function-level acks are too coarse and let a contributor accidentally ack a new finding by adding a circuit after the annotation.

### CI workflow

```bash
# Pin the schema
jq -r '.security.findings[] | select(.severity == "critical" or .severity == "high")' \
  /path/to/security-profile.json
```

An acknowledged finding's severity is `info`, so it doesn't appear in a critical+high filter. The annotation is the in-source contract between the contract author and the audit pipeline.

## `security-profile.json` artifact

Written alongside `report.html` as a sibling of the compiler's `security-analysis.json`. Versioned with `schema_version: "1.0.0"`.

```jsonc
{
  "schema_version": "1.0.0",
  "contract_file":  "<path>",
  "analyzer_version": "1.0.0",
  "generated_at":   "<ISO-8601>",

  "profile": {
    "schemaVersion": "1.0.0",
    "valuePosture":   "none|receives|holds|mints|bridges",
    "privacyPosture": "open|selective|strong-with-disclosures|strong",
    "authorityModel": "permissionless|single-owner|multi-key|membership-proof|unclear",
    "tokenPrimitives": [ { "primitive": "...", "circuit": "...", "location": {...} } ],
    "ledgerSurface":   { fieldsTotal, fieldsSealed,
                         balanceLike, commitmentLike, nullifierLike,
                         counterLike, keyLike },
    "externalCustodyHints": [ "..." ],
    "circuitCount": <int>,
    "exportedCircuitCount": <int>,
    "witnessFunctionCount": <int>
  },

  "value_inventory": {
    "schemaVersion": "1.0.0",
    "mintOperations":    [ { primitive, circuit, location, authorizedBy } ],
    "sendOperations":    [ { primitive, circuit, location } ],
    "receiveOperations": [ { primitive, circuit, location } ],
    "balanceFields":     [ { field, type, trackedByCircuits, overflowAssertionPresent } ],
    "commitmentNullifierPairs": [ { commitmentField, nullifierField } ],
    "maintenanceAuthorityRefs": [ {...} ],
    "maxSupplyConstraints":     [ {...} ],
    "offChainCustodySignals":   [ "..." ],
    "valueAtRiskSummary": { estimatedClass, isUnboundedMint, isValueHolding }
  },

  "nonce_analysis": {
    "schemaVersion": "1.0.0",
    "witnessFile":         "<path or null>",
    "witnessFileSkipped":  <bool>,
    "findings": [
      {
        "id":             "nonce-<sha256-prefix-12>",
        "kind":           "constant-return-witness | missing-counter-increment",
        "severity":       "critical|high|medium|low|info",
        "witnessFunction": "<name or null>",
        "ledgerField":     "<name or null>",
        "sites":   [ { kind, file, line, snippet, circuit } ],
        "evidence": { claimFromSource, compilerDiscloseIndex },
        "recommendation": "<text>",
        "autoDismissible": <bool>
      }
    ]
  }
}
```

The CI integration pattern: parse the JSON, evaluate against a policy, block deploy if predicates fire.

```js
import profile from './security-profile.json';
const blockOn = [
  profile.value_inventory.valueAtRiskSummary.isUnboundedMint,
  profile.profile.authorityModel === 'permissionless'
    && profile.profile.valuePosture !== 'none',
  profile.nonce_analysis.findings.some(f => f.severity === 'critical'),
];
if (blockOn.some(Boolean)) process.exit(1);
```

## Future Work

Compiler-side wishlist (heuristics that move to the compiler when emitted):

1. Access control verification
2. Nullifier tracking
3. State mutation preconditions
4. User-input taint propagation
5. Side-channel detection

Analyzer-side wishlist (phases 2b, 3, 4):

- **Phase 2b**: `multi-call-binding` (witness called more than once per circuit without an equality assert) and `hash-without-blinder` (hash of a stable identifier with no per-event nonce).
- **Phase 3**: **Correlator analyzer**. Cross-circuit join over the compiler's disclose records — flag witnesses disclosed in N circuits with structurally identical exposures (e.g. `disclose(hash(userId))` in both `transfer` and `withdraw` with no blinder). Includes a `@disclose-intent: <tag>` annotation parser so contract authors can acknowledge intentional correlators (e.g. regulator anchors) and downgrade those findings to info.
- **Phase 4**: **Policy assessment block** at the top of the report. Derives a `deploy_recommendation` (`block` | `warn` | `ok`) from `{profile, findings}` via explicit rules. Profile-derived severity adjustment is NOT auto-applied — the policy block is separate and overridable in a config file. A reviewer always sees finding severity as inherent to the rule that fired.

## References

- COIP: `coips/coip-xxxx-security-analysis-output.md` (canonical schema for the compiler-side `security-analysis.json`)
- [Compact Language Specification](https://docs.midnight.network/develop/compact)
- [Nanopass Framework](https://nanopass.org/)
- `contract-deploy-size-limits.md` — source-grounded analysis of the four ledger ceilings that govern contract deploy
