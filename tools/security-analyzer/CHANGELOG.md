# Changelog

All notable changes to the `compact-security-analyzer` tool. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 4: Deploy Policy Assessment

- **PolicyAssessor.** New module that derives a single
  `deployRecommendation` (`block` | `warn` | `ok`) from the
  combination of ContractProfile, ValueInventory, security findings,
  nonce findings, and correlator findings. Each rule that fires
  contributes a stable `rule` identifier plus a one-line message; the
  worst severity sets the recommendation.
- **Rules shipped (block):** `unbounded-mint`,
  `critical-security-finding`, `critical-nonce-in-value-contract`.
- **Rules shipped (warn):** `mint-with-missing-auth-bounded`,
  `high-severity-security-findings`, `high-severity-nonce-findings`,
  `unacknowledged-correlators-on-private-contract`,
  `permissionless-value-contract`.
- **Top-of-report Policy Assessment banner.** Coloured block above the
  Contract Profile, single-glance verdict, followed by the list of
  rules that fired.
- **`security-profile.json` extended** with a `policy_assessment`
  block — first thing a CI gate or operator reads.
- **9 unit tests** in `policy-assessor.test.ts` covering every rule
  and the worst-severity-wins logic.

### Added — Phase 3: Correlator analyzer + `@disclose-intent` honoring

- **CorrelatorAnalyzer.** New module that joins the compiler's witness
  disclosure records (`compiler/security-analysis.json`) to surface
  cross-circuit linkability. Groups disclose entries by witness origin
  (kind + function/argument); when a group spans 2+ distinct circuits
  with structurally similar exposure, emits a Correlator finding.
- **Severity logic:** info if a per-event blinder is present in the
  disclosure path; info if any involved circuit carries a
  `@disclose-intent: <tag>` annotation; otherwise high
  (same final_exposure across sites) or medium (mixed exposures).
- **Stable IDs** of the form `corr-<sha256-prefix-12>` derived from
  `(origin-key, sorted-sites)`.
- **`@disclose-intent: <tag>` honored.** Tags from the schema enum
  (`intentional-correlator`, `nullifier-emission`, `commitment-output`,
  `public-by-design`, `protocol-required`) downgrade matching
  correlator findings to info severity with the tag and reason
  surfaced in the finding's description.
- **Correlators section** rendered in the HTML report after Nonce
  Hygiene. Each finding lists origin, exposure structure, linked
  disclose sites with circuit binding, and recommendation.
- **`security-profile.json` extended** with `correlator_analysis`
  block.
- **5 unit tests** in `correlator-analyzer.test.ts`.

### Added — Phase 2b: multi-call-binding + hash-without-blinder

- **`multi-call-binding` (severity: medium).** Detects witness
  functions called more than once in the same circuit without being
  captured by a single `const` binding. Compact witnesses can return
  different values per invocation; downstream code that assumes
  equality across calls is unsound.
- **`hash-without-blinder` (severity: low).** Detects
  `persistentHash`/`transientHash` invocations whose argument list
  doesn't include a per-event nonce/salt/blinder. The same caller
  computing the same hash twice produces an identical result; for
  commitment-style uses this defeats hiding. Skips when all args are
  literal (constant anchors are intentionally deterministic).
- Both fire under the existing Nonce Hygiene section; both carry
  stable `nonce-<sha256-prefix-12>` IDs. Type-param regex on hash
  calls now handles one level of nested `<...>` (e.g.
  `<[Bytes<32>, Counter]>`).

### Changed — Proving-time / memory metric framing

- Summary cards now show **Worst-case Proving Time** (max across
  circuits) and **Median Proving Time** as the top-line metrics. The
  prior "Total Proving Time" was a sum across all circuits — only
  meaningful if every circuit were proved once sequentially, which is
  not a real workload.
- A collapsible "Cumulative metrics (not a real workload)" details
  section preserves the sums with an explicit qualifier.
- Peak Memory now identifies the slowest-circuit name; the misleading
  "Total Memory" (sum of per-circuit estimates) is demoted into the
  cumulative section with a qualifier that parallel proof workers
  each need their own peak, so the sum isn't a host RAM requirement.

### Removed — Generic attack scenarios

- **GEN-1 Front-Running Attack scenario** deleted. The analyzer
  cannot tell, without semantic analysis of value-bearing public
  state changes, whether a contract is front-runnable. Most Midnight
  contracts use shielded transfers or commitment-reveal patterns that
  defeat naive front-running; the scenario emitted on every contract
  was pure noise.
- **GEN-2 Denial of Service via Resource Exhaustion scenario**
  deleted. Conflated EVM-style consensus DoS (doesn't apply on
  Midnight: DUST fees provide rate limiting), prover-host resource
  pressure (operator concern, not contract concern), and circuit
  complexity (a UX/cost concern already surfaced in the Performance
  section). None are contract-level security findings.

### Added — Automated test suite

- **37 unit tests** under `src/*.test.ts`, run via `npm test`. Built-in
  Node test runner (no extra dependency). Coverage:
  - `annotation-parser.test.ts` — 10 tests. Binding to next circuit,
    unknown-tag handling, key/tag enums, line tracking, orphaned
    annotations, blank-line/continuation tolerance.
  - `profile-analyzer.test.ts` — 14 tests. Value/privacy/authority
    posture derivation, ledger surface classification, value
    inventory shape, isUnboundedMint detection, contract class
    classification.
  - `nonce-analyzer.test.ts` — 13 tests. Constant-return detection,
    CSPRNG short-circuit, non-nonce-name skip, witness file
    auto-detection (same-dir and ../deploy/witnesses base-stem
    fallback), missing-counter-increment, stable-ID determinism.
- `npm test` builds the project first; `npm run test:only` re-runs the
  test files without rebuilding.

### Added — `--from-build-dir` flag

- **Skip-compilation mode for CI pipelines.** New `--from-build-dir <path>`
  option on the `report` command. When set, the analyzer skips the
  internal `compact compile` invocation and reads
  `<path>/compiler/{contract-info,security-analysis,contract-manifest}.json`
  and `<path>/zkir/<circuit>.zkir` from the supplied directory.
- `zkir/` is optional; when absent, constraint metrics are skipped
  but security/profile/nonce analysis still runs.
- The user-supplied directory is never modified or deleted.

### Added — In-source audit annotations

- **AnnotationParser.** New `annotation-parser.ts` module. Parses
  `// @<key>: <tag>` comments and binds them to the next circuit
  declaration. Recognised keys: `access-control`, `disclose-intent`,
  `audit-ack`.
- **`@access-control: <tag>` honoured.** When a circuit carries this
  annotation, the "Missing authorization check" / "Disabled
  authorization check" finding is replaced by a single `info`-severity
  "Access-control acknowledged: <circuit> (<tag>)" finding. Tags:
  `intentional-permissionless`, `witness-gated`, `compliance-gated`,
  `read-only`, `documented`. Unknown tags are flagged at `low`
  severity so typos can't silently disable findings.
- **`@disclose-intent: <tag>` and `@audit-ack: <id>` parsed.** Stored
  but not yet honoured — future analyzers (phase 3 correlator
  detector, per-finding acknowledgement support) will consume them.
  Adding these annotations today does no harm.

### Added — Phase 2: Nonce Hygiene

- **NonceAnalyzer.** New detector for nonce-related privacy failures.
  Two kinds shipped:
  - `constant-return-witness` (severity: critical). Inspects the
    witness JS/TS implementation file for nonce-role witnesses
    (functions named `*nonce`, `*salt`, `*blinder`, `*random`, `*seed`)
    whose body matches a constant-return pattern (`new Uint8Array(N)`
    without fill, `Buffer.alloc`, hardcoded byte literals) and contains
    no CSPRNG call (`crypto.randomBytes`, `crypto.getRandomValues`).
    Catches pattern7a's `getCommitmentNonce` constant-zero return.
  - `missing-counter-increment` (severity: high). Detects `Counter`-typed
    ledger fields used inside a `persistentHash`/`transientHash` call
    where no circuit increments the field (via `.increment()` or
    `X = (X + 1) as Counter`). Same value enters the hash on every
    call.
- **Witness-file auto-detection.** Searches conventional layouts
  (`<dir>/<stem>-witnesses.{ts,js}`, `<dir>/witnesses/<stem>.{ts,js}`,
  `<dir>/../deploy/witnesses/<stem>-witnesses.{ts,js}`, …) and tries
  progressively-shorter stems (`pattern7a-custodial` →
  `pattern7a`). Pass `--witness-file <path>` to override.
- **Stable finding IDs.** `nonce-<sha256-prefix-12>` derived from
  `(kind, witness/field, sorted-sites)`. Same finding produces the same
  ID across runs; CI can pin known IDs as accepted and alert only on
  new ones.
- **Nonce Hygiene section** rendered in the HTML report below the
  Security Findings section. Findings ordered by severity, with witness
  implementation snippet, circuit call sites, and a recommendation per
  finding.
- **`security-profile.json` extended** with `nonce_analysis` block:
  ```
  {
    "nonce_analysis": {
      "schema_version": "1.0.0",
      "witnessFile": "<resolved path or null>",
      "witnessFileSkipped": <bool>,
      "findings": [<NonceFinding>]
    }
  }
  ```

### Added — Phase 1: Contract Profile + Value Inventory

- **ProfileAnalyzer.** New module that classifies the contract by
  three postures at the top of every report:
  - **Value posture**: `none` | `receives` | `holds` | `mints` |
    `bridges`. Derived from stdlib token-primitive invocations
    (`mintShielded/Unshielded`, `sendShielded/Unshielded`,
    `receiveShielded/Unshielded`), ledger field shapes (balance-like
    names), and off-chain custody signals (`vault`, `reserves`,
    `custodian`, `escrow`, `treasury`, `solven*`).
  - **Privacy posture**: `open` | `selective` | `strong-with-disclosures`
    | `strong`. Derived from witness count and the structure of
    `disclose()` calls.
  - **Authority model**: `permissionless` | `single-owner` | `multi-key`
    | `membership-proof` | `unclear`. Cross-references the
    access-control findings from the SecurityAnalyzer.
- **Ledger Surface enumeration** by field-name pattern:
  balance-like, commitment-like, nullifier-like, counter-like,
  key-like.
- **ValueInventory.** Per-operation list of every mint, send, and
  receive call with `circuit:primitive:authorizedBy` triples; balance
  fields with overflow-assertion presence; commitment+nullifier
  pairings; max-supply assertions; off-chain custody signals;
  `valueAtRiskSummary` synthesising `isUnboundedMint` and
  `isValueHolding` flags plus an `estimatedClass` enum
  (`custodial-token`, `shielded-token`, `voting`, `auction`, …).
- **`security-profile.json` sibling artifact** written next to
  `report.html` for CI / dashboard consumption. Versioned with
  `schema_version: "1.0.0"`.
- **Contract Profile section** at the top of the HTML report with
  colored posture badges and an UNBOUNDED-MINT / value-holding flag
  row in the Value Inventory block.

### Changed

- **Severity sort.** Security findings are rendered in severity order
  (critical → high → medium → low → info), then alphabetical by title
  for stable cross-run ordering. Previously findings rendered in
  insertion order.
- **`isStateMutating` heuristic.** Now also detects direct
  ledger-field assignment (`vaultBalance = ...`), the most common
  Compact write pattern. Previously only matched ADT methods
  (`.write/.insert/.increment/...`).
- **`checkAuthorizationPattern` heuristic.** Recognises the real
  Compact authorization pattern (`persistentHash<...>(...) ==
  <ledgerField>` and internal-circuit dispatch like
  `requireOwner()`). Previously required `.read()` syntax that does
  not exist in Compact.
- **`parseCircuits`.** Now detects inline `export circuit foo(...)`
  declarations. Previously only matched `export { foo }` block
  syntax, so contracts using inline exports had every circuit
  registered as not-exported and skipped by access-control checks.
- **`parseStateVariables`.** Accepts `export ledger`, `sealed ledger`,
  and `export sealed ledger` forms. Previously only matched plain
  `ledger`.
- **Privacy-leak deduplication.** "Direct disclosure of private
  witness" and "Exported circuit returns disclosed data" no longer
  emit one finding per `disclose()` site. Deduped per (circuit,
  witness) — multiple sites are listed inside one finding.
- **Heuristic prefix awareness.** Filters that look for
  `Missing authorization` / `Disabled authorization` titles now use
  substring match rather than prefix match, since merged findings
  carry a `[Heuristic]` prefix added by the compiler-security-reader.

### Removed

- **EVM-template attack scenarios.** Deleted SM-1 reentrancy scenario
  (Midnight has no synchronous external call primitive — SWC-107
  doesn't apply). Deleted associated `balance.write` / `external_call`
  pseudocode and CVE-2016 / CVE-2018 / CVE-2021 references.
- **Reentrancy heuristic.** Was firing whenever a circuit had any
  state write and the body string contained `external` or `call` —
  false-positive engine. Reentrancy is not expressible on Midnight.
- **`getScripts()` inline script block** in the HTML report. Was
  decorative (table-row click highlight, Ctrl+P intercept). Removal
  enables `script-src 'none'` in the report's CSP.

### Security

- **CSP meta tag** added to the HTML report:
  ```
  Content-Security-Policy:
    default-src 'none'; style-src 'unsafe-inline';
    img-src data: blob: file:; font-src data:;
  ```
- **HTML escaping** applied to every dynamic interpolation in
  `report-generator.ts` (security findings, contract profile, value
  inventory, circuit table, insights, recommendations, visualizations,
  metadata). Severity values are restricted to a known enum before
  reflection into class names. Inline scripts removed.

## [1.0.0] - prior

Initial release of the constraint and privacy analyzer for Midnight
Compact contracts. Consumes `compiler/security-analysis.json`
(COIP v1.0.0) plus a heuristic layer for categories not covered by
the compiler.
