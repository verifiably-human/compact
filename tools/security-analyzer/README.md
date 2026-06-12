# Compact Circuit Analyzer

Constraint analysis, security review, and value/privacy-at-risk assessment for Midnight Compact smart contracts.

## Features

- 🧭 **Contract Profile** (phase 1). Value posture (`none|receives|holds|mints|bridges`), privacy posture, authority model, contract class, and a Value Inventory enumerating every mint/send/receive operation, balance field, and off-chain custody signal. Sets the triage lens before any individual finding.
- 🎲 **Nonce Hygiene** (phase 2). Inspects the witness JS/TS implementation and the contract source for nonce-reuse failures. Catches constant-return witnesses (`new Uint8Array(N)` etc.) and ledger Counter fields used in hashes without an increment.
- 🔒 **Compiler-grounded security analysis**. Consumes `compiler/security-analysis.json` (COIP v1.0.0) for authoritative witness data-flow paths. Heuristic layer fills categories the compiler does not emit; heuristic findings overlapping a compiler finding are dropped.
- 📄 **`security-profile.json` sibling artifact**. Versioned (`schema_version: 1.0.0`) machine-readable output containing the profile, value inventory, and nonce analysis. CI gates and dashboards consume this directly.
- 📊 **Per-circuit constraint metrics** from real compactc output (constraint counts, K-values, proving-time estimates).
- 🎨 **Visual diagrams**: dependency graphs, constraint flows, performance heatmaps.
- 🛡️ **Severity-sorted findings** with stable IDs for cross-run tracking. Fan-out deduped per (circuit, witness).
- 🚫 **Midnight-native by design**. No EVM-template rules (reentrancy, `msg.sender`, `delegatecall`, SWC numbers). Findings describe attacks expressible in the Midnight execution model.
- 🔧 **CI/CD ready**: structured JSON, exit codes, no inline scripts in the HTML report (CSP-tight).

## Installation

### Prerequisites

**Required:**
- [Compact compiler](https://docs.midnight.network/develop/tutorial/compiling) must be installed and available in your PATH

**Optional (for visualizations):**
- [Graphviz](https://graphviz.org/) for generating PNG/SVG/PDF diagrams

Verify installation:
```bash
compact --version
dot -V  # For visualizations
```

**Install Graphviz:**
```bash
# macOS
brew install graphviz

# Ubuntu/Debian
sudo apt-get install graphviz

# Windows
# Download from https://graphviz.org/download/
```

### Install CLI Tool

This tool lives inside the `compact-coip-security` repo and is not published to npm. Build from source:

```bash
# from the repo root
cd tools/security-analyzer
npm install
npm run build
```

Pick one of the following to expose the `compact-analyzer` command on your PATH.

**Option A — run directly (no install).** Always works:

```bash
node /path/to/compact-coip-security/tools/security-analyzer/dist/cli.js analyze contract.compact

# or alias it
echo 'alias compact-analyzer="node /path/to/compact-coip-security/tools/security-analyzer/dist/cli.js"' >> ~/.zshrc
```

**Option B — `npm link` (writable npm prefix required).** `npm link` writes into npm's global prefix. If Node is installed via Nix, Homebrew without a custom prefix, or any read-only location, this fails with `EACCES`. Set a user-writable prefix once:

```bash
mkdir -p ~/.npm-global
npm config set prefix ~/.npm-global
# add to your shell rc if not already there:
echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

cd tools/security-analyzer
npm link
# remove later with: npm unlink -g compact-security-analyzer
```

**Option C — manual symlink.** Skip npm entirely:

```bash
ln -s /path/to/compact-coip-security/tools/security-analyzer/dist/cli.js \
      ~/.local/bin/compact-analyzer
chmod +x dist/cli.js
```

## Usage

### Analysis Commands

**Analyze a single contract:**
```bash
compact-analyzer analyze contract.compact
```

**Analyze multiple contracts:**
```bash
compact-analyzer analyze token.compact election.compact dao.compact
```

### Visualization Commands

**Generate visual diagrams:**
```bash
compact-analyzer visualize contract.compact
```

**Custom visualization options:**
```bash
# SVG format with dark theme
compact-analyzer visualize contract.compact --format svg --theme dark

# Specific visualization types
compact-analyzer visualize contract.compact --type dependency performance

# Custom output directory
compact-analyzer visualize contract.compact --output ./diagrams
```

### Comprehensive Report Command

**Generate all-in-one HTML report:**
```bash
compact-analyzer report contract.compact
```

This generates a single HTML file containing:
- Circuit analysis metrics (constraints, proving time, memory)
- Performance insights and bottlenecks
- Optimization recommendations
- All embedded visualizations (dependency graph, constraint flow, variable map, ledger interactions, performance heatmap)

**Custom report options:**
```bash
# Dark theme with PNG visualizations
compact-analyzer report contract.compact --theme dark --viz-format png

# Custom output location
compact-analyzer report contract.compact --output ./docs/circuit-analysis.html

# Report without visualizations (faster)
compact-analyzer report contract.compact --no-visualizations

## Security Analysis

The analyzer includes comprehensive security analysis with two levels of detection:

### Compiler Semantic Analysis (Recommended)

**Source: `<output-dir>/compiler/security-analysis.json` — COIP v1.0.0**

The Compact compiler runs a witness data-flow taint analysis (the "witness-protection program") on every compile. It refuses to compile a contract that would expose a witness value outside an explicit `disclose()` carve-out, and on success it writes the analysis result to `compiler/security-analysis.json`. The analyzer consumes that file directly — it does not re-run the analysis.

Findings carry:

- The **origin** of the witness value: a witness function return, a constructor argument, or a circuit argument.
- The **disclosure site** with file/line/column.
- The full **data-flow path** from origin to site, point-by-point, with per-step exposure annotations.
- A **final exposure** label such as `"the witness value"` (raw disclosure) or `"a hash of the witness value"` (privacy-preserving disclosure).

The analyzer maps these to severities:

| `final_exposure`              | Severity | Meaning                                                                        |
|-------------------------------|----------|--------------------------------------------------------------------------------|
| Any leak record               | critical | Compiler blocked compilation. In practice not emitted (file written on success). |
| `"the witness value"`         | high     | Raw witness value is published. Confirm intent; prefer a commitment.            |
| Anything else (hash, …)       | info     | Intentional privacy-preserving disclosure. Reviewer confirms transform is hiding. |

**Example:**
```compact
witness private$secret(): Bytes { ... }

circuit leak(): Void {
  disclose(private$secret());  // Compiler rejects: emits a leak. Compile fails.
}

circuit safe(): Void {
  disclose(persistentHash(private$secret()));  // Recorded as a disclosure with
                                               // final_exposure: "a hash of the witness value".
                                               // Reported as INFO.
}
```

### Heuristic Analysis (Supplement)

The analyzer also runs regex-based heuristics over the source. These cover categories the compiler analysis does not (yet) cover:

- Access control issues
- State mutation risks
- Nullifier misuse
- Taint propagation
- Side-channel vulnerabilities

Heuristic privacy-leak findings that target a circuit the compiler already covered are dropped to avoid duplication. The compiler is authoritative for privacy claims. All surviving heuristic findings are prefixed `[Heuristic]` and require manual verification.

If `compiler/security-analysis.json` is missing (e.g. the compiler in use does not implement the COIP), the analyzer falls back to heuristic-only output and announces it on stderr.

### Checking Your Compiler Version

```bash
compact-analyzer version
```

### Understanding Findings

**Compiler-verified disclosure (raw witness value):**
```
[HIGH] Direct witness disclosure in public_key

Source: witness function `private$secret_key` (declared at examples/tiny.compact:70:1)
Site:   disclose() call at examples/tiny.compact:126:10
Result: the witness value

Data-flow path (origin → site):
  1. the binding of sk @ examples/tiny.compact:56:9
  2. the argument to public_key @ examples/tiny.compact:57:15
```

**Compiler-verified disclosure (transformed — accepted as intentional):**
```
[INFO] Transformed witness disclosure in public_key (a hash of the witness value)

Source: argument `sk` of circuit `public_key` (examples/tiny.compact:125:20)
Site:   disclose() call at examples/tiny.compact:126:10
Result: a hash of the witness value

Data-flow path (origin → site):
  1. the argument to persistentHash @ examples/tiny.compact:126:19 [exposure: a hash of]
```

**Heuristic finding:**
```
[MEDIUM] [Heuristic] Exported circuit returns disclosed data: vote

Note: This finding is based on regex pattern matching. Consider it 
a suggestion for manual review.
```

For detailed information, see [SECURITY_ANALYSIS.md](./SECURITY_ANALYSIS.md).

```

### Output Formats

**Console (default):**
```bash
compact-analyzer analyze contract.compact
```

**Markdown report:**
```bash
compact-analyzer analyze contract.compact -f markdown -o ANALYSIS.md
```

**JSON export:**
```bash
compact-analyzer analyze contract.compact -f json -o analysis.json
```

### Options

**Analysis Command:**
```
Usage: compact-analyzer analyze [options] <files...>

Options:
  -o, --output <file>     Output file (default: console)
  -f, --format <format>   Output format: console, markdown, json (default: "console")
  -v, --verbose           Show detailed metrics
  --no-warnings           Suppress warnings for large circuits
  --timeout <ms>          Compilation timeout in milliseconds (default: "120000")
  -h, --help              Display help
```

**Visualization Command:**
```
Usage: compact-analyzer visualize [options] <file>

Options:
  -o, --output <dir>      Output directory (default: "./circuit-visualizations")
  -f, --format <format>   Output format: png, svg, pdf, dot (default: "png")
  -t, --theme <theme>     Theme: default, dark, light, colorful (default: "default")
  --type <types...>       Visualization types: dependency, constraint, variable, ledger, performance, all (default: ["all"])
  --no-details            Exclude detailed information
  --no-legend             Exclude legend from diagrams
  --performance           Include performance metrics
  --timeout <ms>          Compilation timeout in milliseconds (default: "120000")
  -h, --help              Display help
```

**Report Command:**
```
Usage: compact-analyzer report [options] <file>

Options:
  -o, --output <dir>         Output directory (default: contract name)
  -t, --theme <theme>        Theme: light, dark (default: "light")
  --viz-format <format>      Visualization format: svg, png (default: "svg")
  --no-visualizations        Exclude visualizations from report
  --witness-file <path>      Path to witness JS/TS implementation file.
                             Used by the Nonce Hygiene analyzer to detect
                             constant-return witnesses. When omitted, the
                             analyzer searches conventional locations
                             (<dir>/<stem>-witnesses.{ts,js}, etc.).
  --from-build-dir <path>    Skip compilation; consume an existing compactc
                             output directory. The directory must contain
                             at least 'compiler/' (with contract-info.json
                             and optionally security-analysis.json). 'zkir/'
                             enables constraint counts; if absent, the
                             report skips those metrics. 'keys/' is
                             unused by the analyzer.
  --timeout <ms>             Compilation timeout in milliseconds (default: "120000")
  -h, --help                 Display help
```

### Pre-compiled workflow

`--from-build-dir` is for CI pipelines that compile the contract elsewhere (e.g., a build stage upstream of the audit stage) and want the analyzer to consume those artifacts without paying the compile cost again.

```bash
# CI build stage
compact compile +0.31.107 my-contract.compact out/

# CI audit stage (no compactc needed in this stage)
compact-analyzer report my-contract.compact --from-build-dir out/ --output audit/
```

What's required in the build directory:

| Artifact | Required? | What it enables |
|---|---|---|
| `compiler/contract-info.json` | yes | Circuit and witness enumeration. |
| `compiler/security-analysis.json` | strongly recommended | The compiler's witness data-flow report (COIP v1.0.0). When present, drives privacy findings; when absent, falls back to heuristics. |
| `compiler/contract-manifest.json` | optional | Sizes and hashes of other artifacts. |
| `zkir/<circuit>.zkir` | optional | Constraint counts and proving-time estimates. Without it, the constraint table is empty but security analysis still runs. |
| `keys/<circuit>.verifier` | not used | Verifier keys are unused by this tool. (They're used by the separate `deploy-check` tool.) |

The user-supplied directory is never modified or deleted by the analyzer. The temp-directory cleanup that runs in the default mode does not apply.

**Output Structure:**
```
contract-name/               # Or custom directory name
├── report.html             # Main HTML report
└── visualizations/         # Embedded visualizations
    ├── dependency-graph.svg (or .png)
    ├── constraint-flow.svg
    ├── variable-map.svg
    ├── ledger-interactions.svg
    └── performance-heatmap.svg
```

### Examples

**Analysis Examples:**
```bash
# Generate README documentation
compact-analyzer analyze examples/*.compact -f markdown -o CONSTRAINTS.md

# CI/CD integration - save JSON for tracking
compact-analyzer analyze src/contract.compact -f json -o analysis.json

# Generate markdown report for PR comments
compact-analyzer analyze src/contract.compact -f markdown -o comment.md

# Verbose analysis
compact-analyzer analyze contract.compact -v
```

**Visualization Examples:**
```bash
# Generate all visualizations (default PNG format)
compact-analyzer visualize contract.compact

# SVG format with dark theme
compact-analyzer visualize contract.compact --format svg --theme dark --output ./docs/diagrams

# Only dependency and performance visualizations
compact-analyzer visualize contract.compact --type dependency performance

# High-quality PDF for documentation
compact-analyzer visualize contract.compact --format pdf --theme light

# DOT files for custom processing
compact-analyzer visualize contract.compact --format dot

# Colorful theme for presentations
compact-analyzer visualize contract.compact --theme colorful --performance
```

**Comprehensive Report Examples:**
```bash
# Generate comprehensive HTML report (creates 'contract-name/' directory)
compact-analyzer report contract.compact

# Dark theme report with PNG visualizations
compact-analyzer report contract.compact --theme dark --viz-format png

# Custom output directory
compact-analyzer report contract.compact --output ./my-analysis

# Fast report without visualizations
compact-analyzer report contract.compact --no-visualizations

# For CI/CD pipelines
compact-analyzer report contract.compact --output ./reports/$(date +%Y-%m-%d)
```

**Default Behavior:**
The `report` command automatically creates a directory named after your contract:
```bash
# Running this:
compact-analyzer report token.compact

# Creates this structure:
token/
├── report.html
└── visualizations/
    ├── dependency-graph.svg
    ├── constraint-flow.svg
    ├── variable-map.svg
    ├── ledger-interactions.svg
    └── performance-heatmap.svg
```

## Contract Profile + Value Inventory (phase 1)

Every `report` invocation also produces a **Contract Profile** at the top of the HTML report and a sibling `security-profile.json` artifact. The profile classifies the contract by three postures before any individual finding, so a reviewer can triage in one glance:

```
🧭 Contract Profile
  Value posture:     bridges                  [red badge]
  Privacy posture:   selective                 [yellow]
  Authority model:   permissionless            [red]
  Circuits:          6/9 exported, 8 witness function(s)

  Ledger Surface (21 fields, 1 sealed)
    Balance-like:    vaultBalance, totalDistributed, …
    Commitment-like: recipientAccountCommitment, …
    Key-like:        owner

  Value Inventory
    Estimated class: custodial-token  [UNBOUNDED-MINT] [value-holding]
    Mint operations: 2 (mintToVault:mintShieldedToken[auth=missing],
                       prepareWithdrawal:mintUnshieldedToken[auth=missing])
    Send operations: 1
    Receive operations: 1
    Balance fields:  4 (vaultBalance, totalDistributed [no overflow assert], …)
    Max-supply constraints: 0
    Off-chain custody hints: vaultBalance, publishReserves, isSolvent, …
```

### Postures

| Field | Values | Derived from |
|---|---|---|
| **Value posture** | `none`, `receives`, `holds`, `mints`, `bridges` | Stdlib token-primitive invocations + balance-like field count + custody signals. `bridges` = mints + sends + off-chain custody. |
| **Privacy posture** | `open`, `selective`, `strong-with-disclosures`, `strong` | Witness count + density and shape of `disclose()` calls. |
| **Authority model** | `permissionless`, `single-owner`, `multi-key`, `membership-proof`, `unclear` | Access-control finding coverage + owner-like ledger field count. |

### Contract class enum

`estimatedClass` is one of: `custodial-token`, `shielded-token`, `unshielded-token`, `nft`, `escrow`, `voting`, `auction`, `registry`, `amm`, `bridge`, `compute-only`, `unknown`. Used by CI to apply class-specific deploy policies (e.g., "block deploy if class is custodial-token and authorityModel is permissionless").

## Nonce Hygiene (phase 2)

Nonces underpin most privacy claims in shielded protocols. A constant or deterministic nonce defeats unlinkability without breaking the proof system — the compiler accepts it. The Nonce Hygiene section flags two failure modes:

### `constant-return-witness` (CRITICAL)

The witness JS/TS implementation of a nonce-role function (named `*nonce`, `*salt`, `*blinder`, `*random`, `*seed`) returns a constant value. Detected patterns:

- `new Uint8Array(N)` with no fill → all-zero bytes
- `Buffer.alloc(N)` → all-zero bytes
- Hardcoded array literals (`new Uint8Array([0, 0, …])`)
- `Buffer.from(<string-literal>)` → deterministic bytes

A function is treated as safe if its body contains a CSPRNG call (`crypto.randomBytes`, `crypto.getRandomValues`).

Each finding lists the witness implementation line **and** the circuit call sites:

```
[CRITICAL] constant-return-witness — getCommitmentNonce
  claim: new Uint8Array(N) → all-zero bytes. Witness returns the same bytes
         on every call; downstream commitments and nullifiers derived from
         it are deterministic.
  sites:
    [witness-impl]  pattern7a-witnesses.js:22   new Uint8Array(32)
    [circuit-call]  pattern7a-custodial.compact:249  getCommitmentNonce(
    [circuit-call]  pattern7a-custodial.compact:330  getCommitmentNonce(
  recommendation: In pattern7a-witnesses.js, replace the constant return
    with a fresh draw from a CSPRNG (Node: crypto.randomBytes(N); Browser:
    crypto.getRandomValues(new Uint8Array(N))). …
```

### `missing-counter-increment` (HIGH)

A ledger field typed `Counter` (or named `*nonce`, `sequence`, `*Version`, `*Counter`) appears inside a `persistentHash`/`transientHash` call but no circuit increments it (`.increment()` or `X = (disclose(X) + 1) as Counter`). The same value enters the hash on every call.

### Witness file resolution

The analyzer auto-detects the witness implementation file from conventional layouts. Search order:

1. Explicit `--witness-file <path>` flag (if provided).
2. Same directory as the contract: `<stem>-witnesses.{ts,js}`, `<stem>.witnesses.{ts,js}`, `witness.{ts,js}`, `witnesses.{ts,js}`.
3. `./witnesses/<stem>-witnesses.{ts,js}` and `./witnesses/<stem>.{ts,js}`.
4. `../witnesses/`, `../deploy/witnesses/`, `../../deploy/witnesses/`, `../src/witnesses/` with the same patterns.
5. Falls back through progressively shorter hyphen-stems (e.g. `pattern7a-custodial` → `pattern7a`), so `pattern7a-custodial.compact` resolves to `pattern7a-witnesses.js`.

If no file is found, the constant-return check is skipped and a one-line note is printed. The `missing-counter-increment` check runs from source only and is unaffected.

### Stable IDs

Every nonce finding carries an `id` of the form `nonce-<sha256-prefix-12>`, derived from `(kind, witness/field, sorted-sites)`. The same finding produces the same ID across runs — CI can pin known IDs as accepted and alert only on new ones.

## Correlators (phase 3)

Cross-circuit linkability detector. Groups the compiler's witness disclosure records by origin and flags cases where the same witness flows to disclose sites in multiple circuits without a per-event blinder. The detector is a prompt for human review — many contracts deliberately publish a correlator (regulator anchors, dedupe keys, public identity proofs).

```
[INFO] corr-5e609702ca3d  (blinder present)
  origin: witness-return-value getCommitmentNonce
  sites:  2 (custodialTransfer, prepareWithdrawal)
  → A per-event blinder is present; direct hash-value correlation is weakened.
```

### Acknowledging intentional correlators

Add a `// @disclose-intent: <tag>` annotation above any of the involved circuits to downgrade the finding to info:

```compact
// @disclose-intent: intentional-correlator
//
// recipientAccountCommitment is intentionally derivable by the
// recipient given their accountHash + nonce — that's how they
// confirm incoming transfers.
export circuit custodialTransfer(...): [] { ... }
```

Tags: `intentional-correlator`, `nullifier-emission`, `commitment-output`, `public-by-design`, `protocol-required`.

## Deploy Policy Assessment (phase 4)

Synthesises a single deploy recommendation (`block` / `warn` / `ok`) from the profile + findings combination. Each rule that fires contributes one reason. The recommendation is the worst-severity reason.

```
🚦 Deploy Policy Assessment
   ⛔ BLOCK

   [BLOCK] unbounded-mint: Contract mints tokens via at least one circuit
           whose access control is missing or disabled, and no max-supply
           assertion guards the mint. Any caller can mint arbitrary amounts.
   [BLOCK] critical-security-finding: Critical: Disabled authorization check:
           initializeToken
   [WARN]  permissionless-value-contract: Contract has value posture
           "bridges" but authority model is "permissionless".
```

Default rules shipped:

| Rule | Severity | Triggers when |
|---|---|---|
| `unbounded-mint` | block | Mints with missing auth AND no max-supply assertion |
| `critical-security-finding` | block | Any critical security finding (excluding acknowledged) |
| `critical-nonce-in-value-contract` | block | Critical nonce finding on a value-holding contract |
| `mint-with-missing-auth-bounded` | warn | Mint with missing auth but max-supply is asserted |
| `high-severity-security-findings` | warn | Any high-severity security finding |
| `high-severity-nonce-findings` | warn | Any high-severity nonce finding |
| `unacknowledged-correlators-on-private-contract` | warn | Correlators without `@disclose-intent` acks, on a contract claiming privacy |
| `permissionless-value-contract` | warn | Value-handling contract with no recognised access control |

A CI gate parses `security-profile.json` and pins on `policy_assessment.deployRecommendation`:

```bash
case $(jq -r '.policy_assessment.deployRecommendation' security-profile.json) in
  block) echo "Deploy blocked — see security-profile.json"; exit 1 ;;
  warn)  echo "Deploy with caution — review reasons" ;;
  ok)    echo "Deploy OK" ;;
esac
```

## `security-profile.json`

Sibling artifact written next to `report.html`. Versioned (`schema_version: "1.0.0"`). Top-level shape:

```jsonc
{
  "schema_version": "1.0.0",
  "contract_file": "path/to/foo.compact",
  "analyzer_version": "1.0.0",
  "generated_at": "<ISO-8601>",
  "profile":          { …ContractProfile… },
  "value_inventory":  { …ValueInventory… },
  "nonce_analysis":   { …NonceAnalysis… }
}
```

Consumers (CI gates, dashboards, deploy pipelines) parse this directly without scraping the HTML. Pin on `profile.valuePosture`, `value_inventory.valueAtRiskSummary.isUnboundedMint`, and `nonce_analysis.findings[].kind` to build deploy policies.

## In-source audit annotations

Contract authors can acknowledge design choices directly in the source. The analyzer recognises `// @<key>: <tag>` comments immediately above a circuit declaration and downgrades the corresponding finding from a "fix this" to an "intentional design" entry.

### `@access-control: <tag>`

For exported circuits with no recognised authorization guard:

```compact
// @access-control: intentional-permissionless
//
// processCompliantPayment is callable by any address — the access
// gate is the in-circuit compliance assertions (KYC level, KYC
// expiry, sanctions-proof freshness, reporting threshold).
export circuit processCompliantPayment(...): Boolean {
  // ...
}
```

Recognised tags:

| Tag | When to use |
|---|---|
| `intentional-permissionless` | Anyone can call. Demo, public utility, KYC-gated, or compliance-gated contract. |
| `witness-gated` | Authorization is enforced through witness assertions (e.g., a private key check inside the circuit). |
| `compliance-gated` | Authorization through a `runComplianceChecks`-style internal circuit that asserts KYC, sanctions, etc. |
| `read-only` | Circuit performs no real mutation despite syntactic appearance (e.g., default assignment that's a no-op). |
| `documented` | The design intent is documented in the contract docstring; see <ref>. |

### What the annotation does

- A "Missing authorization check" or "Disabled authorization check" finding for the annotated circuit is replaced with an `info`-severity "Access-control acknowledged" finding.
- The tag and any reason text following the annotation line are surfaced in the report.
- The finding remains in the JSON (so CI/dashboards record the acknowledgement) but does not trigger fail-on-finding policies that target only critical/high severity.

### Rules

- The annotation must immediately precede the `circuit` or `export circuit` declaration. Blank lines and continuation comments (`//`) between the tag line and the declaration are allowed; any other top-level form orphans the annotation.
- Multiple `// @<key>: <tag>` annotations on the same circuit are allowed; only the first `@access-control` annotation is honoured.
- An unknown tag (e.g., `// @access-control: probably-fine`) is parsed but not honoured; the finding stays at its original severity with a note about the unknown tag.

### Future annotation keys

The same mechanism is forward-compatible with phase-3 work:

- `@disclose-intent: <tag>` — acknowledge a deliberate correlator. Tags: `intentional-correlator`, `nullifier-emission`, `commitment-output`, `public-by-design`, `protocol-required`.
- `@audit-ack: <finding-id>` — acknowledge a specific reviewed finding by its stable ID.

These are parsed today (the parser accepts any of the three keys) but not yet honoured by the corresponding analyzers. Adding them now does no harm.

## Testing

Unit tests live in `src/*.test.ts` next to the modules they exercise. The test harness uses Node's built-in test runner — no extra dev dependency.

```bash
# Build then run all tests (37 tests across 3 suites)
npm test

# Re-run tests without rebuilding (when iterating on test files only)
npm run test:only
```

Coverage today:

- `annotation-parser` — parsing, binding, unknown tags, line tracking, orphan handling.
- `profile-analyzer` — posture derivation for every value/privacy/authority enum value, ledger surface classification, value inventory shape, contract class detection.
- `nonce-analyzer` — constant-return detection, CSPRNG short-circuit, non-nonce-name skip, witness file auto-detection (same-dir and base-stem fallback), missing-counter-increment, stable ID determinism.

End-to-end report generation is exercised by `npm run check:examples` (existing script), which compiles a fixture contract through `compact-analyzer report` and asserts the output structure.

## Visualization Types

The `visualize` command generates the following diagram types:

### 1. Dependency Graph
Shows circuit dependencies and relationships between circuits and ledgers.
- **Features**: Circuit complexity coloring, ledger types, dependency arrows
- **Use Cases**: Understanding circuit architecture, identifying circular dependencies

### 2. Constraint Flow
Visualizes the flow of constraints within and between circuits.
- **Features**: Sequential flow arrows, constraint count details, complexity-based coloring
- **Use Cases**: Debugging constraint execution, optimizing constraint order

### 3. Variable Map
Maps variable dependencies and usage patterns across circuits.
- **Features**: Variable nodes with circuit context, dependency relationships, type information
- **Use Cases**: Identifying unused variables, understanding data flow

### 4. Ledger Interactions
Shows how circuits interact with ledger state.
- **Features**: Ledger nodes with type information, read/write operations, circuit relationships
- **Use Cases**: Understanding state management, identifying race conditions

### 5. Performance Heatmap
Identifies performance bottlenecks and optimization opportunities.
- **Features**: Color-coded by proving time, memory estimates, constraint counts
- **Use Cases**: Performance profiling, identifying bottlenecks, planning optimizations

## Visualization Themes

- **default**: Clean, professional appearance for documentation
- **dark**: High contrast for presentations and demos
- **light**: Minimalist design for printing
- **colorful**: Vibrant colors for engaging presentations

## Visualization Formats

- **PNG**: High-quality raster images (good for web and documentation)
- **SVG**: Scalable vector graphics (perfect for web and print)
- **PDF**: Professional documentation format (high-quality printing)
- **DOT**: Source format for Graphviz (fully customizable)

## Output

### Console Format

```
📊 Compact Circuit Analysis
================================================================================

Contract: token-transfer.compact
Compiled: 2026-02-03T12:00:00.000Z
Duration: 6389ms
Compiler: compact 0.4.0

Circuits (2):

Circuit                  │  Constraints │ K-value │  Proof Size │ Proving Time
─────────────────────────────────────────────────────────────────────────────
transfer                 │      174,432 │      18 │      ~1.0 KB │       13.2s
mint                     │       69,072 │      17 │      ~972 B  │        5.3s
─────────────────────────────────────────────────────────────────────────────

Total: 243,504 constraints across 2 circuits
```

### Markdown Format

```markdown
# Circuit Analysis: token-transfer.compact

**Generated:** 2026-02-03T12:00:00.000Z
**Compilation Time:** 6389ms
**Compiler Version:** compact 0.4.0

## Summary

- **Total Circuits:** 2
- **Total Constraints:** 243,504

## Circuits

| Circuit | Constraints | K-value | Proof Size | Proving Time (est) |
|---------|-------------|---------|------------|-------------------|
| transfer | 174,432 | 18 | ~1.0 KB | 13.2s |
| mint | 69,072 | 17 | ~972 B | 5.3s |
```

### JSON Format

```json
{
  "contractFile": "token-transfer.compact",
  "circuits": [
    {
      "name": "transfer",
      "constraints": 174432,
      "kValue": 18,
      "proofSize": 1024,
      "zkirSize": 14536,
      "provingTimeEstimate": 13.2,
      "memoryEstimate": 4096
    }
  ],
  "totalConstraints": 243504,
  "compilationTime": 6389,
  "timestamp": "2026-02-03T12:00:00.000Z",
  "compilerVersion": "0.4.0"
}
```

## How It Works

1. **Compilation**: Shells out to `compact compile` with `--skip-zk` flag
2. **Parsing**: Reads `.zkir` files from compilation output
3. **Analysis**: Calculates constraints using empirical formula: `constraints ≈ zkir_size × 12`
4. **Metrics**: Estimates proving time, memory, proof size, and K-value
5. **Reporting**: Generates formatted output

## Accuracy

**100% accurate** - Uses the real Compact compiler output, not heuristics.

The constraint counts come directly from the `.zkir` files generated by `compactc`. Proving time and memory estimates are based on empirical measurements and may vary based on hardware.

## CI/CD Integration

### GitHub Actions

```yaml
name: Analyze Constraints

on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Compact
        run: |
          # Install compact compiler
          # (see Midnight docs for installation)

      - name: Install Analyzer (from source — not published to npm)
        run: |
          cd tools/security-analyzer
          npm ci
          npm run build
          npm link

      - name: Analyze Contracts
        run: |
          compact-analyzer analyze src/*.compact -f markdown -o analysis.md

      - name: Comment PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const analysis = fs.readFileSync('analysis.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: analysis
            });
```

### Git Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Analyzing Compact contracts..."
compact-analyzer analyze src/*.compact -f console

if [ $? -ne 0 ]; then
  echo "❌ Constraint analysis failed"
  exit 1
fi
```

## Troubleshooting

### "Compact compiler not found"

Ensure `compact` is installed and in your PATH:

```bash
which compact
compact --version
```

### "Compilation failed"

Check that your Compact contract has valid syntax:

```bash
compact compile contract.compact output/
```

### Timeout Issues

For large contracts, increase the timeout:

```bash
compact-analyzer analyze contract.compact --timeout 300000  # 5 minutes
```

## Comparison with Web Tool

| Feature | CLI Tool | Web Tool |
|---------|----------|----------|
| **Accuracy** | 0% error | ±88% error |
| **Speed** | ~5-10 seconds | Instant |
| **Setup** | Requires compiler | None |
| **Use Case** | Production | Learning |
| **CI/CD** | ✅ Yes | ❌ No |
| **Offline** | ✅ Yes | ❌ No |

**Recommendation:** Use CLI tool for development and production. Use web tool for quick learning and exploration.

## Contributing

Issues and PRs welcome on the parent `compact-coip-security` repository.

## License

Apache 2.0
