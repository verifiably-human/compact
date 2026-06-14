# SPEC-2: SARIF 2.1.0 output

## Problem

The analyzer emits HTML for humans and `security-profile.json` for downstream tooling. Neither plugs into GitHub Code Scanning, GitLab SAST, Sonarqube, or any of the security platforms teams already use. Findings stay in the tool's silo; PR reviewers don't see them inline next to the code.

SARIF (Static Analysis Results Interchange Format) 2.1.0 is the standard interchange. GitHub Advanced Security ingests it natively via the `github/codeql-action/upload-sarif` action. Adding a `--format sarif` flag turns the analyzer from a standalone tool into a first-class part of the PR review pipeline.

deploy-check has the same gap. A failed ceiling check is a finding worth surfacing on the PR that introduced it.

## Goal

- security-analyzer: `--format sarif` emits a SARIF 2.1.0 file with one `result` per finding, mapped to the right rule, level, and source location.
- deploy-check: `--format sarif` emits a SARIF file with one `result` per failed ceiling check, pointing at the contract source.
- Both tools' SARIF output validates against the SARIF JSON schema and uploads cleanly via `codeql-action/upload-sarif`.

## Non-goals

- Generating fix suggestions (SARIF supports `fixes`, but we don't have machine-applicable fixes yet).
- Supporting SARIF 2.0 or earlier — 2.1.0 only.
- Emitting both SARIF and JSON at the same time. Use one flag per invocation.

## SARIF mapping — security-analyzer

Each finding maps to one `Result`:

```jsonc
{
  "ruleId": "<rule-key>",                          // e.g. "access-control:missing"
  "level": "error" | "warning" | "note",
  "message": { "text": "<title>: <description>" },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": { "uri": "<relative path to .compact>" },
        "region": { "startLine": N, "endLine": M }
      }
    }
  ],
  "partialFingerprints": {
    "stableId/v1": "<the sha256-prefix-12 from the finding>"
  },
  "properties": {
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "category": "<finding.type>",
    "annotations": { "...": "..." }   // pass-through of any @access-control / @disclose-intent / @audit-ack
  }
}
```

Mapping rules:
- `level`: critical/high → `error`; medium → `warning`; low/info → `note`.
- `partialFingerprints["stableId/v1"]`: lets GitHub Code Scanning correlate the same finding across runs even if the location shifts slightly.
- `ruleId`: stable rule key. The full `rules` array in `tool.driver.rules` carries the human-readable name and helpUri.

### Tool driver block

```jsonc
{
  "driver": {
    "name": "security-analyzer",
    "version": "<package version>",
    "informationUri": "https://github.com/verifiably-human/compact",
    "rules": [
      {
        "id": "access-control:missing",
        "name": "MissingAuthorizationCheck",
        "shortDescription": { "text": "Circuit lacks an authorization check" },
        "fullDescription": { "text": "..." },
        "defaultConfiguration": { "level": "error" },
        "helpUri": "<link to SECURITY_ANALYSIS.md anchor>"
      }
    ]
  }
}
```

Rule IDs from the existing detector taxonomy:
- `access-control:missing`
- `access-control:disabled` (commented-out auth call)
- `privacy-leak`
- `nonce:constant-return-witness`
- `nonce:missing-counter-increment`
- `nonce:multi-call-binding`
- `nonce:hash-without-blinder`
- `correlator:cross-circuit`
- `correlator:per-witness-emission`

## SARIF mapping — deploy-check

Each failed ceiling check maps to one `Result`:

```jsonc
{
  "ruleId": "ceiling:block-bytes-written" |
            "ceiling:transaction-byte-limit" |
            "ceiling:per-entry-point-metadata",
  "level": "error",
  "message": {
    "text": "Deploy exceeds block bytes_written budget: 56000 / 50000 (12% over)"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": { "uri": "<largest contributing circuit's .compact path>" }
      }
    }
  ],
  "partialFingerprints": {
    "contractName/v1": "<contract name from contract-info.json>"
  },
  "properties": {
    "used_bytes": 56000,
    "limit_bytes": 50000,
    "overage_bytes": 6000,
    "mode": "estimator" | "exact"
  }
}
```

Headroom warnings (when implemented per SPEC-3) emit `level: "warning"` results with the same shape.

## CLI surface

Both tools:
```
--format <text|json|sarif>   Output format. Default: text.
--output-file <path>         Where to write structured output. Default: stdout.
                             For sarif, defaults to <build-dir>/security-results.sarif
                             or <build-dir>/deploy-check.sarif.
```

When `--format sarif` is set, the human-readable text output goes to stderr at info level (so CI logs still get a summary), and the SARIF goes to stdout (or the output-file).

## Validation

Both tools' SARIF output is validated against the official schema at:
- https://json.schemastore.org/sarif-2.1.0.json

A unit test runs the JSON through an Ajv validator and fails the test on any schema violation.

End-to-end: the test fixtures' SARIF outputs are uploaded to a test GitHub repo via the codeql-action and the run output is checked.

## CI integration example

```yaml
- name: Analyze
  run: pnpm --filter=security-analyzer cli ./contract --format sarif --output-file security.sarif

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security.sarif
    category: security-analyzer
```

Findings appear inline on PRs in the "Files changed" view.

## Test plan

Unit:
- One test per rule ID that maps to a SARIF result.
- Schema validation passes on every test fixture.
- Empty findings list produces a valid SARIF run with zero results (not an error).
- `--output-file` writes to the given path.

Integration:
- Round-trip: emit SARIF → reparse → assert same finding count and severities.
- Upload a sample SARIF to a GitHub test repo via `gh api`. Confirm the run shows the expected number of findings.

## Open questions

1. Should the SARIF emit `tool.driver.rules` only for rules that fired, or all defined rules? GitHub Code Scanning shows the help text from the rule definition on hover, so listing all rules makes help text always available. Argument against: bigger SARIF files.

   **Decision (proposed):** list all defined rules (it's small, fixed-size, and improves the PR review experience).

2. Should `--format sarif` imply `--baseline-mode accounting-only` (acked findings still appear in SARIF but don't break the build)? Argument for: GitHub Code Scanning has its own dismissal UI; double-suppression confuses reviewers. Against: teams that committed to a baseline want consistency.

   **Decision (proposed):** SARIF emits all findings; suppression metadata goes in `properties.suppressed` so GitHub Code Scanning can show "dismissed by tool"; exit code still respects `--baseline-mode`.
