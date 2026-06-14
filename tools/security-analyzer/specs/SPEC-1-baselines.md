# SPEC-1: Baseline files and finding suppressions

## Problem

Today every analyzer run reports every finding from scratch. A contract with 50 findings stays at 50 forever — auditors triage them once, mark 45 as known/accepted, and the next CI run still says 50. Alert fatigue follows. Teams stop running the scanner.

The tool already emits stable finding IDs (`sha256-prefix-12` of `(circuit, rule, location)`). What's missing is a way to record "we've reviewed this finding and it's acceptable" and have the next run honor that decision.

## Goal

- Let teams check a `.security-analyzer-baseline.json` into their repo.
- Findings present in the baseline are suppressed (downgraded to info, or omitted from CI exit-code accounting — configurable).
- Net-new findings are surfaced loudly and break CI.
- The baseline carries enough metadata (who, when, why) that a reviewer six months later can decide whether the ack is still load-bearing.

## Non-goals

- Auto-generating ack rationale. The tool prompts for it; the human writes it.
- Cross-repo central baseline. Per-contract, per-repo only.
- Time-based expiry (ack auto-expires after N days). Possible future, not v1.

## Finding ID stability — what changes break it

Stable IDs MUST survive these contract edits:
- Adding/removing unrelated circuits.
- Adding/removing unrelated witnesses.
- Reformatting whitespace inside the affected circuit.

Stable IDs MAY break on:
- Renaming the affected circuit (treated as a new finding — the human re-reviews).
- Renaming the affected witness (same).
- Moving the contract file path (same).

The ID derivation function is documented as part of v1.0.0 of the schema and frozen.

## File format

`.security-analyzer-baseline.json` at the repo root (configurable path via `--baseline-file <path>`):

```json
{
  "schema_version": "1.0.0",
  "generated_by": "security-analyzer@<version>",
  "generated_at": "2026-06-13T14:30:00Z",
  "contract_path_glob": "contracts/**/*.compact",
  "acks": [
    {
      "id": "ac-7f9e3a2b1c4d",
      "rule": "access-control:missing",
      "severity_at_time_of_ack": "high",
      "title": "Missing authorization check: processCompliantPayment",
      "ack_by": "alice@example.com",
      "ack_at": "2026-04-15T09:12:00Z",
      "ack_reason": "Intentionally permissionless to allow demo runs. See docs/pattern5-design.md.",
      "ack_expires_at": null
    }
  ]
}
```

Fields:
- `id` — the finding's stable ID. Required.
- `rule` — copy of the rule key at ack time. Helps human reviewers find the file later if the rule changes name.
- `severity_at_time_of_ack` — recorded so the auditor can see if severity escalated since the ack.
- `title` — copy of the original title. Helps reviewers understand context without re-running the tool.
- `ack_by` — free-text identifier. Email, handle, name. Required.
- `ack_at` — ISO 8601 UTC. Required.
- `ack_reason` — required. The tool refuses to write an entry without a reason.
- `ack_expires_at` — optional ISO 8601. When set, the ack is honored only until that date; after that the finding re-surfaces.

## CLI surface

```
--baseline-file <path>       Honor a baseline file when reporting findings.
                             Default: ./.security-analyzer-baseline.json if present.
--no-baseline                Ignore any baseline file. Useful for first-run audits.

--update-baseline            Interactive mode: walk every current finding not in
                             the baseline, prompt for ack reason, write entries.
--update-baseline-from-stdin Non-interactive variant; reads {id: reason} pairs
                             from stdin as JSON. For CI workflows that auto-ack.

--baseline-mode <mode>       suppress | downgrade-to-info | accounting-only
                             default: suppress
```

Modes:
- `suppress` — Acked findings disappear from the report entirely.
- `downgrade-to-info` — Acked findings show as info, with the ack metadata visible in the report.
- `accounting-only` — Findings still appear in full; only the exit code / policy assessment ignores them.

Default is `suppress` because that's what most CI workflows want. Auditors doing a fresh review pass would use `downgrade-to-info`.

## Exit code behavior

Without baseline:
- Critical/high findings → exit 1.
- Otherwise → exit 0.

With baseline + `--baseline-mode suppress` or `accounting-only`:
- Critical/high findings present in the baseline → exit 0 (suppressed).
- Critical/high findings NOT in the baseline → exit 1 (net-new).

Net-new is what CI gates on.

## Report changes

HTML report:
- Add a "Suppressed" section listing acked findings with their `ack_reason`. Always visible.
- The headline finding counts show both (acked) and (net-new) numbers: "12 findings (5 acked, 7 net-new)".

`security-profile.json`:
- New `baseline` object at root: `{ "file": "...", "acks_applied": N, "net_new_findings": M, "acks_expired": [...] }`.
- Findings carry a new `ack` field when an ack applies: `{ ack_by, ack_at, ack_reason, ack_expires_at }`.

## Test plan

Unit tests:
- ID derivation is stable across whitespace-only edits to an unrelated circuit.
- ID changes when the affected circuit is renamed.
- Baseline loader rejects entries without `ack_reason`.
- Baseline loader rejects malformed schema_version.
- Expired acks re-surface.
- `--baseline-mode` switching produces expected counts/report content.

Integration test:
- Fixture contract with 3 findings; baseline acks 2 of them.
- Run with `--baseline-mode suppress`: report shows 1 finding, exit 1.
- Run after acking the 3rd: exit 0.
- Run after adding a 4th finding (net-new): report shows 4 (3 acked, 1 net-new), exit 1.

## Open questions

1. Should the baseline file be the only place acks live, or also support inline `// @audit-ack: <reason>` annotations? The annotation parser already exists. Argument for both: inline acks scale better at the file level; central baseline scales better for audit summary.

   **Decision (proposed):** support both. Inline annotations always apply (they live next to the code); baseline file applies on top for things that can't be annotated (e.g., a finding emitted by the compiler pass at no specific source line).

2. Severity escalation handling. If an ack was recorded at "medium" and the rule's severity moves to "high" in a later release, should the ack still hold? Argument for: the team accepted the underlying risk. Against: severity bumps signal new information that warrants re-review.

   **Decision (proposed):** the ack holds, but the report shows a "severity escalated since ack" annotation prominently. Human re-reviews.

3. Glob support for `contract_path_glob`. Useful for multi-contract repos, but adds complexity. Defer to v1.1 unless real users hit the case.
