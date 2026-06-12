/**
 * Correlator analyzer (phase 3).
 *
 * Joins the compiler's witness-disclosure records to surface
 * cross-circuit linkability candidates. The compiler's
 * `security-analysis.json` already tells us every disclose() with
 * its witness origin and data-flow path; the correlator detector
 * groups those entries by origin and looks for pairs/sets where:
 *
 *   - The same witness flows to disclose sites in 2+ circuits.
 *   - The disclosures have similar exposure shape (same
 *     final_exposure, no per-call blinder visible in the path).
 *
 * The detector is a prompt for human review. Many contracts emit
 * deliberate correlators (regulator anchors, dedupe keys, public
 * identity proofs). The `@disclose-intent: <tag>` annotation
 * downgrades the finding to info when the contract author
 * acknowledges the linkability is intentional.
 */

import { createHash } from 'crypto';
import {
  CompilerSecurityAnalysis,
  Disclosure,
  Origin as CompilerOrigin,
  Path as CompilerPath,
  Point as CompilerPoint,
  SrcLoc as CompilerSrcLoc,
} from './compiler-security-reader.js';
import {
  CircuitAnnotationMap,
  findAnnotation,
} from './annotation-parser.js';
import {
  Correlator,
  CorrelatorAnalysis,
  CorrelatorOrigin,
  DISCLOSE_INTENT_TAGS,
  ExposureStructure,
  IntentCheck,
  LinkedDisclosureSite,
  SourceLocation,
} from './types.js';

const BLINDER_NAME_PATTERNS = [/nonce/i, /salt/i, /blinder/i, /random/i, /seed/i];

export interface CorrelatorAnalyzerInput {
  compilerAnalysis: CompilerSecurityAnalysis;
  // Map from circuit name → annotations attached to that circuit.
  // Used to honor @disclose-intent acknowledgements.
  annotations: CircuitAnnotationMap;
  // List of all circuits in the contract, used to identify which
  // circuit each disclose site lives in.
  circuits: { name: string; bodyStartLine?: number; bodyEndLine?: number }[];
}

export class CorrelatorAnalyzer {
  private input: CorrelatorAnalyzerInput;

  constructor(input: CorrelatorAnalyzerInput) {
    this.input = input;
  }

  analyze(): CorrelatorAnalysis {
    const findings = this.detectCorrelators();
    return {
      schemaVersion: '1.0.0',
      findings,
    };
  }

  private detectCorrelators(): Correlator[] {
    // Group disclosures by origin-key. Each disclosure entry may carry
    // multiple witnesses; we treat each (witness, disclosure) pair as a
    // distinct site, since the origin is per-witness.
    type Site = {
      originKey: string;
      origin: CompilerOrigin;
      path: CompilerPath;
      discloseIndex: number;
      siteLocation: CompilerSrcLoc;
    };
    const sites: Site[] = [];
    this.input.compilerAnalysis.disclosures.forEach((d, i) => {
      for (const w of d.witnesses) {
        for (const path of w.paths) {
          sites.push({
            originKey: this.originKey(w.origin),
            origin: w.origin,
            path,
            discloseIndex: i,
            siteLocation: d.location,
          });
        }
      }
    });

    const groups = new Map<string, Site[]>();
    for (const s of sites) {
      const arr = groups.get(s.originKey) ?? [];
      arr.push(s);
      groups.set(s.originKey, arr);
    }

    const findings: Correlator[] = [];
    for (const [originKey, group] of groups) {
      if (group.length < 2) continue;

      // Determine which circuits these sites live in. We approximate
      // the bound circuit by scanning the input.circuits list for the
      // name that contains the disclose-site line. If we can't bind a
      // site to a circuit (e.g., the disclose is in a constructor),
      // we still record the file/line.
      const linkedSites: LinkedDisclosureSite[] = group.map(s => {
        const loc = this.toSourceLocation(s.siteLocation);
        const circuit = this.circuitForLine(loc.line) ?? '(unbound)';
        return {
          circuit,
          location: loc,
          finalExposure: s.path.final_exposure,
          compilerDiscloseIndex: s.discloseIndex,
        };
      });

      // Deduplicate: if every site lives in the same circuit, it's
      // not a cross-circuit correlator — same circuit's multiple
      // disclosures of the same origin are noise unless we have a
      // story for "same circuit = correlatable across invocations."
      // We require sites to span 2+ distinct circuits.
      const distinctCircuits = new Set(linkedSites.map(s => s.circuit));
      if (distinctCircuits.size < 2) continue;

      // Exposure structure analysis.
      const exposureStructure = this.analyzeExposure(group.map(g => g.path));

      // If a blinder is present on every path, the linkability is
      // weakened — observers can't directly correlate on the hash
      // value. We still surface as info-severity because the witness
      // origin is shared, but downgrade.
      const baseSeverity: Correlator['severity'] = exposureStructure.blinderPresent
        ? 'info'
        : exposureStructure.sameFinalExposure
          ? 'high'
          : 'medium';

      // Annotation check: did any of the involved circuits carry a
      // @disclose-intent acknowledgement? If so, downgrade to info.
      const intentCheck = this.checkIntent(linkedSites);

      const severity = intentCheck.annotationPresent
        ? 'info'
        : baseSeverity;

      const origin = this.toCorrelatorOrigin(group[0].origin);
      const id = this.makeId(originKey, linkedSites);

      const linkabilitySummary = this.buildSummary(
        origin,
        linkedSites,
        exposureStructure,
        intentCheck,
      );

      const recommendation = intentCheck.annotationPresent
        ? `Acknowledged via \`// @disclose-intent: ${intentCheck.annotationTag}\`. Reviewer confirms the linkability is intentional. No code change needed.`
        : exposureStructure.blinderPresent
          ? `A per-event blinder appears in the disclosure path, so direct hash-value correlation is unlikely. Still, the witness origin is shared across circuits — confirm that no other side channel (transaction timing, public state coupling) enables cross-event linkage. If correlation is intentional, add \`// @disclose-intent: intentional-correlator\` above the affected circuits.`
          : `The same witness flows to disclose sites in ${distinctCircuits.size} circuits without a per-event blinder. An observer who can hash a candidate witness value can correlate every event from the same source. Either (a) add a per-event nonce to the hash and persist it for openings, or (b) annotate the affected circuits with \`// @disclose-intent: <tag>\` if the linkability is intentional (regulator anchor, dedupe key, identity proof).`;

      findings.push({
        id,
        severity,
        witnessOrigin: origin,
        linkedDisclosureSites: linkedSites,
        exposureStructure,
        linkabilitySummary,
        intentCheck,
        recommendation,
        autoDismissible: intentCheck.annotationPresent,
      });
    }

    // Stable order: by severity (critical first), then by id.
    const severityRank: Record<Correlator['severity'], number> = {
      critical: 0, high: 1, medium: 2, low: 3, info: 4,
    };
    findings.sort((a, b) => {
      const r = severityRank[a.severity] - severityRank[b.severity];
      if (r !== 0) return r;
      return a.id.localeCompare(b.id);
    });

    return findings;
  }

  // -------------------------------------------------------------------------
  // Helpers.
  // -------------------------------------------------------------------------

  private originKey(o: CompilerOrigin): string {
    switch (o.kind) {
      case 'witness-return-value':
        return `witness-return:${o.function}`;
      case 'constructor-argument':
        return `constructor-arg:${o.argument}`;
      case 'circuit-argument':
        // Same argument name across different circuits should still
        // count as the same origin only if it's the same circuit.
        // Cross-circuit correlation for circuit-argument origins is
        // less meaningful unless the same arg is passed everywhere.
        // Key by (function, argument) — only matches if both align.
        return `circuit-arg:${o.function}:${o.argument}`;
    }
  }

  private toCorrelatorOrigin(o: CompilerOrigin): CorrelatorOrigin {
    const location = this.toSourceLocation(o.location);
    switch (o.kind) {
      case 'witness-return-value':
        return { kind: o.kind, function: o.function, location };
      case 'constructor-argument':
        return { kind: o.kind, argument: o.argument, location };
      case 'circuit-argument':
        return {
          kind: o.kind,
          function: o.function,
          argument: o.argument,
          location,
        };
    }
  }

  private toSourceLocation(loc: CompilerSrcLoc): SourceLocation {
    if ('line' in loc && loc.line !== undefined) {
      return { file: loc.file, line: loc.line, column: 'column' in loc ? loc.column : undefined };
    }
    return { file: loc.file };
  }

  private circuitForLine(line: number | undefined): string | null {
    if (line === undefined) return null;
    for (const c of this.input.circuits) {
      if (c.bodyStartLine === undefined || c.bodyEndLine === undefined) continue;
      if (line >= c.bodyStartLine && line <= c.bodyEndLine) return c.name;
    }
    return null;
  }

  private analyzeExposure(paths: CompilerPath[]): ExposureStructure {
    const finals = new Set(paths.map(p => p.final_exposure));
    const sameFinalExposure = finals.size === 1;
    const exposureLabel = paths[0]?.final_exposure ?? '';
    const blinderPresent = paths.some(p =>
      p.points.some(pt => this.pointLooksLikeBlinder(pt)),
    );
    // Stable identifier present is approximated by: at least one path
    // has a point whose description mentions a binding of an arg or
    // a witness call without an obvious blinder name.
    const stableIdentifierPresent = paths.some(p =>
      p.points.some(pt => /binding|argument/.test(pt.description)
                          && !BLINDER_NAME_PATTERNS.some(rp => rp.test(pt.description))),
    );
    return { sameFinalExposure, blinderPresent, stableIdentifierPresent, exposureLabel };
  }

  private pointLooksLikeBlinder(pt: CompilerPoint): boolean {
    if (BLINDER_NAME_PATTERNS.some(p => p.test(pt.description))) return true;
    if (pt.exposure && BLINDER_NAME_PATTERNS.some(p => p.test(pt.exposure!))) return true;
    return false;
  }

  private checkIntent(linkedSites: LinkedDisclosureSite[]): IntentCheck {
    for (const site of linkedSites) {
      const ann = findAnnotation(this.input.annotations, site.circuit, 'disclose-intent');
      if (ann && DISCLOSE_INTENT_TAGS.has(ann.tag)) {
        return {
          docstringSaysCorrelatable: null,
          annotationPresent: true,
          annotationTag: ann.tag,
          annotationReason: ann.reason,
        };
      }
    }
    return {
      docstringSaysCorrelatable: null,
      annotationPresent: false,
    };
  }

  private buildSummary(
    origin: CorrelatorOrigin,
    linkedSites: LinkedDisclosureSite[],
    structure: ExposureStructure,
    intent: IntentCheck,
  ): string {
    const originDesc = origin.kind === 'witness-return-value'
      ? `witness function \`${origin.function}\``
      : origin.kind === 'constructor-argument'
        ? `constructor argument \`${origin.argument}\``
        : `argument \`${origin.argument}\` of circuit \`${origin.function}\``;
    const circuits = [...new Set(linkedSites.map(s => s.circuit))].join(', ');
    const blinderClause = structure.blinderPresent
      ? 'A per-event blinder is present in the disclosure path; direct hash-value correlation is weakened.'
      : 'No per-event blinder is visible in the disclosure path; observers can correlate events by hashing candidate witness values.';
    const intentClause = intent.annotationPresent
      ? ` Acknowledged via \`@disclose-intent: ${intent.annotationTag}\`.`
      : '';
    return (
      `${originDesc} is disclosed in ${linkedSites.length} sites across ${new Set(linkedSites.map(s => s.circuit)).size} circuits ` +
      `(${circuits}) with final exposure "${structure.exposureLabel}". ${blinderClause}${intentClause}`
    );
  }

  private makeId(originKey: string, linkedSites: LinkedDisclosureSite[]): string {
    const siteKey = linkedSites
      .map(s => `${s.circuit}:${s.location.line ?? '?'}:${s.compilerDiscloseIndex}`)
      .sort()
      .join('|');
    const h = createHash('sha256');
    h.update(`${originKey}|${siteKey}`);
    return `corr-${h.digest('hex').slice(0, 12)}`;
  }
}
