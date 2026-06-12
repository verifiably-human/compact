/**
 * Annotation parser for in-source audit acknowledgements.
 *
 * Recognises comments of the form:
 *
 *   // @<key>: <tag>
 *   //
 *   // <optional multi-line reason>
 *   export circuit foo(...): T { ... }
 *
 * Each annotation is bound to the NEXT circuit declaration that follows
 * it. The annotation downgrades a specific class of finding from a real
 * "fix this" to an acknowledged design choice. The finding is still
 * emitted (so a reviewer sees it) but severity drops to `info` and the
 * tag + reason are surfaced.
 *
 * Initial keys:
 *   @access-control: <tag>   acknowledges a circuit's authorization model
 *
 * Future keys (placeholders, parser is generic):
 *   @disclose-intent: <tag>  for correlator analysis (phase 3)
 *   @audit-ack:       <id>   for specific reviewed findings
 */

import { CircuitForProfile } from './profile-analyzer.js';

/** Annotation keys recognised by the parser. */
export type AnnotationKey =
  | 'access-control'
  | 'disclose-intent'
  | 'audit-ack';

/** Tags for @access-control annotations. */
export type AccessControlTag =
  | 'intentional-permissionless'  // anyone can call by design
  | 'witness-gated'                // auth via witness data, not source-visible guard
  | 'compliance-gated'             // auth via runComplianceChecks-style internal circuit
  | 'read-only'                    // no real mutation despite appearances
  | 'documented';                  // see contract docstring

export const ACCESS_CONTROL_TAGS: ReadonlySet<string> = new Set([
  'intentional-permissionless',
  'witness-gated',
  'compliance-gated',
  'read-only',
  'documented',
]);

export interface CircuitAnnotation {
  key: AnnotationKey;
  tag: string;            // not yet narrowed to enum; consumer enforces
  reason: string;         // free-text reason from the trailing comment lines
  line: number;           // source line of the annotation
  tagKnown: boolean;      // false for unrecognised tags (still parsed, not honoured)
}

/** Map from circuit name → annotations attached to that circuit. */
export type CircuitAnnotationMap = Map<string, CircuitAnnotation[]>;

/**
 * Parse all annotations in the contract source and bind them to the
 * next circuit declaration that follows.
 *
 * The binding rule: an annotation block (one or more consecutive
 * `// @key: tag` and `//` continuation lines, allowing blank lines
 * between) attaches to the FIRST circuit declared after the block,
 * provided no other top-level declaration intervenes.
 */
export function parseAnnotations(
  contractSource: string,
  circuits: CircuitForProfile[],
): CircuitAnnotationMap {
  const result: CircuitAnnotationMap = new Map();
  const lines = contractSource.split('\n');

  // Precompute, for each circuit, the source line of its declaration.
  const circuitLines = new Map<string, number>();
  for (const c of circuits) {
    const decl = new RegExp(`(?:export\\s+)?circuit\\s+${c.name}\\b`);
    for (let i = 0; i < lines.length; i++) {
      if (decl.test(lines[i])) {
        circuitLines.set(c.name, i);
        break;
      }
    }
  }

  // Walk the source line by line. When we find an annotation comment,
  // collect the contiguous annotation block (including reason lines),
  // then attach it to the first circuit whose declaration line is
  // greater than the block-end line, provided no non-comment, non-blank
  // line intervenes.
  let i = 0;
  while (i < lines.length) {
    const annoMatch = matchAnnotationLine(lines[i]);
    if (!annoMatch) {
      i++;
      continue;
    }

    const annoLine = i;
    const { key, tag } = annoMatch;
    const reasonParts: string[] = [];

    let j = i + 1;
    while (j < lines.length) {
      const l = lines[j];
      if (matchAnnotationLine(l)) break; // start of a new annotation block
      const reason = matchContinuationComment(l);
      if (reason === null) break; // not a comment-continuation line
      if (reason.length > 0) reasonParts.push(reason);
      j++;
    }

    // Walk forward from j to find the bound circuit. Skip blank lines
    // and other comments. Stop on any other declaration (witness, ledger,
    // constructor) — annotations are circuit-scoped only.
    let bound: string | null = null;
    for (let k = j; k < lines.length; k++) {
      const line = lines[k];
      if (/^\s*$/.test(line) || /^\s*\/\//.test(line) || /^\s*\/\*/.test(line)) {
        continue;
      }
      const circuitDecl = /^(?:export\s+)?circuit\s+(\w+)/.exec(line);
      if (circuitDecl) {
        bound = circuitDecl[1];
        break;
      }
      // Some other top-level form intervenes — annotation is orphaned.
      break;
    }

    if (bound) {
      const tagKnown = key === 'access-control'
        ? ACCESS_CONTROL_TAGS.has(tag)
        : true; // other keys: any tag accepted for now
      const annotation: CircuitAnnotation = {
        key,
        tag,
        reason: reasonParts.join(' ').trim(),
        line: annoLine + 1,
        tagKnown,
      };
      const arr = result.get(bound) ?? [];
      arr.push(annotation);
      result.set(bound, arr);
    }

    i = j;
  }

  return result;
}

/**
 * Match a comment line that starts an annotation block:
 *   // @key: tag
 * Returns { key, tag } or null.
 */
function matchAnnotationLine(line: string): { key: AnnotationKey; tag: string } | null {
  const m = /^\s*\/\/\s*@(access-control|disclose-intent|audit-ack)\s*:\s*(\S+)/.exec(line);
  if (!m) return null;
  return { key: m[1] as AnnotationKey, tag: m[2] };
}

/**
 * Match a continuation comment line (starts with //). Returns the text
 * after the // (possibly empty), or null if the line is not a comment.
 */
function matchContinuationComment(line: string): string | null {
  const m = /^\s*\/\/\s?(.*)$/.exec(line);
  if (!m) return null;
  return m[1];
}

/**
 * Convenience: look up the first annotation of a given key for a circuit.
 */
export function findAnnotation(
  map: CircuitAnnotationMap,
  circuitName: string,
  key: AnnotationKey,
): CircuitAnnotation | null {
  const arr = map.get(circuitName);
  if (!arr) return null;
  return arr.find(a => a.key === key) ?? null;
}
