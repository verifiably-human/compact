import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  findAnnotation,
  parseAnnotations,
  ACCESS_CONTROL_TAGS,
} from './annotation-parser.js';

const circuits = (...names: string[]) =>
  names.map(n => ({ name: n, body: '', isExported: true, returnType: '[]' }));

describe('parseAnnotations', () => {
  it('binds @access-control to the next circuit declaration', () => {
    const src = [
      '// @access-control: intentional-permissionless',
      '//',
      '// Demo contract; anyone can call.',
      'export circuit foo(): [] { return; }',
    ].join('\n');
    const map = parseAnnotations(src, circuits('foo'));
    const a = findAnnotation(map, 'foo', 'access-control');
    assert.ok(a, 'expected an annotation on foo');
    assert.equal(a.tag, 'intentional-permissionless');
    assert.equal(a.tagKnown, true);
    assert.match(a.reason, /anyone can call/);
  });

  it('marks unknown tags with tagKnown=false', () => {
    const src = [
      '// @access-control: probably-fine',
      'circuit foo(): [] { return; }',
    ].join('\n');
    const map = parseAnnotations(src, circuits('foo'));
    const a = findAnnotation(map, 'foo', 'access-control');
    assert.ok(a);
    assert.equal(a.tag, 'probably-fine');
    assert.equal(a.tagKnown, false);
  });

  it('accepts the inline export form', () => {
    const src = [
      '// @access-control: witness-gated',
      'export circuit bar(x: Field): Field { return x; }',
    ].join('\n');
    const map = parseAnnotations(src, circuits('bar'));
    assert.ok(findAnnotation(map, 'bar', 'access-control'));
  });

  it('orphans the annotation when a non-circuit form intervenes', () => {
    const src = [
      '// @access-control: documented',
      'witness w(): Field;',
      'circuit qux(): [] { return; }',
    ].join('\n');
    const map = parseAnnotations(src, circuits('qux'));
    assert.equal(map.size, 0, 'annotation should not bind across a witness decl');
  });

  it('allows blank // continuation lines between tag and reason', () => {
    const src = [
      '// @access-control: compliance-gated',
      '//',
      '// First reason paragraph.',
      '//',
      '// Second reason paragraph.',
      'export circuit doIt(): [] { return; }',
    ].join('\n');
    const map = parseAnnotations(src, circuits('doIt'));
    const a = findAnnotation(map, 'doIt', 'access-control')!;
    assert.match(a.reason, /First reason paragraph/);
    assert.match(a.reason, /Second reason paragraph/);
  });

  it('records line numbers for the annotation', () => {
    const src = [
      'pragma language_version >= 0.23;',
      '',
      '// @access-control: read-only',
      'circuit ro(): Field { return 0; }',
    ].join('\n');
    const map = parseAnnotations(src, circuits('ro'));
    const a = findAnnotation(map, 'ro', 'access-control')!;
    assert.equal(a.line, 3);
  });

  it('supports @disclose-intent and @audit-ack keys (forward-compat)', () => {
    const src = [
      '// @disclose-intent: protocol-required',
      '// @audit-ack: corr-abc123def456',
      'circuit foo(): Field { return 0; }',
    ].join('\n');
    const map = parseAnnotations(src, circuits('foo'));
    assert.ok(findAnnotation(map, 'foo', 'disclose-intent'));
    assert.ok(findAnnotation(map, 'foo', 'audit-ack'));
  });

  it('returns empty map when no annotations present', () => {
    const src = 'export circuit foo(): [] { return; }';
    const map = parseAnnotations(src, circuits('foo'));
    assert.equal(map.size, 0);
  });

  it('binds across blank lines and comment-continuation lines', () => {
    const src = [
      '// @access-control: intentional-permissionless',
      '',
      '// This is some other comment after a blank line.',
      'export circuit gap(): [] { return; }',
    ].join('\n');
    const map = parseAnnotations(src, circuits('gap'));
    // Blank lines + plain comments between the annotation block and
    // the circuit decl are allowed; the annotation still binds.
    assert.ok(findAnnotation(map, 'gap', 'access-control'));
  });

  it('exposes the known access-control tag set', () => {
    assert.ok(ACCESS_CONTROL_TAGS.has('intentional-permissionless'));
    assert.ok(ACCESS_CONTROL_TAGS.has('witness-gated'));
    assert.ok(ACCESS_CONTROL_TAGS.has('compliance-gated'));
    assert.ok(ACCESS_CONTROL_TAGS.has('read-only'));
    assert.ok(ACCESS_CONTROL_TAGS.has('documented'));
    assert.equal(ACCESS_CONTROL_TAGS.size, 5);
  });
});
