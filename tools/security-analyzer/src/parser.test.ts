/**
 * Tests for the circuit-size reader.
 *
 * Fixtures in test-fixtures/zkir/ were compiled with compactc 0.34.0, and
 * their k values were confirmed against a 9.0.0-rc.7 proof server's /k:
 *   oneVar  (one Jubjub ecMul, ZKIR v2)               k=10
 *   reenc52 (52-point re-randomisation, ZKIR v2)      k=12
 *   secpVar (one secp256k1 ecMul, ZKIR v3)            k=14
 * The previous size x 12 heuristic reported k=15 and k=21 for the first
 * two, and ranked reenc52 above circuits that are larger.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';
import {
  getWarningMessage,
  parseCircuits,
  parseZkirDirectory,
  readZkirMajorVersion,
} from './parser.js';
import type { CircuitMetrics } from './types.js';

const fixtures = fileURLToPath(new URL('../test-fixtures/zkir/', import.meta.url));

async function withProofServer(
  handler: (body: Buffer) => { status: number; body: string },
  run: (url: string, requests: Buffer[]) => Promise<void>
): Promise<void> {
  const requests: Buffer[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      requests.push(body);
      const reply = handler(body);
      res.writeHead(reply.status).end(reply.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await run(`http://127.0.0.1:${port}`, requests);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function byName(circuits: CircuitMetrics[], name: string): CircuitMetrics {
  const circuit = circuits.find((c) => c.name === name);
  assert.ok(circuit, `circuit ${name} missing`);
  return circuit;
}

test('reads the ZKIR major version from the header', () => {
  assert.equal(readZkirMajorVersion(readFileSync(`${fixtures}oneVar.zkir`, 'utf8')), 2);
  assert.equal(readZkirMajorVersion(readFileSync(`${fixtures}secpVar.zkir`, 'utf8')), 3);
  assert.equal(readZkirMajorVersion('not json'), null);
});

test('pairs each .zkir with its .bzkir', () => {
  const files = parseZkirDirectory(fixtures);
  assert.deepEqual(files.map((f) => f.name).sort(), ['oneVar', 'reenc52', 'secpVar']);
  assert.ok(files.every((f) => f.binaryPath?.endsWith('.bzkir')));
});

test('ZKIR v2 k comes from the local package and matches the proof server', async () => {
  const circuits = await parseCircuits(fixtures, { proofServer: undefined });
  const oneVar = byName(circuits, 'oneVar');
  const reenc52 = byName(circuits, 'reenc52');
  assert.deepEqual(
    [oneVar.kValue, oneVar.domainRows, oneVar.kSource, oneVar.zkirVersion],
    [10, 1024, 'zkir-v2', 2]
  );
  assert.deepEqual([reenc52.kValue, reenc52.kSource], [12, 'zkir-v2']);
});

test('ZKIR v3 without a proof server reports k as unknown, with the reason', async () => {
  const saved = process.env.MIDNIGHT_PROOF_SERVER;
  delete process.env.MIDNIGHT_PROOF_SERVER;
  try {
    const secp = byName(await parseCircuits(fixtures), 'secpVar');
    assert.equal(secp.kValue, null);
    assert.equal(secp.domainRows, null);
    assert.equal(secp.kSource, 'unavailable');
    assert.match(secp.kNote ?? '', /zkir-v3 is not installed/);
    assert.match(secp.kNote ?? '', /no proof server configured/);
  } finally {
    if (saved !== undefined) process.env.MIDNIGHT_PROOF_SERVER = saved;
  }
});

test('ZKIR v3 k comes from the proof server, which receives the .bzkir bytes', async () => {
  const bzkir = readFileSync(`${fixtures}secpVar.bzkir`);
  await withProofServer(
    () => ({ status: 200, body: '14' }),
    async (url, requests) => {
      const secp = byName(await parseCircuits(fixtures, { proofServer: `${url}/` }), 'secpVar');
      assert.deepEqual([secp.kValue, secp.domainRows, secp.kSource, secp.zkirVersion], [14, 16384, 'proof-server', 3]);
      // Only the v3 circuit should have gone to the proof server.
      assert.equal(requests.length, 1);
      assert.ok(requests[0].equals(bzkir));
    }
  );
});

test('a proof server error leaves k unknown and records the status', async () => {
  await withProofServer(
    () => ({ status: 400, body: 'unsupported IR version' }),
    async (url) => {
      const secp = byName(await parseCircuits(fixtures, { proofServer: url }), 'secpVar');
      assert.equal(secp.kValue, null);
      assert.match(secp.kNote ?? '', /HTTP 400: unsupported IR version/);
    }
  );
});

test('warns from k, not from an estimate', () => {
  const base: CircuitMetrics = {
    name: 'c',
    zkirVersion: 2,
    kValue: 16,
    domainRows: 65536,
    kSource: 'zkir-v2',
    zkirSize: 0,
  };
  assert.equal(getWarningMessage(base), null);
  assert.match(getWarningMessage({ ...base, kValue: 17, domainRows: 131072 }) ?? '', /k=17 \(up to 131,072 rows\)/);
  assert.equal(getWarningMessage({ ...base, kValue: null, domainRows: null, kSource: 'unavailable' }), null);
});
