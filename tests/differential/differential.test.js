import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEml } from '../../src/parser/eml.js';
import { detect } from '../../src/detectors/mime.js';
import { CASES } from './cases.js';

for (const c of CASES) {
  test(`diferencial: ${c.name}`, () => {
    const email = parseEml(c.eml);
    const ids = detect(email).map((f) => f.id);
    for (const id of c.expect) assert.ok(ids.includes(id), `${c.name}: falta ${id} (hay ${ids.join(', ') || 'nada'})`);
    assert.ok(c.check(email), `${c.name}: no se cumple la decisión «${c.decision}»`);
  });
}

test('las muestras legítimas no dan ningún mime.*', async () => {
  const { readFileSync } = await import('node:fs');
  for (const name of ['01-legitimo-newsletter', '02-legitimo-pedido']) {
    const email = parseEml(readFileSync(new URL(`../../samples/${name}.eml`, import.meta.url), 'utf8'));
    assert.deepEqual(detect(email).map((f) => f.id), [], name);
  }
});

test('un límite alcanzado da un aviso mime.limit informativo', () => {
  const head = Array.from({ length: 1100 }, (_, i) => `X-H${i}: v`).join('\r\n');
  const f = detect(parseEml(`From: a@b.test\r\n${head}\r\n\r\nhola`)).find((x) => x.id === 'mime.limit');
  assert.equal(f?.severity, 'info');
});
