import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../../src/lib/limits.js';
import { LIMITS as PARSER_LIMITS } from '../../src/parser/eml.js';

test('límites centralizados con los valores de la 2.2', () => {
  assert.deepEqual({ ...LIMITS }, {
    depth: 20, parts: 500, links: 200, attachments: 100,
    attachmentBytes: 10 * 1024 * 1024, rawBytes: 25 * 1024 * 1024,
  });
  assert.equal(PARSER_LIMITS, LIMITS);
});
