import { test } from 'node:test';
import assert from 'node:assert/strict';
import { entetesSecurite } from '../src/http.js';

const entetes = o => { const h = {}; entetesSecurite({ setHeader: (k, v) => { h[k] = v; } }, o); return h; };

test('HSTS : en HTTPS sur un nom, jamais en clair ni sur localhost', () => {
  assert.match(entetes({ secure: true, hote: 'hub.exemple:8100' })['Strict-Transport-Security'], /max-age=63072000; includeSubDomains/);
  assert.match(entetes({ secure: true })['Strict-Transport-Security'], /max-age/, 'sans hôte connu : comme avant');
  assert.equal(entetes({ secure: false, hote: 'hub.exemple' })['Strict-Transport-Security'], undefined);
  for (const h of ['localhost:8100', '127.0.0.1:8100', '[::1]:8100']) assert.equal(entetes({ secure: true, hote: h })['Strict-Transport-Security'], undefined, h);
});
