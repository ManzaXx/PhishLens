// Vista «Campañas» y aviso del modo sencillo (spec 2.3, §5.2).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll, tag } from '../helpers/dom.js';
import { BATCHES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeBatch } from '../../src/core/batch.js';
import { buildGraph } from '../../src/intel/graph.js';
import { findCampaigns } from '../../src/intel/campaigns.js';

let dom;
let campaignsPanel;
let renderSimple;
let batch;
const makeBatch = (entries) => ({ entries, skipped: [], graph: buildGraph(entries), campaigns: findCampaigns(entries), current: entries[0].key });
before(async () => {
  dom = installDom();
  globalThis.matchMedia = () => ({ matches: true });
  ({ campaignsPanel } = await import('../../src/ui/panels/campaigns.js'));
  ({ renderSimple } = await import('../../src/ui/views/simple.js'));
  const files = BATCHES[0].files.map((f) => ({ name: f.split('/').pop(), size: 1, text: async () => SAMPLE_TEXTS[f] }));
  batch = makeBatch((await analyzeBatch(files, { yieldFn: async () => {} })).entries);
});
after(() => dom.restore());

const byAction = (root, action) => findAll(root, (n) => n.getAttribute?.('data-action') === action);

test('una campaña: botón elegido con su resumen y el detalle con correos, pistas, marca y técnicas', () => {
  const panel = campaignsPanel(batch.entries[0].report, { batch });
  const picks = byAction(panel, 'pick-campaign');
  assert.equal(picks.length, 1);
  assert.equal(picks[0].getAttribute('aria-current'), 'true');
  assert.equal(picks[0].textContent, 'Campaña 1 · 4 correos · Phishing casi seguro');
  const emails = byAction(panel, 'pick-email');
  assert.equal(emails.length, 4);
  assert.deepEqual(emails.map((b) => b.getAttribute('data-key')).sort(), batch.entries.map((e) => e.key).sort());
  const text = panel.textContent;
  assert.ok(text.includes('Mismo dominio de envío: correos-envios[.]test'));
  assert.ok(text.includes('Misma IP de entrada: 203[.]0[.]113[.]7'));
  assert.ok(text.includes('Mismo adjunto: aviso-entrega.pdf (SHA-256 '));
  assert.match(text, /Misma plantilla: \d+ % parecida/);
  assert.ok(text.includes('Marca que suplanta'));
  assert.ok(text.includes('Correos'));
  assert.ok(text.includes('Técnicas ATT&CK'));
  assert.ok(text.includes('T1204 · User Execution'));
});

test('lote sin campañas: estado vacío', () => {
  const entries = batch.entries.map((e, i) => ({ ...e, report: { ...e.report, level: i ? 'safe' : e.report.level } }));
  const panel = campaignsPanel(entries[0].report, { batch: makeBatch(entries) });
  assert.ok(panel.textContent.includes('Sin campañas'));
  assert.ok(panel.textContent.includes('Ningún correo del lote comparte infraestructura, adjuntos ni plantilla.'));
});

test('campaña elegida que ya no existe: se vuelve a la primera', () => {
  const panel = campaignsPanel(batch.entries[0].report, { batch, campaign: 'campaign:nada' });
  assert.equal(byAction(panel, 'pick-campaign')[0].getAttribute('aria-current'), 'true');
});

test('modo sencillo: aviso de campaña solo con lote', () => {
  const report = batch.entries[0].report;
  const withBatch = renderSimple(report, { batch });
  assert.ok(withBatch.textContent.includes('Este correo forma parte de la Campaña 1, con 3 correos más del lote que comparten remitente, adjunto o plantilla.'));
  assert.equal(byAction(withBatch, 'view-campaign').length, 1);
  assert.ok(!renderSimple(report).textContent.includes('forma parte de la Campaña'));
});

test('asuntos y nombres hostiles salen como texto revelado', () => {
  const entries = batch.entries.map((e, i) => (i ? e : { ...e, name: 'x\u202E<script>.eml', report: { ...e.report, email: { ...e.report.email, subject: '<script>alert(1)</script>' } } }));
  const panel = campaignsPanel(entries[0].report, { batch: makeBatch(entries) });
  assert.ok(panel.textContent.includes('⟦U+202E⟧<script>.eml'));
  assert.equal(find(panel, tag('script')), null);
});
