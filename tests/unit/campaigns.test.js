import { test } from 'node:test';
import assert from 'node:assert/strict';
import { kitOf, similarity, KIT_THRESHOLD } from '../../src/intel/kit.js';
import { findCampaigns } from '../../src/intel/campaigns.js';
import { analyzeInput } from '../../src/core/engine.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { entry, shuffle } from '../helpers/batch.js';

const template = (name, amount, link) => `Estimado ${name}, su paquete con número de seguimiento ES${amount}88 está retenido en nuestra oficina de distribución.
Para recibirlo debe abonar ${amount},99 EUR de gastos de aduana antes de 48 horas o será devuelto al remitente.
Pulse aquí para pagar: ${link} y confirme su dirección de entrega. Gracias por confiar en nuestro servicio de envíos.`;

const report = (id) => analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id] });

test('kit: la misma plantilla con otro nombre, importe y enlace se parece; plantillas distintas no', () => {
  const a = kitOf({ email: { subject: 'Su paquete está retenido', text: template('Ana', 2, 'https://a.test/x') } });
  const b = kitOf({ email: { subject: 'RE: Su paquete está retenido', text: template('Luis Pérez', 7, 'https://b.test/y?id=9') } });
  assert.equal(KIT_THRESHOLD, 0.6);
  assert.ok(similarity(a, b) >= 0.6, `similitud ${similarity(a, b)}`);
  assert.ok(similarity(kitOf(report('03-phishing-banco')), kitOf(report('05-phishing-microsoft365'))) < 0.6);
  const short = kitOf({ email: { subject: '', text: 'hola qué tal estás hoy' } });
  assert.equal(similarity(short, short), 0);
});

const keysOf = (c) => c.emails;

test('cadena: A–B por dominio de envío y B–C por hash dan una campaña de 3 con dos pistas', () => {
  const h = 'a'.repeat(64);
  const list = [
    entry({ key: 'A', email: { from: { address: 'x@evil.test' } } }),
    entry({ key: 'B', email: { from: { address: 'y@evil.test' }, attachments: [{ filename: 'f.zip', sha256: h }] } }),
    entry({ key: 'C', email: { from: { address: 'z@otro.test' }, attachments: [{ filename: 'g.zip', sha256: h }] } }),
  ];
  const [c, ...rest] = findCampaigns(list);
  assert.equal(rest.length, 0);
  assert.deepEqual(keysOf(c), ['A', 'B', 'C']);
  assert.equal(c.name, 'Campaña 1');
  assert.match(c.id, /^campaign:[0-9a-f]{16}$/);
  assert.deepEqual(c.reasons, [
    { kind: 'hash', type: 'sha256', value: h, emails: ['B', 'C'] },
    { kind: 'infra', type: 'sender-domain', value: 'evil.test', emails: ['A', 'B'] },
  ]);
});

test('proveedores grandes y correos legítimos no forman campaña', () => {
  const none = (list) => assert.deepEqual(findCampaigns(list), []);
  none([
    entry({ email: { from: { address: 'a@gmail.com' } } }),
    entry({ email: { from: { address: 'b@gmail.com' } } }),
  ]);
  none([
    entry({ email: { from: { address: 'a@uno.test' }, links: [{ href: 'https://www.microsoft.com/es' }, { href: 'https://bit.ly/abc' }] } }),
    entry({ email: { from: { address: 'b@dos.test' }, links: [{ href: 'https://microsoft.com/' }, { href: 'https://bit.ly/zzz' }] } }),
  ]);
  none([
    entry({ level: 'safe', email: { from: { address: 'a@tienda.test' } } }),
    entry({ level: 'safe', email: { from: { address: 'b@tienda.test' } } }),
  ]);
});

test('IP de entrada y dominio de enlace también unen; la marca, las técnicas y el nivel salen de los correos', () => {
  const brand = { name: 'Correos', domains: ['correos.es'] };
  const list = [
    entry({ key: 'P', level: 'suspicious', findings: [{ brand }], techniques: [{ id: 'T1566.002', name: 'Spearphishing Link' }],
      email: { from: { address: 'p@a.test' }, route: [{ ip: '203.0.113.7', entry: true }] } }),
    entry({ key: 'Q', level: 'critical', findings: [{ brand: null }], techniques: [{ id: 'T1204.001', name: 'Malicious Link' }, { id: 'T1566.002', name: 'Spearphishing Link' }],
      email: { from: { address: 'q@b.test' }, route: [{ ip: '203.0.113.7', entry: true }], links: [{ href: 'https://pago.kit.test/x' }] } }),
    entry({ key: 'R', level: 'phishing', email: { from: { address: 'r@c.test' }, links: [{ href: 'https://otra.kit.test/y' }] } }),
  ];
  const [c] = findCampaigns(list);
  assert.deepEqual(c.emails, ['P', 'Q', 'R']);
  assert.deepEqual(c.reasons.map((r) => `${r.type}:${r.value}`), ['entry-ip:203.0.113.7', 'link-domain:kit.test']);
  assert.deepEqual(c.brands, ['Correos']);
  assert.deepEqual(c.techniques.map((t) => t.id), ['T1204.001', 'T1566.002']);
  assert.equal(c.level, 'critical');
});

test('kit: dos correos de la misma plantilla sin nada más en común forman campaña con su similitud', () => {
  const list = [
    entry({ key: 'K1', email: { from: { address: 'a@uno.test' }, subject: 'Su paquete está retenido', text: template('Ana', 2, 'https://a.test/x') } }),
    entry({ key: 'K2', email: { from: { address: 'b@dos.test' }, subject: 'Su paquete está retenido', text: template('Luis', 7, 'https://b.test/y') } }),
  ];
  const [c] = findCampaigns(list);
  assert.equal(c.reasons.length, 1);
  assert.equal(c.reasons[0].kind, 'kit');
  assert.match(c.reasons[0].value, /^(0\.[6-9]\d|1\.00)$/);
  assert.deepEqual(c.reasons[0].emails, ['K1', 'K2']);
});

test('varias campañas: la más grande primero; propiedad: el orden no cambia el resultado', () => {
  const list = [
    entry({ key: 'a1', email: { from: { address: 'x@uno.test' } } }),
    entry({ key: 'a2', email: { from: { address: 'y@uno.test' } } }),
    entry({ key: 'b1', email: { from: { address: 'x@dos.test' } } }),
    entry({ key: 'b2', email: { from: { address: 'y@dos.test' } } }),
    entry({ key: 'b3', email: { from: { address: 'z@dos.test' } } }),
    entry({ key: 'solo', email: { from: { address: 'z@tres.test' } } }),
  ];
  const base = findCampaigns(list);
  assert.deepEqual(base.map((c) => [c.name, c.emails.length]), [['Campaña 1', 3], ['Campaña 2', 2]]);
  for (let seed = 1; seed <= 20; seed++) assert.deepEqual(findCampaigns(shuffle(list, seed)), base);
});
