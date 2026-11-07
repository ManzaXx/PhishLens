// Vista «URLs» (spec 2.3, §5.3): cadena de saltos desenvuelta, motivos y nada clicable.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, findAll, tag } from '../helpers/dom.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';

let dom;
let urlsPanel;
before(async () => {
  dom = installDom();
  ({ urlsPanel } = await import('../../src/ui/panels/urls.js'));
});
after(() => dom.restore());

const report13 = () => analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS['13-redireccion-anidada'] });
const withLinks = (hrefs) => ({ email: { links: hrefs.map((href) => ({ href, text: href })) }, findings: [], iocs: {} });

test('la muestra 13: cadena de 3 saltos, motivos y todo defanged, sin un solo enlace', () => {
  const panel = urlsPanel(report13(), {});
  assert.equal(findAll(panel, tag('a')).length, 0);
  const cards = findAll(panel, (n) => n.classList?.contains('url-card'));
  assert.equal(cards.length, 1);
  const hops = findAll(cards[0], (n) => n.localName === 'li' && n.parentNode?.classList?.contains('url-card__hops'));
  assert.equal(hops.length, 3);
  assert.ok(hops[1].textContent.includes('parámetro «url»'));
  assert.ok(hops[2].textContent.includes('base64'));
  const text = panel.textContent;
  assert.ok(text.includes('Destino final'));
  assert.ok(text.includes('hxxps://xk7q2vz9pw4m[.]top:8443/entrega/pago'));
  assert.ok(!/https?:\/\//.test(text), 'queda una URL sin defang');
  for (const reason of ['Salta 2 veces antes de llegar al destino.', 'Usa el puerto 8443, que las webs normales no indican.', 'El nombre del dominio parece escrito al azar.']) {
    assert.ok(text.includes(reason), reason);
  }
});

test('una URL limpia lo dice; IP disfrazada y credenciales tienen su frase', () => {
  const clean = urlsPanel(withLinks(['https://tienda.test/']), {}).textContent;
  assert.ok(clean.includes('Nada raro en la dirección en sí.'));
  const bad = urlsPanel(withLinks(['http://3232235777/', 'https://u:p@bank.test/']), {}).textContent;
  assert.ok(bad.includes('La dirección IP está escrita de forma rara para que no se reconozca.'));
  assert.ok(bad.includes('Lleva un usuario y una contraseña antes del dominio.'));
});

test('150 enlaces: 100 tarjetas, las más sospechosas primero, y lo dice', () => {
  const hrefs = [...Array.from({ length: 149 }, (_, i) => `https://t${String(i).padStart(3, '0')}.test/`), 'http://3232235777/'];
  const panel = urlsPanel(withLinks(hrefs), {});
  const cards = findAll(panel, (n) => n.classList?.contains('url-card'));
  assert.equal(cards.length, 100);
  assert.ok(cards[0].textContent.includes('192[.]168[.]1[.]1'));
  assert.ok(panel.textContent.includes('Se muestran 100 de 150 enlaces, primero los más sospechosos.'));
});

test('enlaces repetidos cuentan una vez; con lote dice en cuántos correos aparece el destino', () => {
  const a = withLinks(['https://pago.test/a', 'https://pago.test/a']);
  assert.equal(findAll(urlsPanel(a, {}), (n) => n.classList?.contains('url-card')).length, 1);
  const b = withLinks(['https://pago.test/b']);
  const batch = { entries: [{ key: 'k1', name: 'a.eml', report: a }, { key: 'k2', name: 'b.eml', report: b }] };
  assert.ok(urlsPanel(a, { batch }).textContent.includes('Aparece en 2 correos del lote.'));
  assert.ok(!urlsPanel(withLinks(['https://otro.test/']), { batch }).textContent.includes('Aparece en'));
});
