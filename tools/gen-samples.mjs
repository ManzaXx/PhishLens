// Genera samples/data.js con el texto de cada muestra, para que la página no tenga que pedirlas por red
// (la CSP lleva connect-src 'none'). Uso: npm run samples. tests/unit/samples.test.js comprueba que está al día.
// También escribe las muestras 11 y 12, cuyos adjuntos se construyen byte a byte: son inofensivos
// (una cabecera PE sin código, un PDF con un app.alert y un ZIP sin datos), pero tienen la forma real.
import { readFileSync, writeFileSync } from 'node:fs';
import { SAMPLES } from '../samples/index.js';
import { makeZip } from '../tests/helpers/files.js';

const dir = new URL('../samples/', import.meta.url);
const b64 = (bytes) => Buffer.from(bytes).toString('base64').replace(/.{76}/g, '$&\n');
const enc = (s) => new TextEncoder().encode(s);

/** Cabecera PE mínima sin una sola instrucción: basta para que el tipo real sea «ejecutable». */
function fakePe() {
  const b = new Uint8Array(0x100);
  b.set(enc('MZ'), 0);
  b.set([0x80, 0, 0, 0], 0x3c);
  b.set(enc('PhishLens: muestra inofensiva, sin codigo.'), 0x40);
  b.set(enc('PE\0\0'), 0x80);
  b.set([0x4c, 0x01], 0x84);
  return b;
}

const activePdf = () => enc([
  '%PDF-1.7',
  '1 0 obj << /Type /Catalog /Pages 3 0 R /OpenAction 2 0 R >> endobj',
  "2 0 obj << /S /JavaScript /JS (app.alert\\('PhishLens: muestra inofensiva'\\)) >> endobj",
  '3 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj',
  'trailer << /Root 1 0 R >>',
  '%%EOF',
].join('\n'));

const part = (boundary, name, type, bytes) => [
  `--${boundary}`, `Content-Type: ${type}; name="${name}"`, `Content-Disposition: attachment; filename="${name}"`,
  'Content-Transfer-Encoding: base64', '', b64(bytes), '',
].join('\n');

const GENERATED = {
  '11-adjunto-tipo-falso.eml': [
    'Authentication-Results: mx.example.com;',
    ' spf=fail smtp.mailfrom=envios-paqueteria.test;',
    ' dkim=none;',
    ' dmarc=fail header.from=envios-paqueteria.test',
    'Received: from envios-paqueteria.test (unknown [203.0.113.77]) by mx.example.com; Thu, 05 Nov 2026 08:41:10 +0100',
    'Return-Path: <no-reply@envios-paqueteria.test>',
    'From: "Administración" <administracion@envios-paqueteria.test>',
    'To: pablo@example.com',
    'Subject: Factura pendiente de pago - último aviso',
    'Date: Thu, 05 Nov 2026 08:41:00 +0100',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="tf-11"',
    '',
    '--tf-11',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Hola:',
    '',
    'Le adjuntamos la factura pendiente. Ábrala hoy mismo para evitar el corte del servicio',
    'y un recargo del 20 %. Es urgente.',
    '',
    'Administración',
    '',
    part('tf-11', 'factura.pdf', 'application/pdf', fakePe()),
    '--tf-11--',
    '',
  ].join('\n'),
  '12-pdf-activo-zip.eml': [
    'Authentication-Results: mx.example.com;',
    ' spf=fail smtp.mailfrom=notificaciones-hacienda.test;',
    ' dkim=fail header.d=notificaciones-hacienda.test;',
    ' dmarc=fail header.from=notificaciones-hacienda.test',
    'Received: from notificaciones-hacienda.test (unknown [198.51.100.23]) by mx.example.com; Thu, 05 Nov 2026 10:02:44 +0100',
    'Return-Path: <rebotes@envio-masivo.test>',
    'From: "Agencia Tributaria" <avisos@notificaciones-hacienda.test>',
    'Reply-To: devoluciones@gestoria-rapida.test',
    'To: pablo@example.com',
    'Subject: Notificación urgente: devolución pendiente',
    'Date: Thu, 05 Nov 2026 10:02:30 +0100',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="pz-12"',
    '',
    '--pz-12',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Estimado contribuyente:',
    '',
    'Tiene una devolución pendiente. Abra el aviso adjunto y confirme sus datos bancarios',
    'en las próximas 24 horas o perderá el derecho a la devolución.',
    'La contraseña del archivo documentos.zip es 1234.',
    '',
    part('pz-12', 'aviso.pdf', 'application/pdf', activePdf()),
    part('pz-12', 'documentos.zip', 'application/zip', makeZip([{ name: 'Factura_0193.pdf.exe', encrypted: true, size: 48213 }])),
    '--pz-12--',
    '',
  ].join('\n'),
};
for (const [file, text] of Object.entries(GENERATED)) writeFileSync(new URL(file, dir), text);

const entries = SAMPLES.map((s) => `  ${JSON.stringify(s.id)}: ${JSON.stringify(readFileSync(new URL(s.file, dir), 'utf8'))},`);
writeFileSync(new URL('data.js', dir), `// Generado por tools/gen-samples.mjs a partir de los .eml de esta carpeta. No editar a mano.
export const SAMPLE_TEXTS = Object.freeze({
${entries.join('\n')}
});
`);
