// Genera samples/data.js con el texto de cada muestra, para que la página no tenga que pedirlas por red
// (la CSP lleva connect-src 'none'). Uso: npm run samples. tests/unit/samples.test.js comprueba que está al día.
// También escribe las muestras 11 y 12, cuyos adjuntos se construyen byte a byte: son inofensivos
// (una cabecera PE sin código, un PDF con un app.alert y un ZIP sin datos), pero tienen la forma real.
import { readFileSync, writeFileSync } from 'node:fs';
import { mkdirSync } from 'node:fs';
import { SAMPLES, BATCHES } from '../samples/index.js';
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

// Lote de campaña (spec 2.3, §7): cuatro falsos avisos de «Correos» que se unen por pistas distintas.
// 1 y 2 salen del mismo dominio y la misma IP; 2 y 3 llevan el mismo PDF; 3 y 4 son la misma plantilla.
const noticePdf = () => enc([
  '%PDF-1.4',
  '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj',
  '2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj',
  '% PhishLens: muestra inofensiva, sin contenido activo.',
  'trailer << /Root 1 0 R >>',
  '%%EOF',
].join('\n'));

const customs = (name, ref, amount) => [
  `Estimado ${name}:`,
  '',
  `Su paquete con número de seguimiento ${ref} está retenido en nuestra oficina de distribución`,
  `por gastos de aduana pendientes. Para recibirlo debe abonar ${amount} EUR antes de 48 horas`,
  'o será devuelto al remitente. Pulse en el enlace para pagar y confirme su dirección de entrega.',
  '',
  'Gracias por confiar en nuestro servicio de envíos.',
];

const lotEmail = ({ domain, ip, from, subject, date, boundary, body, link, attachment }) => [
  'Authentication-Results: mx.example.com;',
  ` spf=fail smtp.mailfrom=${domain};`,
  ' dkim=none;',
  ` dmarc=fail header.from=${domain}`,
  `Received: from ${domain} (unknown [${ip}]) by mx.example.com; ${date}`,
  `Return-Path: <rebotes@${domain}>`,
  `From: "Correos" <${from}@${domain}>`,
  'To: pablo@example.com',
  `Subject: ${subject}`,
  `Date: ${date}`,
  'MIME-Version: 1.0',
  `Content-Type: multipart/mixed; boundary="${boundary}"`,
  '',
  `--${boundary}`,
  'Content-Type: text/plain; charset=utf-8',
  '',
  ...body,
  ...(link ? ['', link] : []),
  '',
  ...(attachment ? [part(boundary, 'aviso-entrega.pdf', 'application/pdf', noticePdf())] : []),
  `--${boundary}--`,
  '',
].join('\n');

const LOT = {
  'lote-campana/1-entrega-fallida.eml': lotEmail({
    domain: 'correos-envios.test', ip: '203.0.113.7', from: 'avisos', boundary: 'lc-1',
    subject: 'Su envío no ha podido ser entregado', date: 'Mon, 02 Nov 2026 09:12:00 +0100',
    body: ['Hola:', '', 'Hemos intentado entregar su envío pero faltan 1,99 EUR de franqueo.', 'Abone el importe hoy mismo para programar una nueva entrega.'],
    link: 'https://pago-correos-envios.test/franqueo?id=55102',
  }),
  'lote-campana/2-aviso-adjunto.eml': lotEmail({
    domain: 'correos-envios.test', ip: '203.0.113.7', from: 'notificaciones', boundary: 'lc-2',
    subject: 'Aviso de llegada de su paquete', date: 'Tue, 03 Nov 2026 11:40:00 +0100',
    body: ['Buenos días:', '', 'Le enviamos el aviso de llegada de su paquete.', 'Imprímalo y preséntelo en su oficina en un plazo de 3 días.'],
    attachment: true,
  }),
  'lote-campana/3-aduana-retenido.eml': lotEmail({
    domain: 'seguimiento-paquete.test', ip: '198.51.100.40', from: 'aduanas', boundary: 'lc-3',
    subject: 'Su paquete está retenido en aduana', date: 'Wed, 04 Nov 2026 16:05:00 +0100',
    body: customs('Ana', 'ES20488172', '2,99'), link: 'https://aduana-pago.test/pagar?ref=ES20488172', attachment: true,
  }),
  'lote-campana/4-aduana-recordatorio.eml': lotEmail({
    domain: 'aduana-envio.test', ip: '192.0.2.91', from: 'clientes', boundary: 'lc-4',
    subject: 'RE: Su paquete está retenido en aduana', date: 'Thu, 05 Nov 2026 08:20:00 +0100',
    body: customs('Luis Pérez', 'ES77310094', '3,49'), link: 'https://pago-aduanas-es.test/p?ref=ES77310094',
  }),
};
mkdirSync(new URL('lote-campana/', dir), { recursive: true });
for (const [file, text] of Object.entries(LOT)) writeFileSync(new URL(file, dir), text);

const entries = [
  ...SAMPLES.map((s) => [s.id, s.file]),
  ...BATCHES.flatMap((b) => b.files.map((f) => [f, f])),
].map(([id, file]) => `  ${JSON.stringify(id)}: ${JSON.stringify(readFileSync(new URL(file, dir), 'utf8'))},`);
writeFileSync(new URL('data.js', dir), `// Generado por tools/gen-samples.mjs a partir de los .eml de esta carpeta. No editar a mano.
export const SAMPLE_TEXTS = Object.freeze({
${entries.join('\n')}
});
`);
