// Correo realista del tamaño pedido: HTML con enlaces, texto y un adjunto base64 que rellena.
export function buildEmail(bytes) {
  const links = Array.from({ length: 40 }, (_, i) => `<p><a href="https://tienda${i}.example/oferta?id=${i}">Oferta ${i}</a> texto de relleno con urgencia y su cuenta.</p>`).join('\n');
  const head = [
    'Received: from mail.example.org (mail.example.org [198.51.100.7]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org',
    'From: "Tienda" <ofertas@example.org>', 'To: ana@example.com', 'Subject: Ofertas de la semana',
    'Date: Wed, 21 Oct 2026 07:03:00 +0000', 'Message-ID: <perf@example.org>', 'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="perf"',
  ].join('\r\n');
  const html = `--perf\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body>${links}</body></html>\r\n`;
  const fixed = `${head}\r\n\r\n${html}--perf\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename="catalogo.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n`;
  const tail = '\r\n--perf--\r\n';
  const room = Math.max(0, bytes - fixed.length - tail.length);
  const line = `${'QUJD'.repeat(19)}\r\n`; // 76 caracteres base64 + CRLF
  const body = line.repeat(Math.floor(room / line.length));
  return fixed + body + tail;
}

export const SIZES = [
  ['1 KB', 1024],
  ['1 MB', 1024 * 1024],
  ['10 MB', 10 * 1024 * 1024],
  ['25 MB', 25 * 1024 * 1024 - 1024],
];
