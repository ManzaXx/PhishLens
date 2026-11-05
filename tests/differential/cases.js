// Correos que dos programas de correo podrían leer de forma distinta (spec 2.2, §8.3).
// Cada caso dice qué decide PhishLens y qué hallazgo deja para que la ambigüedad no pase en silencio.
const CRLF = (lines) => lines.join('\r\n');

export const CASES = [
  {
    name: 'Content-Type duplicado',
    eml: CRLF(['From: a@b.test', 'Content-Type: text/plain', 'Content-Type: text/html', '', '<b>hola</b> https://x.test/']),
    decision: 'PhishLens usa el primer Content-Type (text/plain); otro cliente podría pintar el HTML.',
    expect: ['mime.duplicate-content-type'],
    check: (email) => email.text.includes('<b>hola</b>') && email.html === '',
  },
  {
    name: 'Boundary repetido en dos niveles',
    eml: CRLF([
      'From: a@b.test', 'Content-Type: multipart/mixed; boundary="X"', '',
      '--X', 'Content-Type: multipart/alternative; boundary="X"', '',
      '--X', 'Content-Type: text/plain', '', 'interior', '--X--', '--X--', '']),
    decision: 'PhishLens corta por el boundary del nivel exterior; la parte interior se lee como un multipart vacío.',
    expect: ['mime.boundary-reuse'],
    check: () => true,
  },
  {
    name: 'Charset contradictorio',
    eml: CRLF([
      'From: a@b.test', 'Content-Type: text/html; charset=iso-8859-1', '',
      '<html><head><meta charset="utf-8"></head><body>hola</body></html>']),
    decision: 'PhishLens usa el charset de la cabecera MIME; el navegador del cliente podría hacer caso al <meta>.',
    expect: ['mime.charset-conflict'],
    check: (email) => email.html.includes('hola'),
  },
  {
    name: 'message/rfc822 anidado',
    eml: CRLF([
      'From: a@b.test', 'Content-Type: multipart/mixed; boundary="b"', '',
      '--b', 'Content-Type: text/plain', '', 'mira el reenviado', '--b',
      'Content-Type: message/rfc822', '', 'From: x@evil.test', 'Subject: dentro', '', 'https://evil.test/login', '--b--', '']),
    decision: 'PhishLens no analiza el correo de dentro como uno aparte: lo avisa para que se analice por separado.',
    expect: ['mime.nested-message'],
    check: (email) => !email.links.some((l) => l.href.includes('evil.test')),
  },
  {
    name: 'Cabecera sin dos puntos',
    eml: CRLF(['From: a@b.test', 'Subject: hola', 'X-Rara sin dos puntos', 'Reply-To: c@d.test', '', 'cuerpo']),
    decision: 'PhishLens ignora la línea y sigue leyendo cabeceras; algún cliente daría por terminadas las cabeceras ahí.',
    expect: ['mime.header-without-colon'],
    check: (email) => email.replyTo?.address === 'c@d.test',
  },
  {
    name: 'Boundary dentro del contenido',
    eml: CRLF([
      'From: a@b.test', 'Content-Type: multipart/mixed; boundary="b"', '',
      '--b', 'Content-Type: text/plain', '', 'texto con --b en medio de la línea https://ok.test/', '--b--', '']),
    decision: 'PhishLens solo corta por el boundary al principio de una línea, como dice RFC 2046.',
    expect: ['mime.boundary-in-content'],
    check: (email) => email.text.includes('--b en medio'),
  },
  {
    name: 'Multipart sin cierre',
    eml: CRLF(['From: a@b.test', 'Content-Type: multipart/mixed; boundary="b"', '', '--b', 'Content-Type: text/plain', '', 'sin cierre']),
    decision: 'PhishLens lee las partes que hay y avisa de que falta el cierre.',
    expect: ['mime.unclosed-multipart'],
    check: (email) => email.text.includes('sin cierre'),
  },
];
