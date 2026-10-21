# PhishLens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Analizador de phishing 100 % en el navegador que puntúa un email (.eml / texto / URL) de 0 a 100 con indicadores explicados.

**Architecture:** Motor puro en módulos ES (`src/parser`, `src/detectors`, `src/engine.js`) sin acceso al DOM, testeable con Node; capa `src/ui` que solo pinta con `textContent`. Página estática servida por GitHub Pages.

**Tech Stack:** HTML, CSS, JavaScript ES2022 (módulos ES), `node --test` (Node ≥ 20), GitHub Actions.

**Spec:** `proyectoCiber/docs/specs/2026-10-21-phishlens-design.md`

## Global Constraints

- Sin dependencias de runtime ni de desarrollo; sin paso de compilación. `package.json` solo con `"type": "module"` y el script `test`.
- Ningún dato del email sale del navegador: sin `fetch`, sin analítica. CSP en `index.html`: `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`.
- El contenido del email nunca se inserta con `innerHTML`; los enlaces del email no son clicables.
- Puntos por severidad: info 0, low 5, medium 15, high 30. Nota = min(100, suma). Verde 0–24 "Probablemente legítimo", ámbar 25–59 "Sospechoso", rojo 60–100 "Probable phishing".
- Límite de fichero: 5 MB. Textos de la UI y de los hallazgos en español.
- Todo el código vive en `proyectoCiber/`; los tests se ejecutan con `cd proyectoCiber && node --test`.

## Review Focus

- Email con cabeceras plegadas (línea siguiente empieza por espacio/tab) y asuntos codificados RFC 2047 (`=?UTF-8?B?...?=`): deben decodificarse, no aparecer en crudo.
- Email con saltos de línea `\r\n` (formato real de .eml): el parser debe tratarlo igual que `\n`.
- Email multipart anidado (multipart/mixed > multipart/alternative) con adjunto: debe encontrar texto, HTML y adjunto.
- Dominio legítimo exacto (paypal.com, subdominio www.paypal.com): typosquatting NO debe marcarlo.
- Entrada vacía o basura sin cabeceras: no debe lanzar; debe analizar como texto y avisar.

---

### Task 1: Esqueleto, parser de URLs y CI de tests

**Files:**
- Create: `proyectoCiber/package.json`, `proyectoCiber/src/parser/url.js`, `proyectoCiber/tests/url.test.js`, `.github/workflows/phishlens-tests.yml`

**Interfaces:**
- Produces: `parseUrl(raw: string) -> {href, protocol, host, hostname, registrableDomain, tld, isIp, hasAt, isPunycode} | null`; `extractUrls(text: string) -> string[]`; `registrableDomain(hostname) -> string` (últimas 2 etiquetas, 3 si la penúltima es `co|com|org|gob|gov|net|edu` y la última tiene 2 letras).

- [ ] Tests: `parseUrl('https://www.paypal.com/x').registrableDomain === 'paypal.com'`; `parseUrl('http://192.168.1.10/login').isIp === true`; `parseUrl('http://paypal.com@evil.xyz/').hasAt === true` y `hostname === 'evil.xyz'`; `parseUrl('https://xn--pypal-4ve.com').isPunycode === true`; `parseUrl('www.bbva.es')` añade `http://`; `parseUrl('no es url')` → `null`; `registrableDomain('login.bbc.co.uk') === 'bbc.co.uk'`; `extractUrls('ve a https://a.com/x, y http://b.es.')` → `['https://a.com/x','http://b.es']`.
- [ ] Ejecutar `node --test` → FAIL. Implementar con `URL` nativo. Ejecutar → PASS.
- [ ] Workflow: on push/PR con `paths: proyectoCiber/**`, `actions/setup-node@v4` Node 22, `working-directory: proyectoCiber`, `node --test`.
- [ ] Commit.

### Task 2: Parser de .eml

**Files:** Create `src/parser/eml.js`, `tests/eml.test.js`

**Interfaces:**
- Produces: `parseEml(raw: string) -> Email` con `Email = {headers: Map<string,string[]> (claves en minúsculas), from: Address|null, replyTo: Address|null, returnPath: string|null, subject: string, text: string, html: string, links: {text: string, href: string}[], attachments: {filename: string, contentType: string}[], hasHeaders: boolean}`, `Address = {name: string, address: string, domain: string}`. También `parseAddress(value) -> Address|null`, `htmlToText(html) -> string`, `emailFromUrl(url) -> Email` (email mínimo con un único enlace).

- [ ] Tests (fixtures inline): cabecera plegada se une con un espacio; `\r\n` funciona; `Subject: =?UTF-8?B?w5psdGltbyBhdmlzbw==?=` → `Último aviso` y `=?UTF-8?Q?Factura_pendiente?=` → `Factura pendiente`; `From: "PayPal" <service@paypa1.com>` → `{name:'PayPal', address:'service@paypa1.com', domain:'paypa1.com'}`; cuerpo quoted-printable (`=C3=A9`, soft break `=\n`) y base64 decodificados como UTF-8; multipart anidado devuelve `text`, `html` y un adjunto `factura.pdf.exe` (nombre tomado de `filename=` o `name=`); enlaces del HTML: `<a href="http://evil.xyz">https://paypal.com</a>` → `{text:'https://paypal.com', href:'http://evil.xyz'}`; URLs sueltas del texto plano entran en `links` con `text === href`; entrada sin cabeceras → `hasHeaders:false` y todo el texto en `text`; cadena vacía no lanza.
- [ ] FAIL → implementar (decodificar con `TextDecoder`, extraer `<a>` con regex sobre el HTML, nunca DOM) → PASS.
- [ ] Commit.

### Task 3: Datos y detectores de autenticación y remitente

**Files:** Create `src/data/brands.js`, `src/data/lists.js`, `src/detectors/finding.js`, `src/detectors/auth.js`, `src/detectors/sender.js`, tests `tests/auth.test.js`, `tests/sender.test.js`

**Interfaces:**
- Produces: `finding({id, detector, severity, title, detail, evidence}) -> Finding` (calcula `points` con `SEVERITY_POINTS = {info:0, low:5, medium:15, high:30}` exportado). Cada detector exporta `name: string` y `detect(email: Email) -> Finding[]`.
- `BRANDS: {name: string, domains: string[], keywords: string[]}[]` (PayPal, Amazon, Microsoft, Apple, Google, Netflix, Correos, DHL, Santander, BBVA, CaixaBank, Agencia Tributaria, Facebook/Meta, Instagram, LinkedIn).
- `lists.js`: `FREE_MAIL_DOMAINS`, `URL_SHORTENERS`, `SUSPICIOUS_TLDS`, `DANGEROUS_EXTENSIONS`, `URGENCY_PATTERNS` / `CREDENTIAL_PATTERNS` / `THREAT_PATTERNS` / `PRIZE_PATTERNS` (RegExp, es+en, insensibles a mayúsculas).

- [ ] auth tests: `spf=fail` → high `auth.spf`; `spf=softfail` → medium; `dkim=fail` → high; `dmarc=fail` → high; sin `Authentication-Results` y `hasHeaders` → low `auth.missing`; todo `pass` → ningún hallazgo.
- [ ] sender tests: dominio de `Reply-To` ≠ dominio de `From` → medium `sender.replyto-mismatch`; `Return-Path` con otro dominio registrable → low; nombre visible que contiene una marca y dominio que no está en sus `domains` → high `sender.brand-impersonation`; marca + dominio de correo gratuito → high (mismo id); remitente legítimo (`PayPal <service@paypal.com>` con reply-to igual) → ningún hallazgo.
- [ ] FAIL → implementar → PASS → commit.

### Task 4: Detectores de enlaces y typosquatting

**Files:** Create `src/detectors/links.js`, `src/detectors/lookalike.js`, tests.

**Interfaces:**
- Consumes: `parseUrl`, `registrableDomain`, `BRANDS`, `lists`.
- Produces: `levenshtein(a, b) -> number`, `normalizeHomoglyphs(s) -> string` (0→o, 1→l, 3→e, 5→s, rn→m, vv→w), `findLookalike(domain) -> {brand, domain}|null` exportados desde `lookalike.js`.

- [ ] links tests: texto con dominio distinto del `href` → high `links.mismatch`; IP → high `links.ip`; acortador → medium `links.shortener`; `@` en URL → high `links.at-sign`; punycode → high `links.punycode`; TLD sospechoso (`.xyz`, `.top`, `.zip`…) → medium `links.tld`; `http://` con palabra de login en la ruta → medium `links.insecure-login`; enlace normal `https://www.amazon.es/pedidos` → nada. Un hallazgo por (id, href), sin duplicados.
- [ ] lookalike tests: `paypa1-login.xyz` → paypal (se compara la etiqueta completa y cada trozo separado por `-`); `micr0soft.com` → microsoft; `arnazon.com` → amazon; `paypal.com` y `www.paypal.com` → `null`; `google.com` → `null`; `bbva-seguridad.com` (marca exacta + palabra extra en dominio no oficial) → medium `lookalike.brand-in-domain`; distancia ≤ 2 o igualdad tras homoglifos → high `lookalike.typosquat`. Revisa dominios de `From` y de todos los enlaces.
- [ ] FAIL → implementar → PASS → commit.

### Task 5: Detectores de adjuntos y lenguaje, y motor

**Files:** Create `src/detectors/attachments.js`, `src/detectors/language.js`, `src/engine.js`, tests `tests/attachments.test.js`, `tests/language.test.js`, `tests/engine.test.js`

**Interfaces:**
- Produces: `analyze(email: Email, detectors = DEFAULT_DETECTORS) -> Report`, `Report = {score: number, level: 'safe'|'suspicious'|'phishing', label: string, findings: Finding[] (ordenados high→info), errors: {detector, message}[], summary: string, email: {from, subject, links, attachments}}`; `levelFor(score) -> {level, label}`; `analyzeInput({kind: 'eml'|'text'|'url', value: string}) -> Report`.

- [ ] attachments tests: `factura.pdf.exe` → high `attachments.double-extension`; `nota.js` → high `attachments.dangerous`; `informe.docm` → medium `attachments.macro`; `foto.jpg` → nada.
- [ ] language tests: "Su cuenta será suspendida en 24 horas" → medium urgency; "verifique su contraseña" → high credentials; "Has ganado un iPhone" → medium prize; "Your account will be locked" → medium; texto neutro → nada. Un hallazgo por categoría como máximo, con la frase coincidente en `evidence`.
- [ ] engine tests: suma y tope a 100; `levelFor(24).level==='safe'`, `levelFor(25)==='suspicious'`, `levelFor(60)==='phishing'`; un detector que lanza aparece en `errors` y el resto sigue; `analyzeInput({kind:'url', value:'http://192.168.0.1/paypal/login'})` → `phishing`; entrada `text` sin cabeceras añade hallazgo info `input.no-headers`.
- [ ] FAIL → implementar → PASS → commit.

### Task 6: Emails de ejemplo y test de integración

**Files:** Create `samples/` con `01-legitimo-newsletter.eml`, `02-legitimo-pedido.eml`, `03-phishing-banco.eml`, `04-phishing-correos.eml`, `05-phishing-microsoft365.eml`, `06-phishing-factura-adjunto.eml`, `samples/index.js` (exporta `SAMPLES: {id, title, file}[]`), `tests/samples.test.js`.

- [ ] Test: los `01`–`02` dan `safe`; los `03`–`06` dan `phishing`. Usar dominios ficticios o reservados (`example.com`, `.test`) para los atacantes cuando no sea necesario un dominio parecido a una marca; ningún enlace real malicioso.
- [ ] FAIL → escribir samples → PASS → commit.

### Task 7: Interfaz web

**Files:** Create `index.html`, `assets/css/styles.css`, `src/ui/app.js`, `src/ui/render.js`, `assets/favicon.svg`.

**Interfaces:**
- Consumes: `analyzeInput`, `SAMPLES`.
- Produces: `renderReport(container: HTMLElement, report: Report)`, `reportToJson(report) -> string`.

- [ ] Página según spec §6: lema de privacidad, pestañas (arrastrar `.eml` / pegar email / URL), botones de ejemplos (cargan con `fetch('samples/...')` del mismo origen), medidor circular SVG, resumen, hallazgos agrupados por detector, cabeceras clave, enlaces extraídos como texto, exportar JSON (Blob + descarga), imprimir, tema claro/oscuro con `prefers-color-scheme` y conmutador, foco visible, móvil a 360 px.
- [ ] Rechazar >5 MB con mensaje; todo con `textContent`.
- [ ] Verificar en Chromium (Playwright) a 1280 y 390 px: cargar cada sample y comprobar nota y color; capturas a `docs/img/`.
- [ ] Commit.

### Task 8: README, índice y despliegue

**Files:** Create `proyectoCiber/README.md`, `.github/workflows/phishlens-pages.yml`; Modify `README.md` (fila nueva en el índice).

- [ ] README: qué es, demo, capturas, privacidad, tabla de detectores, sistema de puntuación, arquitectura, cómo ejecutar (`python -m http.server` y `node --test`), limitaciones, ideas futuras, aviso ético.
- [ ] Workflow de Pages: `actions/upload-pages-artifact` con `path: proyectoCiber`, `actions/deploy-pages`; solo en push a `main`.
- [ ] `node --test` → PASS. Commit, push y PR.
