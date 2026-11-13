# Matriz de cobertura

Generada con `npm run coverage` (`tools/gen-coverage.mjs`); `tests/unit/coverage-matrix.test.js` falla si no está al día.
Una regla cuenta como probada si su id aparece en algún test o si alguna muestra de `samples/` la produce.

86 reglas, 86 probadas.

| Regla | ATT&CK | Muestras | Tests | |
| --- | --- | --- | --- | --- |
| `attachments.archive` | T1566.001, T1204.002 | 12 | `unit/attachments-review.test.js`, `unit/attachments.test.js`, `unit/engine.test.js` | ✅ |
| `attachments.archive-executable` | T1204.002, T1566.001 | 12 | `unit/attachments-review.test.js`, `unit/attachments.test.js`, `unit/samples.test.js` | ✅ |
| `attachments.dangerous` | T1566.001, T1204.002 | — | `unit/attachments.test.js`, `unit/mitre.test.js`, `unit/scoring.test.js` | ✅ |
| `attachments.disk-image` | T1553.005, T1204.002 | — | `unit/attachments.test.js` | ✅ |
| `attachments.double-extension` | T1036.007, T1204.002 | 06 | `unit/advice.test.js`, `unit/attachments.test.js`, `unit/limits.test.js`, `unit/mitre.test.js`, `unit/scoring.test.js` | ✅ |
| `attachments.encrypted-archive` | T1027.013, T1566.001 | 12 | `unit/attachments.test.js`, `unit/samples.test.js` | ✅ |
| `attachments.html-smuggling` | T1027.006, T1204.002 | — | `unit/attachments.test.js` | ✅ |
| `attachments.lnk` | T1204.002, T1566.001 | — | `unit/attachments.test.js` | ✅ |
| `attachments.macro` | T1566.001, T1204.002 | — | `unit/attachments.test.js`, `unit/mitre.test.js`, `unit/scoring.test.js` | ✅ |
| `attachments.ole-macro` | T1059.005, T1204.002 | — | `unit/attachments.test.js` | ✅ |
| `attachments.pdf-active` | T1204.002, T1059.007 | 12 | `unit/attachments.test.js`, `unit/samples.test.js` | ✅ |
| `attachments.rtl-override` | T1036.002, T1204.002 | — | `unit/attachments.test.js`, `unit/mitre.test.js` | ✅ |
| `attachments.type-mismatch` | T1036.008, T1204.002 | 11 | `unit/attachments.test.js`, `unit/samples.test.js` | ✅ |
| `auth.dkim` | T1684.002 | 03, 04, 07, 11, 12, 13 | `unit/auth.test.js`, `unit/plain.test.js` | ✅ |
| `auth.dkim-body-modified` | T1684.002 | — | `unit/auth-evaluate.test.js` | ✅ |
| `auth.dkim-body-verified` | — | — | `unit/auth-evaluate.test.js`, `unit/scoring.test.js` | ✅ |
| `auth.dkim-verified-aligned` | — | — | `unit/auth-evaluate.test.js` | ✅ |
| `auth.dkim-weak` | — | — | `unit/auth-evaluate.test.js`, `unit/scoring.test.js` | ✅ |
| `auth.dmarc` | T1684.002 | 03, 04, 05, 07, 11, 12, 13 | `unit/auth-evaluate.test.js`, `unit/auth.test.js`, `unit/coverage-matrix.test.js`, `unit/plain.test.js` | ✅ |
| `auth.dmarc-declared-mismatch` | T1684.002 | — | `unit/auth-evaluate.test.js` | ✅ |
| `auth.dmarc-unaligned` | T1684.002 | 04 | `unit/auth-evaluate.test.js`, `unit/scoring.test.js` | ✅ |
| `auth.forged-results` | T1684.002 | — | `unit/auth-evaluate.test.js`, `unit/mitre.test.js`, `unit/trust-layouts.test.js` | ✅ |
| `auth.missing` | — | 06, 08, 09, 10 | `unit/auth-evaluate.test.js`, `unit/auth.test.js`, `unit/mitre.test.js`, `unit/scoring.test.js` | ✅ |
| `auth.spf` | T1684.002 | 03, 04, 11, 12, 13 | `unit/auth-evaluate.test.js`, `unit/auth.test.js`, `unit/coverage-matrix.test.js`, `unit/eval.test.js`, `unit/finding.test.js`, `unit/plain.test.js` | ✅ |
| `auth.spf-offline` | T1684.002 | — | `unit/auth-evaluate.test.js` | ✅ |
| `headers.duplicate` | — | 09 | `unit/headers.test.js`, `unit/samples.test.js` | ✅ |
| `headers.duplicate-from` | T1684.002 | 09 | `unit/headers.test.js`, `unit/mitre.test.js`, `unit/samples.test.js` | ✅ |
| `headers.future-date` | — | — | `unit/headers.test.js` | ✅ |
| `headers.mailer` | — | 03 | `unit/headers.test.js`, `unit/mitre.test.js`, `unit/scoring.test.js` | ✅ |
| `headers.messageid-domain` | — | 03, 14, 16 | `unit/headers.test.js` | ✅ |
| `headers.missing-date` | — | — | `unit/headers.test.js` | ✅ |
| `headers.missing-messageid` | — | 04, 05, 06, 11, 12, 13 | `unit/headers.test.js` | ✅ |
| `html.data-uri` | T1598 | — | `unit/html.test.js`, `unit/security.test.js` | ✅ |
| `html.form` | T1598 | 07 | `unit/html.test.js`, `unit/mitre.test.js`, `unit/scoring.test.js` | ✅ |
| `html.hidden-text` | T1027 | 07 | `unit/html.test.js` | ✅ |
| `html.image-only` | T1027 | — | `unit/html.test.js` | ✅ |
| `html.script` | T1059.007 | — | `unit/html.test.js` | ✅ |
| `input.invalid-url` | — | — | `unit/engine.test.js` | ✅ |
| `input.no-headers` | — | — | `unit/coverage-matrix.test.js`, `unit/engine.test.js`, `unit/finding.test.js`, `unit/mitre.test.js` | ✅ |
| `language.credentials` | T1598 | 03, 05, 07, 10, 12 | `unit/advice.test.js`, `unit/engine.test.js`, `unit/language.test.js`, `unit/scoring.test.js` | ✅ |
| `language.prize` | T1204 | — | `unit/language.test.js` | ✅ |
| `language.threat` | T1204 | 03, 04, 05, 06, 08, 11 | `unit/language.test.js`, `unit/scoring.test.js` | ✅ |
| `language.urgency` | T1204 | 03, 04, 05, 06, 11, 12, 13, 15 | `unit/coverage-matrix.test.js`, `unit/eval.test.js`, `unit/language.test.js`, `unit/scoring.test.js` | ✅ |
| `links.at-sign` | T1566.002, T1204.001 | — | `unit/links.test.js` | ✅ |
| `links.brand-in-path` | T1566.002, T1204.001 | 04, 07 | `unit/links.test.js`, `unit/scoring.test.js` | ✅ |
| `links.credentials-in-url` | T1566.002, T1204.001 | — | `unit/links.test.js`, `unit/plain.test.js` | ✅ |
| `links.download` | T1566.002, T1204.001 | — | `unit/links.test.js` | ✅ |
| `links.high-entropy` | T1566.002, T1204.001 | 13 | `unit/golden.test.js`, `unit/links.test.js`, `unit/plain.test.js` | ✅ |
| `links.insecure-login` | T1566.002, T1204.001 | 03, 07 | `unit/coverage-matrix.test.js`, `unit/links.test.js`, `unit/scoring.test.js` | ✅ |
| `links.ip` | T1566.002, T1204.001 | 07 | `unit/coverage-matrix.test.js`, `unit/engine.test.js`, `unit/eval.test.js`, `unit/links.test.js`, `unit/mitre.test.js`, `unit/plain.test.js`, `unit/scoring.test.js` | ✅ |
| `links.mismatch` | T1566.002, T1204.001 | 03, 07 | `unit/advice.test.js`, `unit/finding.test.js`, `unit/links.test.js`, `unit/mitre.test.js`, `unit/rules-en.test.js`, `unit/scoring.test.js` | ✅ |
| `links.nested-redirect` | T1566.002, T1204.001 | 13 | `unit/golden.test.js`, `unit/links.test.js`, `unit/plain.test.js` | ✅ |
| `links.non-standard-port` | T1566.002, T1204.001 | 13 | `unit/golden.test.js`, `unit/links.test.js`, `unit/plain.test.js` | ✅ |
| `links.obfuscated-ip` | T1566.002, T1204.001 | — | `unit/links.test.js`, `unit/plain.test.js` | ✅ |
| `links.open-redirect` | T1566.002, T1204.001 | 13 | `unit/golden.test.js`, `unit/links.test.js`, `unit/plain.test.js` | ✅ |
| `links.punycode` | T1566.002, T1204.001 | 10 | `unit/links.test.js` | ✅ |
| `links.shortener` | T1566.002, T1204.001 | 04 | `unit/links.test.js`, `unit/scoring.test.js` | ✅ |
| `links.tld` | T1566.002, T1204.001 | 13 | `unit/links.test.js` | ✅ |
| `links.tracking` | T1566.002, T1204.001 | — | `unit/links.test.js` | ✅ |
| `lookalike.brand-in-domain` | T1583.001 | 03, 08, 10 | `unit/lookalike.test.js`, `unit/rules-evaluate.test.js`, `unit/samples.test.js`, `unit/scoring.test.js` | ✅ |
| `lookalike.deceptive-subdomain` | T1583.001 | 10 | `unit/lookalike.test.js`, `unit/samples.test.js` | ✅ |
| `lookalike.homoglyph` | T1583.001 | — | `unit/lookalike.test.js` | ✅ |
| `lookalike.mixed-script-domain` | T1583.001 | 10 | `unit/lookalike.test.js`, `unit/samples.test.js` | ✅ |
| `lookalike.typosquat` | T1583.001 | 04, 05 | `unit/lookalike.test.js`, `unit/mitre.test.js`, `unit/scoring.test.js` | ✅ |
| `lookalike.whole-script` | T1583.001 | 10 | `unit/lookalike.test.js`, `unit/samples.test.js` | ✅ |
| `mime.boundary-in-content` | T1027 | — | `differential/cases.js` | ✅ |
| `mime.boundary-reuse` | T1027 | — | `differential/cases.js` | ✅ |
| `mime.charset-conflict` | T1027 | — | `differential/cases.js` | ✅ |
| `mime.duplicate-content-type` | T1027 | — | `differential/cases.js` | ✅ |
| `mime.header-without-colon` | — | — | `differential/cases.js` | ✅ |
| `mime.limit` | — | — | `differential/differential.test.js` | ✅ |
| `mime.nested-message` | — | — | `differential/cases.js` | ✅ |
| `mime.unclosed-multipart` | — | — | `differential/cases.js` | ✅ |
| `route.helo-mismatch` | T1684.002 | 08 | `unit/mitre.test.js`, `unit/route.test.js`, `unit/samples.test.js` | ✅ |
| `route.private-ip-boundary` | T1684.002 | 08 | `unit/mitre.test.js`, `unit/route.test.js`, `unit/samples.test.js` | ✅ |
| `route.slow-delivery` | — | 08 | `unit/engine.test.js`, `unit/localize.test.js`, `unit/mitre.test.js`, `unit/route.test.js`, `unit/samples.test.js` | ✅ |
| `route.time-travel` | T1684.002 | 08 | `unit/mitre.test.js`, `unit/route.test.js`, `unit/samples.test.js` | ✅ |
| `route.too-many-hops` | — | — | `unit/localize.test.js`, `unit/route.test.js` | ✅ |
| `route.unparseable` | — | — | `unit/route.test.js` | ✅ |
| `sender.brand-impersonation` | T1684.001 | 03, 04, 05, 08, 09, 12 | `unit/advice.test.js`, `unit/engine.test.js`, `unit/localize.test.js`, `unit/mitre.test.js`, `unit/plain.test.js`, `unit/scoring.test.js`, `unit/sender.test.js` | ✅ |
| `sender.display-name-address` | T1684.001 | 09 | `unit/samples.test.js`, `unit/scoring.test.js`, `unit/sender.test.js` | ✅ |
| `sender.invisible-chars` | T1027 | 07 | `unit/sender.test.js` | ✅ |
| `sender.mixed-script` | T1684.001 | 07 | `unit/sender.test.js` | ✅ |
| `sender.replyto-mismatch` | T1566 | 03, 06, 12 | `unit/sender.test.js` | ✅ |
| `sender.returnpath-mismatch` | T1566 | 03, 12, 14 | `unit/sender.test.js` | ✅ |
| `sender.sender-mismatch` | T1566 | 09 | `unit/samples.test.js`, `unit/sender.test.js` | ✅ |
