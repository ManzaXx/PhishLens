# Auditoría de seguridad

Estado de cada punto de seguridad de PhishLens y la prueba que lo sostiene. ✅ = comprobado por un test automático; 👁️ = comprobado a mano. El porqué de cada medida está en el [modelo de amenazas](threat-model.md).

## 2.1

| Punto | Estado | Prueba |
| --- | --- | --- |
| Sin `innerHTML`, `document.write` ni `eval` en la web | ✅ | `tests/unit/security.test.js` |
| CSP sin `unsafe-inline` ni `unsafe-eval`, con Trusted Types | ✅ | `tests/unit/security.test.js` |
| Prototype pollution con `__proto__` en entidades, parámetros MIME y Authentication-Results | ✅ | `tests/unit/security.test.js` |
| ReDoS: miles de `<`, nombres gigantes, `Received` enormes | ✅ | `tests/unit/security.test.js` |
| Miles de enlaces y adjuntos acotados; MIME recursivo sin desbordar la pila | ✅ | `tests/unit/security.test.js` |
| Caracteres bidi e invisibles visibles en el informe | ✅ | `tests/unit/security.test.js` |
| Enlaces `javascript:` marcados como peligrosos | ✅ | `tests/unit/security.test.js` |
| Anti-clickjacking por JavaScript | 👁️ | `src/ui/app.js` (la CSP en `<meta>` no admite `frame-ancestors`) |
| `localStorage` solo acepta `light` o `dark` | 👁️ | `src/ui/app.js` |
| Actions fijadas por SHA, `persist-credentials: false`, permisos mínimos | 👁️ | `.github/workflows/` |

## 2.2

| Punto | Estado | Prueba |
| --- | --- | --- |
| `connect-src 'none'`, `worker-src 'none'` y `x-dns-prefetch-control: off` | ✅ | `tests/unit/security.test.js` |
| Ninguna petición fuera del origen al analizar las 10 muestras y un correo lleno de contenido remoto, en claro y oscuro, por todas las pestañas | ✅ | `tests/e2e/privacy.e2e.js` (Chromium) |
| El detector de fugas funciona (control negativo) | ✅ | `tests/e2e/privacy.e2e.js` con `tests/fixtures/privacy/leaky.html` |
| Ni un `fetch` al propio origen conecta | ✅ | `tests/e2e/privacy.e2e.js` |
| Límites de 25 MB, 1.000 cabeceras y 64 KB por cabecera sin lanzar | ✅ | `tests/unit/limits.test.js` |
| 25 MB en menos de 4 s | ✅ | `tests/perf/perf.test.js`, [benchmark](benchmark.md) |
| Fuzzing con semilla: nunca lanza, menos de 2 s, nota en rango | ✅ | `tests/fuzz/fuzz.test.js` |
| Ambigüedades MIME convertidas en hallazgos | ✅ | `tests/differential/differential.test.js` |
| `Authentication-Results` falsificadas no cuentan como verificadas | ✅ | `tests/unit/auth-evaluate.test.js` |
| Cero dependencias en ejecución; las de test fijadas en `package-lock.json` | ✅ | `tests/unit/security.test.js` |
| `npm audit --audit-level=high` y Dependabot (npm y Actions) | ✅ | Job `e2e` de CI, `.github/dependabot.yml` |
| `npm ci --ignore-scripts`: ningún script de instalación de terceros | 👁️ | `.github/workflows/phishlens-tests.yml` |
| Accesibilidad: axe sin problemas serios ni críticos, uso completo con teclado | ✅ | `tests/e2e/a11y.e2e.js` |
| Sin Web Worker sin CSP | ✅ | [ADR 0003](adr/0003-sin-web-worker.md), `tests/unit/security.test.js` |
| Cada regla con al menos un test o una muestra | ✅ | `tests/unit/coverage-matrix.test.js`, [matriz](coverage-matrix.md) |

## 2.3

| Punto | Estado | Prueba |
| --- | --- | --- |
| Lectores de adjuntos (ZIP, OLE2, PDF, HTML) que nunca lanzan ni leen fuera de rango | ✅ | `tests/fuzz/files.test.js`, `tests/unit/files-*.test.js` |
| Casos adversarios (FAT en ciclo, EOCD falso, 10 MB de cabeceras centrales o de `/`) en menos de 2 s | ✅ | `tests/fuzz/files.test.js` |
| Adjunto recortado o ilegible: sin hashes ni afirmaciones sobre su interior | ✅ | `tests/unit/attachments.test.js`, `tests/unit/files-inspect.test.js` |
| SHA-1 y MD5 probados con los vectores de FIPS 180-4 y RFC 1321 | ✅ | `tests/unit/hashes.test.js` |
| Técnicas ATT&CK nuevas comprobadas contra el bundle oficial 20.1 | 👁️ | `node tools/check-mitre.mjs enterprise-attack-20.1.json` |
| Ningún fuente con caracteres bidireccionales literales (Trojan Source) | ✅ | `tests/unit/structure.test.js` |
| `src/parser/files/` solo importa de `lib/`, `data/` y otros lectores | ✅ | `tests/unit/structure.test.js` |
| Revisión de seguridad del PR7 sin hallazgos explotables | 👁️ | skill `security-review` sobre el diff |
| Lote: 50 correos y 100 MB, repetidos, archivos que no son `.eml` y análisis abortado | ✅ | `tests/unit/batch.test.js`, `tests/e2e/batch.e2e.js` |
| Grafo SVG sin `innerHTML` y con lista blanca de etiquetas y atributos | ✅ | `tests/unit/graph-ui.test.js` |
| Grafo y campañas independientes del orden y sin lanzar con correos mutados | ✅ | `tests/fuzz/batch.test.js` |
| Privacidad con un lote de 10 correos por todas las vistas, en claro y oscuro | ✅ | `tests/e2e/batch.e2e.js` |
| Revisión de seguridad del PR8 sin hallazgos explotables | 👁️ | skill `security-review` sobre el diff |
| Desenvolver URLs: 10 saltos, base64 y `%` roto sin lanzar y en menos de 50 ms | ✅ | `tests/unit/url-intel.test.js` |
| Vista «URLs» sin enlaces pulsables y todo defanged | ✅ | `tests/unit/urls-ui.test.js`, `tests/e2e/a11y.e2e.js` |
| STIX: patrones escapados, solo `JSON.stringify`, referencias que existen y bundle válido para todo lote mutado | ✅ | `tests/unit/stix.test.js`, `tests/fuzz/batch.test.js` |
| STIX: ids de observables iguales a los de la librería oficial `stix2` y bundles válidos para el validador de OASIS | ✅ / 👁️ | `tests/unit/stix.test.js`; `stix2_validator` a mano (14 de 14 válidos) |
| Descarga STIX sin red ni errores, en Chromium | ✅ | `tests/e2e/batch.e2e.js` |
| Revisión de seguridad del PR9 sin hallazgos explotables | 👁️ | skill `security-review` sobre el diff |

## 3.0

| Punto | Estado | Prueba |
| --- | --- | --- |
| Historial apagado por defecto: sin base `phishlens` tras analizar correos y un lote | ✅ | `tests/e2e/history.e2e.js` |
| El informe guardado no permite reconstruir el correo (prueba de propiedad, también en lo importado) | ✅ | `tests/unit/storage-schema.test.js` |
| Import: `__proto__`, tipos inesperados, listas mal formadas, cadenas y ficheros enormes | ✅ | `tests/unit/storage-schema.test.js`, `tests/unit/storage-history.test.js` |
| «Borrar todo» borra la base entera y lo comprueba | ✅ | `tests/e2e/history.e2e.js` |
| Vista «Historial» sin `innerHTML`, sin enlaces y defanged; axe en claro y oscuro | ✅ | `tests/unit/history-ui.test.js`, `tests/e2e/history.e2e.js` |
| Revisión final del PR10: «Borrar todo» cuenta lo guardado y no lo filtrado; otra pestaña que borra la base ya no apaga el historial de esta; entradas sin veredicto válido se rechazan | ✅ | `tests/unit/history-ui.test.js`, `tests/unit/history-control.test.js`, `tests/unit/storage-schema.test.js` |
| Revisión de seguridad del PR10: dos hallazgos arreglados (el import podía meter el cuerpo del correo; listas mal formadas rompían la búsqueda) | ✅ | `tests/unit/storage-schema.test.js` |
| Panel: texto del correo en las gráficas solo como `textContent`, SVG con lista blanca, sin enlaces | ✅ | `tests/unit/bar-chart.test.js`, `tests/unit/dashboard-ui.test.js` |
| Panel: `data-sha` validado como 64 hex antes de buscar; lotes guardados validados con `validateBatch` | ✅ | `tests/unit/storage-history.test.js`, `tests/unit/storage-schema.test.js` |
| Panel: privacidad (sin peticiones externas ni violaciones de CSP) y axe, en claro y oscuro, encendido y apagado | ✅ | `tests/e2e/dashboard.e2e.js` |
| Revisión de seguridad del PR11: sin hallazgos explotables; el fallo encontrado era funcional (las pistas de campaña se guardaban como objetos y el lote se descartaba) | ✅ | `tests/unit/history-control.test.js` |

| Informe forense: notas y texto del correo solo como `textContent`, defanged; notas de 5.000 caracteres como mucho | ✅ | `tests/unit/forensic-ui.test.js`, `tests/unit/storage-schema.test.js` |
| Informe forense: hashes iguales a `node:crypto` (también con CRLF y no ASCII); `reportSha256` detecta cualquier cambio | ✅ | `tests/unit/forensic.test.js`, `tests/e2e/forensic.e2e.js` |
| Informe forense: la impresión solo muestra el informe abierto; privacidad y axe del diálogo en claro y oscuro | ✅ | `tests/e2e/forensic.e2e.js`, `tests/e2e/a11y.e2e.js` |
| Revisión de seguridad del PR12 sin hallazgos explotables | 👁️ | revisión del diff |

| Reglas propias: sin `RegExp` en `src/rules/`, campos y operadores en listas cerradas, claves peligrosas rechazadas | ✅ | `tests/unit/rules-validate.test.js` |
| Reglas propias: el validador nunca lanza ni pasa de 50 ms con 2.000 ficheros mutados | ✅ | `tests/fuzz/rules.test.js` |
| Reglas propias: nunca bajan la nota; 100 × 20 condiciones sobre 1 MB en menos de 300 ms | ✅ | `tests/unit/rules-evaluate.test.js` |
| Reglas propias: con el historial apagado no se crea la base; se van con «Borrar todo»; migración v1 → v2; privacidad y axe en claro y oscuro | ✅ | `tests/e2e/rules.e2e.js` |
| Revisión de seguridad del PR13 | 👁️ | revisión del diff |

## Pendiente

- Probar la privacidad también en Firefox y WebKit.
