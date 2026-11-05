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

## Pendiente

- Probar la privacidad también en Firefox y WebKit.
