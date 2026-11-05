# ADR 0003 · Sin Web Worker

- **Estado:** aceptada
- **Fecha:** 2026-11-05

## Contexto

Con la entrada máxima en 25 MB, lo natural sería mover el análisis a un Web Worker para que la pestaña no se congele mientras tanto. PhishLens se publica en GitHub Pages, que no deja enviar cabeceras HTTP: toda la política de seguridad vive en un `<meta http-equiv="Content-Security-Policy">`.

Un worker no hereda la CSP del `<meta>` del documento. Su política sale de las cabeceras de la respuesta que sirve el script del worker, y en Pages esa respuesta no lleva ninguna. Dentro del worker no habría `connect-src 'none'`: un fallo en el parser que permitiera ejecutar código podría usar `fetch` sin que el navegador lo bloqueara. Hoy ese mismo fallo chocaría con la CSP de la página.

## Decisión

El análisis se queda en el hilo principal (`worker-src 'none'` en la CSP). A cambio:

- Todos los límites están en `src/lib/limits.js` y nunca lanzan: recortan, anotan en `parseNotes` y bajan la confianza.
- Un adjunto de más de 10 MB no se decodifica entero; su tamaño sale de la longitud del base64.
- `tests/perf/perf.test.js` exige menos de 4 s para 25 MB; `docs/benchmark.md` da unos 0,2–0,3 s en un servidor normal.
- El fuzzing (`tests/fuzz/`) exige que ninguna entrada tarde más de 2 s.

## Consecuencias

- Con un correo enorme la pestaña puede quedarse sin responder unas décimas de segundo. Es aceptable para una herramienta que se usa de uno en uno.
- Si algún día PhishLens se sirve desde un sitio que permita cabeceras (Cloudflare Pages, Netlify), se puede revisar: el script del worker llevaría su propia CSP con `connect-src 'none'` y habría que probar que la hereda con el mismo test de `tests/e2e/privacy.e2e.js`.
