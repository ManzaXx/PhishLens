# ADR 0007 · Análisis en un Web Worker que hereda la CSP

- **Estado:** aceptada (sustituye a [ADR 0003](0003-sin-web-worker.md))
- **Fecha:** 2026-11-13

## Contexto

El [ADR 0003](0003-sin-web-worker.md) dejó el análisis en el hilo principal porque «un worker no hereda la CSP del
`<meta>` del documento» y en GitHub Pages no hay cabeceras. Esa premisa es cierta para un worker cargado **desde una
URL** (su política sale de las cabeceras de la respuesta que lo sirve), pero no para uno creado **desde `blob:`**: la
especificación CSP3 manda que un worker cuyo script es `blob:`, `data:` o `about:` herede la política del documento
que lo crea («inherit the policy of the owner document»). La auditoría 3.1 (P5) lo puso a prueba antes de decidir
nada: con un correo de 25 MB la pestaña se queda quieta décimas de segundo o segundos según el equipo, y un botón de
cancelar no existía.

## Prueba

`tests/fixtures/worker/csp-probe.html` lleva **la misma CSP que `index.html`** (el e2e lo comprueba byte a byte) y
crea un module worker desde `blob:` igual que la app. Desde dentro del worker se intenta `fetch` al propio origen,
`fetch` a un dominio ajeno, `import()` de un script remoto, `XMLHttpRequest`, `WebSocket`, `eval` e `importScripts`.
En Chromium todo queda bloqueado y el worker recibe los `securitypolicyviolation` de `connect-src` y `script-src`;
el único import que funciona es el del motor, del mismo origen. Playwright no ve salir ninguna petición: el import
remoto aparece como una petición creada y **cortada por el navegador** (`requestfailed`, motivo `csp`), exactamente
igual que el mismo import hecho desde el documento. El job `worker-csp` de CI repite la prueba en Firefox y WebKit.

Trusted Types también se aplica al constructor: con `require-trusted-types-for 'script'`, `new Worker(cadena)` lanza
`TypeError`; hace falta una política. La CSP solo admite la política `phishlens-worker`, que vive dentro de
`src/ui/analysis-worker.js` y únicamente acepta un `blob:` del propio origen. Crear otra política (otro nombre, o el
mismo nombre por segunda vez, al no haber `'allow-duplicates'`) lanza.

## Decisión

El botón «Analizar» analiza en un module worker creado desde `blob:` con `import()` del motor
(`src/ui/analysis-worker.js`). La CSP de `index.html` pasa de `worker-src 'none'` a `worker-src blob: 'self'` y de
`trusted-types 'none'` a `trusted-types phishlens-worker`; todo lo demás sigue igual.

`'self'` está en `worker-src` solo por Firefox: comprueba contra `worker-src` (y no contra `script-src`, como
Chromium) los módulos que importa un worker, así que con `worker-src blob:` a secas bloqueaba `src/parser/eml.js` y
el resto del motor («blocked a worker script (worker-src)») y la app caía al hilo principal. `'self'` no permite
crear un worker desde una URL en la práctica: con Trusted Types `new Worker` exige la política, y la política solo
acepta `blob:`. Mientras el worker trabaja la
página muestra «Analizando…» con un botón **Cancelar** que termina el worker (`terminate()`), la única forma de parar
un análisis a medias.

Si el navegador no tiene `Worker`, no permite crear la política o el worker falla al arrancar o al cargar el motor,
el análisis vuelve al hilo principal, como hasta la 3.1, y no se vuelve a intentar el worker en esa sesión. Un error
del motor con un correo concreto **no** cuenta como fallo del worker: llega a la interfaz como el aviso de siempre.

Lo que sigue en el hilo principal: el re-análisis al pegar un registro SPF o una clave DKIM y al cargar reglas
propias (misma entrada, ya analizada una vez), y los lotes, que ya ceden el hilo entre correo y correo.

## Por qué no abre una puerta nueva

- **El worker no tiene red.** Hereda `connect-src 'none'` y `script-src 'self'`; lo prueban los e2e en tres motores.
  Un fallo del parser que llegara a ejecutar código dentro del worker choca con la misma CSP que en la página.
- **`worker-src blob: 'self'` no deja cargar workers remotos**, y el único script que admite Trusted Types para
  `new Worker` es el `blob:` que crea la política privada del módulo (una URL del propio origen tampoco pasa). Un script inyectado (que ya tendría que haber burlado `script-src 'self'`) no puede
  crear otra política ni usar esta con una URL remota.
- **Lo que viaja al worker es el texto del correo y las reglas propias (JSON); lo que vuelve es el informe.** Los dos
  se copian con el algoritmo de clonado estructurado: ni funciones ni prototipos.
- **Los límites no cambian:** se comprueban antes de enviar nada (25 MB) y dentro del motor, igual que antes.

## Consecuencias

- La página responde durante un análisis grande; en el e2e, cancelar un análisis de 8 MB se atiende en decenas de ms.
- Dos copias del texto en memoria durante el análisis (la de la página y la del worker). Con 25 MB es asumible.
- Si algún motor no aplicara la CSP heredada, el job `worker-csp` lo diría; la vuelta atrás es apagar
  `createAnalyzer` (el hilo principal sigue siendo el camino de respaldo).
- `tests/unit/security.test.js` exige `worker-src blob: 'self'` sin ninguna URL remota ni `data:`, y `trusted-types`
  sin `'allow-duplicates'`.
