# Modelo de amenazas

PhishLens analiza correos escritos por un atacante dentro del navegador de la víctima. Este documento dice qué se protege, de quién y con qué prueba. El resumen para usuarios está en [SECURITY.md](../SECURITY.md) y el estado punto por punto en [security-audit.md](security-audit.md).

## Activos

1. **El correo del usuario y su privacidad.** Nada de lo que se pega o arrastra puede salir del navegador: ni el texto, ni los dominios que contiene, ni el hecho de que se está analizando.
2. **La integridad de la pestaña.** El correo no puede ejecutar código ni cambiar lo que el informe dice.
3. **La honestidad del veredicto.** El informe no puede decir «verificado» de algo que solo declara una cabecera.

## Adversarios

| Adversario | Qué controla | Qué quiere |
| --- | --- | --- |
| **Remitente malicioso** | Todo el `.eml`: cabeceras, MIME, HTML, nombres y tamaño de adjuntos, codificaciones | Que el correo salga como legítimo, colgar o romper el análisis, ejecutar código o saber que lo están analizando (píxel, precarga DNS) |
| **Página comprometida** | Una web que incrusta PhishLens o un fallo futuro en su propio código | Leer el correo y enviarlo fuera, o engañar al usuario con un marco |

**Fuera de alcance:** un navegador o un sistema operativo comprometidos, extensiones del navegador y alguien con permiso de escritura en el repositorio.

## Superficies y mitigaciones

### Parser (`src/parser/`)

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| Entrada enorme o con miles de cabeceras | Límites en `src/lib/limits.js` (25 MB, 1.000 cabeceras, 64 KB por cabecera, 500 partes, 20 niveles). Nunca lanzan: anotan y bajan la confianza | `tests/unit/limits.test.js`, `tests/perf/perf.test.js` |
| ReDoS y entradas patológicas | Regex acotadas, textos recortados antes de buscar | `tests/unit/security.test.js` |
| Entradas aleatorias que rompen el parser | Cada detector aislado; el motor nunca lanza | `tests/fuzz/fuzz.test.js` (semilla fija, 2.000 casos; `npm run fuzz` para 20.000) |
| MIME ambiguo: el filtro ve una cosa y el cliente otra | Las ambigüedades se convierten en hallazgos `mime.*` en vez de pasar en silencio | `tests/differential/differential.test.js` |
| Contaminación de prototipos | `Object.hasOwn` y `Object.create(null)` | `tests/unit/security.test.js` |
| Adjuntos construidos para colgar o engañar a los lectores (ZIP con un EOCD que promete 65.535 entradas, FAT en bucle, offsets fuera del fichero, 10 MB de `/` en un PDF) | Lectores de solo lectura en `src/parser/files/` sobre un lector acotado que devuelve `null` fuera de rango; topes de 1.000 entradas y 4.096 sectores; ciclos cortados con un conjunto de visitados; un solo recorrido lineal en el PDF | `tests/fuzz/files.test.js` (2.000 adjuntos mutados y casos fijos adversarios), `tests/unit/files-*.test.js` |
| Un adjunto que dice ser otra cosa (`factura.pdf` que es un `.exe`, `factura.exe.`) | Tipo real por bytes mágicos y extensión leída como la lee Windows (sin puntos ni espacios finales) | `tests/unit/attachments.test.js` |
| Nombres hostiles dentro de un ZIP (`../../x.exe`, RLO, CP437, 64 KB) | Recortados a 260 caracteres y pintados con `el()`, que revela los caracteres invisibles | `tests/unit/files-zip.test.js` |
| Un lote para agotar memoria o colgar la pestaña | 50 correos y 100 MB en total; uno a uno, cediendo el hilo entre correos; un análisis nuevo aborta el lote en curso | `tests/unit/batch.test.js`, `tests/e2e/batch.e2e.js` |
| Grafo y campañas con entradas mutadas o en otro orden | Funciones puras sobre `Map`/`Set`, sin red ni DNS; SVG con como mucho 150 nodos y tabla con 500 filas | `tests/fuzz/batch.test.js`, `tests/perf/perf.test.js` |
| Campañas falsas por proveedores compartidos | Gmail y otros correos gratuitos, acortadores, dominios de seguimiento y dominios oficiales de marcas no cuentan como pista; los correos «probablemente legítimos» no entran | `tests/unit/campaigns.test.js`, `tests/unit/batch-samples.test.js` |
| URLs construidas para colgar o engañar al desenvolverlas (15 niveles, 1 MB de base64, `%` roto, ciclos) | 10 saltos como máximo, conjunto de visitados, base64 de 8 KB como mucho y 3 decodificaciones; cada salto es más corto que el anterior, así que la cadena siempre acaba; nunca se visita nada | `tests/unit/url-intel.test.js` |
| IP disfrazada que `new URL` ya normaliza (`3232235777`, `0xC0A80001`, `0300.0250.0.1`) | Se mira el host del texto original con un regex acotado a 300 caracteres | `tests/unit/url-intel.test.js` |
| Valores del atacante dentro de un patrón STIX (`'`, `\`, `]`) o que rompan el JSON | Patrones con `\` y `'` escapados; un único `JSON.stringify`; validador propio y fuzzing con lotes mutados | `tests/unit/stix.test.js`, `tests/unit/stix-validate.test.js`, `tests/fuzz/batch.test.js` |
| Un feed STIX que marque como maliciosos dominios legítimos | Indicadores solo para correos de phishing y nunca para marcas, acortadores, seguimiento, correo gratuito, redes sociales o alojamiento compartido | `tests/unit/stix.test.js` |

### Render (`src/ui/`)

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| XSS con el HTML del correo | Solo `textContent`; el HTML se recorre sin crear nodos; ningún `innerHTML`, `document.write` ni `eval` en `src/` | `tests/unit/security.test.js` |
| Trojan Source, RLO, invisibles | Se muestran como `⟦U+202E⟧` | `tests/unit/security.test.js` |
| URLs del correo que se puedan pulsar en la vista «URLs» | Ningún `<a>`: todo texto defanged en `textContent` | `tests/unit/urls-ui.test.js`, `tests/e2e/a11y.e2e.js` |
| Inyección en el grafo SVG por nombres de nodos (asuntos, dominios, nombres de fichero) | `svgEl()` con lista blanca de etiquetas y atributos (sin `<a>`, `<foreignObject>`, `href` ni `on*`); el texto en `textContent`; valores defanged | `tests/unit/graph-ui.test.js` |
| Clickjacking | La página no se ejecuta dentro de un iframe | Revisión manual (`src/ui/app.js`) |
| Veredicto engañoso | Estados de autenticación separados y nunca «verificado» sin comprobarlo | `tests/unit/auth-evaluate.test.js` |

### CSP y red (`index.html`)

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| Fuga por `fetch`, píxel o CSS | `default-src 'none'`, `connect-src 'none'`, `img-src 'self' data:`, `no-referrer`; las muestras van dentro de `samples/data.js` | `tests/e2e/privacy.e2e.js` en Chromium real, con control negativo que sí filtra |
| Precarga DNS (`<link rel=dns-prefetch>`, dominios de `<img>`) | El HTML del correo nunca llega al DOM: el render solo crea nodos de texto, así que no hay elemento que dispare la consulta. `x-dns-prefetch-control: off` como segunda barrera | `tests/unit/security.test.js` (sin `innerHTML` y el meta presente). El e2e no ve consultas DNS: Playwright solo intercepta peticiones HTTP |
| Un fallo futuro que inserte HTML | Trusted Types (`require-trusted-types-for 'script'; trusted-types 'none'`) | `tests/unit/security.test.js` |
| Worker sin CSP (red libre dentro del worker) | El worker nace de `blob:` y hereda la CSP del documento (`connect-src 'none'`, `script-src 'self'`); `worker-src blob:` sin URLs y Trusted Types con una sola política privada que solo acepta `blob:` propio, ver [ADR 0007](adr/0007-worker-con-csp-heredada.md) | `tests/e2e/worker.e2e.js` (Chromium, Firefox y WebKit en CI: fetch, XHR, WebSocket, import remoto, eval e importScripts bloqueados desde dentro del worker), `tests/unit/security.test.js`, `tests/unit/analysis-worker.test.js` |

### Historial (`src/storage/`)

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| Datos del correo guardados sin querer | Apagado por defecto: sin el interruptor no se abre IndexedDB. `slimReport` quita el cuerpo, el HTML, las cabeceras en bruto y los bytes de los adjuntos, y recorta a 40 caracteres la evidencia de las reglas de lenguaje y HTML. `validateEntry` vuelve a recortar todo lo que llega de un fichero o de otra pestaña | `tests/unit/storage-schema.test.js` (prueba de propiedad), `tests/e2e/history.e2e.js` (`indexedDB.databases()` sin `phishlens` con el historial apagado) |
| Entradas manipuladas (otra pestaña, una extensión, un fichero importado) | `JSON.parse` con reviver que descarta `__proto__`, `constructor` y `prototype`; copia limpia solo con objetos planos; esquema propio (UUID, fecha ISO, nivel, puntuación, 500 hallazgos, listas de técnicas e IOCs, cadenas de 10.000 caracteres, 1 MB por entrada); importación de 20 MB y 500 entradas como mucho; todo se pinta con `textContent` y defanged | `tests/unit/storage-schema.test.js`, `tests/unit/storage-history.test.js`, `tests/unit/history-ui.test.js` |
| Borrado parcial que deja restos | «Borrar todo» usa `indexedDB.deleteDatabase` y no la vuelve a crear hasta el siguiente análisis guardado | `tests/unit/history-control.test.js`, `tests/e2e/history.e2e.js` |

### Panel (`src/intel/stats.js`, `src/ui/panels/dashboard.js`)

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| Texto del atacante (remitente, dominio, técnica) dentro de las gráficas | Las gráficas se hacen con `svgEl` y su lista blanca de etiquetas y atributos; nombres y valores van en `textContent`, con los caracteres de control de dirección revelados y recortados a 80 caracteres; la tabla equivalente lleva el texto entero | `tests/unit/bar-chart.test.js` (`<script>`, RLO y 10.000 caracteres), `tests/unit/dashboard-ui.test.js` |
| `data-ioc` y `data-sha` usados como algo más que texto | `data-ioc` solo rellena la búsqueda del historial (sin enlaces, defanged en pantalla); `data-sha` solo se acepta como 64 hex y solo sirve de clave del índice `sha256` | `tests/unit/storage-history.test.js`, `tests/e2e/dashboard.e2e.js` |
| Lotes guardados manipulados | `validateBatch`: id, fecha ISO, listas de cadenas y 200 campañas como mucho; los que no cumplen se ignoran | `tests/unit/storage-schema.test.js`, `tests/unit/history-control.test.js` |
| Cifras que dependen de claves del correo | Recuentos con `Map` (nunca objetos indexados con texto del correo) y desempates por cadena | `tests/unit/stats.test.js` (prueba de propiedad con 50 órdenes) |

### Informe forense (`src/intel/forensic.js`, `src/ui/views/forensic.js`)

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| Texto del atacante o de las notas interpretado como HTML en el informe | Todo se pinta con `el()` y `textContent`, con los caracteres de control de dirección revelados; IOCs, evidencias y cadenas de URLs van defanged | `tests/unit/forensic-ui.test.js` (`<script>` y RLO), `tests/unit/forensic.test.js` |
| Informe que no corresponde al correo o JSON editado después | SHA-256, SHA-1 y MD5 de los bytes del fichero, también con BOM o Latin-1 (o del texto en UTF-8, y el informe lo dice), comparados con `node:crypto`; `reportSha256` al final del JSON y `verifyForensicJson` que detecta cualquier cambio | `tests/unit/forensic.test.js`, `tests/e2e/forensic.e2e.js` |
| La impresión muestra otro análisis o la interfaz | Al imprimir solo se ve `.forensic`, creado en `beforeprint` con el informe abierto y quitado en `afterprint` | `tests/e2e/a11y.e2e.js`, `tests/e2e/forensic.e2e.js` |

### Notas del analista (`src/storage/history.js`)

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| Notas enormes o de otro tipo en la base o en un import | Cadena de 5.000 caracteres como mucho (se recorta al guardar y `validateEntry` rechaza lo demás); `setNotes` solo acepta un SHA-256 de 64 hex | `tests/unit/storage-schema.test.js`, `tests/unit/storage-history.test.js` |
| Notas guardadas con el historial apagado | `saveNotes` no abre IndexedDB si el historial está apagado | `tests/unit/history-control.test.js`, `tests/e2e/forensic.e2e.js` (privacidad) |

### Reglas propias (`src/rules/`)

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| ReDoS con una regla escrita para bloquear la pestaña | Sin expresiones regulares: ocho operadores de texto y listas sobre valores normalizados una vez por análisis; `body.text` hasta 256 K caracteres | `tests/unit/rules-validate.test.js` (ningún `RegExp(` en `src/rules/`), `tests/unit/rules-evaluate.test.js` (100 reglas × 20 condiciones sobre 1 MB en menos de 300 ms) |
| Prototype pollution o lectura de propiedades internas desde el fichero | Claves desconocidas (también `__proto__`, `constructor` y `prototype`) son error; campos con un `Map` de funciones y operadores con `Object.hasOwn`, nunca `obj[texto]`; las reglas aceptadas son objetos nuevos | `tests/unit/rules-validate.test.js` (Review Focus 1), `tests/fuzz/rules.test.js` |
| Ficheros gigantes o anidados para agotar CPU | 200 KB, 100 reglas, 4 niveles, 20 condiciones y 200 valores; el validador nunca lanza ni pasa de 50 ms | `tests/fuzz/rules.test.js` (2.000 ficheros mutados con semilla) |
| Una regla que esconde el phishing | Las reglas propias solo añaden hallazgos de riesgo (`low` o más) con los mismos techos por categoría | `tests/unit/rules-evaluate.test.js` (prueba de propiedad: 17 muestras × 200 reglas) |
| Texto del fichero en la página | Títulos, ids y errores con `textContent` y los caracteres de dirección revelados | `tests/unit/rules-ui.test.js`, `tests/unit/rules-evaluate.test.js` |
| Reglas guardadas manipuladas en IndexedDB | Se guarda el texto del fichero y se vuelve a validar al leerlo; si no pasa, se ignora | `tests/unit/storage-history.test.js` |

### Cadena de suministro

| Riesgo | Mitigación | Prueba |
| --- | --- | --- |
| Dependencia maliciosa en la web | Cero dependencias en ejecución ([ADR 0001](adr/0001-sin-dependencias-en-ejecucion.md)); Playwright y axe-core solo en tests, fijados en `package-lock.json` | `tests/unit/security.test.js` (sin `dependencies` ni imports externos) |
| Actions o paquetes comprometidos | Actions fijadas por SHA, `persist-credentials: false`, `npm ci --ignore-scripts`, `npm audit` y Dependabot | CI (`.github/workflows/phishlens-tests.yml`) |

## Riesgos aceptados

- La CSP va en un `<meta>`: no hay `frame-ancestors` ni cabeceras de respuesta (GitHub Pages no lo permite).
- Si el navegador no puede crear el worker, el análisis vuelve al hilo principal: con 25 MB la pestaña puede quedarse quieta unas décimas de segundo.
- Durante un análisis el texto del correo está dos veces en memoria (página y worker).
- El test de privacidad solo usa Chromium. La herencia de la CSP en el worker se prueba también en Firefox y WebKit; el resto de los e2e, no.
