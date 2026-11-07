# Arquitectura de PhishLens

PhishLens es una aplicación web estática: todo el análisis ocurre en el navegador y ningún dato del correo sale de él. El código está dividido en capas con una regla de dependencias estricta, comprobada por `tests/unit/structure.test.js`.

## Capas

```
ui ──▶ core ──▶ detectors · auth · intel ──▶ parser ──▶ data · lib
```

| Carpeta | Responsabilidad | Puede importar |
| --- | --- | --- |
| `src/lib/` | Utilidades puras: SHA-256, SHA-1, MD5, UUIDv5, límites, texto seguro | nada interno |
| `src/data/` | Marcas, listas de referencia, mapa MITRE ATT&CK | `lib` |
| `src/parser/` | RFC 5322 + MIME (`eml.js`), cabeceras `Received` (`received.js`), HTML sin DOM (`html.js`), URLs (`url.js`) | `data`, `lib` |
| `src/detectors/` | Un fichero por familia de señales, todos con `detect(email) → Finding[]` | `core/finding.js`, `parser`, `data`, `lib` |
| `src/auth/` | Autenticación verificada / declarada / no verificable (llega en el PR 2 de la 2.2) | `core/finding.js`, `parser`, `data`, `lib` |
| `src/intel/` | Indicadores de compromiso (`ioc.js`), URLs desenvueltas sin red (`url.js`), grafo del lote (`graph.js`), su disposición radial (`layout.js`), huella de plantilla (`kit.js`), campañas (`campaigns.js`) y el bundle STIX 2.1 (`stix.js`) | `parser`, `data`, `lib`, los niveles de `core/scoring.js` |
| `src/storage/` | Historial opcional: informe recortado y validador de entradas (`schema.js`), IndexedDB y memoria detrás de la misma interfaz (`backends.js`), y guardar, listar, buscar, comparar, exportar e importar (`history.js`). Ver [ADR 0004](adr/0004-historial-local-opcional.md) | `core`, `intel`, `lib` |
| `src/core/` | Modelo de hallazgo, motor, recomendaciones; en la 2.2, puntuación contextual | todo salvo `ui` |
| `src/ui/` | Único código que toca el DOM; todo el contenido del correo se inserta con `textContent` (`ui/dom.js`). Dentro: `components/` (piezas sin estado que solo importan `dom.js`, otros componentes y `data/`), `panels/` (cada vista del modo analista), `views/` (modo sencillo y analista), `route.js` (rutas `#analista/<vista>`, funciones puras) y `app.js` (eventos) | todo |

`tools/stix-validate.mjs` valida cualquier bundle STIX (lo usan los tests, el fuzzing y la línea de comandos).

Nada fuera de `src/ui/` usa `document` ni `window`, así que todo el motor se prueba en Node con `node --test`.

## Flujo de un análisis

1. `parseEml(raw)` convierte el texto en un objeto email. Nunca lanza: una entrada basura se trata como texto.
2. `analyze(email)` ejecuta cada detector. Si uno falla, se registra en `errors` y el resto sigue.
3. El informe reúne hallazgos, técnicas ATT&CK e IOCs.
4. `renderReport()` lo pinta sin interpretar nunca el HTML del correo.

Con varios correos, `analyzeBatch()` (`src/core/batch.js`) repite los pasos 1–3 con cada uno, cediendo el hilo entre correos; luego `buildGraph()` y `findCampaigns()` trabajan sobre los informes y `renderReport()` recibe el lote como contexto (`options.batch`).

## Objeto email

Además de `from`, `replyTo`, `returnPath`, `subject`, `text`, `html`, `links` y `attachments`, el parser da:

| Campo | Contenido |
| --- | --- |
| `headers` | `Map` nombre → valores decodificados |
| `headerList` | `[{ name, value, raw, index }]` en orden de aparición, con el texto crudo (plegado incluido) que necesita DKIM |
| `rawBody` | Cuerpo sin decodificar, acotado por `LIMITS.rawBytes` |
| `parseNotes` | `[{ code, detail }]`: límites alcanzados (`limit.*`) y anomalías MIME (`mime.*`) |
| `attachments[]` | `{ filename, contentType, size, bytes, sha256, truncated }`. Los bytes nunca se ejecutan ni se interpretan; el informe no los incluye |

## Hallazgo

```js
{
  id, detector, severity, points, title, detail, evidence, mitre,
  category,     // authentication | sender | links | attachments | language | infrastructure
  reliability,  // high | medium | low
  provenance,   // verified | declared | inferred | unverifiable
  polarity,     // risk | trust
  techniques,   // [{ id, name, url }]
}
```

`category`, `reliability` y `provenance` toman un valor por defecto según el detector (`DETECTOR_DEFAULTS` en `src/core/finding.js`). La puntuación contextual de la 2.2 se construye sobre ellos.

## Límites

Todos en `src/lib/limits.js`: entrada de 25 MB, 1.000 cabeceras de hasta 64 KB, profundidad MIME 20, 500 partes, 200 enlaces, 100 adjuntos, 10 MB decodificados por adjunto y 25 MB de cuerpo crudo. Alcanzar uno nunca rompe el análisis: se anota en `parseNotes`.

## Decisiones

Las decisiones de arquitectura están en [`docs/adr/`](adr/).
