# ADR 0006 · Public Suffix List empaquetada

- **Estado:** aceptada
- **Fecha:** 2026-11-11

## Contexto

Media aplicación compara dominios por su dominio registrable: la alineación DMARC, el Reply-To y el Return-Path de otro dominio, el Message-ID, la ruta, las campañas, los indicadores STIX y los dominios parecidos. Hasta la 3.1 se calculaba con ocho sufijos de segundo nivel escritos a mano. Así `attacker.github.io` y `legit.github.io` eran «el mismo dominio» y quedaban alineados para DMARC, igual que cualquier pareja de clientes de pages.dev, herokuapp.com, netlify.app o duckdns.org. También se juntaban sufijos ICANN enteros como `ne.jp`, `ltd.uk` o `nom.es`, y un dominio en Unicode no coincidía con su forma punycode.

## Opciones

| Opción | A favor | En contra |
| --- | --- | --- |
| PSL completa en un módulo generado | Algoritmo oficial con comodines y excepciones, sección privada incluida, offline y sin dependencias | ~160 KB más en la web (~45 KB comprimidos); hay que regenerarla de vez en cuando |
| Librería `tldts` | Mantenida y probada | Primera dependencia en ejecución, en contra del [ADR 0001](0001-sin-dependencias-en-ejecucion.md) |
| Ampliar la lista a mano | Pequeña | Seguiría fallando con cualquier sufijo olvidado |

## Decisión

- `tools/gen-psl.mjs` convierte una copia de `public_suffix_list.dat` descargada a mano en `src/data/psl.js`, con la fecha, el SHA-256 de la copia y las reglas en punycode. La web nunca descarga la lista.
- `registrableDomain` aplica el algoritmo oficial (la regla más larga, `*.` y `!`) con las secciones **ICANN y privada**. Pasa los IDN a punycode con `new URL()`, que el navegador trae de serie.
- Se usa también la parte privada a propósito: para un analizador de phishing, dos clientes de github.io son organizaciones distintas. DMARC en un servidor real solo usa la parte ICANN, así que PhishLens es más estricto: puede decir «no alineado» donde un servidor diría «alineado», nunca al revés.
- Si un nombre no tiene dominio registrable (una IP, `localhost`, un sufijo público) se devuelve el propio nombre, como antes. `organizationalDomain` devuelve `null` en esos casos y es lo que comprueba la batería oficial.

## Consecuencias

- `tests/unit/psl.test.js` pasa la batería oficial `test_psl.txt` entera, más los casos multiusuario, IDN y DMARC de la auditoría.
- La lista tiene fecha: el test avisa (sin fallar) cuando la copia supera los 180 días. Para actualizarla: `node tools/gen-psl.mjs public_suffix_list.dat`.
- `src/data/psl.js` es un fichero bajo la Mozilla Public License 2.0, como la PSL. El resto de PhishLens sigue siendo MIT.
- DMARCbis cambia la PSL por un recorrido del árbol DNS: sin red no se puede hacer, y queda en [limitaciones](../limitations.md).
