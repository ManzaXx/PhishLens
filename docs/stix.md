# Exportar a STIX 2.1

PhishLens puede descargar el análisis en [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html), el formato estándar para compartir inteligencia de amenazas. Está en **Exportar → Descargar STIX 2.1**. El fichero se genera en el navegador y no sale de él hasta que tú lo subas a algún sitio.

- **Sin lote:** se exporta el correo (o la URL) que tienes abierto.
- **Con un lote:** se exporta el lote entero, con sus campañas.

## Qué objetos salen

| Objeto STIX | De dónde sale | Cuándo |
| --- | --- | --- |
| `email-message` | Remitente, asunto, fecha y adjuntos (nunca el cuerpo) | Si se analizó un correo, no una URL suelta |
| `email-addr`, `domain-name`, `url`, `ipv4-addr`, `ipv6-addr` | Los IOCs del correo (las URLs ya desenvueltas) | Siempre |
| `file` | Cada adjunto, con SHA-256, SHA-1, MD5, nombre y tamaño | Si hay adjuntos |
| `indicator` | Un patrón STIX por IOC (`[url:value = '…']`, `[file:hashes.'SHA-256' = '…']`…) | Solo en correos «Probable phishing» o «Phishing casi seguro», y para los adjuntos con un hallazgo grave |
| `attack-pattern` | Cada técnica de MITRE ATT&CK, con su referencia externa | Si el análisis encontró técnicas |
| `campaign` | Cada campaña del lote y lo que tienen en común sus correos | Solo con un lote |
| `relationship` | `based-on` (indicador → observable), `indicates` (indicador → técnica o campaña) y `uses` (campaña → técnica) | Siempre que haya ambos extremos |

Los dominios que salen en el phishing sin ser del atacante no se marcan como indicadores: los de marcas reales, los acortadores, el email marketing, el correo gratuito, las redes sociales y las plataformas de alojamiento. Siguen apareciendo como observables.

## Ids deterministas

El mismo correo da siempre los mismos ids. Así, si exportas dos veces o desde dos equipos, la plataforma que lo reciba no duplica nada.

- **Observables** (`domain-name`, `url`, `file`…): UUIDv5 con el namespace oficial de STIX y sus propiedades de identidad (STIX 2.1, §2.9). Son los mismos ids que calcula la librería oficial [`stix2`](https://github.com/oasis-open/cti-python-stix2) de OASIS, y los tests lo comprueban.
- **Indicadores, técnicas, campañas y relaciones**: UUIDv5 con un namespace propio de PhishLens.

El JSON se genera con `JSON.stringify`, nunca concatenando texto. Los valores dentro de un patrón se escapan (`\` → `\\`, `'` → `\'`).

## Validar un fichero

```bash
node tools/stix-validate.mjs phishlens-stix-2026-11-07.json
```

Comprueba las propiedades obligatorias, el formato de ids y timestamps, `spec_version`, los patrones de los tipos que usa PhishLens y que cada referencia apunte a un objeto del bundle. Lo usan también los tests y el fuzzing: todo lote generado da un bundle válido.

Además, los bundles de las 13 muestras y del lote de campaña se pasaron una vez por el validador oficial de OASIS ([`stix2-validator`](https://github.com/oasis-open/cti-stix-validator)): los 14 son válidos y no hay ningún error. Quedan tres avisos, que son decisiones conscientes:
- **{103}:** los ids no son UUIDv4. Son UUIDv5 a propósito, para que sean deterministas.
- **{302}:** la referencia de MITRE no lleva hash.
- **{202}:** la relación `based-on` apunta a un observable.

## Importarlo en una plataforma de CTI

**OpenCTI:** *Data → Import → Upload files* con el `.json` y el conector *ImportFileStix*. Los observables, indicadores, técnicas y campañas aparecen enlazados.

**MISP:** *Event Actions → Import from… → STIX 2.1* (o `POST /events/upload_stix/2`). MISP crea un evento con un atributo por observable o indicador.

> **Prueba manual pendiente:** la spec (§1, criterio 4) pide probar la importación una vez a mano en OpenCTI o MISP. Resultado: _(por rellenar tras la prueba)_.
