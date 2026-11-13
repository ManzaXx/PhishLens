# Evaluación del motor

Cómo se mide si PhishLens acierta, con qué datos y qué significan los números. La herramienta es `tools/eval.mjs`
(`npm run eval`); no necesita red y no saca nada del equipo.

## Qué se mide y por qué así

La nota (0–100) es un **indicador heurístico, no una probabilidad** ([docs/scoring.md](scoring.md)). Por eso no se
evalúa el número, sino los **tramos** que ve el usuario:

- **Sospechoso o peor (≥ 25):** el correo pide atención. Aquí se quiere **cobertura** (que casi ningún phishing quede
  por debajo) aceptando algún legítimo raro.
- **Probable phishing o peor (≥ 60):** el correo se trata como phishing. Aquí se quiere **precisión**: un legítimo en
  este tramo es un falso positivo de verdad, el peor error para la confianza en la herramienta.

Para cada umbral se da la matriz de confusión (aciertos, falsos negativos, falsos positivos, legítimos bien
clasificados) y tres tasas:

| Tasa | Qué responde |
| --- | --- |
| Precisión | De lo que marcamos, ¿cuánto era phishing? |
| Cobertura (recall) | Del phishing que había, ¿cuánto marcamos? |
| Tasa de falsos positivos | De los legítimos, ¿cuántos marcamos? |

Además:

- **Distribución de notas** por tramo de 10 y por clase: dos clases bien separadas se ven a simple vista; un solape
  entre 25 y 60 dice que el umbral está apretado.
- **Lista nominal** de los legítimos marcados (≥ 60), de los legítimos en «Sospechoso» y del phishing por debajo de 60,
  con las reglas que saltaron en cada uno. Son los correos que hay que mirar uno a uno.
- **Reglas por clase:** en cuántos legítimos y en cuántos phishing salta cada regla. Una regla que salta en muchos
  legítimos y en poco phishing es candidata a bajar de gravedad o a ser informativa (así se decidieron `auth.missing` y
  `headers.missing-messageid` en la auditoría 3.1).

## Con qué datos

### Muestras empaquetadas (`samples/`)

Las 17 muestras que trae la web. Están **construidas a mano** para enseñar cada regla: las de phishing concentran
señales y las legítimas son limpias o «difíciles» a propósito (plataforma de envío con `Return-Path` ajeno y enlaces de
seguimiento, reseteo de contraseña con prisa, lista de correo con `From` reescrito, reenvío con las cabeceras del
original en el cuerpo). Sirven para **no romper lo que ya funciona** (los goldens de `tests/unit/golden.test.js`), no
para estimar tasas reales: 17 correos no dan ninguna estadística.

### Corpus propio (`corpus/`, fuera de git)

Para una evaluación honesta hacen falta correos reales, y los correos reales son privados. Por eso el corpus vive en
`corpus/`, que está en `.gitignore`, y la herramienta **nunca imprime el contenido** de un correo: solo el nombre del
fichero, la nota y los ids de las reglas. `--write-docs` se niega a funcionar con un corpus propio.

Formato:

```
corpus/
├── manifest.csv
├── 2026-11-02-newsletter-banco.eml
├── 2026-11-03-aviso-correos-falso.eml
└── …
```

`manifest.csv`, una línea por correo, `fichero,etiqueta[,nota]`, con la etiqueta `legit` o `phishing`:

```
# fichero,etiqueta,nota
2026-11-02-newsletter-banco.eml,legit,newsletter real de mi banco
2026-11-03-aviso-correos-falso.eml,phishing,recibido el 3/11, enlace a dominio .top
```

Y se ejecuta `npm run eval -- corpus/`. Para que la medida valga algo conviene que el corpus tenga **más legítimos
que phishing** (en una bandeja real es así) y legítimos **variados**: facturas, notificaciones de servicios, correos
internos, reenvíos, listas, boletines.

## Cómo leer un cambio

Antes de tocar la puntuación o una regla se guarda la salida de `npm run eval` (sobre las muestras y, si lo hay, sobre el
corpus); después se vuelve a ejecutar y se comparan:

1. **Falsos positivos a ≥ 60.** Si suben, el cambio no entra salvo justificación escrita.
2. **Falsos negativos a ≥ 60.** Si suben, hay que mirar cada correo: ¿pierde una señal real o la nota anterior se la
   daba una señal que no debía contar?
3. **Reglas por clase.** Una regla nueva que salta en más del 20 % de los legítimos necesita bajar de peso.

## Límites

- Las muestras no son una distribución real; los porcentajes de la tabla siguiente **no se pueden extrapolar**.
- Sin corpus propio, lo único que se garantiza es que los ejemplos documentados no cambian de tramo sin querer.
- La herramienta mide el motor, no la interfaz: lo que ve el usuario (veredicto, pasos, señales) se prueba en los e2e.

## Resultados con las muestras empaquetadas

Generado con `npm run eval -- --write-docs`.

<!-- eval:start -->
Corpus: samples/ (muestras empaquetadas) · 17 correos (6 legítimos, 11 phishing) · 2026-11-13

| Umbral | Aciertos (phishing) | Falsos negativos | Falsos positivos | Legítimos bien | Precisión | Cobertura | Tasa de falsos positivos |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Sospechoso o peor (≥ 25) | 11 | 0 | 0 | 6 | 100 % | 100 % | 0 % |
| Probable phishing o peor (≥ 60) | 10 | 1 | 0 | 6 | 100 % | 91 % | 0 % |

**Distribución de notas**

| Tramo | Legítimos | Phishing |
| --- | --- | --- |
| 0–9 | 5 | 0 |
| 10–19 | 1 | 0 |
| 50–59 | 0 | 1 |
| 60–69 | 0 | 1 |
| 70–79 | 0 | 3 |
| 80–89 | 0 | 2 |
| 90–100 | 0 | 4 |

**Legítimos marcados como phishing (≥ 60)**

- ninguno

**Legítimos en «Sospechoso» (25–59)**

- ninguno

**Phishing por debajo de «Probable phishing» (< 60)**

- `09-cabeceras-trampa.eml` → 55 (suspicious): headers.duplicate, headers.duplicate-from, sender.brand-impersonation, sender.display-name-address, sender.sender-mismatch

**Reglas por clase** (en cuántos legítimos y en cuántos phishing salta cada una; arriba, las que más saltan en legítimos)

| Regla | Legítimos | Phishing |
| --- | --- | --- |
| `headers.messageid-domain` | 2/6 | 1/11 |
| `language.urgency` | 1/6 | 7/11 |
| `sender.returnpath-mismatch` | 1/6 | 2/11 |
| `auth.dmarc` | 0/6 | 7/11 |
| `auth.dkim` | 0/6 | 6/11 |
| `language.threat` | 0/6 | 6/11 |
| `sender.brand-impersonation` | 0/6 | 6/11 |
| `auth.spf` | 0/6 | 5/11 |
| `language.credentials` | 0/6 | 5/11 |
| `lookalike.brand-in-domain` | 0/6 | 3/11 |
| `sender.replyto-mismatch` | 0/6 | 3/11 |
| `links.brand-in-path` | 0/6 | 2/11 |
| `links.insecure-login` | 0/6 | 2/11 |
| `links.mismatch` | 0/6 | 2/11 |
| `lookalike.typosquat` | 0/6 | 2/11 |
| `attachments.archive` | 0/6 | 1/11 |
| `attachments.archive-executable` | 0/6 | 1/11 |
| `attachments.double-extension` | 0/6 | 1/11 |
| `attachments.encrypted-archive` | 0/6 | 1/11 |
| `attachments.pdf-active` | 0/6 | 1/11 |
| `attachments.type-mismatch` | 0/6 | 1/11 |
| `auth.dmarc-unaligned` | 0/6 | 1/11 |
| `headers.duplicate` | 0/6 | 1/11 |
| `headers.duplicate-from` | 0/6 | 1/11 |
| `headers.mailer` | 0/6 | 1/11 |
| `html.form` | 0/6 | 1/11 |
| `html.hidden-text` | 0/6 | 1/11 |
| `links.high-entropy` | 0/6 | 1/11 |
| `links.ip` | 0/6 | 1/11 |
| `links.nested-redirect` | 0/6 | 1/11 |
| `links.non-standard-port` | 0/6 | 1/11 |
| `links.open-redirect` | 0/6 | 1/11 |
| `links.punycode` | 0/6 | 1/11 |
| `links.shortener` | 0/6 | 1/11 |
| `links.tld` | 0/6 | 1/11 |
| `lookalike.deceptive-subdomain` | 0/6 | 1/11 |
| `lookalike.mixed-script-domain` | 0/6 | 1/11 |
| `lookalike.whole-script` | 0/6 | 1/11 |
| `route.helo-mismatch` | 0/6 | 1/11 |
| `route.private-ip-boundary` | 0/6 | 1/11 |
| `route.slow-delivery` | 0/6 | 1/11 |
| `route.time-travel` | 0/6 | 1/11 |
| `sender.display-name-address` | 0/6 | 1/11 |
| `sender.invisible-chars` | 0/6 | 1/11 |
| `sender.mixed-script` | 0/6 | 1/11 |
| `sender.sender-mismatch` | 0/6 | 1/11 |
<!-- eval:end -->
