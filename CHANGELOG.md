# Changelog

## 3.1.0 · 2026-11-11 · Español e inglés

Especificación en [docs/specs/2026-11-11-phishlens-3.1-i18n-design.md](docs/specs/2026-11-11-phishlens-3.1-i18n-design.md).

### Añadido
- **Interfaz en español e inglés**: botón ES / EN en la cabecera, junto al tema. La primera vez se elige el idioma del navegador y luego se recuerda. Cambiar de idioma traduce lo que está a la vista sin volver a analizar ni guardar nada en el historial; las notas del informe forense se conservan. `<html lang>` cambia también.
- `src/i18n/`: diccionarios `es.js` y `en.js` (unos 545 textos cada uno) y `t(clave, params)` con plurales (`Intl.PluralRules`), fechas y números del idioma activo. Sin dependencias.
- La ruta no cambia (`#analista/senales`): los enlaces ya compartidos siguen funcionando, solo cambian los rótulos.
- Pruebas: paridad de claves y `{param}` entre los dos idiomas, un test que falla si queda un texto fijo en `src/ui/`, y e2e en inglés (axe en claro y oscuro, 360 px, privacidad, cambio en mitad de un análisis).
- **El informe también en inglés**: las 86 reglas (título, detalle y texto llano), el veredicto, los tres pasos, la confianza, el resumen, la autenticación, las campañas, los errores de las reglas propias, los títulos de las muestras y el informe forense.
- El motor sigue escribiendo en español y deja al lado referencias neutras (`params` en cada hallazgo; `summaryRef`, `mainReasonRef`, `verdict.stepCodes`, `confidence.codes`, `auth.*.detailRef`). La interfaz traduce en un solo sitio (`src/ui/localize.js`) y, si falta una traducción o un parámetro, usa el texto en español entero: los análisis guardados con la 3.0 se siguen leyendo.
- Las exportaciones llevan `lang` (`es` o `en`): el JSON del informe, cada objeto STIX ([docs/stix.md](docs/stix.md)) y el informe forense. Los ids no cambian con el idioma y el `reportSha256` vale en los dos.
- Las reglas propias se muestran tal cual las escribió su autor, en cualquier idioma.
- Capturas en inglés en `docs/img/en/` (`node tools/screenshots.mjs --lang en`).
- `tests/unit/rules-en.test.js` ejecuta los tests de los detectores guardando cada hallazgo real y comprueba que su texto en inglés no pierde ningún parámetro.

## 3.0.0 · 2026-11-11 · Plataforma de Threat Intel local

Especificación en [docs/specs/2026-11-07-phishlens-3.0-design.md](docs/specs/2026-11-07-phishlens-3.0-design.md).

### Añadido
- **Historial local opcional** (apagado por defecto, [ADR 0004](docs/adr/0004-historial-local-opcional.md)): un interruptor en la portada guarda en IndexedDB el informe de cada análisis y de cada lote, nunca el correo. Hasta 500 análisis; los repetidos se actualizan.
- Vista **«Historial»** en el modo analista: tabla paginada, búsqueda de un IOC en todo lo guardado, filtros por nivel, fecha y técnica, comparar dos análisis, abrir uno guardado, borrar uno o todo, y exportar o importar en `.json` (20 MB y 500 entradas como mucho, cada una validada).
- Vista **«Panel»** en el modo analista (grupo Historial): cifras clave (análisis guardados, probable phishing o peor, campañas, IOCs distintos, con adjunto peligroso), niveles en el tiempo por día o semana, técnicas ATT&CK más vistas, IOCs repetidos que abren su búsqueda, remitentes y dominios más frecuentes y campañas recientes con «Abrir el último correo».
- Gráficas SVG propias (`stackedBars`, `hBars`) con lista blanca, `<title>` al pasar el ratón, leyenda con texto y su tabla de datos plegada; tokens `--chart-*` validados para daltonismo en claro y oscuro.
- `src/intel/stats.js`: todas las cifras en una pasada, sin depender del orden de entrada.
- Los lotes guardados conservan sus campañas con las pistas en texto.
- **Informe forense** ([docs/forensic.md](docs/forensic.md)) en «Exportar»: PDF desde el diálogo de impresión, con el SHA-256 y el número de página al pie, y JSON `phishlens-forense-AAAA-MM-DD.json` con `reportSha256` para detectar cambios. Identificación con SHA-256, SHA-1 y MD5, hallazgos por gravedad, autenticación, cronología con los saltos que van atrás, IOCs, adjuntos, URLs y límites. Sustituye a «Imprimir».
- **Notas del analista** (5.000 caracteres como mucho) en el informe; con el historial activado se guardan con el análisis y entran en la exportación.
- **Reglas propias en JSON** ([docs/rules.md](docs/rules.md), [ADR 0005](docs/adr/0005-reglas-declarativas-sin-regex.md)): «Reglas propias → Cargar reglas (.json)» en la portada valida el fichero entero (errores con regla, ruta y motivo), enseña una vista previa sobre el historial y las activa como un detector más (`custom`). Campos y operadores en listas cerradas, sin expresiones regulares, con topes de 200 KB, 100 reglas, 4 niveles, 20 condiciones y 200 valores. Una regla propia nunca baja la nota. Con el historial se guardan en un store nuevo (`rules`, base v2).
- `samples/rules/ejemplo.json` con tres reglas de ejemplo y `docs/rules.schema.json` (JSON Schema 2020-12).
- `src/storage/` con su validador de esquema y su informe recortado, y e2e del historial (privacidad, recarga, borrar, exportar e importar, axe, teclado y diseño).

## 2.3.0 · 2026-11-07 · Threat Intel local

Especificación en [docs/specs/2026-11-06-phishlens-2.3-design.md](docs/specs/2026-11-06-phishlens-2.3-design.md).

### Añadido
- **Modo sencillo** por defecto: veredicto en una frase («Parece legítimo», «Ten cuidado», «No te fíes: es phishing») con el porqué, tres pasos de qué hacer y hasta cinco señales en lenguaje llano.
- **Modo analista** con navegación lateral agrupada (Correo e Inteligencia) que pasa a barra horizontal en el móvil, y la vista en la URL (`#analista/<vista>`); el último modo elegido se recuerda.
- **Texto llano por regla** (`finding.plain`) para las 86 reglas, sin jerga y de 140 caracteres como mucho, y `report.verdict` en el JSON.
- **Sistema de diseño** ([docs/design-system.md](docs/design-system.md)): `tokens.css` con contraste ≥ 4,5 comprobado en claro y oscuro, escalas de espacio, tipo y radio, y componentes (`verdictCard`, `stepList`, `signalRow`, `findingCard`, `severityTag`, `meter`, `dataTable`, `chip`, `emptyState`, `navRail`, `modeSwitch`, `menuButton`).
- **Menú Exportar** con el patrón ARIA de menú (flechas, Inicio, Fin, Escape) y «Analizar otro» como acción principal.
- **E2E de diseño** a 360, 768 y 1280 px: sin scroll horizontal y objetivos táctiles de 44 px; axe, teclado y privacidad recorren los dos modos y todas las vistas.
- `tools/screenshots.mjs` para regenerar las capturas del README.
- **Adjuntos por dentro, sin abrirlos**: tipo real por sus primeros bytes, lista de un ZIP leída de su directorio central, macros VBA en documentos OLE y OOXML, instrucciones activas en PDF (también ofuscadas con `#xx`) y HTML smuggling. Nada se descomprime ni se ejecuta.
- **Ocho reglas nuevas**: `attachments.type-mismatch`, `archive-executable`, `encrypted-archive`, `pdf-active`, `ole-macro`, `html-smuggling`, `disk-image` y `lnk`, con técnicas ATT&CK T1036.008, T1027.006, T1027.013, T1553.005 y T1059.005.
- **SHA-1 y MD5** de cada adjunto, además de SHA-256, en el informe y en los IOCs.
- Vista **«Adjuntos»** en el modo analista y dos muestras nuevas: un `factura.pdf` que es un ejecutable y un correo con un PDF activo y un ZIP con contraseña (construidas byte a byte, sin código).
- Fuzzing por formato de adjunto (`tests/fuzz/files.test.js`).
- **Lotes**: hasta 50 `.eml` y 100 MB a la vez, analizados uno a uno cediendo el hilo entre correos, con un selector para ver cada uno. Los repetidos cuentan una vez y se dice qué archivos se saltan y por qué.
- **Grafo de IOCs** determinista (`src/intel/graph.js`): correos, direcciones, dominios, IPs, URLs y hashes unidos por `envía`, `enlaza`, `adjunta`, `resuelve-en` y `responde-a`, dibujado en SVG con una disposición radial, recorrible con el teclado y con una tabla equivalente.
- **Campañas** (`src/intel/campaigns.js`): correos que comparten dominio de envío, IP de entrada, dominio de enlace, adjunto o plantilla (similitud de *shingles* ≥ 0,6), con la marca que suplantan y sus técnicas ATT&CK. Gmail, los acortadores, el seguimiento y los dominios oficiales de las marcas no unen campañas.
- Vista **«Campañas»**, aviso de campaña en el modo sencillo y un **lote de ejemplo** de 4 correos.
- Fuzzing del lote (`tests/fuzz/batch.test.js`): el grafo y las campañas no lanzan y no dependen del orden.
- **URLs sin visitarlas** (`src/intel/url.js`): se desenvuelven las redirecciones dentro de la propia URL (parámetros como `url`, `next` o `redirect`, Google, Safe Links, Facebook, LinkedIn, base64 y codificación doble) con 10 saltos como máximo, y se detectan IPs disfrazadas (`http://3232235777`, hex, octal), credenciales, puertos raros y hosts con aspecto aleatorio.
- **Seis reglas nuevas**: `links.nested-redirect`, `links.open-redirect`, `links.obfuscated-ip`, `links.credentials-in-url`, `links.high-entropy` y `links.non-standard-port` (86 reglas en total). El resto de reglas de enlaces mira ya el destino final.
- Vista **«URLs»**: cada enlace con su cadena de saltos, su destino final y por qué es sospechoso; nada es clicable y todo va defanged. Muestra nueva **13 · Redirección anidada**.
- **Exportar → Descargar STIX 2.1** ([docs/stix.md](docs/stix.md)): `email-message`, observables, `file` con sus hashes, `indicator`, `attack-pattern`, `campaign` y sus relaciones, con ids UUIDv5 deterministas (los observables, iguales a los de la librería oficial `stix2`). Con un lote se exporta el lote entero.
- **Validador STIX propio** (`tools/stix-validate.mjs`), usado por los tests y el fuzzing. Los bundles de las muestras pasan además el validador oficial de OASIS sin errores.

### Cambiado
- La portada saca sus cifras del código (10 detectores, 86 reglas, ATT&CK 20.1) y «Cómo funciona» explica el motor real: topes por categoría, combinaciones y confianza. Ya no habla de «leve 5, media 15, grave 30».
- La cabecera es sólida y el informe deja de ser una región viva entera: un aviso corto anuncia el resultado al lector de pantalla y el foco va al título de cada vista nueva.
- Un nombre como `factura.exe.` o `factura.exe ` se lee como lo lee Windows, sin los puntos ni espacios del final.
- Los adjuntos salen de «Cabeceras y ruta» y pasan a su propia vista.
- `render.js` se parte en `ui/dom.js`, `ui/components/`, `ui/panels/` y `ui/views/`.

## 2.2.0 · 2026-11-05 · Motor fiable

Especificación en [docs/specs/2026-11-05-phishlens-2.2-design.md](docs/specs/2026-11-05-phishlens-2.2-design.md).

### Añadido
- **SHA-256 de cada adjunto**, calculado en local sin abrir el fichero, y exportado como IOC.
- El parser conserva las cabeceras en orden con su texto crudo, el cuerpo sin decodificar y anota en `parseNotes` cada límite alcanzado o multipart sin cerrar.
- Cada hallazgo indica su **categoría**, su **fiabilidad** y su **procedencia** (verificado, declarado, deducido o no verificable).
- **Autenticación en estados**: cada resultado de SPF, DKIM y DMARC dice si lo ha comprobado PhishLens, si lo declara el servidor receptor o si lo declara una cabecera sin confirmar. Nueva pestaña «Autenticación» y `report.auth` en el JSON.
- **Cabeceras `Authentication-Results` falsificadas**: se detectan las que imitan al receptor o a un proveedor conocido pero ya estaban escritas cuando el correo llegó (`auth.forged-results`).
- **DMARC sin alineación** (`auth.dmarc-unaligned`) y DMARC declarado como pass sin ningún resultado alineado (`auth.dmarc-declared-mismatch`).
- **DKIM sin red**: canonicalización RFC 6376 y comprobación del hash de cuerpo `bh=` (`auth.dkim-body-modified`, `auth.dkim-body-verified`, `auth.dkim-weak`). Con la clave pegada, verificación de la firma RSA-SHA256 o Ed25519 con WebCrypto, probada contra firmas de dkimpy.
- **SPF offline**: pegando el registro, evalúa `ip4`, `ip6` y `all` contra la IP de origen (`auth.spf-offline`); `include`, `a`, `mx` y similares quedan como no verificables.
- **Ruta `Received`**: detector nuevo con IP privada en el salto de entrada, horas que retroceden, entregas de más de 24 h, rutas de más de 25 saltos y HELO que dice ser una marca sin serlo. La pestaña de cabeceras marca cada salto con su aviso.
- **Cabeceras trampa**: varios `From`, cabeceras únicas repetidas, nombre visible con la dirección de otro dominio y `Sender` ajeno sin firma DKIM.
- **Dominios con otros alfabetos**: decodificador punycode propio (RFC 3492), tabla de confusables de Unicode 16 (UTS #39), dominios que mezclan alfabetos o están enteros en cirílico, homógrafos de marca con cualquier alfabeto (`ɑpple.com`, cherokee, copto), subdominios engañosos y combosquatting. Los dominios `xn--` se enseñan también en Unicode y la evidencia nombra cada letra extranjera (`⟦U+0430 а→a⟧`).
- **22 marcas españolas** con sus dominios oficiales comprobados y fechados.
- Tres muestras nuevas: ruta falsificada, cabeceras trampa y dominios Unicode.
- **Nota contextual**: seis categorías que saturan, combinaciones peligrosas (suplantación + autenticación fallida, suplantación + credenciales, marca + IP, credenciales + enlace sospechoso, adjunto + presión, mismo lookalike en remitente y enlaces), una firma DKIM verificada y alineada rebaja lo blando y nivel nuevo **«Phishing casi seguro»** (80+). Explicado en [docs/scoring.md](docs/scoring.md), con tests de propiedades.
- **Confianza del análisis** (alta, media o baja) con sus motivos, independiente de la nota.
- **MITRE ATT&CK 20.1** fijado y comprobado contra el bundle STIX oficial (`tools/check-mitre.mjs`): varias técnicas por señal, con su táctica y el motivo.
- [ADR 0002](docs/adr/0002-autenticacion-offline.md) y primera versión de [limitaciones](docs/limitations.md).
- Documentación de [arquitectura](docs/architecture.md) y primer ADR.
- **Límites de 2.2**: entrada de 25 MB, 1.000 cabeceras y 64 KB por cabecera, sin lanzar nunca; los adjuntos enormes no se decodifican enteros. Pasado el límite de cabeceras se siguen leyendo las que cambian el veredicto (From, Content-Type, Authentication-Results…), y si no se ha podido leer todo el correo la confianza baja a «baja».
- **Detector `mime`**: cabecera sin `:`, `Content-Type` repetido, boundary reutilizado o dentro del contenido, `message/rfc822` anidado y charset contradictorio, con tests diferenciales que documentan qué decide PhishLens en cada caso ambiguo.
- **Fuzzing con semilla** (2.000 casos en CI, `npm run fuzz` para 20.000), test de rendimiento hasta 25 MB y [benchmark](docs/benchmark.md).
- **Privacidad en un Chromium real** (`npm run test:e2e`): las 10 muestras y un correo lleno de contenido remoto, por todas las pestañas y en los dos temas, sin una sola petición fuera del origen; con control negativo.
- **Accesibilidad comprobada** con axe-core (cero problemas serios o críticos) y con teclado.
- [Modelo de amenazas](docs/threat-model.md), [auditoría de seguridad](docs/security-audit.md), [ADR 0003](docs/adr/0003-sin-web-worker.md) y [matriz de cobertura](docs/coverage-matrix.md) generada (`npm run coverage`).
- CI con job de navegador, `npm audit` y Dependabot para npm y Actions.
- Tests nuevos: golden de las 7 muestras (demuestra que la reestructura no cambia ningún veredicto), SHA-256 con vectores de NIST y regla de dependencias entre capas.

### Cambiado
- La nota ya no es una suma de puntos: las muestras de phishing pasan a 60–95, y cinco a «Phishing casi seguro». `auth.dkim-body-verified` ya no es señal a favor: un `bh=` correcto se puede fabricar. Las insignias de cada señal muestran su gravedad y su fiabilidad en lugar de los puntos.
- ATT&CK 20 revocó T1656 y T1672: las señales de suplantación pasan a **T1684.001** y las de cabeceras falseadas a **T1684.002**. Las cabeceras técnicas genéricas ya no se asocian a ninguna técnica.
- `links.punycode` es leve salvo que el dominio imite letras latinas: un dominio internacional normal (`españa.es`) ya no se marca como grave.
- Código reorganizado en `core/`, `parser/`, `intel/` y `lib/`; tests en `tests/unit/`.
- `connect-src` baja de `'self'` a `'none'`: las muestras van dentro de `samples/data.js` (`npm run samples`) en lugar de pedirse por red. Se añade `x-dns-prefetch-control: off`.
- Al imprimir, los «¿Por qué?» se abren y el informe sale en claro aunque la pantalla esté en oscuro. La cifra de cada categoría se lee «18 de 20» con lector de pantalla y su nombre ya no se corta.
- «Una señal grave o media» en singular, y con nota 0 el informe ya no repite que no hay señales.
- `auth.missing` (no hay cabeceras de autenticación) ya no se asocia a T1684.002: no tenerlas no es falsificarlas.
- `proyectoCiber/` es autónomo, con sus propios workflows, para poder publicarlo como repositorio independiente.

### Seguridad
- `finding()` ya no acepta severidades heredadas del prototipo como `constructor`.
- El informe exportado en JSON no incluye los bytes de los adjuntos.

## 2.1.0 · 2026-10-21 · Seguridad

Auditoría de seguridad completa. Detalles en [SECURITY.md](SECURITY.md).

### Seguridad
- **Trusted Types** y CSP más estricta (`default-src 'none'`, `frame-src`, `worker-src`, `object-src` y `form-action` a `'none'`).
- Protección contra **clickjacking**: no se ejecuta dentro de un iframe.
- **Contaminación de prototipos**: entidades HTML, resultados de autenticación y parámetros MIME ya no aceptan `__proto__` ni `constructor`.
- **Límites contra DoS**: profundidad y número de partes MIME, enlaces, adjuntos, cabeceras `Received` y dominios parecidos.
- **ReDoS** eliminado en `parseAddress` y en la detección de letras mezcladas.
- Caracteres bidi e invisibles visibles en todo el informe (`⟦U+202E⟧`).
- Los enlaces `javascript:` y `vbscript:` se detectan como código incrustado.
- Solo se enlaza a MITRE ATT&CK con URLs validadas, y el tema guardado se valida.
- GitHub Actions fijadas por SHA, `persist-credentials: false` y tiempo límite.

### Cambiado
- Las señales de enlaces repetidas se agrupan en una sola (`(12 enlaces)`).
- 13 tests de seguridad nuevos (142 en total).

## 2.0.0 · 2026-10-21

### Añadido
- Detectores nuevos: **cabeceras técnicas** (Message-ID, Date, X-Mailer, ruta Received) y **contenido HTML** (formularios, scripts, `data:`, texto oculto, emails solo imagen).
- Remitente: letras de otros alfabetos camufladas y caracteres invisibles.
- Adjuntos: nombres invertidos con el carácter RLO.
- Enlaces: descargas directas, enlaces de seguimiento y desenvoltura de Safe Links, Google y LinkedIn.
- Mapeo de cada señal a **MITRE ATT&CK** y extracción de **IOCs defanged**.
- Interfaz: pestañas del informe, vista segura con resaltado, ruta del email, desglose por categoría, recomendaciones, copiar IOCs y soltar archivos en toda la página.
- Ejemplo 07 con un ataque avanzado, imagen para compartir, licencia MIT.

### Corregido
- Falsos positivos con dominios oficiales por país (`outlook.es`, `amazon.fr`…) y con palabras contenidas en marcas (`cloud` ⊂ `icloud`).
- Parser de HTML, Received y URLs en tiempo lineal: un email malicioso ya no puede congelar la pestaña.

## 1.0.0 · 2026-10-21

- Primera versión: parser `.eml`, 6 detectores, puntuación de 0 a 100, interfaz web y 6 ejemplos.
