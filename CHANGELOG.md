# Changelog

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
- **Límites de 2.2**: entrada de 25 MB, 1.000 cabeceras y 64 KB por cabecera, sin lanzar nunca; los adjuntos enormes no se decodifican enteros.
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
