# Changelog

## 2.2.0 · en desarrollo · Motor fiable

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
- [ADR 0002](docs/adr/0002-autenticacion-offline.md) y primera versión de [limitaciones](docs/limitations.md).
- Documentación de [arquitectura](docs/architecture.md) y primer ADR.
- Tests nuevos: golden de las 7 muestras (demuestra que la reestructura no cambia ningún veredicto), SHA-256 con vectores de NIST y regla de dependencias entre capas.

### Cambiado
- `links.punycode` es leve salvo que el dominio imite letras latinas: un dominio internacional normal (`españa.es`) ya no se marca como grave.
- Código reorganizado en `core/`, `parser/`, `intel/` y `lib/`; tests en `tests/unit/`.
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
