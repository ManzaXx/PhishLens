# Changelog

## 2.2.0 · en desarrollo · Motor fiable

Especificación en [docs/specs/2026-11-05-phishlens-2.2-design.md](docs/specs/2026-11-05-phishlens-2.2-design.md).

### Añadido
- **SHA-256 de cada adjunto**, calculado en local sin abrir el fichero, y exportado como IOC.
- El parser conserva las cabeceras en orden con su texto crudo, el cuerpo sin decodificar y anota en `parseNotes` cada límite alcanzado o multipart sin cerrar.
- Cada hallazgo indica su **categoría**, su **fiabilidad** y su **procedencia** (verificado, declarado, deducido o no verificable).
- Documentación de [arquitectura](docs/architecture.md) y primer ADR.
- Tests nuevos: golden de las 7 muestras (demuestra que la reestructura no cambia ningún veredicto), SHA-256 con vectores de NIST y regla de dependencias entre capas.

### Cambiado
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
