# Changelog

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
