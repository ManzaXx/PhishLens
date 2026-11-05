# Seguridad de PhishLens

PhishLens analiza emails que pueden haber sido escritos por un atacante, así que el propio analizador es un objetivo. Este documento explica de qué se protege y cómo.

## Modelo de amenazas

**Activo:** el email del usuario (privacidad) y la pestaña donde se analiza (integridad).

**Atacante:** controla por completo el contenido del `.eml`, el texto pegado o la URL: cabeceras, cuerpo, HTML, nombres de adjuntos, tamaño y codificación.

**Fuera de alcance:** un navegador o un sistema operativo comprometidos, o alguien con acceso de escritura al repositorio.

## Qué podría intentar el atacante y cómo se evita

| Ataque | Mitigación |
|---|---|
| **XSS**: HTML o JavaScript en el email que se ejecuta al mostrarlo | El email nunca se interpreta como HTML: la interfaz solo escribe con `textContent`, sin `innerHTML` ni `insertAdjacentHTML`. El HTML se recorre con un escáner propio que no crea nodos. |
| **XSS por un fallo futuro** | CSP sin `unsafe-inline` ni `unsafe-eval` (`script-src 'self'`) y **Trusted Types** (`require-trusted-types-for 'script'; trusted-types 'none'`): el navegador bloquea cualquier asignación de HTML aunque alguien la añada por error. |
| **Fuga de datos** a un servidor del atacante | `default-src 'none'`, `connect-src 'none'` (las muestras van en un módulo JS, no se piden por red), `img-src 'self' data:`, `form-action 'none'` y `<meta name="referrer" content="no-referrer">` y `x-dns-prefetch-control: off`. `tests/e2e/privacy.e2e.js` lo comprueba en un Chromium real. Los enlaces del email no son clicables. |
| **Enlaces peligrosos en el informe** | El único enlace externo que se genera es a MITRE ATT&CK y solo si coincide con `https://attack.mitre.org/techniques/Txxxx/`. Los enlaces `javascript:`, `vbscript:` y `data:` del email se señalan como sospechosos. |
| **DoS por ReDoS**: entradas que hacen que un regex tarde minutos | Parser en tiempo lineal, regex con cuantificadores acotados y textos recortados antes de buscar en ellos. Hay tests con 200 000 `<`, miles de paréntesis y nombres gigantes. |
| **DoS por tamaño**: emails enormes o anidados | Máximo 5 MB, 20 niveles de MIME, 500 partes, 200 enlaces, 100 adjuntos, 30 cabeceras `Received` y 10 dominios parecidos. Las señales repetidas se agrupan en una sola. |
| **Contaminación de prototipos** (`__proto__`, `constructor`) | Los mapas de entidades y severidades se consultan con `Object.hasOwn`, y los parámetros MIME se guardan en `Object.create(null)`. |
| **Suplantación visual con Unicode** (Trojan Source, RLO, caracteres invisibles) | Los caracteres bidi e invisibles se muestran como `⟦U+202E⟧` en todo el informe, así `factura⟦U+202E⟧gpj.exe` ya no se puede hacer pasar por `facturaexe.jpg`. |
| **Clickjacking**: cargar PhishLens dentro de un iframe engañoso | La página se niega a ejecutarse dentro de un iframe y ofrece abrirse en su propia pestaña (`frame-ancestors` no funciona en una CSP por `<meta>`). |
| **Datos guardados manipulados** | Solo se guarda el tema en `localStorage` y solo se acepta `light` o `dark`. |
| **Cadena de suministro** | Cero dependencias. Las GitHub Actions están fijadas por SHA de commit, con `persist-credentials: false`, permisos mínimos y tiempo límite. |
| **Un email que rompe el análisis** | Cada detector se ejecuta aislado y un error inesperado muestra un mensaje en vez de dejar la página rota. Un fuzzer prueba miles de entradas aleatorias. |

## Cómo se comprueba

```bash
cd proyectoCiber
node --test tests/security.test.js
```

`tests/security.test.js` cubre la contaminación de prototipos, los límites de tamaño, ReDoS, el fuzzing, los caracteres invisibles y los enlaces `javascript:`.

## Limitaciones

- Las cabeceras HTTP (`Content-Security-Policy`, `X-Frame-Options`) no se pueden configurar en GitHub Pages, por eso la CSP va en un `<meta>` y la protección contra iframes es por JavaScript.
- PhishLens no abre adjuntos ni visita enlaces, así que no puede analizar lo que hay detrás.

## Reportar una vulnerabilidad

Abre un issue en [ManzaXx/ProyectosPersonales](https://github.com/ManzaXx/ProyectosPersonales/issues) sin detalles explotables y te contactaré para ver el resto en privado.
