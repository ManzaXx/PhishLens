# PhishLens — Especificación de diseño

Fecha: 2026-10-21 · Autor: Pablo Manzanedo · Estado: pendiente de revisión

## 1. Objetivo

Analizador de phishing que funciona **100 % en el navegador**, pensado como proyecto de portfolio (GitHub + LinkedIn). El usuario arrastra un `.eml`, pega un email en crudo o pega una URL, y obtiene una **puntuación de riesgo de 0 a 100** con un semáforo y la lista de indicadores explicados en lenguaje claro.

**Criterios de éxito**
- Se puede probar con un clic desde un enlace de GitHub Pages, sin instalar nada.
- Ningún dato sale del navegador: no hay backend, ni peticiones de red con el contenido del email, ni analítica.
- El código del motor es legible y está cubierto por tests automáticos que pasan en CI.
- El README explica qué detecta, cómo y por qué, con capturas y una demo.

**Fuera de alcance (YAGNI)**: consultas a servicios externos (VirusTotal, WHOIS, listas negras online), análisis del contenido de adjuntos, soporte de `.msg` de Outlook, cuentas de usuario e historial en servidor.

## 2. Ubicación y tecnología

- Carpeta `proyectoCiber/` en el repo `ManzaXx/ProyectosPersonales`, añadida al índice del README raíz.
- HTML + CSS + JavaScript puro con módulos ES, sin frameworks ni paso de compilación (mismo estilo que AEROVELO).
- Tests con `node --test` (sin dependencias). El motor no toca el DOM, así que se puede testear en Node.
- GitHub Actions: un workflow ejecuta los tests y otro publica `proyectoCiber/` en GitHub Pages. *Nota*: Pages en un repo privado requiere GitHub Pro; si no está disponible, la demo se publica desde un repo público aparte o el repo pasa a público (decisión de Pablo).

## 3. Arquitectura

```
proyectoCiber/
├── index.html              # UI: zona de arrastre, textarea, campo URL, informe
├── assets/css/styles.css
├── src/
│   ├── parser/
│   │   ├── eml.js          # Cabeceras (con plegado RFC 5322), cuerpo multipart, quoted-printable, base64, RFC 2047
│   │   └── url.js          # Normalización y descomposición de URLs, punycode
│   ├── detectors/          # Un módulo por detector, misma interfaz
│   │   ├── auth.js
│   │   ├── sender.js
│   │   ├── links.js
│   │   ├── lookalike.js
│   │   ├── attachments.js
│   │   └── language.js
│   ├── data/               # Listas: marcas, TLDs sospechosos, acortadores, palabras clave es/en
│   ├── engine.js           # Ejecuta detectores, suma puntuación y devuelve el informe
│   └── ui/                 # Render del informe, carga de ficheros, ejemplos, exportación
├── samples/                # 6 emails .eml de ejemplo (ficticios)
├── tests/                  # Un fichero de test por módulo + tests del motor con los samples
└── README.md
```

**Interfaz de un detector**

```js
// detect(email) -> Finding[]
// email: { headers: Map<string,string[]>, from, replyTo, returnPath, subject,
//          text, html, links: [{text, href}], attachments: [{filename, contentType}] }
// Finding: { id, detector, severity: 'info'|'low'|'medium'|'high', points, title, detail, evidence }
```

Una URL suelta se convierte en un `email` mínimo con un único enlace, así los detectores de enlaces y typosquatting se reutilizan.

**Flujo de datos**: entrada (fichero / texto / URL) → `parser` → objeto `email` → `engine` ejecuta los 6 detectores → lista de `Finding` → puntuación → `ui` dibuja el informe.

## 4. Detectores

| Detector | Qué comprueba | Ejemplo de hallazgo |
|---|---|---|
| auth | `Authentication-Results`: SPF, DKIM, DMARC (`fail`, `softfail`, `none`, ausencia) | "DMARC falla para paypal.com" |
| sender | `From` vs `Reply-To` vs `Return-Path`; nombre visible con una marca y dominio que no es de esa marca; dominios gratuitos usados por "empresas" | "Se presenta como 'Banco Santander' pero escribe desde gmail.com" |
| links | Texto del enlace que muestra otro dominio; IP en lugar de dominio; acortadores; `@` en la URL; punycode `xn--`; TLD sospechoso; `http` sin TLS en formularios de login | "El enlace dice paypal.com pero apunta a paypa1-login.xyz" |
| lookalike | Distancia de Levenshtein ≤ 2 y sustituciones homoglifo (0/o, 1/l, rn/m) frente a una lista de marcas (PayPal, Amazon, Microsoft, Apple, Google, Netflix, Correos, DHL, Santander, BBVA, CaixaBank, Agencia Tributaria…) | "micr0soft-support.com se parece a microsoft.com" |
| attachments | Extensiones ejecutables o con macros (`.exe`, `.scr`, `.js`, `.vbs`, `.iso`, `.docm`, `.xlsm`, `.html`…), dobles extensiones, `Content-Type` incoherente | "factura.pdf.exe: doble extensión que oculta un ejecutable" |
| language | Urgencia, amenazas, premios, petición de credenciales o datos bancarios, en español e inglés | "Pide verificar tu contraseña en menos de 24 h" |

## 5. Puntuación

- Cada hallazgo suma puntos según su severidad: info 0, low 5, medium 15, high 30.
- Puntuación = mínimo(100, suma). Semáforo: 0–24 verde ("Probablemente legítimo"), 25–59 ámbar ("Sospechoso"), 60–100 rojo ("Probable phishing").
- Los pesos viven en un único objeto de configuración para poder ajustarlos y testearlos.
- El informe siempre muestra el porqué de la nota: cada hallazgo con su evidencia literal.

## 6. Interfaz

- Una sola página: cabecera con el lema de privacidad ("tu email nunca sale de tu navegador"), tres pestañas de entrada (arrastrar `.eml`, pegar email, pegar URL), botones "Probar un ejemplo" y el informe.
- Informe: medidor circular con la nota, resumen de una frase, hallazgos agrupados por detector y ordenados por severidad, cabeceras clave y lista de enlaces extraídos.
- Exportar informe a JSON e imprimir (CSS de impresión).
- Modo claro y oscuro, accesible (contraste AA, navegable con teclado) y adaptado a móvil.
- Seguridad de la propia app: el contenido del email nunca se inserta como HTML (solo `textContent`), los enlaces del email no son clicables y hay una Content-Security-Policy estricta en `index.html`.

## 7. Errores

- Fichero que no es `.eml` o supera 5 MB: mensaje claro y no se analiza.
- Email sin cabeceras reconocibles: se analiza como texto y se avisa de que faltan cabeceras.
- Si un detector lanza una excepción, el motor la captura, la muestra como aviso y sigue con el resto.

## 8. Tests

- Tests unitarios de `eml.js` y `url.js` (plegado de cabeceras, codificaciones, multipart, punycode).
- Tests de cada detector con casos positivos y negativos.
- Tests del motor con los 6 emails de `samples/`: los legítimos quedan en verde y los de phishing en rojo.
- CI en GitHub Actions ejecuta `node --test` en cada push.

## 9. Entregables para LinkedIn

- README con GIF de la demo, tabla de detectores, decisiones técnicas y enlace a la demo.
- Los 6 emails de ejemplo: 2 legítimos y 4 de phishing (banco, paquetería, Microsoft 365, factura con adjunto).
