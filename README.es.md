<div align="center">

<img src="assets/img/favicon.svg" width="72" alt="">

# PhishLens

**¿Es phishing? Descúbrelo y entiende por qué, sin que tu email salga del navegador.**

[English](README.md) · **Español**

[![Tests](https://github.com/ManzaXx/PhishLens/actions/workflows/tests.yml/badge.svg)](https://github.com/ManzaXx/PhishLens/actions/workflows/tests.yml)
![Tests](https://img.shields.io/badge/tests-786%20%2B%2081%20e2e-15803d)
![Dependencias](https://img.shields.io/badge/dependencias-0-0f766e)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-f7df1e?logo=javascript&logoColor=000)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-c0392b)
[![Licencia MIT](https://img.shields.io/badge/licencia-MIT-blue)](LICENSE)

</div>

![PhishLens en modo sencillo: «No te fíes: es phishing», qué hacer ahora y por qué](docs/img/sencillo-claro.png)

PhishLens analiza un email (archivo `.eml` o texto pegado) o una URL y devuelve una **puntuación de riesgo de 0 a 100**. Explica cada señal en lenguaje claro, la relaciona con su técnica de **MITRE ATT&CK** y extrae los **indicadores de compromiso (IOCs)** listos para compartir con un equipo de seguridad.

**[Pruébalo en el navegador → manzaxx.github.io/PhishLens](https://manzaxx.github.io/PhishLens/)**

Todo se ejecuta en tu navegador. No hay servidor, cookies ni analítica, y una Content-Security-Policy estricta impide cualquier conexión a terceros.

La interfaz está en español e inglés: sigue el idioma del navegador y el botón **ES/EN** la cambia. Los informes, los paquetes STIX y el informe forense salen en el idioma elegido.

## ✨ Funcionalidades

- **Dos niveles de detalle**: el **modo sencillo** da el veredicto en una frase («No te fíes: es phishing»), tres pasos de qué hacer y las señales en lenguaje llano; el **modo analista** tiene navegación lateral por Resumen, Señales, Vista segura, Autenticación, Cabeceras y ruta, Adjuntos, URLs, IOCs, Campañas, ATT&CK , Panel e Historial, con la vista en la URL (`#analista/senales`).
- **10 detectores y 86 reglas**: autenticación, remitente, cabeceras, ruta, estructura MIME, enlaces, dominios parecidos, adjuntos, HTML y lenguaje. Cada regla tiene su texto llano y su técnica ATT&CK.
- **Informe explicado**: nota con semáforo, motivo principal, confianza del análisis, riesgo por categoría, combinaciones peligrosas y recomendaciones de qué hacer.
- **Vista segura**: el email como texto plano, sin enlaces activos y con las frases de ingeniería social resaltadas.
- **Ruta del email**: reconstruye los saltos `Received` con sus IPs.
- **IOCs defanged** (`hxxp://evil[.]xyz`) con botón de copiar para pegarlos en un ticket.
- **Varios correos a la vez**: suelta hasta 50 `.eml` (100 MB en total) y elige cuál ver. Un **grafo de IOCs** en SVG une correos, remitentes, dominios, IPs, URLs y adjuntos (con teclado y una tabla equivalente), y las **campañas** agrupan los correos que comparten infraestructura, un adjunto o la misma plantilla.
- **MITRE ATT&CK**: cada señal enlazada a su técnica (T1566.002, T1036.007, T1684.001…), con su táctica y el motivo, según ATT&CK 20.1.
- **URLs sin visitarlas**: desenvuelve redirecciones (Safe Links, Google, Facebook, LinkedIn, parámetros como `url` o `next`, base64 y codificación doble, hasta 10 saltos) y detecta IPs disfrazadas (`http://3232235777`), credenciales en el enlace, puertos raros y dominios con aspecto aleatorio. La vista **«URLs»** enseña la cadena de saltos sin que nada se pueda pulsar.
- **Exportar** (JSON, **STIX 2.1**, copiar IOCs, informe forense) desde un menú accesible con teclado. El bundle STIX lleva observables, indicadores, técnicas ATT&CK y campañas con ids deterministas, y pasa el validador oficial de OASIS ([docs/stix.md](docs/stix.md)).
- **Sistema de diseño propio** ([docs/design-system.md](docs/design-system.md)): tokens con contraste comprobado en claro y oscuro, objetivos táctiles de 44 px y sin scroll horizontal a 360 px, comprobados en un Chromium real.
- **Historial opcional en el navegador** (apagado por defecto): guarda el informe de cada análisis, nunca el correo. Busca un IOC en todo lo guardado, filtra por nivel, fecha o técnica, compara dos análisis y exporta o importa el historial en `.json`. «Borrar todo» borra la base entera.
- **Panel SOC** sobre el historial: cifras clave, niveles en el tiempo, técnicas ATT&CK más vistas, IOCs que se repiten (un clic los busca), remitentes y dominios más frecuentes y campañas recientes. Gráficas SVG propias, con su tabla de datos y colores comprobados para daltonismo.
- **Informe forense** en PDF (desde el diálogo de impresión) y en JSON: identificación con SHA-256, SHA-1 y MD5, veredicto, hallazgos por gravedad, autenticación, cronología, IOCs, adjuntos, URLs y las notas del analista. El JSON lleva `reportSha256` para comprobar que nadie lo ha tocado ([docs/forensic.md](docs/forensic.md)).
- **Reglas propias en JSON**: añade tus señales (dominios de tu empresa, adjuntos que nunca recibes, combinaciones con las reglas de PhishLens) con un formato cerrado sin expresiones regulares. Se validan enteras, se prueban contra el historial antes de activarlas y nunca bajan la nota ([docs/rules.md](docs/rules.md)).
- **13 emails de ejemplo y un lote de campaña** de 4 correos que se cargan con un clic.

| Modo sencillo (oscuro) | Móvil | Email legítimo |
|---|---|---|
| ![Modo sencillo en tema oscuro](docs/img/sencillo-oscuro.png) | ![Modo sencillo en el móvil](docs/img/movil-sencillo.png) | ![Modo sencillo con un email legítimo](docs/img/sencillo-legitimo.png) |

| Modo analista: resumen | Señales | Autenticación |
|---|---|---|
| ![Modo analista con el anillo de riesgo y las categorías](docs/img/analista-resumen.png) | ![Señales agrupadas con gravedad, fiabilidad y ATT&CK](docs/img/analista-senales.png) | ![Autenticación SPF, DKIM y DMARC con su estado](docs/img/analista-autenticacion.png) |

| Vista segura | Cabeceras y ruta | Adjuntos |
|---|---|---|
| ![Vista segura con frases resaltadas](docs/img/analista-vista-segura.png) | ![Ruta Received con avisos por salto](docs/img/analista-cabeceras.png) | ![Adjuntos por dentro: PDF activo y ZIP con contraseña](docs/img/analista-adjuntos.png) |

| Grafo de IOCs del lote | Campañas | Lote en el móvil |
|---|---|---|
| ![Grafo radial de IOCs de un lote de cuatro correos](docs/img/analista-grafo.png) | ![Campaña de cuatro correos con lo que tienen en común](docs/img/analista-campanas.png) | ![Selector del lote y aviso de campaña en el móvil](docs/img/movil-lote.png) |

| URLs | IOCs | ATT&CK |
|---|---|---|
| ![Cadena de saltos de un enlace con redirección anidada](docs/img/analista-urls.png) | ![IOCs defanged con dominios Unicode](docs/img/analista-iocs.png) | ![Técnicas ATT&CK](docs/img/analista-attack.png) |

| Historial | Historial en el móvil | Panel en el móvil |
|---|---|---|
| ![Historial con búsqueda, filtros y dos análisis marcados para comparar](docs/img/analista-historial.png) | ![Historial en el móvil, tema oscuro](docs/img/movil-historial.png) | ![Panel en el móvil, tema oscuro](docs/img/movil-panel.png) |

![Panel SOC: siete análisis guardados, niveles en el tiempo, técnicas ATT&CK, IOCs repetidos y una campaña](docs/img/analista-panel.png)

| Informe forense impreso | Diálogo del informe en el móvil |
|---|---|
| ![Informe forense: identificación con hashes, veredicto y hallazgos por gravedad](docs/img/informe-forense.png) | ![Diálogo «Informe forense» con notas del analista, tema oscuro](docs/img/forense-dialogo.png) |

| Reglas propias: vista previa | Reglas propias en el móvil |
|---|---|
| ![Tres reglas propias cargadas con su vista previa sobre el historial](docs/img/reglas-vista-previa.png) | ![Reglas propias en el móvil, tema oscuro](docs/img/movil-reglas.png) |

## 🔍 Qué detecta

| Detector | Señales | ATT&CK |
|---|---|---|
| **Autenticación** | SPF, DKIM y DMARC con su **estado** (verificado por PhishLens, declarado por el receptor, declarado sin confirmar, no verificable sin DNS); `Authentication-Results` **falsificadas**; DMARC sin alineación; cuerpo modificado tras la firma DKIM (hash `bh=` comprobado en local); firma DKIM y SPF verificables pegando la clave o el registro | T1684.002 |
| **Remitente** | `Reply-To` y `Return-Path` de otro dominio, marca suplantada desde un dominio ajeno o un correo gratuito, letras cirílicas o griegas camufladas (`Pаypal`), caracteres invisibles, nombre visible con otra dirección (`"soporte@paypal.com" <x@evil.test>`), `Sender` de otro dominio sin firmar | T1684.001, T1027 |
| **Cabeceras técnicas** | `Message-ID` de otro dominio, falta `Date` o `Message-ID`, fecha futura, `X-Mailer` de kits de phishing (PHPMailer…), varios `From` o cabeceras únicas repetidas | T1684.002 (varios `From`) |
| **Ruta del correo** | IP privada en el salto de entrada, horas que retroceden, entrega de más de 24 h, más de 25 saltos, servidor que dice ser una marca (HELO) sin serlo | T1684.002 |
| **Enlaces** | Texto que muestra otro dominio, IPs (también disfrazadas en decimal, hex u octal), acortadores, `@` que oculta el host, usuario y contraseña en el enlace, punycode, TLD baratos, login sin HTTPS, marca en la ruta, descarga directa de ejecutables, enlaces de seguimiento, redirecciones anidadas o abiertas, puertos raros y dominios aleatorios | T1566.002, T1204.001 |
| **Dominios parecidos** | Levenshtein y homoglifos (`0→o`, `1→l`, `rn→m`) frente a 37 marcas (22 españolas verificadas), confusables de Unicode UTS #39, dominios con alfabetos mezclados o enteros en cirílico (`аррӏе.com`), homógrafos con letras latinas raras o de otros alfabetos (`ɑpple.com`), subdominios engañosos (`paypal.com.cuenta-segura.test`), marca + palabra de acceso (combosquatting) | T1583.001 |
| **Adjuntos** | Ejecutables, doble extensión (`factura.pdf.exe`), nombre invertido con RLO, y por dentro sin abrirlos: tipo real que no cuadra con la extensión, ZIP con programas o con contraseña, macros VBA, PDF que actúa al abrirse, HTML smuggling, imágenes de disco y accesos directos. SHA-256, SHA-1 y MD5 | T1566.001, T1204.002, T1036.007, T1036.002, T1036.008, T1027.006, T1027.013, T1553.005, T1059.005 |
| **Contenido HTML** | Formularios dentro del email, JavaScript o iframes, enlaces `data:`, texto oculto para burlar filtros, emails que son solo una imagen | T1598, T1059.007, T1027 |
| **Lenguaje** | Urgencia, amenazas, premios y peticiones de credenciales, en español e inglés | T1204, T1598 |

### Puntuación

La nota (0–100) combina seis categorías: Autenticación, Remitente, Enlaces, Adjuntos, Lenguaje e Infraestructura.

- Cada señal pesa según su gravedad y su fiabilidad, y cada categoría satura: diez enlaces raros no valen más que uno muy grave.
- Las **combinaciones peligrosas** suben la nota, por ejemplo suplantación de marca con autenticación fallida.
- Una firma DKIM verificada rebaja las señales blandas.

Aparte de la nota, el informe da la **confianza del análisis** (alta, media o baja) según lo que se pudo comprobar. Detalle y ejemplo resuelto en [docs/scoring.md](docs/scoring.md).

| Nota | Veredicto |
|---|---|
| 0–24 | 🟢 Probablemente legítimo |
| 25–59 | 🟠 Sospechoso |
| 60–79 | 🔴 Probable phishing |
| 80–100 | 🟣 Phishing casi seguro |

## 🚀 Pruébalo

```bash
git clone https://github.com/ManzaXx/PhishLens.git
cd PhishLens
python -m http.server 8080      # o: npx serve .
# abre http://localhost:8080
```

Pulsa cualquiera de los ejemplos o arrastra tu propio `.eml` a la página. En Gmail se descarga con <kbd>⋮</kbd> → *Descargar mensaje*. También puedes copiar el original desde *Mostrar original* y pegarlo.

Los ejemplos son ficticios: los dominios de los atacantes usan el TLD reservado `.test` y no existen.

## 🏗️ Arquitectura

Detalle de capas, modelos de datos y límites en [docs/architecture.md](docs/architecture.md); decisiones en [docs/adr/](docs/adr/).

```mermaid
flowchart LR
  A[".eml · texto · URL"] --> B["parser/eml.js<br/>parser/url.js"]
  B --> C{{"Objeto Email"}}
  C --> D1[auth] & D2[sender] & D3[headers] & D4[links] & D5[lookalike] & D6[attachments] & D7[html] & D8[language]
  D1 & D2 & D3 & D4 & D5 & D6 & D7 & D8 --> E["core/engine.js<br/>puntuación + ATT&CK"]
  C --> F["intel/ioc.js<br/>IOCs defanged"]
  E & F --> G["ui/render.js<br/>(solo textContent)"]
```

```
PhishLens/
├── index.html               # Página única con CSP estricta
├── assets/                  # CSS (tema claro/oscuro), favicon e imagen para compartir
├── src/
│   ├── lib/                 # Utilidades puras: SHA-256, límites, texto seguro
│   ├── data/                # Marcas, listas de referencia, patrones y mapa MITRE ATT&CK
│   ├── parser/              # eml.js (RFC 5322 + MIME), received.js, html.js (sin DOM), url.js
│   ├── detectors/           # 10 detectores con la misma interfaz: detect(email) -> Finding[]
│   ├── intel/               # IOCs defanged, URLs desenvueltas, grafo, campañas, STIX 2.1, panel e informe forense
│   ├── rules/               # Reglas propias: validador, motor sin regex y vista previa
│   ├── storage/             # Historial opcional en IndexedDB, con su validador
│   ├── core/                # Modelo de hallazgo, motor y recomendaciones
│   └── ui/                  # Render del informe, resaltado y controlador de la página
├── docs/                    # Arquitectura, ADRs, especificaciones y planes
├── SECURITY.md              # Modelo de amenazas y mitigaciones
├── samples/                 # 13 emails .eml de ejemplo, un lote de campaña y reglas de ejemplo
├── tools/                   # Muestras, capturas, matriz de cobertura y validador STIX
└── tests/                   # unit/, e2e/, fuzz/ y perf/ con node:test
```

### Decisiones técnicas

- **JavaScript puro con módulos ES**, sin frameworks ni compilación: el código que se lee es el que se ejecuta.
- **El motor no toca el DOM**, así que todo el análisis se prueba en Node con `node --test`, sin dependencias.
- **El email nunca se interpreta como HTML.** Se inserta con `textContent`, los enlaces del email no son clicables y el HTML se recorre con un escáner propio, sin crear nodos.
- **Resistente a emails maliciosos.** El parser trabaja en tiempo lineal y los regex tienen cuantificadores acotados. Hay tests que comprueban que miles de etiquetas sin cerrar, paréntesis o puntos no bloquean la pestaña (ReDoS).
- **Detectores aislados.** Si uno falla, el motor lo registra y sigue con el resto.
- **Seguridad auditada.** Trusted Types, CSP sin `unsafe-inline`, límites contra DoS, protección contra contaminación de prototipos y clickjacking. Ver [SECURITY.md](SECURITY.md).
- **Privacidad por diseño.** La CSP (`connect-src 'none'`, `script-src 'self'`, sin `unsafe-inline`) impide enviar datos fuera aunque hubiera un fallo, y un test en Chromium real comprueba que analizar un correo no hace ni una petición fuera del origen.

## 🧪 Tests

```bash
node --test                 # unitarios, golden, fuzzing (2.000 casos), diferenciales y rendimiento
npm run fuzz                # 20.000 casos de fuzzing
npm run bench               # reescribe docs/benchmark.md
npm ci && npx playwright install chromium && npm run test:e2e   # privacidad y accesibilidad en Chromium
```

GitHub Actions ejecuta todo en cada push (`.github/workflows/tests.yml`), más `npm audit`, y Dependabot vigila las dependencias de test y las Actions. Los tests cubren el parser, cada detector con casos positivos y negativos, el motor, los IOCs, el mapa ATT&CK, las 13 muestras y el lote de campaña de principio a fin, el grafo y las campañas (también con el lote barajado) y la resistencia a entradas maliciosas. La [matriz de cobertura](docs/coverage-matrix.md) dice dónde se prueba cada regla; el [modelo de amenazas](docs/threat-model.md) y la [auditoría](docs/security-audit.md), qué protege cada test.

## 🌐 Publicar la demo

La demo está en **https://manzaxx.github.io/PhishLens/**. El workflow `.github/workflows/pages.yml` la vuelve a publicar en cada push a `main`, después de pasar los tests. En un fork, elige *GitHub Actions* como origen en *Settings → Pages*.

## ⚠️ Limitaciones

- Son heurísticas: una nota baja **no garantiza** que un email sea seguro, y un email legítimo mal configurado puede salir sospechoso.
- No consulta servicios externos (listas negras, WHOIS, VirusTotal), porque eso exigiría enviar datos fuera del navegador.
- Las campañas son una pista, no una prueba: se unen por cadena (A comparte algo con B y B con C) y solo entran los correos que no parecen legítimos.
- Sin red no sabe la edad de un dominio ni desenvuelve un acortador (`bit.ly`, `t.co`): solo lo que va escrito dentro de la propia URL.
- Sin red no consulta DNS: la firma DKIM y el SPF solo se verifican si pegas la clave o el registro. Detalles en [docs/limitations.md](docs/limitations.md).
- Mira dentro de los adjuntos sin abrirlos, pero no descomprime nada: un PDF dentro de un ZIP o el contenido comprimido de un PDF no se revisan. Tampoco lee el formato `.msg` de Outlook.

## 🗺️ Próximos pasos

- [x] Verificación de firmas DKIM con WebCrypto (2.2)
- [x] Modo por lotes, grafo de IOCs y campañas (2.3)
- [x] URLs sin visitarlas y exportación STIX 2.1 (2.3)
- [x] Historial, panel SOC, informe forense y reglas propias (3.0)
- [x] Interfaz en inglés (3.1)
- [ ] Extensión de navegador para analizar el email abierto en Gmail u Outlook

## 📄 Licencia y aviso

[MIT](LICENSE) © 2026 Pablo Manzanedo. `src/data/psl.js` es una copia de la [Public Suffix List](https://publicsuffix.org/) bajo la MPL 2.0.

PhishLens es un proyecto educativo de ciberseguridad defensiva. Si recibes un email sospechoso, contacta con la empresa por un canal oficial y repórtalo. En España puedes llamar a INCIBE al **017**.

---

<div align="center">Hecho por <b>Pablo Manzanedo</b> · <a href="https://github.com/ManzaXx">GitHub</a></div>
