# Sistema de diseño de PhishLens

CSS puro y funciones de JavaScript sin dependencias, compatibles con la CSP estricta (`style-src 'self'`, Trusted Types). Tres hojas, en este orden:

| Hoja | Qué contiene | Regla |
|---|---|---|
| `assets/css/tokens.css` | Colores de los dos temas, escalas, sombras, tipografías | Único sitio con valores de color, tamaño de letra y radio |
| `assets/css/styles.css` | Página: cabecera, portada, analizador, rejillas | Solo tokens |
| `assets/css/components.css` | Componentes de `src/ui/components/` y las dos vistas | Solo tokens |

`tests/unit/tokens.test.js` hace cumplir la regla: rechaza colores en hexadecimal, `rgb()` o `hsl()`, tamaños de letra que no sean `var(--text-*)` y radios que no sean `var(--radius-*)` fuera de `tokens.css`. También comprueba que cada pareja de texto y fondo llega a 4,5:1 en claro y en oscuro.

## Tokens

### Color

Cada color tiene su pareja `-soft` para fondos. El texto nunca va sobre un fondo que no se haya comprobado.

| Token | Uso | Pareja comprobada (≥ 4,5:1) |
|---|---|---|
| `--bg`, `--surface`, `--surface-2` | Fondo de página, tarjetas, zonas hundidas | — |
| `--text`, `--text-strong`, `--muted` | Texto normal, títulos, texto secundario | sobre `--bg`, `--surface` y `--surface-2` |
| `--accent`, `--accent-strong`, `--accent-soft`, `--on-accent` | Marca, acción principal, elemento actual | `--on-accent`/`--accent`, `--accent-strong`/`--accent-soft` |
| `--safe`, `--suspicious`, `--phishing`, `--critical` | Niveles del veredicto | cada uno sobre su `-soft` |
| `--sev-high`, `--sev-medium`, `--sev-low` | Gravedad de una señal | cada uno sobre su `-soft` |
| `--info` | Señales informativas | sobre `--info-soft` |
| `--focus` | Anillo de foco (3 px) | — |

Tema oscuro: `[data-theme="dark"]` o `prefers-color-scheme: dark` sin `[data-theme="light"]`. Los dos bloques tienen las mismas variables y el test lo comprueba. Al imprimir se usan siempre los colores claros.

**El color nunca es la única señal.** La gravedad se escribe («GRAVE», «Media»), el veredicto tiene titular e icono y cada barra lleva su cifra.

### Escalas

| Escala | Valores |
|---|---|
| Espacio `--space-1…10` | 4, 8, 12, 16, 20, 24, 32, 40, 48, 64 px |
| Tipo `--text-xs…3xl` | 12, 14, 16, 18, 22, 28, 36 px (`--text-display` 52 px, solo el titular de la portada) |
| Radio `--radius-sm/md/lg/xl/pill` | 6, 10, 16, 24, 999 px |
| Movimiento `--dur-fast`, `--dur` | 120 y 200 ms; con `prefers-reduced-motion` no se anima nada |
| Sombra `--shadow-1`, `--shadow-2` | Botón pulsado y tarjeta |

Los títulos que crecen con la pantalla usan `clamp(var(--text-…), Nvw, var(--text-…))`.

## Principios

1. **Primero el veredicto.** Lo primero que se ve dice qué hacer, en palabras normales. El detalle técnico está a un clic, nunca delante.
2. **Texto, nunca HTML.** Todo pasa por `el()` de `src/ui/dom.js`, que usa `textContent` y muestra los caracteres invisibles o de control (`⟦U+202E⟧`). El DOM de test hace que `innerHTML` lance.
3. **Objetivos de 44 px** y sin scroll horizontal a 360 px (`tests/e2e/layout.e2e.js`).
4. **Un solo origen para cada cifra.** La portada lee `FACTS` y `levelLegend()`; ningún número se escribe a mano.

## Componentes

Todos están en `src/ui/components/`, son funciones puras `(…) → Element` y solo importan `dom.js`, otros componentes y `data/` (`tests/unit/structure.test.js`). Se prueban en Node con `tests/helpers/dom.js`.

### verdictCard(verdict, {score, confidence})

Veredicto del modo sencillo.

| Propiedad | Tipo | Descripción |
|---|---|---|
| `verdict.tone` | `'safe' \| 'suspicious' \| 'phishing'` | Colores y clase `verdict--{tone}`; otro valor cae en `suspicious` |
| `verdict.headline` | texto | `<h2>`, enlazado con `aria-labelledby` |
| `verdict.because` | texto | Una frase con el porqué |
| `score`, `confidence` | número, `{level}` | Línea «95 de 100 · confianza alta»; si falta un dato no se inventa |

Accesibilidad: `<section aria-labelledby>`; el icono es decorativo y el tono también se dice en el titular.

| ✅ Hacer | ❌ No hacer |
|---|---|
| Un titular de cuatro palabras como mucho | Poner la nota como titular |
| El porqué con la marca y el dominio reales | Jerga (SPF, DKIM, ATT&CK) |

### stepList(steps)

`<ol>` con un paso por `<li>`; en el modo sencillo son tres tarjetas en fila que pasan a columna por debajo de 640 px. Los pasos salen de `adviceFor()` y, si hay menos de tres, de una lista fija de consejos generales.

### signalRow(finding)

`<li class="signal">` con un punto de color decorativo, `finding.plain` (o el título si no hay texto llano) y la gravedad en texto. Va dentro de `<ul class="signals">`.

### findingCard(finding)

Tarjeta del modo analista: `severityTag`, título, línea «fiabilidad alta · T1566.002», detalle, evidencia en monoespaciada y enlaces a MITRE. Solo se enlaza `https://attack.mitre.org/techniques/…`; cualquier otra URL se pinta como texto. Las señales a favor no llevan técnica.

### severityTag(severity)

`<span class="sev sev--high">GRAVE</span>`. Valores `high`, `medium`, `low`, `info`; cualquier otro (incluido `constructor`) es `info`.

### meter({label, value, max, severity})

Fila con etiqueta, cifra «19,9 / 20» que se lee «19,9 de 20» (`aria-label`) y barra decorativa (`aria-hidden`) con `--w`. El valor se recorta a 0–100 % y `max` 0 da 0 %.

### dataTable({caption, columns, rows})

`<table>` con `<caption>` y `<th scope="col">` dentro de `<div class="table-scroll" tabindex="0" role="region" aria-label>`: en el móvil la tabla se desplaza sola, sin mover la página, y se puede recorrer con teclado. Una celda puede ser texto o un nodo.

### chip(text, {tone})

Pastilla corta para recuentos y etiquetas. Tonos: `neutral`, `safe`, `suspicious`, `phishing`, `info`, `accent`.

### emptyState(title, text)

Título y una frase que dice qué significa que esté vacío. Ejemplo: «Sin señales de riesgo. No hemos encontrado nada sospechoso en este correo. Una nota baja no garantiza que sea seguro.»

### navRail({groups, current, counts})

`<nav aria-label="Secciones del informe">` con un `<h3>` por grupo y un enlace `#analista/<vista>` por vista; la actual lleva `aria-current="page"` y el contador va en texto. Columna fija desde 900 px; por debajo, una fila con desplazamiento horizontal en la que la vista actual siempre queda a la vista.

| Estado | Aspecto |
|---|---|
| Normal | Texto `--text` |
| Hover | Fondo `--surface-2` |
| Actual | Fondo `--accent-soft`, texto `--accent-strong` en negrita |
| Foco | Anillo `--focus` de 3 px |

### modeSwitch(mode)

`<div role="group" aria-label="Nivel de detalle">` con dos botones «Sencillo» y «Modo analista» y `aria-pressed`. Cambia la URL; un único `hashchange` repinta y lleva el foco al título de la vista nueva.

### menuButton({label, items})

Patrón ARIA de botón con menú: `aria-haspopup="menu"`, `aria-expanded`, `aria-controls`; `<ul role="menu">` con `<button role="menuitem" tabindex="-1">`.

| Tecla | Efecto |
|---|---|
| Enter, Espacio, ↓ en el botón | Abre y enfoca el primer elemento (↑ el último) |
| ↓ ↑ | Siguiente o anterior, circular (`menuKey`) |
| Inicio, Fin | Primero, último |
| Escape | Cierra y devuelve el foco al botón |
| Tab | Cierra y sigue el orden normal |
| Clic fuera | Cierra |

## Vistas

- **Modo sencillo** (`views/simple.js`): `verdictCard` → «Qué hacer ahora» (`stepList`) → «Por qué lo decimos» (`signalRow` × 5 como mucho, sin repetir texto) → botón «Ver todos los detalles (modo analista)».
- **Modo analista** (`views/analyst.js`): `navRail` | vista con su `<h2 tabindex="-1">` | lateral con riesgo por categoría, combinaciones, señales a favor y qué hacer. Tres columnas desde 1200 px, dos desde 900 px y una por debajo.

Rutas (`src/ui/route.js`): `''` es el modo sencillo y `#analista/<vista>` el analista. Cualquier otra cosa cae en el resumen sin lanzar, y una vista sin contenido (Autenticación en una URL suelta) también.

## Lector de pantalla

El informe no es una región viva: al terminar un análisis, `#report-status` (`role="status"`) dice «Resultado: No te fíes: es phishing. 95 de 100.», y al cambiar de vista el foco va a su título.
