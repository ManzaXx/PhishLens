# Limitaciones conocidas

PhishLens trabaja sin red y en el navegador. Estas son las consecuencias, para que nadie lea en el informe más de lo que dice.

## Autenticación

- **SPF sin DNS.** Sin el registro pegado, SPF solo puede leerse en cabeceras. Con el registro, se evalúan `ip4`, `ip6` y `all`; si antes de un acierto aparece `include`, `a`, `mx`, `exists`, `ptr` o `redirect`, el resultado es «no verificable» y se indica qué habría que consultar. No se siguen macros.
- **DKIM sin clave.** El hash del cuerpo (`bh=`) se comprueba siempre, pero la firma solo se verifica si se pega la clave pública. Sin ella, DKIM queda como «no verificable». Solo se verifica la primera firma con la clave pegada.
- **DMARC sin política.** No se conoce `p=`, `adkim=` ni `aspf=`: se asume alineación relaxed y no se puede decir qué haría el receptor.
- **Dominio organizativo con una copia de la PSL.** La alineación y las comparaciones de dominio usan la Public Suffix List empaquetada (ICANN y privada, [ADR 0006](adr/0006-public-suffix-list.md)), con la fecha que dice `src/data/psl.js`. Un sufijo añadido después de esa fecha no se conoce hasta regenerarla. Al usar también la parte privada, PhishLens es más estricto que un servidor real: dos clientes de github.io nunca se consideran alineados. DMARCbis recorre el árbol DNS en vez de usar la PSL; sin red no se puede hacer.
- **Cuerpo tras decodificar.** El navegador lee el `.eml` como UTF-8, así que en correos con cuerpo `8bit` que no sea UTF-8 los bytes pueden cambiar y el hash de cuerpo dar `bodyHashOk: false` aunque el correo esté intacto.
- **Zona de confianza.** Se basa en el orden de las cabeceras `Received` y en el nombre inverso (rDNS) que escribe el receptor entre paréntesis: un salto solo cuenta como interno si ese nombre es de la organización receptora, si su IP es privada o si cae en un rango interno conocido de un proveedor (Exchange Online). Las líneas `Received: by` sin nombre de host de arriba (las internas de Gmail) se saltan. Las `Authentication-Results` sin authserv-id (formato de Exchange Online) solo se aceptan si el receptor es un proveedor conocido. Un correo reenviado o retocado por un sistema intermedio puede romper la frontera; en ese caso las cabeceras quedan «sin confirmar», nunca «de confianza» por error.
- **Cabeceras justo debajo de la entrada.** Postfix con OpenDKIM/OpenDMARC y Gmail escriben su `Authentication-Results` justo debajo de su propio `Received`, que es también donde cae lo que el remitente puso al principio del mensaje. Ahí no se puede saber quién la escribió: queda «sin confirmar» (ni suma riesgo ni da confianza). Solo se marca como falsificada si el receptor ya dejó la suya por encima, si la contradice, o si por debajo hay `Received` inventados con el nombre del receptor. Cuando el receptor deja un `ARC-Authentication-Results` por encima (Gmail, Microsoft 365), ese es el que se lee como de confianza.
- **Alineación incompleta.** Si `Authentication-Results` da un `pass` sin `smtp.mailfrom` ni `header.d`, no se puede saber si estaba alineado y no se emite `auth.dmarc-unaligned`.

## Dominios

- **Confusables limitados a ASCII.** La tabla de Unicode 16 solo incluye caracteres que se confunden con `a–z` o `0–9`. Imitaciones entre dos alfabetos no latinos no se detectan.
- **Palochka y ambigüedades ASCII.** Unicode 16 asigna `ӏ` a `i`, pero en pantalla se lee como `l`; por eso la comparación pliega también `i/l/1`, `0/o`, `rn/m` y `vv/w` en ambos lados.
- **Lista de marcas manual.** Solo se protege a las marcas de `src/data/brands.js`. Los dominios oficiales que no se pudieron confirmar no están, y un correo legítimo desde uno de ellos puede salir como suplantación.
- **Marcas que son palabras corrientes** (Orange, ING, SEUR, GLS, DGT, Steam) solo cuentan como etiqueta exacta, nunca por parecido.

## Adjuntos

Los adjuntos se miran por dentro sin abrirlos: nunca se descomprime ni se ejecuta nada. Por eso:

- **Tipo real por los primeros bytes.** Se reconocen PE, ELF, ZIP, OLE2, PDF, RTF, ISO 9660, LNK, HTML y scripts con `#!`. Las imágenes y el resto de formatos salen como «Desconocido» y no se comparan con su extensión.
- **ZIP: solo la lista, nunca el contenido.** Se leen nombres, tamaños y si están cifrados del directorio central, y si este no cuadra con su propia cuenta también de las cabeceras locales (lo que leen algunos descompresores); el informe avisa de que la lista puede estar incompleta. Un PDF dentro de un ZIP no se revisa. No se leen ZIP64 ni ZIP partidos; como mucho, 1.000 entradas. Los nombres de más de 260 caracteres se recortan por delante para que se vea la extensión.
- **OLE2 (Office antiguo): solo el directorio.** Se buscan los nombres de un proyecto VBA. La FAT se lee de la cabecera (109 sectores); un documento que necesite la DIFAT extendida se lee hasta donde llega y se avisa.
- **PDF: solo el texto sin comprimir.** Se buscan `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile` y `/URI`, también ofuscados con `#xx`. Lo que vaya dentro de un flujo comprimido (`/FlateDecode` y otros) o de un flujo de objetos no se ve: el informe dice cuántos flujos comprimidos se han quedado sin mirar.
- **PDF con formularios.** Un formulario rellenable de Acrobat lleva JavaScript propio (`AFNumber_Format` y similares) y sale como «PDF que actúa al abrirlo» de gravedad media, aunque sea legítimo: PhishLens no lee el código para distinguirlo.
- **HTML: solo los primeros 2 MB** y solo si hay un `<script>`.
- **ISO, IMG y VHD: no se abren.** Se avisa de que son imágenes de disco, pero no se lista lo que llevan dentro.
- **Adjuntos recortados o ilegibles** (más de 10 MB o base64 roto): solo cuentan las reglas por nombre.

## Ruta

- La ruta se lee de las cabeceras `Received`, que el remitente puede inventar por debajo del salto de entrada. Las horas solo se comparan si se pueden interpretar, con 5 minutos de margen.

## Tamaño y rendimiento

- **URL con usuario, host y puerto de más de 1.024 caracteres** se ignoran como enlace: un nombre DNS no pasa de 253 caracteres y parsear un «host» de megabytes bloqueaba los detectores. La query y la ruta pueden ser tan largas como quieran (se analizan las redirecciones anidadas).
- **Los límites cuentan caracteres, no bytes.** El navegador entrega el archivo como texto, así que los 25 MB son 25 millones de unidades UTF-16: un `.eml` con mucho texto no ASCII puede ocupar en disco hasta el doble.
- **El análisis va en un Web Worker** ([ADR 0007](adr/0007-worker-con-csp-heredada.md)) que hereda la CSP de la página, con un botón para cancelar. Si el navegador no puede crearlo, se analiza en el hilo principal como antes y la página puede quedarse quieta unas décimas de segundo con un correo enorme. El re-análisis con SPF/DKIM o reglas propias y los lotes siguen en el hilo principal.
- **Adjuntos de más de 10 MB.** No se decodifican enteros: su tamaño sale de la longitud del base64, no se calculan sus hashes y no se mira dentro.
- **Navegadores.** La privacidad y la accesibilidad se prueban en Chromium. Que el worker hereda la CSP se prueba además en Firefox y WebKit (job `worker-csp` de CI); el resto de los e2e sigue solo en Chromium.

## General

- Son heurísticas: una nota baja no garantiza que un correo sea seguro.
- **La nota no es una probabilidad.** 60 no significa «60 % de probabilidades de phishing», sino que se han acumulado varias señales medias o alguna grave. Lo que se evalúa son los tramos del veredicto, no el número ([docs/evaluation.md](evaluation.md)).
- **Pesos a mano.** Los pesos, las combinaciones y la escala de la nota están calibrados con las muestras y los ejemplos de la especificación, no entrenados con datos reales. Las muestras empaquetadas (17) no dan estadística: para medir tasas de acierto hace falta un corpus propio en `corpus/`, fuera de git.
- **Una sola categoría llena es «Sospechoso».** Por diseño (escala 40), un correo cuyas señales caen todas en una categoría se queda en 50–55 aunque sean graves: la muestra 09 (dos `From`, nombre con dirección falsa) está en 55 desde la auditoría 3.1, porque antes llegaba a 60 gracias a la falta de `Authentication-Results`, que no es una señal de phishing.
- **La confianza mide carencias, no aciertos.** Una confianza alta dice que se pudo revisar casi todo, no que el veredicto sea correcto.
- No se consultan listas negras, WHOIS ni servicios de reputación.
- No se analiza el formato `.msg` de Outlook.

## Lotes y campañas

- **El lote vive en memoria** mientras la pestaña esté abierta: al recargar se pierde. El historial persistente llegará en la 3.0.
- **Las campañas son una pista.** Se unen por cadena: si A comparte el dominio con B y B el adjunto con C, los tres salen juntos aunque A y C no compartan nada. Cada campaña dice qué une a cada par.
- **Solo los correos que no parecen legítimos** entran en una campaña, y los proveedores compartidos (correo gratuito, acortadores, seguimiento, dominios oficiales de marcas) no cuentan como pista.
- **Sin DNS.** `resuelve-en` solo une el dominio del remitente con la IP del salto de entrada que figura en las cabeceras, no con lo que diría el DNS hoy.
- **La plantilla** se compara por *shingles* de tres palabras; un kit que reescribe el texto con otras palabras no se reconoce, y los cuerpos de menos de 10 palabras no se comparan.
- **Grafos grandes.** El SVG dibuja como mucho 150 nodos y la tabla 500 filas; con más, lo dicen en texto.

## URLs y STIX

- **Solo lo que está escrito.** Se desenvuelve lo que va dentro de la propia URL (parámetros, base64, codificación doble). Un acortador (`bit.ly`, `t.co`) o una redirección del servidor no se pueden seguir sin visitarlos, y PhishLens nunca visita nada.
- **Sin edad de dominio.** No se sabe si un dominio se registró ayer: haría falta WHOIS o RDAP. En un lote, la vista «URLs» dice en cuántos correos aparece cada destino.
- **Aspecto aleatorio** solo mira el nombre del dominio. Un camino aleatorio es lo normal en los enlaces de seguimiento de cualquier newsletter, así que se mide y se enseña, pero no puntúa. Además del azar (3,5 bits por carácter o más) pide algo que las palabras reales no tienen: cifras mezcladas con letras o casi ninguna vocal.
- **Redirección anidada** solo cuenta los saltos que esconden el destino (un parámetro o base64). Safe Links o el `/url` de Google delante de un enlace de seguimiento no la disparan.
- **Indicadores STIX** solo para correos «Probable phishing» o «Phishing casi seguro» (y adjuntos con un hallazgo grave). Los dominios de marcas reales, acortadores, email marketing, correo gratuito, redes sociales, alojamiento compartido e infraestructura de correo compartida (SES, Mimecast, Outlook…) salen como observables, nunca como indicadores. De las IP de las cabeceras `Received` solo la de entrada es indicador, y no si es de un gran proveedor. Las direcciones de correo de una marca o de un proveedor tampoco lo son; las de correo gratuito sí, porque la cuenta la abrió el atacante.
- **Ids UUIDv5**, no UUIDv4: el validador de OASIS lo marca como aviso, pero es a propósito para que el mismo correo dé el mismo bundle.
- **Importación en OpenCTI o MISP** pendiente de probar a mano una vez ([docs/stix.md](stix.md)).

## Historial

- **Opcional y apagado por defecto.** Con el interruptor apagado no se crea la base de datos.
- **Qué se guarda:** el informe (nivel, puntuación, hallazgos, técnicas, IOCs, remitente y asunto) y el SHA-256 del texto analizado. **Qué no:** el cuerpo, el HTML, las cabeceras en bruto ni los bytes de los adjuntos. La evidencia de las reglas de lenguaje, de HTML y de las reglas propias se recorta a 40 caracteres; la de una regla propia sobre `body.text` es solo el término buscado, nunca el cuerpo.
- **Un análisis guardado no se puede volver a analizar** ni verificar su DKIM: el correo no está.
- **500 análisis como mucho.** Al pasar, se borra el más antiguo y se avisa.
- **Sin cifrado.** Lo guardado está en el perfil del navegador: quien use ese perfil lo puede ver. La exportación `.json` tampoco va cifrada.
- **Ventana privada o almacenamiento bloqueado:** el historial se apaga y lo dice; el análisis sigue funcionando.
- **Las reglas propias** no pueden mirar el cuerpo de un análisis guardado, porque no está.

## Panel

- **Fechas en UTC.** Los días y las semanas de «Niveles en el tiempo» se cortan en UTC, no en la hora local: un análisis de las 00:30 en Madrid puede caer en el día anterior.
- **30 días o 26 semanas.** Con más de 30 días de historia se agrupa por semanas (de lunes a domingo) y solo se pintan las 26 últimas; las más antiguas se cuentan y se avisa.
- **Las listas tienen tope:** 10 técnicas, 20 IOCs repetidos (solo dominios, IPs y hashes; URLs y direcciones no), 10 remitentes, 10 dominios y 5 campañas.
- **Un lote guardado no se vuelve a abrir entero.** «Abrir el último correo» abre el análisis más reciente de la campaña; el grafo del lote no se guarda.
- **Un análisis guardado con fecha ilegible o futura** cuenta como de hoy.

## Informe forense

- **Con un fichero suelto, los hashes son los de sus bytes** y coinciden con `sha256sum`. **En un lote, con texto pegado o desde el historial son los del texto analizado en UTF-8:** un correo con BOM o en otra codificación da otro hash. El informe dice cuál de los dos es en «Hashes de».
- **Desde el historial no hay SHA-1, MD5 ni tamaño:** el correo no se guarda, solo su SHA-256.
- **El pie con el SHA-256 y el número de página** usa las cajas de margen de `@page`, que solo pinta Chromium. En Firefox y Safari el PDF sale sin pie, pero el SHA-256 sigue en «Identificación».
- **`reportSha256` detecta cambios, no firma:** quien edite el JSON puede recalcularlo.
- **La hora local** es la del navegador que hizo el análisis.

## Reglas propias

- **Sin expresiones regulares.** No se pueden escribir patrones con comodines; `contains`, `starts-with`, `ends-with` y las listas cubren lo habitual.
- **La vista previa solo prueba las reglas que miran `finding.id`.** El historial no guarda el correo, así que una regla sobre el asunto, el remitente o los enlaces no se puede probar con lo guardado.
- **`body.text` mira hasta 256 K caracteres** del cuerpo. Lo que venga después no lo ve ninguna regla.
- **Sin historial, las reglas duran lo que la pestaña.** Con historial se guardan en el navegador, sin cifrar, y «Borrar todo» las borra.
- **Activarlas rehace el análisis abierto**, pero no un lote ni un análisis abierto desde el historial: hay que volver a soltar el lote.
- **Una regla propia no puede bajar la nota** ni quitar un hallazgo de PhishLens. Para ignorar un falso positivo no hay reglas de excepción.
- **`finding.id` solo ve los hallazgos de PhishLens**, no los de otras reglas propias: no se encadenan.
