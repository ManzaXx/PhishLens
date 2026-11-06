# Limitaciones conocidas

PhishLens trabaja sin red y en el navegador. Estas son las consecuencias, para que nadie lea en el informe más de lo que dice.

## Autenticación

- **SPF sin DNS.** Sin el registro pegado, SPF solo puede leerse en cabeceras. Con el registro, se evalúan `ip4`, `ip6` y `all`; si antes de un acierto aparece `include`, `a`, `mx`, `exists`, `ptr` o `redirect`, el resultado es «no verificable» y se indica qué habría que consultar. No se siguen macros.
- **DKIM sin clave.** El hash del cuerpo (`bh=`) se comprueba siempre, pero la firma solo se verifica si se pega la clave pública. Sin ella, DKIM queda como «no verificable». Solo se verifica la primera firma con la clave pegada.
- **DMARC sin política.** No se conoce `p=`, `adkim=` ni `aspf=`: se asume alineación relaxed y no se puede decir qué haría el receptor.
- **Dominio organizativo sin PSL.** La alineación usa una aproximación del dominio registrable (con los sufijos más comunes), no la Public Suffix List completa. En sufijos raros puede considerar alineados dominios que no lo están, o al revés.
- **Cuerpo tras decodificar.** El navegador lee el `.eml` como UTF-8, así que en correos con cuerpo `8bit` que no sea UTF-8 los bytes pueden cambiar y el hash de cuerpo dar `bodyHashOk: false` aunque el correo esté intacto.
- **Zona de confianza.** Se basa en el orden de las cabeceras `Received` y en el nombre inverso (rDNS) que escribe el receptor entre paréntesis: un salto solo cuenta como interno si ese nombre es de la organización receptora. Las `Authentication-Results` sin authserv-id (formato de Exchange Online) solo se aceptan si el receptor es un proveedor conocido. Un correo reenviado o retocado por un sistema intermedio puede romper la frontera; en ese caso las cabeceras quedan «sin confirmar», nunca «de confianza» por error.
- **Alineación incompleta.** Si `Authentication-Results` da un `pass` sin `smtp.mailfrom` ni `header.d`, no se puede saber si estaba alineado y no se emite `auth.dmarc-unaligned`.

## Dominios

- **Confusables limitados a ASCII.** La tabla de Unicode 16 solo incluye caracteres que se confunden con `a–z` o `0–9`. Imitaciones entre dos alfabetos no latinos no se detectan.
- **Palochka y ambigüedades ASCII.** Unicode 16 asigna `ӏ` a `i`, pero en pantalla se lee como `l`; por eso la comparación pliega también `i/l/1`, `0/o`, `rn/m` y `vv/w` en ambos lados.
- **Lista de marcas manual.** Solo se protege a las marcas de `src/data/brands.js`. Los dominios oficiales que no se pudieron confirmar no están, y un correo legítimo desde uno de ellos puede salir como suplantación.
- **Marcas que son palabras corrientes** (Orange, ING, SEUR, GLS, DGT, Steam) solo cuentan como etiqueta exacta, nunca por parecido.

## Adjuntos

Los adjuntos se miran por dentro sin abrirlos: nunca se descomprime ni se ejecuta nada. Por eso:

- **Tipo real por los primeros bytes.** Se reconocen PE, ELF, ZIP, OLE2, PDF, RTF, ISO 9660, LNK, HTML y scripts con `#!`. Las imágenes y el resto de formatos salen como «Desconocido» y no se comparan con su extensión.
- **ZIP: solo el directorio central.** Se leen nombres, tamaños y si están cifrados, pero no el contenido: un PDF dentro de un ZIP no se revisa. No se leen ZIP64, ZIP partidos ni ZIP cuyo directorio central contradiga las cabeceras locales; como mucho, 1.000 entradas.
- **OLE2 (Office antiguo): solo el directorio.** Se buscan los nombres de un proyecto VBA. La FAT se lee de la cabecera (109 sectores); un documento que necesite la DIFAT extendida se lee hasta donde llega y se avisa.
- **PDF: solo el texto sin comprimir.** Se buscan `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile` y `/URI`, también ofuscados con `#xx`. Lo que vaya dentro de un flujo comprimido (`/FlateDecode` y otros) o de un flujo de objetos no se ve: el informe dice cuántos flujos comprimidos se han quedado sin mirar.
- **HTML: solo los primeros 2 MB** y solo si hay un `<script>`.
- **ISO, IMG y VHD: no se abren.** Se avisa de que son imágenes de disco, pero no se lista lo que llevan dentro.
- **Adjuntos recortados o ilegibles** (más de 10 MB o base64 roto): solo cuentan las reglas por nombre.

## Ruta

- La ruta se lee de las cabeceras `Received`, que el remitente puede inventar por debajo del salto de entrada. Las horas solo se comparan si se pueden interpretar, con 5 minutos de margen.

## Tamaño y rendimiento

- **Los límites cuentan caracteres, no bytes.** El navegador entrega el archivo como texto, así que los 25 MB son 25 millones de unidades UTF-16: un `.eml` con mucho texto no ASCII puede ocupar en disco hasta el doble.
- **Sin Web Worker.** El análisis corre en el hilo principal ([ADR 0003](adr/0003-sin-web-worker.md)): con un correo enorme la página puede quedarse quieta unas décimas de segundo.
- **Adjuntos de más de 10 MB.** No se decodifican enteros: su tamaño sale de la longitud del base64, no se calculan sus hashes y no se mira dentro.
- **Navegadores.** La privacidad y la accesibilidad se prueban en Chromium; Firefox y Safari aplican la misma CSP, pero no se prueban en CI.

## General

- Son heurísticas: una nota baja no garantiza que un correo sea seguro.
- **Pesos a mano.** Los pesos, las combinaciones y la escala de la nota están calibrados con las muestras y los ejemplos de la especificación, no entrenados con datos reales.
- **La confianza mide carencias, no aciertos.** Una confianza alta dice que se pudo revisar casi todo, no que el veredicto sea correcto.
- No se consultan listas negras, WHOIS ni servicios de reputación.
- No se analiza el formato `.msg` de Outlook.
