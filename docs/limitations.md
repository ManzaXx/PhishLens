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

## Ruta

- La ruta se lee de las cabeceras `Received`, que el remitente puede inventar por debajo del salto de entrada. Las horas solo se comparan si se pueden interpretar, con 5 minutos de margen.

## General

- Son heurísticas: una nota baja no garantiza que un correo sea seguro.
- **Pesos a mano.** Los pesos, las combinaciones y la escala de la nota están calibrados con las muestras y los ejemplos de la especificación, no entrenados con datos reales.
- **La confianza mide carencias, no aciertos.** Una confianza alta dice que se pudo revisar casi todo, no que el veredicto sea correcto.
- No se consultan listas negras, WHOIS ni servicios de reputación.
- No se analiza el contenido de los adjuntos (solo nombre, tipo y SHA-256), ni el formato `.msg` de Outlook.
