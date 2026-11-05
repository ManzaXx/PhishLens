# Limitaciones conocidas

PhishLens trabaja sin red y en el navegador. Estas son las consecuencias, para que nadie lea en el informe más de lo que dice.

## Autenticación

- **SPF sin DNS.** Sin el registro pegado, SPF solo puede leerse en cabeceras. Con el registro, se evalúan `ip4`, `ip6` y `all`; si antes de un acierto aparece `include`, `a`, `mx`, `exists`, `ptr` o `redirect`, el resultado es «no verificable» y se indica qué habría que consultar. No se siguen macros.
- **DKIM sin clave.** El hash del cuerpo (`bh=`) se comprueba siempre, pero la firma solo se verifica si se pega la clave pública. Sin ella, DKIM queda como «no verificable». Solo se verifica la primera firma con la clave pegada.
- **DMARC sin política.** No se conoce `p=`, `adkim=` ni `aspf=`: se asume alineación relaxed y no se puede decir qué haría el receptor.
- **Dominio organizativo sin PSL.** La alineación usa una aproximación del dominio registrable (con los sufijos más comunes), no la Public Suffix List completa. En sufijos raros puede considerar alineados dominios que no lo están, o al revés.
- **Cuerpo tras decodificar.** El navegador lee el `.eml` como UTF-8, así que en correos con cuerpo `8bit` que no sea UTF-8 los bytes pueden cambiar y el hash de cuerpo dar `bodyHashOk: false` aunque el correo esté intacto.
- **Zona de confianza.** Se basa en el orden de las cabeceras `Received`. Un correo reenviado o retocado por un sistema intermedio puede romper la frontera; en ese caso las cabeceras quedan «sin confirmar», nunca «de confianza» por error.
- **Alineación incompleta.** Si `Authentication-Results` da un `pass` sin `smtp.mailfrom` ni `header.d`, no se puede saber si estaba alineado y no se emite `auth.dmarc-unaligned`.

## General

- Son heurísticas: una nota baja no garantiza que un correo sea seguro.
- No se consultan listas negras, WHOIS ni servicios de reputación.
- No se analiza el contenido de los adjuntos (solo nombre, tipo y SHA-256), ni el formato `.msg` de Outlook.
