# ADR 0002 · Autenticación sin red

- **Estado:** aceptada
- **Fecha:** 2026-11-05

## Contexto

Verificar de verdad SPF, DKIM y DMARC exige consultar DNS: el registro SPF del dominio del sobre, la clave pública DKIM (`selector._domainkey.dominio`) y la política DMARC (`_dmarc.dominio`). Hasta la 2.1, PhishLens se fiaba de la primera cabecera `Authentication-Results`, que cualquier remitente puede escribir.

La opción obvia sería DNS-over-HTTPS desde el navegador. Se descarta porque cada consulta revela a un tercero (Cloudflare, Google…) qué dominios aparecen en el correo que estás analizando, y eso rompe la promesa de que nada sale del navegador. Además añadiría una dependencia de red a una herramienta que hoy funciona sin conexión.

## Decisión

PhishLens no hace ninguna petición de red para autenticar. En su lugar, separa con claridad tres cosas:

1. **Lo que comprueba él mismo**, siempre: el hash del cuerpo DKIM (`bh=`), la alineación DMARC entre el From y los dominios de SPF y DKIM, y si cada `Authentication-Results` está por encima de la frontera de confianza (añadida por el receptor) o es una falsificación que imita al receptor.
2. **Lo que comprueba si el analista pega el dato**: la firma DKIM con la clave TXT (WebCrypto, RSA-SHA256 y Ed25519) y el registro SPF (solo `ip4`, `ip6` y `all`).
3. **Lo que solo se puede leer**: los resultados declarados en cabeceras, marcados como `declared-trusted` o `declared-untrusted`.

Cada mecanismo tiene un estado (`verified`, `declared-trusted`, `declared-untrusted`, `unverifiable`, `absent`) y la interfaz nunca escribe «verificado» si el estado no es `verified`.

## Consecuencias

- La privacidad se mantiene: cero peticiones, comprobado en el smoke test de navegador.
- El analista que quiera certeza total tiene que consultar DNS por su cuenta y pegar el resultado.
- La política DMARC (`p=`, `adkim=`, `aspf=`) se desconoce, así que se asume alineación relaxed.
- El dominio organizativo se calcula con una copia empaquetada de la Public Suffix List ([ADR 0006](0006-public-suffix-list.md)).
