# ADR 0001 · Sin dependencias en tiempo de ejecución

- **Estado:** aceptada
- **Fecha:** 2026-11-05

## Contexto

PhishLens analiza correos potencialmente maliciosos en el navegador de quien lo usa. Cualquier librería que se cargue en la página tiene acceso a ese contenido. Un ataque a la cadena de suministro (un paquete comprometido o una CDN alterada) podría robar los correos o romper la promesa de privacidad.

## Decisión

El código que se ejecuta en el navegador es JavaScript propio con módulos ES, sin frameworks, sin compilación y sin paquetes de npm. Se escriben a mano las piezas pequeñas que harían falta (SHA-256, escáner HTML lineal, parser MIME, punycode).

Las herramientas de desarrollo (Playwright, axe-core) se permiten como `devDependencies`, solo en los tests de navegador, y nunca se sirven en la demo.

## Consecuencias

- La superficie de cadena de suministro en producción es cero, y la CSP puede ser `script-src 'self'` sin excepciones.
- El código que se audita es exactamente el que se ejecuta.
- A cambio, PhishLens mantiene implementaciones propias que deben llevar tests con vectores oficiales (por ejemplo, los de NIST para SHA-256).
