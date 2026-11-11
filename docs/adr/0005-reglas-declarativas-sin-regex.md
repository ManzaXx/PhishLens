# ADR 0005 · Reglas declarativas sin regex

- **Estado:** aceptada
- **Fecha:** 2026-11-11

## Contexto

Un SOC quiere añadir sus propias señales: los dominios de su empresa y de sus proveedores, los tipos de adjunto que nunca reciben o combinaciones con las reglas de PhishLens. Las reglas llegan en un fichero que alguien ha escrito o descargado, y el motor las ejecuta sobre correos de atacantes. Es una superficie nueva por dos lados: el fichero puede venir manipulado y el correo también.

## Decisión

- Las reglas son **datos, no código**: un JSON (`rules/1`) con condiciones `{ field, op, value }` y grupos `all`, `any` y `not`.
- **Campos y operadores salen de listas cerradas.** Los campos se leen con un `Map` de funciones (`FIELDS` en `src/rules/evaluate.js`), nunca con `obj[texto del fichero]`. Las cabeceras que se pueden mirar son 20 fijas.
- **Sin expresiones regulares.** Solo `equals`, `contains`, `starts-with`, `ends-with`, `in`, `not-in`, `exists` y `count-gte`, sobre texto normalizado a NFKC y en minúsculas. Un test comprueba que `src/rules/` no construye ningún `RegExp`.
- **Topes:** 200 KB por fichero, 100 reglas, 4 niveles, 20 condiciones por regla, 200 valores por lista, y `body.text` hasta 256 K caracteres.
- **Validador propio** que rechaza el fichero entero ante el primer error y explica todos (hasta 50) con regla, ruta y motivo. Las reglas aceptadas son objetos nuevos con solo las claves conocidas. Se prueba con fuzzing de 2.000 ficheros mutados (nunca lanza ni pasa de 50 ms).
- Una regla propia **solo añade riesgo**: hallazgos con polaridad `risk` y gravedad `low` o más, puntuados con los mismos techos que el resto.

## Alternativas descartadas

- **Expresiones regulares en las reglas:** son lo que un analista espera, pero una regex escrita sin cuidado (o a propósito) bloquea la pestaña con un correo pensado para ella (ReDoS). Sin un motor de regex lineal no hay forma segura de aceptarlas.
- **JavaScript o un lenguaje de expresiones** (`eval`, `new Function`, un intérprete propio): rompe la CSP y abre ejecución de código desde un fichero.
- **YARA o Sigma:** formatos conocidos, pero necesitan un parser y un motor que no caben sin dependencias, y Sigma está pensado para logs, no para correos.
- **JSON Schema como validador:** necesitaría una librería en ejecución; queda como documentación (`docs/rules.schema.json`).

## Consecuencias

- Algunas reglas no se pueden escribir (patrones con comodines, «tres dígitos seguidos»). `contains` y las listas cubren los casos habituales de un SOC.
- La vista previa sobre el historial solo puede probar las reglas que miran `finding.id`, porque el historial no guarda el correo ([ADR 0004](0004-historial-local-opcional.md)).
- Las reglas guardadas se vuelven a validar al leerlas, como todo lo que sale de IndexedDB.
