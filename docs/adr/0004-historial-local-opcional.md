# ADR 0004 · Historial local opcional

- **Estado:** aceptada
- **Fecha:** 2026-11-07

## Contexto

La 3.0 necesita guardar análisis para buscar IOCs entre correos, comparar y, más adelante, montar el dashboard y el informe forense. PhishLens promete que nada sale del navegador y hasta ahora tampoco guardaba nada del correo. Guardar es una superficie nueva: lo guardado sobrevive a la pestaña, lo pueden leer otras pestañas del mismo origen y se puede importar desde un fichero.

## Decisión

- El historial va en **IndexedDB** del propio navegador (base `phishlens`), sin servidor y sin cambiar la CSP (`connect-src 'none'`).
- Viene **apagado**. Con el interruptor apagado no se abre la base; lo comprueba un e2e con `indexedDB.databases()`.
- Se guarda el **informe recortado** (`slimReport`), nunca el correo: sin cuerpo, HTML, cabeceras en bruto ni bytes de adjuntos, y la evidencia de las reglas de lenguaje y HTML a 40 caracteres. El SHA-256 del texto analizado sirve para no repetir entradas.
- **Todo lo que se lee se valida y se recorta** (`validateEntry`), venga de la base o de un `.json`: puede venir manipulado por otra pestaña, una extensión o un fichero viejo.
- **500 entradas** como mucho; al pasar se borra la más antigua y se avisa. «Borrar todo» usa `deleteDatabase`.
- El acceso a IndexedDB se **inyecta** (`backends.js`), para probarlo todo en Node con un backend en memoria.

## Alternativas descartadas

- **`localStorage`:** 5 MB, síncrono y solo texto; no da para 500 informes ni índices.
- **Guardar el correo entero** para poder reanalizarlo: rompe la promesa de privacidad y convierte el historial en un archivo de correos de phishing con datos personales.
- **Cifrar con una contraseña:** añade una contraseña que olvidar y no protege de quien ya controla el perfil del navegador. Se documenta como limitación.

## Consecuencias

- Un análisis guardado no se puede volver a analizar ni verificar su DKIM.
- Lo guardado no va cifrado: quien use el mismo perfil del navegador lo ve.
- Las reglas propias (PR13) solo podrán mirar lo que queda en el informe, no el cuerpo.
