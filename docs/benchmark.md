# Benchmark del motor

Generado con `npm run bench` (`tools/bench.mjs`). Cada correo lo crea `tests/perf/build.js`: HTML con 40 enlaces
y un adjunto PDF en base64 que rellena hasta el tamaño pedido. El tiempo es la mediana de 3 ejecuciones de
`analyzeInput`; la memoria es el `heapUsed` máximo medido justo después de cada una.

- Node: v22.23.4
- CPU: Intel(R) Xeon(R) Processor (4 núcleos)
- Fecha: 2026-11-05

| Tamaño | Tiempo | Memoria (heapUsed) |
| --- | --- | --- |
| 1 KB | 7 ms | 6.1 MB |
| 1 MB | 47 ms | 11.0 MB |
| 10 MB | 290 ms | 47.1 MB |
| 25 MB | 189 ms | 86.1 MB |

Un adjunto de más de 10 MB (`LIMITS.attachmentBytes`) no se decodifica entero: su tamaño real sale de la
longitud del base64. Por eso 25 MB no cuesta 2,5 veces lo que cuestan 10 MB.

El test `tests/perf/perf.test.js` exige menos de 4 s para 25 MB. En un navegador los números cambian según el
equipo, pero el orden de magnitud es el mismo porque el motor es el mismo código.
