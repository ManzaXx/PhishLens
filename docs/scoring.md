# Cómo se calcula la nota y la confianza

PhishLens da dos números distintos:

- **Riesgo (0–100):** cuánta evidencia de phishing hay. Es un **indicador heurístico, no una probabilidad**: 60 no significa «un 60 % de probabilidades de phishing», sino que se han acumulado varias señales medias o alguna grave. Por eso el veredicto va por tramos (§6) y la evaluación se hace sobre los tramos, no sobre el número ([docs/evaluation.md](evaluation.md)).
- **Confianza del análisis (alta, media o baja):** cuánto del correo se pudo comprobar. Mide carencias de la entrada, nunca el riesgo.

Un texto pegado sin cabeceras puede tener riesgo 0 y confianza baja: no hay señales, pero tampoco había mucho que mirar.

El código está en `src/core/scoring.js` y `src/core/confidence.js`. Son funciones puras con tests de propiedades.

## 1. Peso de cada señal

Cada hallazgo de riesgo pesa:

```
peso = base(gravedad) × factor(fiabilidad)
```

| Gravedad | base | | Fiabilidad | factor |
| --- | --- | --- | --- | --- |
| leve | 0,25 | | alta | 1 |
| media | 0,5 | | media | 0,75 |
| grave | 0,9 | | baja | 0,5 |

Los avisos informativos y las señales a favor (`polarity: 'trust'`) no suman.

## 2. Nota de cada categoría

| Categoría | Detectores | Máximo |
| --- | --- | --- |
| Autenticación | auth | 25 |
| Remitente y suplantación | sender, lookalike del `From`, varios `From` | 20 |
| Enlaces y contenido | links, html, lookalike de enlaces | 20 |
| Adjuntos | attachments | 15 |
| Lenguaje | language | 10 |
| Infraestructura | headers, route | 10 |

Cada categoría combina sus pesos con un **OR ruidoso**:

```
nota_c = máximo_c × (1 − Π(1 − pesoᵢ))
```

Diez enlaces sospechosos se acercan a 20 pero nunca lo superan.

**Un hecho, una señal.** «El `From` dice ser la marca X y su dominio no es de X» lo ven a la vez `sender.brand-impersonation` y el detector de dominios parecidos (`lookalike.*` sobre el `From`). Dentro de Remitente, las señales de suplantación de **la misma marca** se funden en una y cuenta la de más peso; las dos siguen en el informe y en las combinaciones (§4). Dos marcas distintas son dos hechos, y un dominio parecido en un enlace es otro hecho (categoría Enlaces).

Los avisos informativos no suman. Desde la auditoría 3.1 lo son también **no tener `Authentication-Results`** (`auth.missing`: un `.eml` exportado de «Enviados» o reenviado como adjunto no lo trae) y **no tener `Message-ID`** (`headers.missing-messageid`: muchos clientes lo quitan al exportar). La falta de autenticación sigue bajando la confianza (§8).

## 3. Nota total

Las categorías se combinan con un segundo OR ruidoso:

```
base = 100 × (1 − Π_c (1 − nota_c / 40))
```

**Por qué no se suman sin más.** La especificación (§7.1) proponía sumar las categorías, y la suma de sus máximos es 100. Pero con la suma simple sus propios ejemplos no se cumplen:

- Ocho enlaces sospechosos se quedaban en «legítimo» (~19).
- Suplantación + `.exe` + DMARC fallido no llegaba a «crítico» (~54).

Con la escala de 40 (`SCALE`):

- Una sola categoría llena da como mucho ~50, que es «sospechoso».
- Dos categorías fuertes dan «phishing».
- Tres dan «crítico».

Los máximos siguen pesando: Autenticación llena (25) aporta más que Lenguaje lleno (10).

## 4. Combinaciones peligrosas

Algunas señales son mucho más graves juntas que por separado. Cada combinación que se cumple suma `(100 − nota) × 0,25`, como mucho dos:

| Combinación | Cuándo |
| --- | --- |
| Suplantación de marca con autenticación fallida | Suplantación (`sender.brand-impersonation`, `display-name-address`, `mixed-script` o un lookalike en el `From`) + un fallo de autenticación de gravedad media o alta. No tener cabecera de autenticación no cuenta como fallo |
| Suplantación de marca que pide credenciales | Suplantación, dominio parecido en un enlace o marca en la ruta de un enlace raro (IP o login sin HTTPS) + formulario, petición de credenciales o login sin HTTPS |
| Marca suplantada con enlaces a una dirección IP | Lo mismo + `links.ip` |
| Pide credenciales y da un enlace sospechoso para ello | Petición de credenciales o formulario + un enlace sospechoso (acortador, IP, texto engañoso…) |
| Adjunto peligroso con presión para abrirlo | Adjunto ejecutable, con macros o con extensión engañosa + urgencia o amenaza |
| Enlace que imita a la misma marca que el remitente | Lookalike en un enlace de la misma marca que suplanta el remitente |

## 5. Señales contradictorias

Si PhishLens **verifica** la firma DKIM con la clave pública pegada y el dominio firmante coincide con el del `From` (`auth.dkim-verified-aligned`), las categorías Lenguaje e Infraestructura valen la mitad. Las señales blandas pesan menos en un correo con firma válida.

Un `bh=` que cuadra no basta: cualquiera puede calcular el hash de su propio cuerpo y escribir una firma falsa.

Nunca se rebajan Remitente, Enlaces ni Adjuntos: un atacante puede firmar sus propios correos.

## 6. Niveles

| Nota | Veredicto |
| --- | --- |
| 0–24 | Probablemente legítimo |
| 25–59 | Sospechoso |
| 60–79 | Probable phishing |
| 80–100 | Phishing casi seguro |

## 7. Ejemplo resuelto: muestra 03 (falso Banco Santander)

| Categoría | Nota |
| --- | --- |
| Autenticación | 22,9 / 25 |
| Remitente | 19,3 / 20 |
| Enlaces | 19,6 / 20 |
| Adjuntos | 0 / 15 |
| Lenguaje | 6,9 / 10 |
| Infraestructura | 3,4 / 10 |

1. La base es 91,4 (Remitente da 19,3 y no 19,9 porque la suplantación de Santander la ven dos detectores y cuenta una vez).
2. Se cumplen cuatro combinaciones y cuentan las dos primeras: suplantación con autenticación fallida, y suplantación que pide credenciales.
   - 91,4 + 8,6 × 0,25 = 93,6.
   - 93,6 + 6,4 × 0,25 = 95,2, que redondea a **95**, «Phishing casi seguro».
3. Motivo principal: «Suplantación de marca con autenticación fallida».

## 8. Confianza del análisis

Empieza en 1 y resta por cada carencia:

| Carencia | Resta |
| --- | --- |
| Sin cabeceras (texto pegado o URL suelta) | 0,40 |
| Autenticación solo sin confirmar, no verificable o ausente | 0,20 |
| PhishLens no ha verificado nada por sí mismo | 0,10 |
| El parser alcanzó un límite o anotó problemas (`parseNotes`) | 0,15 |
| Algún detector falló | 0,15 |
| Solo una categoría aporta riesgo | 0,10 |

`≥ 0,75` es alta, `≥ 0,45` es media y el resto es baja.

La confianza nunca mira la nota: dos informes con las mismas carencias tienen la misma confianza.

## 9. Propiedades comprobadas en los tests

`tests/unit/scoring.test.js` comprueba 500 conjuntos aleatorios con semilla fija:

- La nota está entre 0 y 100, y cada categoría no pasa de su máximo.
- Añadir una señal de riesgo nunca baja la nota.
- El orden de las señales no cambia nada.
