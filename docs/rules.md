# Reglas propias

Con un fichero JSON puedes añadir tus propias señales a las de PhishLens: dominios de tu empresa, tipos de adjunto que nunca recibes o combinaciones con las reglas que ya trae. Se cargan en la portada, en **«Reglas propias» → «Cargar reglas (.json)»**.

- Se valida **todo el fichero** antes de aceptar nada. Cada error dice la regla, la ruta y el motivo, por ejemplo: «Regla 3, `when.all[1].op`: «matches» no es un operador admitido».
- Antes de activarlas se ve una **vista previa**: en cuántos análisis guardados se cumpliría cada regla. Solo se puede calcular para las reglas que miran únicamente `finding.id`, porque el historial no guarda el correo.
- Activadas, se aplican como un detector más, **después** de los de PhishLens. Sus hallazgos llevan la marca «Regla propia», el id `custom.<id>` y procedencia `declared`.
- Puntúan con los mismos puntos y techos por categoría que el resto. **Una regla propia nunca baja la nota**: solo puede añadir señales de riesgo.
- Con el historial encendido se guardan en el navegador y siguen tras recargar. Sin historial duran hasta que cierres la pestaña. «Borrar todo» y «Quitar reglas» las quitan.
- **Sin expresiones regulares.** Ningún operador construye un `RegExp` con tu texto: no hay ReDoS posible.

## Ejemplo

Es el mismo fichero que [`samples/rules/ejemplo.json`](../samples/rules/ejemplo.json):

```json
{
  "phishlens": "rules/1",
  "rules": [
    {
      "id": "mi-org.factura-falsa",
      "title": "Asunto de factura desde un dominio que no es de la empresa",
      "detail": "El asunto habla de una factura y el remitente no es de la empresa ni de un proveedor conocido.",
      "severity": "medium",
      "category": "sender",
      "technique": "T1566.001",
      "when": { "all": [
        { "field": "subject", "op": "contains", "value": "factura" },
        { "field": "sender.domain", "op": "not-in", "value": ["mi-empresa.es", "proveedor.es"] }
      ] }
    },
    {
      "id": "mi-org.ejecutable-o-imagen",
      "title": "Adjunto ejecutable o imagen de disco",
      "detail": "En esta empresa nadie envía programas ni imágenes de disco por correo.",
      "severity": "high",
      "category": "attachments",
      "technique": "T1204.002",
      "when": { "field": "attachment.extension", "op": "in", "value": ["exe", "scr", "iso", "img", "vhd"] }
    },
    {
      "id": "mi-org.suplantacion-con-enlace",
      "title": "Dominio parecido a una marca y un enlace sospechoso",
      "severity": "medium",
      "category": "links",
      "technique": "T1566.002",
      "when": { "all": [
        { "field": "finding.id", "op": "starts-with", "value": "lookalike." },
        { "field": "finding.id", "op": "starts-with", "value": "links." }
      ] }
    }
  ]
}
```

- **`mi-org.factura-falsa`**: el asunto habla de una factura y el remitente no es de la empresa ni de un proveedor. En las muestras salta con la 06 y la 11.
- **`mi-org.ejecutable-o-imagen`**: un adjunto `.exe`, `.scr`, `.iso`, `.img` o `.vhd`. Salta con la 06 (`Factura_2026-1187.pdf.exe`).
- **`mi-org.suplantacion-con-enlace`**: PhishLens ha visto un dominio parecido a una marca (`lookalike.*`) y además un enlace sospechoso (`links.*`). Salta con la 03, 04 y 10. Como solo mira `finding.id`, la vista previa la puede probar con el historial.

## Formato

```
{ "phishlens": "rules/1", "rules": [ regla, … ] }
```

| Campo de la regla | Obligatorio | Qué es |
| --- | --- | --- |
| `id` | sí | De 3 a 64 caracteres de `a-z`, `0-9`, punto o guion, único en el fichero. El hallazgo se llama `custom.<id>` |
| `title` | sí | Hasta 120 caracteres. Es también el texto del modo sencillo |
| `detail` | no | Hasta 300 caracteres |
| `severity` | sí | `low`, `medium` o `high` (5, 15 o 30 puntos antes de los techos) |
| `category` | sí | `authentication`, `sender`, `links`, `attachments`, `language` o `infrastructure` |
| `technique` | no | Una técnica de ATT&CK que PhishLens conozca (`src/data/mitre.js`), como `T1566.002` |
| `when` | sí | La condición |

**Condición:** una condición simple `{ "field": …, "op": …, "value": … }` o un grupo `{ "all": [ … ] }`, `{ "any": [ … ] }` o `{ "not": condición }`.

**Topes:** 200 KB por fichero, 100 reglas, 4 niveles de grupos, 20 condiciones por regla y 200 valores en `in` y `not-in`.

## Campos

| Campo | Qué lee |
| --- | --- |
| `subject` | El asunto |
| `sender.address`, `sender.domain`, `sender.display` | La dirección del `From`, su dominio y el nombre que se muestra |
| `reply-to.domain`, `return-path.domain` | El dominio de `Reply-To` y de `Return-Path` |
| `link.domain`, `link.url` | El host y la URL de cada enlace (lista) |
| `attachment.name`, `attachment.extension`, `attachment.type`, `attachment.sha256` | Nombre, extensión (sin punto), tipo declarado y SHA-256 de cada adjunto (lista) |
| `body.text` | El texto del cuerpo, o el texto del HTML si no hay parte de texto, hasta 256 K caracteres |
| `finding.id` | Los ids de los hallazgos de PhishLens (lista), no los de otras reglas propias |
| `header:<nombre>` | Una de estas 20 cabeceras: `from`, `to`, `cc`, `reply-to`, `return-path`, `sender`, `subject`, `date`, `message-id`, `x-mailer`, `user-agent`, `x-originating-ip`, `x-priority`, `importance`, `list-unsubscribe`, `authentication-results`, `received-spf`, `x-spam-status`, `x-ms-exchange-organization-scl`, `content-type` |

Un campo de lista se cumple si **algún elemento** cumple la condición. Si el campo no está (un correo sin `Reply-To`, una URL suelta, un texto sin cabeceras), la condición no se cumple, tampoco con `not-in`. Para pedir que falte, usa `{ "not": { "field": …, "op": "exists" } }`.

## Operadores

Se comparan sin distinguir mayúsculas y con el Unicode normalizado a NFKC: `ＦＡＣＴＵＲＡ` cumple `contains "factura"`.

| Operador | `value` | Se cumple si |
| --- | --- | --- |
| `equals` | texto | el valor es igual |
| `contains` | texto | el valor contiene el texto |
| `starts-with` | texto | el valor empieza por el texto |
| `ends-with` | texto | el valor acaba en el texto |
| `in` | lista de textos | el valor es uno de la lista |
| `not-in` | lista de textos | el valor existe y no es ninguno de la lista |
| `exists` | — | el campo tiene algún valor |
| `count-gte` | entero ≥ 0 | la lista tiene al menos ese número de elementos (solo campos de lista) |

## Esquema

[`docs/rules.schema.json`](rules.schema.json) describe el formato en JSON Schema 2020-12, para que tu editor lo autocomplete. Es solo documentación: la validación la hace [`src/rules/validate.js`](../src/rules/validate.js), que además pone los topes de niveles y de condiciones. Por qué así: [ADR 0005](adr/0005-reglas-declarativas-sin-regex.md).
