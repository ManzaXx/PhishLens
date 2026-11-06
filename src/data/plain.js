// Textos del modo sencillo: una frase por regla, en tú, sin jerga y de 140 caracteres como mucho.
// Dicen qué pasa y por qué importa. {marca} se cambia por la marca suplantada cuando la hay.
// tests/unit/plain.test.js comprueba que cada regla de los detectores tiene el suyo.

export const PLAIN = Object.freeze({
  // Adjuntos
  'attachments.archive': 'Trae un archivo comprimido: es una forma habitual de colar programas dañinos.',
  'attachments.dangerous': 'Trae un adjunto que puede instalar un programa en tu equipo si lo abres.',
  'attachments.double-extension': 'El adjunto finge ser un documento, pero su nombre esconde que es un programa.',
  'attachments.macro': 'El documento adjunto puede ejecutar órdenes en tu equipo al abrirlo.',
  'attachments.rtl-override': 'El nombre del adjunto usa un truco para que leas otra cosa distinta de lo que es.',

  // Autenticación
  'auth.dkim': 'No se puede confirmar que el mensaje salga del dominio que dice, ni que nadie lo haya cambiado.',
  'auth.dkim-body-modified': 'El texto del mensaje cambió después de enviarse: alguien pudo tocarlo por el camino.',
  'auth.dkim-body-verified': 'El texto del mensaje no ha cambiado desde que se firmó.',
  'auth.dkim-verified-aligned': 'Hemos comprobado la firma del correo y coincide con el remitente.',
  'auth.dkim-weak': 'La firma del correo es débil o ha caducado, así que vale poco como garantía.',
  'auth.dmarc': 'El dominio del remitente no da por bueno este envío.',
  'auth.dmarc-declared-mismatch': 'El correo dice estar verificado, pero nada lo respalda de verdad.',
  'auth.dmarc-unaligned': 'Nada confirma que lo envíe de verdad el remitente que ves.',
  'auth.forged-results': 'El correo trae una verificación inventada para parecer de fiar.',
  'auth.missing': 'No hay datos para saber si el correo viene de quien dice.',
  'auth.spf': 'El dominio del remitente no confirma que este servidor pueda enviar en su nombre.',
  'auth.spf-offline': 'Según los datos que pegaste, el servidor que lo envió no está autorizado.',

  // Datos técnicos del correo
  'headers.duplicate': 'Algunos datos del correo aparecen repetidos, algo típico de mensajes manipulados.',
  'headers.duplicate-from': 'El correo dice venir de varias direcciones a la vez.',
  'headers.future-date': 'El correo tiene una fecha de envío en el futuro.',
  'headers.mailer': 'Se envió con una herramienta de envíos masivos.',
  'headers.messageid-domain': 'La huella interna del correo apunta a otro dominio distinto del remitente.',
  'headers.missing-date': 'El correo no dice cuándo se envió.',
  'headers.missing-messageid': 'Al correo le falta la huella interna que ponen los servidores normales.',

  // Contenido
  'html.data-uri': 'Un enlace lleva el contenido escondido dentro, para saltarse los filtros.',
  'html.form': 'El correo trae un formulario para que escribas tus datos sin salir de él.',
  'html.hidden-text': 'Esconde texto que no ves, a menudo para engañar a los filtros.',
  'html.image-only': 'El mensaje es solo una imagen, un truco para que los filtros no lean el texto.',
  'html.script': 'El correo trae código que intenta ejecutarse al abrirlo.',

  // Entrada
  'input.invalid-url': 'Eso no parece una dirección web válida.',
  'input.no-headers': 'Solo hemos visto el texto: con el correo original el análisis es más fiable.',

  // Lenguaje
  'language.credentials': 'Te pide contraseñas o datos bancarios, algo que tu banco nunca hace por correo.',
  'language.prize': 'Te promete un premio o un reembolso para que pulses o des tus datos.',
  'language.threat': 'Te amenaza con cerrar o bloquear algo si no actúas.',
  'language.urgency': 'Te mete prisa para que actúes sin pensar.',

  // Enlaces
  'links.at-sign': 'El enlace usa un truco con «@» para esconder a dónde lleva de verdad.',
  'links.brand-in-path': 'El enlace nombra a {marca}, pero lleva a una web que no es suya.',
  'links.download': 'El enlace descarga un archivo en lugar de abrir una página.',
  'links.insecure-login': 'Te lleva a una página para iniciar sesión sin conexión segura.',
  'links.ip': 'El enlace lleva a una dirección numérica en vez de a una web con nombre.',
  'links.mismatch': 'El enlace no lleva a donde dice.',
  'links.punycode': 'El enlace usa letras de otros alfabetos que imitan a las normales.',
  'links.shortener': 'El enlace está acortado y no deja ver a dónde lleva.',
  'links.tld': 'El enlace usa una terminación de web muy usada en estafas.',
  'links.tracking': 'El enlace registra que lo has pulsado antes de llevarte a la web.',

  // Dominios parecidos
  'lookalike.brand-in-domain': 'Usa el nombre de {marca} en una dirección que no es suya.',
  'lookalike.deceptive-subdomain': 'La dirección empieza como la de {marca}, pero en realidad es de otro.',
  'lookalike.homoglyph': 'La dirección cambia letras por otras casi iguales para parecerse a {marca}.',
  'lookalike.mixed-script-domain': 'La dirección mezcla letras de varios alfabetos para engañar a la vista.',
  'lookalike.typosquat': 'La dirección se parece mucho a la de {marca}, pero no es la misma.',
  'lookalike.whole-script': 'La dirección está escrita en otro alfabeto para parecerse a {marca}.',

  // Estructura del correo
  'mime.boundary-in-content': 'El correo tiene una estructura rara que puede esconder partes al leerlo.',
  'mime.boundary-reuse': 'El correo está montado de forma rara, un truco para esconder partes.',
  'mime.charset-conflict': 'El correo se contradice sobre cómo leer su texto.',
  'mime.duplicate-content-type': 'El correo se contradice sobre qué tipo de contenido lleva.',
  'mime.header-without-colon': 'El correo tiene líneas mal formadas que algunos programas leen distinto.',
  'mime.limit': 'El correo es tan grande o enrevesado que una parte no se ha podido revisar.',
  'mime.nested-message': 'Dentro del correo va otro correo.',
  'mime.unclosed-multipart': 'El correo está cortado o mal cerrado.',

  // Ruta
  'route.helo-mismatch': 'El servidor que lo envió se presenta como el de una empresa conocida, y no lo es.',
  'route.private-ip-boundary': 'El correo entró desde una red interna, algo poco habitual.',
  'route.slow-delivery': 'El correo tardó más de un día en llegar.',
  'route.time-travel': 'Las horas del viaje del correo no cuadran, como si alguien las hubiera tocado.',
  'route.too-many-hops': 'El correo dio demasiadas vueltas antes de llegar.',
  'route.unparseable': 'No hemos podido leer por dónde pasó el correo.',

  // Remitente
  'sender.brand-impersonation': 'Se hace pasar por {marca}, pero lo envía otro.',
  'sender.display-name-address': 'El nombre del remitente muestra una dirección distinta de la real.',
  'sender.invisible-chars': 'El remitente lleva caracteres invisibles para despistar.',
  'sender.mixed-script': 'El nombre del remitente usa letras de otro alfabeto camufladas.',
  'sender.replyto-mismatch': 'Si respondes, tu respuesta irá a otra dirección distinta del remitente.',
  'sender.returnpath-mismatch': 'Los avisos de entrega van a otro dominio distinto del remitente.',
  'sender.sender-mismatch': 'Lo envía alguien en nombre de otro dominio.',
});

const GENERIC_BRAND = 'una empresa conocida';

/** Texto llano de una regla con la marca puesta, o el título si la regla no tiene texto. */
export function plainFor(id, brand, title) {
  const text = Object.hasOwn(PLAIN, id) ? PLAIN[id] : null;
  if (!text) return title;
  return text.replaceAll('{marca}', brand || GENERIC_BRAND);
}
