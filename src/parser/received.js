// Ruta del email reconstruida a partir de las cabeceras Received.

/** Devuelve la ruta del email en orden de llegada: [{from, by, ip, date}] */
export function parseReceived(email) {
  // Se acota cada cabecera: un Received de megas con "(" sin cerrar no debe bloquear los regex.
  const hops = (email.headers?.get('received') ?? []).slice(0, 30).map((raw) => raw.slice(0, 1000)).map((value) => ({
    from: /\bfrom\s+(\S+)/i.exec(value)?.[1] ?? '',
    by: /\bby\s+([^\s;]+)/i.exec(value)?.[1] ?? '',
    // La IP que vio el servidor receptor va entre paréntesis: "from x (host [IP])".
    ip: (/\([^)]*\[([0-9a-f.:]+)\][^)]*\)/i.exec(value) ?? /\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)\]/i.exec(value))?.[1] ?? '',
    date: value.includes(';') ? value.slice(value.lastIndexOf(';') + 1).trim() : '',
  }));
  // Cada servidor añade su Received arriba: el primero de la lista es el último salto.
  return hops.reverse();
}
