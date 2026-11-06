// Documento OLE2 / Compound File (MS-CFB): solo se recorre el directorio para saber
// qué streams hay y si alguno es un proyecto VBA. Nunca se lee el contenido de un stream.
import { reader, startsWith } from './bytes.js';
import { OLE_MAGIC } from './magic.js';

export const OLE_MAX_ENTRIES = 1000;
export const OLE_MAX_SECTORS = 4096;
const END = 0xfffffffe;
const FREE = 0xffffffff;
// Nombres que solo aparecen en documentos con macros (MS-OVBA §2.2).
const VBA_NAMES = new Set(['vba', '_vba_project', '_vba_project_cur', 'macros']);

const fail = (reason) => ({ ok: false, streams: [], hasVba: false, reason });

/** `{ok, streams: string[], hasVba, reason}`. Nunca lanza. */
export function readOle(bytes) {
  if (!startsWith(bytes, OLE_MAGIC)) return fail('no es un documento OLE');
  if (bytes.length < 512) return fail('cabecera incompleta');
  const r = reader(bytes);
  const shift = r.u16(30);
  if (shift !== 9 && shift !== 12) return fail('tamaño de sector no válido');
  const size = 1 << shift;
  const sectorAt = (n) => (n + 1) * size;

  // FAT: solo los 109 sectores que lista la propia cabecera.
  const fatSectors = [];
  for (let i = 0; i < 109; i++) {
    const s = r.u32(76 + i * 4);
    if (s === FREE || s === END) break;
    fatSectors.push(s);
  }
  let reason = null;
  if (r.u32(68) !== END && r.u32(68) !== FREE && r.u32(72) > 0) reason = 'FAT extendida no leída';
  const perSector = size / 4;
  const next = (n) => {
    const fs = fatSectors[Math.floor(n / perSector)];
    return fs === undefined ? null : r.u32(sectorAt(fs) + (n % perSector) * 4);
  };

  const streams = [];
  let hasVba = false;
  const visited = new Set();
  let sector = r.u32(48);
  while (sector !== null && sector < END && !visited.has(sector) && visited.size < OLE_MAX_SECTORS && streams.length < OLE_MAX_ENTRIES) {
    visited.add(sector);
    const base = sectorAt(sector);
    if (base + size > bytes.length) break;
    for (let o = base; o < base + size && streams.length < OLE_MAX_ENTRIES; o += 128) {
      const type = r.u8(o + 66);
      const len = r.u16(o + 64);
      if (type !== 1 && type !== 2) continue;
      if (len < 4 || len > 64 || len % 2) continue;
      let name = '';
      for (let c = 0; c < len / 2 - 1; c++) name += String.fromCharCode(r.u16(o + c * 2));
      streams.push(name);
      if (VBA_NAMES.has(name.toLowerCase())) hasVba = true;
    }
    sector = next(sector);
  }
  return { ok: true, streams, hasVba, reason };
}
