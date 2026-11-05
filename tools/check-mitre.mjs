// Herramienta de desarrollo: comprueba src/data/mitre.js contra el bundle STIX oficial de ATT&CK.
// Uso: node tools/check-mitre.mjs enterprise-attack-20.1.json
// Falla si algún id no existe, está revocado o deprecado, o si su nombre o su táctica no coinciden.
import { readFileSync } from 'node:fs';
import { TECHNIQUES, USED_IDS } from '../src/data/mitre.js';

const bundle = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const idOf = (o) => o.external_references?.find((r) => r.source_name === 'mitre-attack')?.external_id;
const patterns = new Map(bundle.objects.filter((o) => o.type === 'attack-pattern').map((o) => [idOf(o), o]));
const tactics = new Map(bundle.objects.filter((o) => o.type === 'x-mitre-tactic').map((o) => [o.x_mitre_shortname, o.name]));

let problems = 0;
const fail = (msg) => { problems++; console.error(`✗ ${msg}`); };
for (const id of new Set([...USED_IDS, ...Object.keys(TECHNIQUES)])) {
  const ours = TECHNIQUES[id];
  const theirs = patterns.get(id);
  if (!ours) { fail(`${id} se usa en las reglas pero no está en TECHNIQUES`); continue; }
  if (!theirs) { fail(`${id} no existe en el bundle`); continue; }
  if (theirs.revoked || theirs.x_mitre_deprecated) fail(`${id} está revocado o deprecado`);
  const parent = id.includes('.') ? patterns.get(id.split('.')[0])?.name : null;
  const name = parent ? `${parent}: ${theirs.name}` : theirs.name;
  if (ours.name !== name) fail(`${id}: nombre «${ours.name}», oficial «${name}»`);
  const official = (theirs.kill_chain_phases ?? []).map((p) => tactics.get(p.phase_name));
  if (!official.includes(ours.tactic)) fail(`${id}: táctica «${ours.tactic}», oficial ${official.join(', ')}`);
}
if (problems) process.exit(1);
console.log(`✓ ${Object.keys(TECHNIQUES).length} técnicas correctas`);
