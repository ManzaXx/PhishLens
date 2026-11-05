// Alineación DMARC (RFC 7489 §3.1) en modo relaxed: el dominio autenticado por SPF o DKIM
// debe compartir dominio organizativo con el From visible. Sin DNS no se conoce la política
// (p=, adkim=, aspf=), así que se asume relaxed y se documenta en docs/limitations.md.
import { registrableDomain } from '../parser/url.js';

const same = (a, b) => Boolean(a && b) && registrableDomain(a) === registrableDomain(b);

export function dmarcAlignment({ fromDomain, spf, dkim = [] }) {
  const spfAligned = spf?.result === 'pass' && same(spf.domain, fromDomain);
  const dkimAligned = dkim.some((d) => d.result === 'pass' && same(d.domain, fromDomain));
  return { aligned: spfAligned || dkimAligned, via: dkimAligned ? 'dkim' : spfAligned ? 'spf' : null, spfAligned, dkimAligned };
}
