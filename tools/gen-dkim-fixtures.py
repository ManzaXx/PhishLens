#!/usr/bin/env python3
"""Genera correos firmados con DKIM para los tests de PhishLens.

Usa dkimpy, una implementación independiente, como oráculo: si PhishLens se probara con
correos firmados por su propio código, un error de canonicalización pasaría desapercibido.

Uso (solo en desarrollo, no forma parte de `npm test`):
    python3 -m venv .venv && .venv/bin/pip install dkimpy cryptography pynacl
    .venv/bin/python tools/gen-dkim-fixtures.py

Escribe tests/fixtures/dkim/*.eml y keys.json (registros TXT públicos). Todo es ficticio:
dominios .test y claves generadas en el momento que no se usan en ningún otro sitio.
"""
import base64
import json
from pathlib import Path

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

OUT = Path(__file__).resolve().parent.parent / 'tests' / 'fixtures' / 'dkim'
DOMAIN = b'banco-ficticio.test'

MESSAGE = (
    b'From: Banco Ficticio <avisos@banco-ficticio.test>\r\n'
    b'To: cliente@example.com\r\n'
    b'Subject:  Aviso   de seguridad \r\n'
    b'Date: Wed, 21 Oct 2026 07:03:05 +0000\r\n'
    b'Message-ID: <aviso-1@banco-ficticio.test>\r\n'
    b'MIME-Version: 1.0\r\n'
    b'Content-Type: text/plain; charset=utf-8\r\n'
    b'\r\n'
    b'Hola,  \r\n'
    b'\r\n'
    b'Hemos detectado un acceso nuevo a tu cuenta.\t \r\n'
    b'Si no has sido tu, llama al 900 000 000.\r\n'
    b'\r\n'
    b'\r\n'
)
HEADERS = [b'from', b'to', b'subject', b'date', b'message-id']


def rsa_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, 'v=DKIM1; k=rsa; p=' + base64.b64encode(spki).decode()


def ed_key():
    key = ed25519.Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(seed), 'v=DKIM1; k=ed25519; p=' + base64.b64encode(pub).decode()


def sign(message, selector, priv, canon, algo=b'rsa-sha256', length=False):
    sig = dkim.sign(message, selector, DOMAIN, priv, canonicalize=canon, include_headers=HEADERS,
                    signature_algorithm=algo, length=length)
    return sig + message


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rsa_priv, rsa_txt = rsa_key()
    ed_priv, ed_txt = ed_key()
    keys = {'rsa2026._domainkey.banco-ficticio.test': rsa_txt, 'ed2026._domainkey.banco-ficticio.test': ed_txt}
    cases = {
        'rsa-relaxed': sign(MESSAGE, b'rsa2026', rsa_priv, (b'relaxed', b'relaxed')),
        'rsa-simple': sign(MESSAGE, b'rsa2026', rsa_priv, (b'simple', b'simple')),
        'ed25519-relaxed-simple': sign(MESSAGE, b'ed2026', ed_priv, (b'relaxed', b'simple'), algo=b'ed25519-sha256'),
        'rsa-length': sign(MESSAGE, b'rsa2026', rsa_priv, (b'relaxed', b'relaxed'), length=True),
    }
    good = cases['rsa-relaxed']
    cases['rsa-body-modified'] = good.replace(b'900 000 000', b'806 000 000')

    def dns(name, timeout=5):
        return keys.get(name.decode().rstrip('.'), '').encode()

    for name, msg in cases.items():
        ok = dkim.verify(msg, dnsfunc=dns)
        expected = name != 'rsa-body-modified'
        assert ok == expected, f'{name}: dkimpy verify={ok}, esperado {expected}'
        (OUT / f'{name}.eml').write_bytes(msg)
    (OUT / 'keys.json').write_text(json.dumps(keys, indent=2) + '\n')
    print(f'{len(cases)} correos y {len(keys)} claves en {OUT}')


if __name__ == '__main__':
    main()
