<div align="center">

<img src="assets/img/favicon.svg" width="72" alt="">

# PhishLens

**Is it phishing? Find out, and understand why, without your email ever leaving the browser.**

**English** · [Español](README.es.md)

[![Tests](https://github.com/ManzaXx/PhishLens/actions/workflows/tests.yml/badge.svg)](https://github.com/ManzaXx/PhishLens/actions/workflows/tests.yml)
![Tests](https://img.shields.io/badge/tests-786%20%2B%2081%20e2e-15803d)
![Dependencies](https://img.shields.io/badge/dependencies-0-0f766e)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-f7df1e?logo=javascript&logoColor=000)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-c0392b)
[![MIT License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

![PhishLens in simple mode: the verdict, what to do now and why](docs/img/en/sencillo-claro.png)

PhishLens analyzes an email (an `.eml` file or pasted text) or a URL and returns a **risk score from 0 to 100**. It explains every signal in plain language, maps it to its **MITRE ATT&CK** technique and extracts the **indicators of compromise (IOCs)**, ready to share with a security team.

**[Try it in your browser → manzaxx.github.io/PhishLens](https://manzaxx.github.io/PhishLens/)**

Everything runs in your browser. There is no server, no cookies and no analytics, and a strict Content-Security-Policy blocks any connection to third parties.

The interface comes in English and Spanish: it follows your browser's language, and the **ES/EN** button switches it. Reports, STIX bundles and forensic reports are written in the language you choose.

## ✨ Features

- **Two levels of detail**: **simple mode** gives the verdict in one sentence, three steps on what to do and the signals in plain language; **analyst mode** has a side navigation with Summary, Signals, Safe view, Authentication, Headers and route, Attachments, URLs, IOCs, Campaigns, ATT&CK, Dashboard and History, with the view kept in the URL (`#analista/senales`).
- **10 detectors and 86 rules**: authentication, sender, headers, route, MIME structure, links, lookalike domains, attachments, HTML and language. Every rule has a plain-language text and an ATT&CK technique.
- **Explained report**: traffic-light score, main reason, analysis confidence, risk per category, dangerous combinations and recommendations.
- **Safe view**: the email as plain text, with no live links and the social-engineering phrases highlighted.
- **Email route**: rebuilds the `Received` hops with their IPs.
- **Defanged IOCs** (`hxxp://evil[.]xyz`) with a copy button to paste them into a ticket.
- **Many emails at once**: drop up to 50 `.eml` files (100 MB in total) and pick which one to view. An SVG **IOC graph** links emails, senders, domains, IPs, URLs and attachments (keyboard-friendly, with an equivalent table), and **campaigns** group the emails that share infrastructure, an attachment or the same template.
- **MITRE ATT&CK**: every signal linked to its technique (T1566.002, T1036.007, T1684.001…), with its tactic and the reason, following ATT&CK 20.1.
- **URLs without visiting them**: unwraps redirects (Safe Links, Google, Facebook, LinkedIn, parameters such as `url` or `next`, base64 and double encoding, up to 10 hops) and spots disguised IPs (`http://3232235777`), credentials in the link, unusual ports and random-looking domains. The **URLs** view shows the hop chain with nothing clickable.
- **Export** (JSON, **STIX 2.1**, copy IOCs, forensic report) from a keyboard-accessible menu. The STIX bundle carries observables, indicators, ATT&CK techniques and campaigns with deterministic ids, and passes the official OASIS validator ([docs/stix.md](docs/stix.md)).
- **Its own design system** ([docs/design-system.md](docs/design-system.md)): tokens with contrast checked in light and dark themes, 44 px touch targets and no horizontal scroll at 360 px, verified in a real Chromium.
- **Optional history in the browser** (off by default): it stores the report of each analysis, never the email. Search an IOC across everything stored, filter by level, date or technique, compare two analyses and export or import the history as `.json`. «Borrar todo» (delete all) wipes the whole database.
- **SOC dashboard** on top of the history: key figures, levels over time, most seen ATT&CK techniques, recurring IOCs (one click searches them), top senders and domains, and recent campaigns. Hand-made SVG charts, each with its data table and colour-blind-safe colours.
- **Forensic report** as PDF (through the print dialog) and JSON: identification with SHA-256, SHA-1 and MD5, verdict, findings by severity, authentication, timeline, IOCs, attachments, URLs and the analyst's notes. The JSON carries `reportSha256` so you can check nobody touched it ([docs/forensic.md](docs/forensic.md)).
- **Custom rules in JSON**: add your own signals (your company's domains, attachments you never receive, combinations with PhishLens rules) in a closed format with no regular expressions. Files are validated as a whole, previewed against the history before you turn them on, and can never lower the score ([docs/rules.md](docs/rules.md)).
- **17 sample emails and a 4-email campaign batch** that load with one click.

| Simple mode (dark) | Mobile | Legitimate email |
|---|---|---|
| ![Simple mode in the dark theme](docs/img/en/sencillo-oscuro.png) | ![Simple mode on mobile](docs/img/en/movil-sencillo.png) | ![Simple mode with a legitimate email](docs/img/en/sencillo-legitimo.png) |

| Analyst mode: summary | Signals | Authentication |
|---|---|---|
| ![Analyst mode with the risk ring and the categories](docs/img/en/analista-resumen.png) | ![Signals grouped by severity, reliability and ATT&CK](docs/img/en/analista-senales.png) | ![SPF, DKIM and DMARC with their status](docs/img/en/analista-autenticacion.png) |

| Safe view | Headers and route | Attachments |
|---|---|---|
| ![Safe view with highlighted phrases](docs/img/en/analista-vista-segura.png) | ![Received route with warnings per hop](docs/img/en/analista-cabeceras.png) | ![Attachments inside: active PDF and password-protected ZIP](docs/img/en/analista-adjuntos.png) |

| Batch IOC graph | Campaigns | Batch on mobile |
|---|---|---|
| ![Radial IOC graph of a four-email batch](docs/img/en/analista-grafo.png) | ![Four-email campaign with what they share](docs/img/en/analista-campanas.png) | ![Batch picker and campaign notice on mobile](docs/img/en/movil-lote.png) |

| URLs | IOCs | ATT&CK |
|---|---|---|
| ![Hop chain of a link with a nested redirect](docs/img/en/analista-urls.png) | ![Defanged IOCs with Unicode domains](docs/img/en/analista-iocs.png) | ![ATT&CK techniques](docs/img/en/analista-attack.png) |

| History | History on mobile | Dashboard on mobile |
|---|---|---|
| ![History with search, filters and two analyses selected to compare](docs/img/en/analista-historial.png) | ![History on mobile, dark theme](docs/img/en/movil-historial.png) | ![Dashboard on mobile, dark theme](docs/img/en/movil-panel.png) |

![SOC dashboard: seven saved analyses, levels over time, ATT&CK techniques, recurring IOCs and a campaign](docs/img/en/analista-panel.png)

| Printed forensic report | Report dialog on mobile |
|---|---|
| ![Forensic report: identification with hashes, verdict and findings by severity](docs/img/en/informe-forense.png) | ![Forensic report dialog with the analyst's notes, dark theme](docs/img/en/forense-dialogo.png) |

| Custom rules: preview | Custom rules on mobile |
|---|---|
| ![Three custom rules loaded with their preview against the history](docs/img/en/reglas-vista-previa.png) | ![Custom rules on mobile, dark theme](docs/img/en/movil-reglas.png) |

## 🔍 What it detects

| Detector | Signals | ATT&CK |
|---|---|---|
| **Authentication** | SPF, DKIM and DMARC with their **status** (verified by PhishLens, declared by the receiver, declared but unconfirmed, not verifiable without DNS); **forged** `Authentication-Results`; DMARC without alignment; body modified after the DKIM signature (`bh=` hash checked locally); DKIM signature and SPF verifiable by pasting the key or the record | T1684.002 |
| **Sender** | `Reply-To` and `Return-Path` from another domain, brand impersonated from an unrelated domain or a free mailbox, disguised Cyrillic or Greek letters (`Pаypal`), invisible characters, display name with another address (`"soporte@paypal.com" <x@evil.test>`), unsigned `Sender` from another domain | T1684.001, T1027 |
| **Technical headers** | `Message-ID` from another domain, missing `Date` or `Message-ID`, future date, phishing-kit `X-Mailer` (PHPMailer…), several `From` or repeated single headers | T1684.002 (several `From`) |
| **Email route** | Private IP on the entry hop, timestamps going backwards, delivery over 24 h, more than 25 hops, a server claiming to be a brand (HELO) when it isn't | T1684.002 |
| **Links** | Text showing another domain, IPs (also disguised as decimal, hex or octal), shorteners, `@` hiding the host, user and password in the link, punycode, cheap TLDs, login without HTTPS, brand in the path, direct download of executables, tracking links, nested or open redirects, unusual ports and random domains | T1566.002, T1204.001 |
| **Lookalike domains** | Levenshtein and homoglyphs (`0→o`, `1→l`, `rn→m`) against 37 brands (22 verified Spanish ones), Unicode UTS #39 confusables, mixed-script or fully Cyrillic domains (`аррӏе.com`), homographs with rare Latin or other-script letters (`ɑpple.com`), misleading subdomains (`paypal.com.cuenta-segura.test`), brand + login word (combosquatting) | T1583.001 |
| **Attachments** | Executables, double extension (`factura.pdf.exe`), names reversed with RLO, and inside without opening them: real type not matching the extension, ZIP with programs or a password, VBA macros, PDF that acts on open, HTML smuggling, disk images and shortcuts. SHA-256, SHA-1 and MD5 | T1566.001, T1204.002, T1036.007, T1036.002, T1036.008, T1027.006, T1027.013, T1553.005, T1059.005 |
| **HTML content** | Forms inside the email, JavaScript or iframes, `data:` links, hidden text to beat filters, emails that are just an image | T1598, T1059.007, T1027 |
| **Language** | Urgency, threats, prizes and credential requests, in Spanish and English | T1204, T1598 |

### Scoring

The score (0–100) combines six categories: Authentication, Sender, Links, Attachments, Language and Infrastructure.

- Each signal weighs according to its severity and its reliability, and each category saturates: ten odd links are not worth more than one very serious one.
- **Dangerous combinations** raise the score, for example brand impersonation with failed authentication.
- A verified DKIM signature softens the weaker signals.

Besides the score, the report gives the **analysis confidence** (high, medium or low) based on what could be checked. Details and a worked example in [docs/scoring.md](docs/scoring.md) (in Spanish).

| Score | Verdict |
|---|---|
| 0–24 | 🟢 Probably legitimate |
| 25–59 | 🟠 Suspicious |
| 60–79 | 🔴 Likely phishing |
| 80–100 | 🟣 Almost certainly phishing |

## 🚀 Run it locally

```bash
git clone https://github.com/ManzaXx/PhishLens.git
cd PhishLens
python -m http.server 8080      # or: npx serve .
# open http://localhost:8080
```

Click any of the samples or drop your own `.eml` on the page. In Gmail you can download it with <kbd>⋮</kbd> → *Download message*, or copy the original from *Show original* and paste it.

The samples are fictional: the attackers' domains use the reserved `.test` TLD and do not exist.

## 🏗️ Architecture

Layers, data models and limits in [docs/architecture.md](docs/architecture.md); decisions in [docs/adr/](docs/adr/). The docs are in Spanish.

```mermaid
flowchart LR
  A[".eml · text · URL"] --> B["parser/eml.js<br/>parser/url.js"]
  B --> C{{"Email object"}}
  C --> D1[auth] & D2[sender] & D3[headers] & D4[links] & D5[lookalike] & D6[attachments] & D7[html] & D8[language]
  D1 & D2 & D3 & D4 & D5 & D6 & D7 & D8 --> E["core/engine.js<br/>score + ATT&CK"]
  C --> F["intel/ioc.js<br/>defanged IOCs"]
  E & F --> G["ui/render.js<br/>(textContent only)"]
```

```
PhishLens/
├── index.html               # Single page with a strict CSP
├── assets/                  # CSS (light/dark theme), favicon and share image
├── src/
│   ├── lib/                 # Pure utilities: SHA-256, limits, safe text
│   ├── data/                # Brands, reference lists, patterns and the MITRE ATT&CK map
│   ├── parser/              # eml.js (RFC 5322 + MIME), received.js, html.js (no DOM), url.js
│   ├── detectors/           # 10 detectors with the same interface: detect(email) -> Finding[]
│   ├── intel/               # Defanged IOCs, unwrapped URLs, graph, campaigns, STIX 2.1, dashboard and forensic report
│   ├── rules/               # Custom rules: validator, regex-free engine and preview
│   ├── storage/             # Optional IndexedDB history, with its validator
│   ├── core/                # Finding model, engine and recommendations
│   └── ui/                  # Report rendering, highlighting and page controller
├── docs/                    # Architecture, ADRs, specs and plans
├── SECURITY.md              # Threat model and mitigations
├── samples/                 # 17 sample .eml emails, a campaign batch and sample rules
├── tools/                   # Samples, screenshots, coverage matrix and STIX validator
└── tests/                   # unit/, e2e/, fuzz/ and perf/ with node:test
```

### Technical decisions

- **Plain JavaScript with ES modules**, no frameworks and no build step: the code you read is the code that runs.
- **The engine never touches the DOM**, so the whole analysis is tested in Node with `node --test`, with no dependencies.
- **The email is never interpreted as HTML.** It is inserted with `textContent`, links in the email are not clickable and the HTML is walked by a custom scanner that creates no nodes.
- **Hardened against malicious emails.** The parser runs in linear time and the regexes have bounded quantifiers. Tests check that thousands of unclosed tags, brackets or dots do not freeze the tab (ReDoS).
- **Isolated detectors.** If one fails, the engine logs it and carries on with the rest.
- **Security audited.** Trusted Types, CSP without `unsafe-inline`, DoS limits, protection against prototype pollution and clickjacking. See [SECURITY.md](SECURITY.md).
- **Privacy by design.** The CSP (`connect-src 'none'`, `script-src 'self'`, no `unsafe-inline`) prevents sending data out even if there were a bug, and a test in a real Chromium checks that analyzing an email makes not a single request outside the origin.

## 🧪 Tests

```bash
node --test                 # unit, golden, fuzzing (2,000 cases), differential and performance
npm run fuzz                # 20,000 fuzzing cases
npm run bench               # rewrites docs/benchmark.md
npm ci && npx playwright install chromium && npm run test:e2e   # privacy and accessibility in Chromium
E2E_BROWSERS=firefox,webkit node --test tests/e2e/worker.e2e.js  # the analysis worker inherits the CSP (CI runs it in Firefox and WebKit too)
```

GitHub Actions runs everything on every push (`.github/workflows/tests.yml`), plus `npm audit`, and Dependabot watches the test dependencies and the Actions. The tests cover the parser, every detector with positive and negative cases, the engine, the IOCs, the ATT&CK map, the 17 samples and the campaign batch end to end, the graph and the campaigns (also with the batch shuffled) and resistance to malicious input. The [coverage matrix](docs/coverage-matrix.md) says where each rule is tested; the [threat model](docs/threat-model.md) and the [audit](docs/security-audit.md), what each test protects.

## 🌐 Demo

The demo lives at **https://manzaxx.github.io/PhishLens/**. The `.github/workflows/pages.yml` workflow republishes it on every push to `main`, after the tests pass. In a fork, choose *GitHub Actions* as the source under *Settings → Pages*.

## ⚠️ Limitations

- These are heuristics: a low score **does not guarantee** that an email is safe, and a badly configured legitimate email can look suspicious.
- It does not query external services (blocklists, WHOIS, VirusTotal), because that would mean sending data out of the browser.
- Campaigns are a hint, not proof: emails are chained (A shares something with B and B with C) and only emails that don't look legitimate are included.
- Without network access it cannot know a domain's age or unwrap a shortener (`bit.ly`, `t.co`): only what is written inside the URL itself.
- Without network access it does not query DNS: the DKIM signature and SPF are only verified if you paste the key or the record. Details in [docs/limitations.md](docs/limitations.md).
- It looks inside attachments without opening them, but decompresses nothing: a PDF inside a ZIP or the compressed content of a PDF are not checked. It does not read Outlook's `.msg` format either.

## 🗺️ Roadmap

- [x] DKIM signature verification with WebCrypto (2.2)
- [x] Batch mode, IOC graph and campaigns (2.3)
- [x] URLs without visiting them and STIX 2.1 export (2.3)
- [x] History, SOC dashboard, forensic report and custom rules (3.0)
- [x] English interface (3.1)
- [ ] Browser extension to analyze the email open in Gmail or Outlook

## 📄 License and disclaimer

[MIT](LICENSE) © 2026 Pablo Manzanedo. `src/data/psl.js` is a copy of the [Public Suffix List](https://publicsuffix.org/) under the MPL 2.0.

PhishLens is an educational defensive-security project. If you receive a suspicious email, contact the company through an official channel and report it. In Spain you can call INCIBE on **017**.

---

<div align="center">Made by <b>Pablo Manzanedo</b> · <a href="https://github.com/ManzaXx">GitHub</a></div>
