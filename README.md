# formguard

**Inspect a reported phishing page for the mechanics of the theft, offline.**

A user reports a link. Someone saves the page, and it sits in a ticket as `index.html`. Opening it
in a browser on a corporate workstation is exactly what the attacker wants, and opening it anywhere
tells you very little because the page looks like the real thing.

`formguard` reads the saved HTML and answers what actually matters: where does the password post,
does the brand on the page match the host, and what does the JavaScript do with what the user types.

<p>
  <img src="https://img.shields.io/badge/python-3.8%2B-0d1117?style=flat-square&logo=python&logoColor=39D353" alt="python" />
  <img src="https://img.shields.io/badge/runtime%20dependencies-zero-0d1117?style=flat-square" alt="zero dependencies" />
  <img src="https://img.shields.io/badge/network-none-0d1117?style=flat-square" alt="no network" />
  <img src="https://img.shields.io/badge/renders-nothing-0d1117?style=flat-square" alt="renders nothing" />
  <img src="https://img.shields.io/badge/license-MIT-0d1117?style=flat-square" alt="MIT" />
</p>

## Why

The visual layer of a phishing page is free to copy. The mechanics cannot be hidden as easily:

- The form has to post somewhere, and that somewhere is almost never the domain in the link.
- The brand in the title has to disagree with the host it is served from.
- The JavaScript has to exfiltrate, which means `fetch`, `XMLHttpRequest` or a beacon.
- Anti-inspection tricks (right-click blocking, `noindex`) are there to defeat scanners.

Each of those is one line of HTML. `formguard` reads all of them and ranks the page.

## Install

One file, standard library only.

```bash
git clone https://github.com/mehulpatel23b-pixel/formguard.git
cd formguard
python3 formguard.py --help
```

## Usage

```bash
# a page saved from a reported link, with the URL it came from
python3 formguard.py index.html --page-url https://office-login.example/

# a folder of samples from a campaign
python3 formguard.py samples/*.html --json

# tighten the brand check for a brand that is not built in
python3 formguard.py index.html --page-url https://initech-verify.example --brand initech

# CI gate
python3 formguard.py index.html --page-url "$URL" --fail-on high
```

Sample output:

```text
formguard 1.0.0
page    : phish-login.html   host: example-assets.net   forms: 1   password fields: 1
brands  : microsoft, outlook
risk    : 70/100  grade E  gate FAIL

SEVERITY RULE                   WHERE      DETAIL
----------------------------------------------------------------------------------------
HIGH     FG-BRAND-MISMATCH      page       page impersonates microsoft, outlook but is served from example-assets.net
HIGH     FG-EXTERNAL-ACTION     form[0]    form on example-assets.net posts credentials to collect.example.net
HIGH     FG-EXFIL-JS            script     page can send data out via fetch(
LOW      FG-ANTI-ANALYSIS       page       blocks inspection or indexing: noindex, oncontextmenu
```

## Rules

| Rule | Severity | What it catches |
| :-- | :-- | :-- |
| `FG-MAILTO-ACTION` | critical | form mails the typed credentials to an address |
| `FG-EXTERNAL-ACTION` | high | form on this host posts to a different registrable domain |
| `FG-PLAINTEXT-ACTION` | high | form action is plain `http://` |
| `FG-IP-ACTION` | high | form posts to a bare IP address |
| `FG-FREEHOST-ACTION` | high | form posts to free hosting or a form relay (`netlify.app`, `workers.dev`, ...) |
| `FG-BRAND-MISMATCH` | high | page names a brand it is not served from (27 brands built in) |
| `FG-EXFIL-JS` | high | `fetch`, `XMLHttpRequest`, `sendBeacon`, `$.post` and friends |
| `FG-NO-ACTION` | medium | credential form with no action, built at runtime by script |
| `FG-GET-CREDENTIALS` | medium | password submitted with `method=get`, so it lands in logs |
| `FG-OBFUSCATION` | medium | `eval`, `atob`, `unescape`, `String.fromCharCode`, `document.write` |
| `FG-KIT-FINGERPRINT` | medium | known kit templates (16shop, Greatness, Evilginx-style, GoPhish decks) |
| `FG-PLAINTEXT-PAGE` | medium | page itself served over http |
| `FG-HIDDEN-FIELDS` | low | two or more pre-filled hidden inputs |
| `FG-NO-USERNAME-FIELD` | low | password-only form, often a second-stage harvest |
| `FG-ANTI-ANALYSIS` | low | right-click blocking, `noindex`, devtools checks |
| `FG-EXTERNAL-SCRIPT` | low | JavaScript loaded from another domain |
| `FG-CREDENTIAL-FORM` | info | records the form that collects the password |
| `FG-NO-CREDENTIAL-INPUT` | info | no password field, so the harvest is elsewhere |
| `FG-PASSWORD-NO-FORM` | info | password input outside any form element |

## Scoring and exit codes

Weights are critical 40, high 22, medium 10, low 4, capped at 100. Grade A is 0-10, B to 25,
C to 45, D to 65, E to 85, F above.

| Code | Meaning |
| :-- | :-- |
| `0` | Nothing at or above `--fail-on` (default `high`) |
| `1` | Threshold breached: treat the page as confirmed phishing |
| `2` | Unreadable or empty input |

## Design

- **Offline and inert.** The HTML is parsed as text with `html.parser`. No browser, no JavaScript
  engine, no fetch, so a live kit cannot fingerprint the analyst.
- **Mechanics over looks.** Rules target what a kit cannot fake cheaply: the post destination, the
  host/brand split, the exfil primitive.
- **Honest severity.** A password form alone is `info`, because every login page has one.
- **Explainable.** Each finding names the form index or page, the reason and the action.

## Ethics

Triage for pages reported to you, or for your own brand-takedown workflow. It renders nothing,
executes nothing and sends nothing.

## License

MIT. See [LICENSE](LICENSE).
