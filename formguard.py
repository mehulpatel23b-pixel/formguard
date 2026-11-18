#!/usr/bin/env python3
"""formguard - inspect a suspected phishing page for credential-harvesting patterns.

The URL is only half the story. A reported phish is a saved HTML file, and the file says
everything: where the password posts, whether the brand on the page matches the domain,
and what the JavaScript does with the keystrokes.

formguard reads the saved page and reports the mechanics, offline.

Zero dependencies. Pure standard library. No network, no rendering.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from html.parser import HTMLParser

__version__ = "1.0.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 40, "high": 22, "medium": 10, "low": 4, "info": 0}
GRADES = [(10, "A"), (25, "B"), (45, "C"), (65, "D"), (85, "E"), (999, "F")]

MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "co.jp", "com.au",
    "net.au", "org.au", "co.nz", "co.za", "com.br", "com.mx", "com.tr", "com.sg", "com.hk",
    "co.kr", "com.cn", "com.tw", "com.ar", "com.co", "com.my", "co.id", "com.ph", "com.vn",
}

FREE_HOSTS = {
    "formspree.io", "getform.io", "netlify.app", "vercel.app", "web.app", "firebaseapp.com",
    "workers.dev", "pages.dev", "glitch.me", "repl.co", "000webhostapp.com", "weebly.com",
    "wixsite.com", "github.io", "gitlab.io", "surge.sh", "herokuapp.com", "azurewebsites.net",
    "r2.dev",
}

BRANDS = {
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com"},
    "outlook": {"outlook.com", "microsoft.com", "live.com"},
    "office 365": {"office.com", "microsoft.com", "office365.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "gmail": {"gmail.com", "google.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "paypal": {"paypal.com", "paypal.me"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.co.in"},
    "sbi": {"onlinesbi.sbi", "sbi.co.in"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
}

EXFIL_PRIMITIVES = ("fetch(", "xmlhttprequest", "sendbeacon", "new image()", "$.post(", "$.ajax(",
                    "axios.")
OBFUSCATION_PRIMITIVES = ("eval(", "atob(", "unescape(", "string.fromcharcode",
                          "document.write(", "fromcharcode", "%u00")
ANTI_ANALYSIS = ("oncontextmenu", "contextmenu", "keydown", "f12", "devtools", "debugger",
                 "noindex", "right-click", "selectstart")
KIT_MARKERS = ("16shop", "greatness", "caffeine", "evilginx", "tycoon", "gophish", "blackeye",
               "zphisher", "sniperphish")


class PageError(Exception):
    """Raised when a page cannot be read."""


class PageParser(HTMLParser):
    """Collect the parts of a page that matter for credential triage."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.inputs = []
        self.scripts = []
        self.images = []
        self.metas = {}
        self.title = ""
        self.text = []
        self.links = []
        self._stack = []
        self._in_title = False
        self._in_script = False
        self.script_text = []

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            form = {"action": attrs.get("action", ""),
                    "method": (attrs.get("method") or "get").lower(),
                    "inputs": [], "id": attrs.get("id", ""), "class": attrs.get("class", "")}
            self.forms.append(form)
            self._stack.append(form)
        elif tag == "input":
            record = {"type": (attrs.get("type") or "text").lower(),
                      "name": attrs.get("name", ""), "id": attrs.get("id", ""),
                      "value": attrs.get("value", ""),
                      "autocomplete": attrs.get("autocomplete", "")}
            self.inputs.append(record)
            if self._stack:
                self._stack[-1]["inputs"].append(record)
        elif tag == "script":
            if attrs.get("src"):
                self.scripts.append(attrs["src"])
            self._in_script = True
        elif tag == "img" and attrs.get("src"):
            self.images.append(attrs["src"])
        elif tag == "meta":
            key = (attrs.get("name") or attrs.get("property")
                   or attrs.get("http-equiv") or "").lower()
            if key:
                self.metas[key] = attrs.get("content", "")
        elif tag == "title":
            self._in_title = True
        elif tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() in ("script", "title"):
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "form" and self._stack:
            self._stack.pop()
        elif tag == "script":
            self._in_script = False
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._in_script:
            self.script_text.append(data)
        else:
            self.text.append(data)


def registrable(host):
    if not host:
        return ""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_of(url, base=None):
    if not url:
        return ""
    url = url.strip()
    if url.startswith(("//", "/", "#", "?", ".")):
        url = urllib.parse.urljoin(base or "https://unknown.invalid/", url)
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""


def looks_like_ip(host):
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""))


def parse_page(html_text):
    parser = PageParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:  # noqa: BLE001 - HTMLParser is lenient, triage must never crash
        raise PageError("could not parse page: %s" % exc) from exc
    parser.raw = html_text.lower()
    parser.script_blob = "".join(parser.script_text).lower()
    return parser


def page_host(parser, page_url):
    if page_url:
        return host_of(page_url) or ""
    for key in ("og:url", "twitter:url"):
        if parser.metas.get(key):
            host = host_of(parser.metas[key])
            if host:
                return host
    for link in parser.links:
        if link.startswith(("http://", "https://")):
            host = host_of(link)
            if host:
                return host
    return ""


def detect_brands(text):
    """Word-boundary match, so `ups` does not fire on `groups` or `backups`."""
    lowered = text.lower()
    hits = set()
    for name in BRANDS:
        if re.search(r"\b" + re.escape(name) + r"\b", lowered):
            hits.add(name)
    return sorted(hits)


def analyse(parser, page_url="", extra_brands=()):
    """Return (findings, host_domain, brands) for a parsed page."""
    found = []
    host = page_host(parser, page_url)
    host_domain = registrable(host)
    raw = getattr(parser, "raw", "")
    script_blob = getattr(parser, "script_blob", "")
    code = script_blob or raw
    lowered = (" ".join(parser.text) + " " + parser.title).lower()

    def add(sev, code, detail, fix, where=""):
        found.append({"severity": sev, "code": code, "where": where,
                      "detail": detail, "fix": fix})

    if page_url.lower().startswith("http://"):
        add("medium", "FG-PLAINTEXT-PAGE", "page delivered over plain http",
            "Any credential typed here is readable in transit.", "page")

    if not parser.forms and any(i["type"] == "password" for i in parser.inputs):
        add("info", "FG-PASSWORD-NO-FORM", "password field exists outside any form element",
            "Usually a JavaScript-driven kit that posts the value itself.", "page")

    for index, form in enumerate(parser.forms):
        has_password = any(i["type"] == "password" for i in form["inputs"])
        action = (form["action"] or "").strip()
        where = "form[%d]" % index
        if has_password:
            add("info", "FG-CREDENTIAL-FORM",
                "form collects a password (action: %s)" % (action or "none"),
                "Expected on any login page. The questions are where it posts and who owns that host.",
                where)
        names = " ".join((i["name"] + i["id"]) for i in form["inputs"]).lower()
        has_user = any(i["type"] == "email" for i in form["inputs"]) or "user" in names or "mail" in names
        if has_password and not has_user:
            add("low", "FG-NO-USERNAME-FIELD", "password form has no username or email field",
                "Real login pages collect both. A password-only form is often a second-stage harvest.",
                where)
        if not action or action == "#":
            add("medium", "FG-NO-ACTION", "credential form has no action attribute",
                "A missing action means JavaScript builds the destination at runtime, "
                "which hides it from scanners.", where)
            continue
        if action.lower().startswith("mailto:"):
            add("critical", "FG-MAILTO-ACTION", "form posts credentials to a mailto: address",
                "Pure credential theft: the page mails what the user types. Block the sender.",
                where)
            continue
        if urllib.parse.urlsplit(action).scheme.lower() == "http":
            add("high", "FG-PLAINTEXT-ACTION", "form action is plain http (%s)" % action[:70],
                "Credentials cross the network in clear text.", where)
        action_host = host_of(action, page_url or "https://unknown.invalid/")
        if action_host and looks_like_ip(action_host):
            add("high", "FG-IP-ACTION", "form posts to a bare IP address (%s)" % action_host,
                "Legitimate logins post to a named domain. An IP is disposable infrastructure.",
                where)
        if action_host and host_domain and registrable(action_host) != host_domain:
            add("high", "FG-EXTERNAL-ACTION",
                "form on %s posts credentials to %s" % (host_domain, registrable(action_host)),
                "Login forms never post to another domain. This is a collector.", where)
        if action_host and registrable(action_host) in FREE_HOSTS:
            add("high", "FG-FREEHOST-ACTION",
                "form posts to free hosting or a form relay (%s)" % registrable(action_host),
                "No brand hosts its login on throwaway hosting.", where)
        if has_password and form["method"] == "get":
            add("medium", "FG-GET-CREDENTIALS", "password field submitted with method=get",
                "The password ends up in the URL, in history and in proxy logs.", where)

    hidden = [i for i in parser.inputs if i["type"] == "hidden" and i["value"]]
    if len(hidden) >= 2:
        add("low", "FG-HIDDEN-FIELDS", "%d pre-filled hidden fields" % len(hidden),
            "Kits pre-fill the victim's email so the form looks personalised and posts a full record.",
            "page")

    for script in parser.scripts:
        script_host = host_of(script, page_url or "https://unknown.invalid/")
        if script_host and host_domain and registrable(script_host) != host_domain:
            add("low", "FG-EXTERNAL-SCRIPT", "loads JavaScript from %s" % registrable(script_host),
                "Check the host. Kits often pull their collector script from a rented service.",
                "script")

    primitives = [p for p in EXFIL_PRIMITIVES if p in code]
    if primitives:
        add("high", "FG-EXFIL-JS", "page can send data out via %s" % ", ".join(sorted(set(primitives))[:4]),
            "Find the destination in the script and block it. Nothing typed here stays local.",
            "script")

    obfuscation = [p for p in OBFUSCATION_PRIMITIVES if p in code]
    if obfuscation:
        add("medium", "FG-OBFUSCATION", "obfuscated payload markers: %s" % ", ".join(sorted(set(obfuscation))[:4]),
            "Decode the string in a sandbox, never with a browser on your workstation.", "script")

    anti = [p for p in ANTI_ANALYSIS if p in raw]
    if len(anti) >= 2:
        add("low", "FG-ANTI-ANALYSIS", "blocks inspection or indexing: %s" % ", ".join(sorted(set(anti))[:4]),
            "Sites that fight inspection are hiding from scanners, not from attackers.", "page")

    brands = set(detect_brands(lowered)) | {b.lower() for b in extra_brands}
    impersonated = []
    for brand in sorted(brands):
        allowed = BRANDS.get(brand, set())
        if host_domain and any(host_domain == d or host_domain.endswith("." + d) for d in allowed):
            continue
        impersonated.append(brand)
    if impersonated:
        add("high", "FG-BRAND-MISMATCH",
            "page impersonates %s but is served from %s"
            % (", ".join(impersonated[:4]), host_domain or "an unknown host"),
            "This is the definition of a phishing page. Report the URL and block the host.", "page")

    kits = [m for m in KIT_MARKERS if m in raw]
    if kits:
        add("medium", "FG-KIT-FINGERPRINT", "phishing-kit markers: %s" % ", ".join(sorted(set(kits))[:3]),
            "Known kit template. Hash the page and look for sibling domains on the same infrastructure.",
            "page")

    if not parser.forms and not any(i["type"] == "password" for i in parser.inputs):
        add("info", "FG-NO-CREDENTIAL-INPUT", "no password field or form in this page",
            "Either the harvest happens on a later step or this is a decoy landing page.", "page")

    found.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"]))
    return found, host_domain, sorted(brands)


def score(findings):
    total = min(100, sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
    return total, next(g for threshold, g in GRADES if total <= threshold)


def scan_file(path, page_url="", extra_brands=()):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            html_text = handle.read()
    except OSError as exc:
        raise PageError("%s: %s" % (path, exc)) from exc
    if not html_text.strip():
        raise PageError("%s: file is empty" % path)
    parser = parse_page(html_text)
    findings, host_domain, brands = analyse(parser, page_url, extra_brands)
    return {
        "file": os.path.basename(path),
        "path": path,
        "host": host_domain,
        "forms": len(parser.forms),
        "password_fields": sum(1 for i in parser.inputs if i["type"] == "password"),
        "brands": brands,
        "findings": findings,
    }


def build_report(pages, errors=None):
    findings = [f for page in pages for f in page["findings"]]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"]))
    risk, grade = score(findings)
    counts = {sev: sum(1 for f in findings if f["severity"] == sev)
              for sev in ("critical", "high", "medium", "low", "info")}
    return {
        "summary": {
            "pages": len(pages),
            "flags": len(findings),
            "risk": risk,
            "grade": grade,
            "counts": counts,
            "gate": "FAIL" if counts["critical"] or counts["high"] else "PASS",
        },
        "pages": pages,
        "findings": findings,
        **({"errors": errors} if errors else {}),
    }


def render(payload):
    s, lines = payload["summary"], []
    lines.append("formguard %s" % __version__)
    for page in payload["pages"]:
        lines.append("page    : %s   host: %s   forms: %d   password fields: %d"
                     % (page["file"], page["host"] or "unknown", page["forms"],
                        page["password_fields"]))
        if page["brands"]:
            lines.append("brands  : %s" % ", ".join(page["brands"]))
    lines.append("risk    : %d/100  grade %s  gate %s" % (s["risk"], s["grade"], s["gate"]))
    lines.append("")
    if payload["findings"]:
        lines.append("%-8s %-22s %-10s %s" % ("SEVERITY", "RULE", "WHERE", "DETAIL"))
        lines.append("-" * 104)
        for f in payload["findings"]:
            lines.append("%-8s %-22s %-10s %s"
                         % (f["severity"].upper(), f["code"], f["where"], f["detail"]))
        lines.append("")
        lines.append("fixes")
        lines.append("-" * 104)
        for f in payload["findings"]:
            if f["severity"] in ("critical", "high"):
                lines.append("[%s] %s  %s" % (f["severity"][:4].upper(), f["code"], f["where"]))
                lines.append("      %s" % f["fix"])
    else:
        lines.append("no findings: the page looks like a normal login")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="formguard",
        description="Inspect a saved suspected-phishing page for credential-harvesting patterns.")
    parser.add_argument("pages", nargs="+", help="saved HTML file(s) of the suspected page")
    parser.add_argument("--page-url", help="the URL the page was served from (sharpens the analysis)")
    parser.add_argument("--brand", action="append", default=[],
                        help="extra brand name to check for (repeatable)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "info", "none"],
                        help="lowest severity that fails the run (default high)")
    parser.add_argument("--version", action="version", version="formguard " + __version__)
    args = parser.parse_args(argv)

    pages, errors = [], []
    for path in args.pages:
        try:
            pages.append(scan_file(path, args.page_url or "", args.brand))
        except PageError as exc:
            errors.append(str(exc))
    if not pages:
        for err in errors:
            sys.stderr.write("formguard: %s\n" % err)
        return 2

    payload = build_report(pages, errors or None)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render(payload))
        for err in errors:
            print("warning: %s" % err, file=sys.stderr)

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f["severity"]] <= threshold for f in payload["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
