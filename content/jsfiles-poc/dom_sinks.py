#!/usr/bin/env python3
"""
dom_sinks.py — find DOM-XSS / open-redirect / postMessage / prototype-pollution sinks in a JS corpus,
and rank by proximity to an attacker-controllable SOURCE (a source near a sink == likely exploitable).
(JS_FILES_TESTING_GUIDE.md §8/§12/§13.)

Usage:
  python3 dom_sinks.py -d out/js -o sinks.txt
"""
import argparse, os, re, sys

SINKS = {
    "dom_xss":   re.compile(r"\.innerHTML|\.outerHTML|document\.write(?:ln)?|insertAdjacentHTML|createContextualFragment|\beval\(|new Function\(|setTimeout\(\s*['\"]|setInterval\(\s*['\"]|dangerouslySetInnerHTML|\.html\("),
    "redirect":  re.compile(r"location\s*=|location\.(?:href|assign|replace)\s*\(|window\.open\("),
    "postmsg":   re.compile(r"addEventListener\(\s*['\"]message['\"]"),
    "proto_pol": re.compile(r"\bmerge\b|defaultsDeep|cloneDeep|setWith|__proto__|constructor\s*\[|deparam|qs\.parse|extend\(\s*true"),
    "code_load": re.compile(r"\bimport\(\s*[^'\"]|\.src\s*=\s*[a-zA-Z]"),
}
SOURCE = re.compile(r"location\.(?:hash|search|href|pathname)|document\.(?:URL|referrer|cookie)|window\.name|URLSearchParams|event\.data|localStorage|sessionStorage|postMessage")
ORIGIN_CHECK = re.compile(r"\.origin\s*(?:===?|!==?|\.indexOf|\.match|\.test|\.startsWith)")

def walk(d):
    for root, _, fs in os.walk(d):
        for f in fs:
            yield os.path.join(root, f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", "--dir", required=True)
    ap.add_argument("-o", "--out")
    ap.add_argument("--window", type=int, default=3, help="lines of proximity for source<->sink")
    a = ap.parse_args()

    hits = []
    for path in walk(a.dir):
        try:
            lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines):
            for kind, rx in SINKS.items():
                if rx.search(line):
                    lo, hi = max(0, i - a.window), min(len(lines), i + a.window + 1)
                    ctx = "\n".join(lines[lo:hi])
                    has_source = bool(SOURCE.search(ctx))
                    score = "LIKELY" if has_source else "REVIEW"
                    note = ""
                    if kind == "postmsg":
                        # a message handler WITHOUT an origin check is the dangerous case
                        win = "\n".join(lines[i:min(len(lines), i + 15)])
                        if not ORIGIN_CHECK.search(win):
                            score, note = "LIKELY", "no event.origin check -> cross-origin DOM-XSS/data-theft"
                        else:
                            score, note = "REVIEW", "origin check present (verify it's strict)"
                    hits.append((score, kind, path, i + 1, line.strip()[:140], note))

    rank = {"LIKELY": 0, "REVIEW": 1}
    hits.sort(key=lambda h: rank.get(h[0], 9))
    out = []
    for score, kind, path, ln, code, note in hits:
        out.append(f"[{score}] {kind}  {path}:{ln}\n        {code}" + (f"\n        ! {note}" if note else ""))
    text = "\n".join(out) if out else "(no sinks found)"
    print(text)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(text + "\n")
        print(f"\n[saved] {a.out}", file=sys.stderr)
    print("\n[!] LIKELY = a controllable source sits near the sink. Confirm the flow FIRES before reporting (§12).", file=sys.stderr)

if __name__ == "__main__":
    main()
