#!/usr/bin/env python3
"""
ssti_detect.py — authorized SSTI detector with DIFFERENTIAL false-positive gating.

It does NOT report a lone {{7*7}}=49 (the #1 SSTI false positive). Instead it:
  1) sends a numeric probe with NON-ROUND operands the page can't already contain (1337*1338=1788906),
  2) sends a string-multiply probe ({{7*'7'}} -> 7777777) to separate a real engine from coincidence,
  3) checks the value is in the SERVER response (not just reflected literally),
  4) fingerprints the engine across {{ }} / ${ } / #{ } / <%= %> / { } delimiters.

(SSTI_TESTING_GUIDE.md §4/§5/§15.)  A hit still needs manual engine-RCE confirmation before reporting.

Usage:
  python3 ssti_detect.py -u "https://target/profile?name=FUZZ"
  python3 ssti_detect.py -u "https://target/api" -m POST -d '{"name":"FUZZ"}' -H "Content-Type: application/json"
"""
import argparse, json, sys, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

A, B = 1337, 1338
PROD = str(A * B)                  # 1788906 — implausible as pre-existing page content
SMULT = "7777777"                  # {{7*'7'}} in Jinja2/Twig

# (label, payload, expected, delimiter-family)
PROBES = [
    ("jinja/twig-num", f"{{{{{A}*{B}}}}}", PROD, "{{}}"),
    ("jinja/twig-str", "{{7*'7'}}", SMULT, "{{}}"),
    ("freemarker/spel-num", f"${{{A}*{B}}}", PROD, "${}"),
    ("ruby/thymeleaf-num", f"#{{{A}*{B}}}", PROD, "#{}"),
    ("erb/ejs-num", f"<%= {A}*{B} %>", PROD, "<%= %>"),
    ("smarty-num", f"{{{A}*{B}}}", PROD, "{ }"),
]

def send(args, payload):
    url, method, data, headers = args.url, args.method, args.data, args.headers
    if "FUZZ" in url:
        url = url.replace("FUZZ", up.quote(payload, safe=""))
    if data and "FUZZ" in data:
        data = data.replace("FUZZ", payload)
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=15, verify=False)
        else:
            r = requests.request(method, url, data=data, headers=headers, timeout=15, verify=False)
        return r.text
    except Exception:
        return ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="mark injection point with FUZZ")
    ap.add_argument("-m", "--method", default="GET")
    ap.add_argument("-d", "--data", help="body with FUZZ (POST)")
    ap.add_argument("-H", "--header", action="append", default=[], help="Header: value (repeatable)")
    a = ap.parse_args()
    a.headers = {"User-Agent": UA}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1); a.headers[k.strip()] = v.strip()

    # literal-control: does the input come back literally (= reflection, not eval)?
    literal_body = send(a, "STSSTI_LITERAL_MARKER_(7*7)")
    reflected_literal = "(7*7)" in literal_body

    results = []
    for label, payload, expected, fam in PROBES:
        body = send(a, payload)
        if expected in body and payload not in body:
            results.append((label, payload, expected, fam))

    print("== SSTI differential detection ==")
    if not results:
        print("[-] No server-side evaluation detected (no probe computed its value).")
        print("    If {{1337*1338}} reaches the BROWSER as literal text and only JS turns it into a number,")
        print("    that's CLIENT-side template injection (CSTI) -> XSS kit, not SSTI.")
        return

    # require BOTH a numeric eval AND the string-multiply differentiator for {{}} family to claim Jinja/Twig
    fams = {r[3] for r in results}
    print("[+] Server-side evaluation CONFIRMED (a server engine computed the expression):")
    for label, payload, expected, fam in results:
        print(f"    {label:18} {payload:24} -> {expected}")

    # engine guess
    got_str = any(r[0] == "jinja/twig-str" for r in results)
    guess = []
    if "{{}}" in fams and got_str:
        guess.append("Jinja2 (Python) or Twig (PHP)  — confirm {{config}} (Jinja) vs Twig filters")
    elif "{{}}" in fams:
        guess.append("Handlebars/Nunjucks or numeric {{}} engine")
    if "${}" in fams:
        guess.append("Freemarker / Velocity / Spring SpEL (Java)")
    if "#{}" in fams:
        guess.append("Ruby (Slim) / Thymeleaf")
    if "<%= %>" in fams:
        guess.append("ERB (Ruby) / EJS (Node)")
    if "{ }" in fams:
        guess.append("Smarty (PHP) / Tornado")
    print("\n[+] Likely engine(s): " + " | ".join(guess))
    print("\n[next] fingerprint precisely (§5), then engine RCE (§7-§10):  python3 ssti_rce.py --engine <engine> --cmd id")
    if reflected_literal:
        print("[note] a literal marker also reflected — ensure the COMPUTED value (not reflection) is what confirms it.")

if __name__ == "__main__":
    main()
