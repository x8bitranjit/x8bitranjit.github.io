#!/usr/bin/env python3
"""
authz_diff.py — authorized BOLA/BFLA differ (the two-account authorization test, à la Burp Autorize).

It replays each request in a file with THREE identities — token A (the "owner"), token B (another account YOU own),
and NO token — and flags any request where B (or no-token) gets the SAME success as A. That same-success-across-
identities is the BOLA/BFLA signal: the endpoint isn't checking who you are.

Request file format (one per line):  METHOD<space>URL_PATH[<space>BODY]
  GET  /api/v1/orders/1002
  PUT  /api/v1/orders/1002 {"note":"x8-test"}
  POST /api/v1/admin/users {"email":"m@test.tld","role":"admin"}
Capture these from Burp/your proxy as ACCOUNT A's own traffic, then point the IDs at B's objects.

Discipline: use YOUR OWN two accounts; a flagged line is a LEAD — confirm the response actually contains B's data /
the action took effect (§17 FP table) before reporting. Bounded, non-destructive (own objects), clean up.

Usage:
  python3 authz_diff.py --base https://api.target.com --token-a "Bearer <A>" --token-b "Bearer <B>" --requests reqs.txt
"""
import argparse, sys
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
SUCCESS = range(200, 300)


def send(method, url, token, body, timeout):
    h = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        h["Authorization"] = token
    data = None
    if body:
        h["Content-Type"] = "application/json"
        data = body
    try:
        r = requests.request(method, url, headers=h, data=data, timeout=timeout,
                             verify=False, allow_redirects=False)
        return r.status_code, len(r.text)
    except Exception as e:
        return None, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="base URL, e.g. https://api.target.com")
    ap.add_argument("--token-a", required=True, help='owner token, e.g. "Bearer <A>"')
    ap.add_argument("--token-b", required=True, help='second account token you own, e.g. "Bearer <B>"')
    ap.add_argument("--requests", required=True, help="file: METHOD PATH [BODY] per line (account A's own traffic)")
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args()

    lines = [l.strip() for l in open(a.requests, encoding="utf-8") if l.strip() and not l.startswith("#")]
    print(f"[*] {len(lines)} request(s); replaying as A / B / no-token. Same success as A on B/none = BOLA/BFLA lead.\n")
    leads = 0
    for ln in lines:
        parts = ln.split(" ", 2)
        method = parts[0].upper()
        path = parts[1] if len(parts) > 1 else "/"
        body = parts[2] if len(parts) > 2 else None
        url = a.base.rstrip("/") + path if path.startswith("/") else path

        sa, la = send(method, url, a.token_a, body, a.timeout)      # baseline (owner)
        sb, lb = send(method, url, a.token_b, body, a.timeout)      # another account you own
        sn, ln_ = send(method, url, None, body, a.timeout)          # no token

        def mark(code, length, base_code, base_len):
            if code in SUCCESS and base_code in SUCCESS:
                # same success family; similar length => very likely same resource served
                sim = "≈" if isinstance(length, int) and isinstance(base_len, int) and abs(length - base_len) <= max(50, base_len * 0.1) else "~"
                return f"{code}{sim}"
            return str(code)

        flag = ""
        if sa in SUCCESS and sb in SUCCESS:
            flag += "  [BOLA/BFLA? B got success] ⭐"
            leads += 1
        if sa in SUCCESS and sn in SUCCESS:
            flag += "  [MISSING-AUTH? no-token success] ⭐"
            leads += 1
        print(f"  {method:6} {path:40} A={sa}({la}) B={mark(sb,lb,sa,la)} none={mark(sn,ln_,sa,la)}{flag}")

    print(f"\n[!] {leads} lead(s). CONFIRM each by hand: does B's/none response actually contain B's data or perform "
          "the action? (echo/200 alone is not proof — §17). Two of YOUR accounts, bounded, clean up.")


if __name__ == "__main__":
    main()
