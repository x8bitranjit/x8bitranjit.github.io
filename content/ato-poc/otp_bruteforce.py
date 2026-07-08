#!/usr/bin/env python3
"""
otp_bruteforce.py - detect a MISSING / resettable OTP rate-limit on YOUR OWN account (authorized only).

This is a rate-limit DETECTOR, not a cracker: it sends a BOUNDED number of WRONG OTP codes to your own account's
2FA/verify endpoint and reports whether a limiter/lockout ever engages. If N wrong codes are all accepted for
processing with no lockout, the OTP is brute-forceable -> 2FA bypass -> ATO. It stops as soon as it has the answer;
it does NOT try to guess the real code. (ACCOUNT_TAKEOVER_TESTING_GUIDE.md §7/§18.)

Usage:
  python3 otp_bruteforce.py -u https://target/2fa/verify --data '{"otp":"FUZZ"}' -H "Cookie: session=YOURS"
  python3 otp_bruteforce.py -u https://target/verify --data 'code=FUZZ' --attempts 40 -H "Cookie: s=..."
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, time, urllib.request, urllib.error

UA = "Mozilla/5.0 (compatible; otp-rl-detector/1.0)"
BLOCK_RE = ("too many", "rate limit", "rate-limit", "locked", "try again later", "slow down",
            "temporarily", "blocked", "exceeded", "captcha")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def send(url, method, headers, body, timeout):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    t0 = time.time()
    try:
        r = _OPENER.open(req, timeout=timeout)
        code, data = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, data = e.code, (e.read() if hasattr(e, "read") else b"")
    except Exception:
        return None, 0, "", 0.0
    txt = data.decode("utf-8", "replace")
    return code, len(data), txt, (time.time() - t0) * 1000.0


def looks_blocked(code, txt):
    if code in (429, 423):
        return True
    low = txt.lower()
    return any(m in low for m in BLOCK_RE)


def wrong_codes(n, width):
    # deterministic WRONG codes (never a real guess): 000001, 000002, ... offset so we don't spam '000000'
    for i in range(1, n + 1):
        yield str(i + 100).zfill(width)


def main():
    ap = argparse.ArgumentParser(description="OTP rate-limit detector (bounded; YOUR OWN account; authorized only).")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--data", required=True, help="body with FUZZ where the OTP goes, e.g. '{\"otp\":\"FUZZ\"}' or 'code=FUZZ'")
    ap.add_argument("--method", default="POST")
    ap.add_argument("-H", "--header", action="append", default=[], help="header 'Name: value' (send your OWN session cookie)")
    ap.add_argument("--attempts", type=int, default=30, help="bounded number of wrong codes (default 30)")
    ap.add_argument("--width", type=int, default=6, help="OTP digit width (default 6)")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between attempts (be gentle)")
    ap.add_argument("--timeout", type=float, default=15.0)
    a = ap.parse_args()

    if a.attempts > 200:
        sys.exit("[!] --attempts capped at 200 for SAFE-PoC; 30-50 is plenty to prove a missing limit.")
    if "FUZZ" not in a.data:
        sys.exit("[!] --data must contain FUZZ where the OTP value goes.")

    headers = {"User-Agent": UA}
    ct = "application/json" if a.data.lstrip().startswith("{") else "application/x-www-form-urlencoded"
    headers["Content-Type"] = ct
    for hh in a.header:
        if ":" in hh:
            k, v = hh.split(":", 1)
            headers[k.strip()] = v.strip()

    print("== OTP rate-limit detector ==   [bounded; your own account]")
    print(f"[i] endpoint: {a.url}   attempts: {a.attempts}   (wrong codes only; not guessing the real one)")

    baseline = None
    blocked_at = None
    for i, code_val in enumerate(wrong_codes(a.attempts, a.width), start=1):
        body = a.data.replace("FUZZ", code_val).encode()
        st, ln, txt, ms = send(a.url, a.method, headers, body, a.timeout)
        if st is None:
            print(f"  [err] attempt {i}: request failed")
            continue
        if baseline is None:
            baseline = (st, ln)
            print(f"  [i] baseline wrong-OTP response: status {st}, {ln} bytes")
        if looks_blocked(st, txt):
            blocked_at = i
            print(f"  [BLOCKED] attempt {i}: limiter/lockout engaged (status {st}) - rate-limiting IS present")
            break
        if a.delay:
            time.sleep(a.delay)

    print()
    if baseline is None:
        print("[!] no valid responses received (every request failed - check URL / session cookie / connectivity).")
        print("    INCONCLUSIVE: cannot claim a missing rate-limit without a working baseline.")
        return 0
    if blocked_at:
        print(f"[-] rate-limited after {blocked_at} attempt(s). OTP brute-force is throttled here.")
        print("    Still test BYPASSES (guide §7): re-request the OTP to reset the counter, rotate X-Forwarded-For,")
        print("    new session per attempt, or a RACE (../RaceCondition/). If any resets the limit -> still brute-forceable.")
    else:
        space = 10 ** a.width
        print(f"[+] NO rate-limit/lockout after {a.attempts} wrong codes -> the OTP verify is BRUTE-FORCEABLE.")
        print(f"    keyspace ~{space} ({a.width} digits); with no limiter an attacker enumerates it -> 2FA BYPASS -> ATO (Critical).")
        print("    PROOF IS DONE (missing limiter shown). Do NOT actually crack a real user's code (guide §18).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
