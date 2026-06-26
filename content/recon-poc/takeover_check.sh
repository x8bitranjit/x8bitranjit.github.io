#!/usr/bin/env bash
# takeover_check.sh — subdomain-takeover sweep (guide §17).
# Fast, clean, high-severity, rarely-duped. Finds subdomains CNAME'd to a 3rd-party that's unclaimed.
#
# AUTHORIZED TESTING ONLY. Claim a dangling resource ONLY to prove control with a benign PoC;
# never host malicious content or touch user data (guide §29).
#
# Usage:  ./takeover_check.sh target.com           (enumerates first)
#         ./takeover_check.sh -l subs_all.txt       (use an existing list)
set -u
have(){ command -v "$1" >/dev/null; }

if [ "${1:-}" = "-l" ]; then SUBS="$2"; else
  D="${1:-}"; [ -z "$D" ] && { echo "usage: $0 <domain> | $0 -l subs.txt"; exit 1; }
  echo "[*] Enumerating subdomains for $D ..."
  SUBS="_subs_$D.txt"
  { have subfinder && subfinder -d "$D" -all -silent; } 2>/dev/null | sort -u > "$SUBS"
  curl -s "https://crt.sh/?q=%25.$D&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u >> "$SUBS"
  sort -u -o "$SUBS" "$SUBS"
fi
echo "    candidates: $(wc -l < "$SUBS")"

echo "[*] Pass 1 — CNAME fingerprints of takeover-prone services..."
if have httpx; then
  httpx -l "$SUBS" -cname -silent 2>/dev/null \
    | grep -Eai 's3\.amazonaws|s3-website|github\.io|herokuapp|herokudns|azurewebsites|cloudapp|trafficmanager|fastly|netlify|surge\.sh|shopify|myshopify|cloudfront|bitbucket\.io|readme\.io|zendesk|unbounce|wpengine|pantheon|ghost\.io|helpscout|statuspage|launchrock|tilda|wufoo|smartling|aha\.io|getresponse' \
    | tee cname_flags.txt
  [ -s cname_flags.txt ] && echo "    [!] $(wc -l < cname_flags.txt) dangling-CNAME candidates — verify the fingerprint."
fi

echo "[*] Pass 2 — nuclei takeover templates (confirms claimable fingerprints)..."
have nuclei && { have httpx && httpx -l "$SUBS" -silent 2>/dev/null | nuclei -t http/takeovers/ -silent 2>/dev/null | tee takeovers_nuclei.txt; }

echo "[*] Pass 3 — subzy..."
have subzy && subzy run --targets "$SUBS" --hide_fails 2>/dev/null | tee takeovers_subzy.txt

echo
echo "[+] Review: cname_flags.txt  takeovers_nuclei.txt  takeovers_subzy.txt"
echo "    For each confirmed: (1) verify the service returns a 'not found' claimable fingerprint,"
echo "    (2) check Set-Cookie domain on the PARENT — if scoped to .${D:-target} -> takeover escalates to ATO (guide §17),"
echo "    (3) claim ONLY to prove control with a harmless PoC file; document; report."
