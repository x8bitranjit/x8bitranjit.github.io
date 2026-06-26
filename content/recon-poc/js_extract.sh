#!/usr/bin/env bash
# js_extract.sh — pull endpoints + secrets + SOURCE MAPS from a target's JavaScript (guide §15).
# The single most under-used recon source: API routes, params, flags, and sometimes secrets live in JS,
# and exposed .js.map files let you reconstruct the ORIGINAL source.
#
# AUTHORIZED TESTING ONLY. In-scope hosts only.
#
# Usage:  ./js_extract.sh https://app.target.com        (or a file of hosts: ./js_extract.sh -l hosts.txt)
set -u
have(){ command -v "$1" >/dev/null; }

if [ "${1:-}" = "-l" ]; then SRC="$2"; INPUT="file"; else TARGET="${1:-}"; INPUT="single"; fi
[ "${1:-}" = "" ] && { echo "usage: $0 https://host  |  $0 -l hosts.txt"; exit 1; }

mkdir -p js_out; cd js_out || exit 1

echo "[*] Collecting JS bundles..."
if [ "$INPUT" = "single" ]; then printf '%s\n' "$TARGET" > _hosts.txt; else cp "../$SRC" _hosts.txt 2>/dev/null || cp "$SRC" _hosts.txt; fi
{ have katana && cat _hosts.txt | katana -jc -d 2 -silent 2>/dev/null | grep -Ei '\.js(\?|$)'; } | sort -u > js_files.txt
{ have subjs  && subjs -i _hosts.txt 2>/dev/null; } | anew -q js_files.txt 2>/dev/null || true
echo "    JS files: $(wc -l < js_files.txt)"

echo "[*] Downloading bundles..."
: > js_dump.txt
while read -r u; do echo "/* $u */"; curl -s "$u"; echo; done < js_files.txt > js_dump.txt

echo "[*] Extracting endpoints..."
grep -oE '"(/[a-zA-Z0-9_./?=&{}-]+)"' js_dump.txt | tr -d '"' | sort -u > js_endpoints.txt
grep -oE 'https?://[a-zA-Z0-9./?=_%-]+' js_dump.txt | sort -u >> js_endpoints.txt
sort -u -o js_endpoints.txt js_endpoints.txt
echo "    endpoints: $(wc -l < js_endpoints.txt)  -> review for /api, /internal, /admin, GraphQL"

echo "[*] Extracting internal hostnames (SSRF targets / more assets §7)..."
grep -oE '[a-zA-Z0-9.-]+\.(internal|local|corp|intranet|test|dev|staging)[a-zA-Z0-9.-]*' js_dump.txt | sort -u > js_internal_hosts.txt

echo "[*] Scanning for secrets (VERIFY before trusting — guide §18)..."
if have trufflehog; then trufflehog filesystem js_dump.txt --only-verified 2>/dev/null > js_secrets.txt; fi
grep -noE '(api[_-]?key|secret|token|password|aws_access_key_id|AIza[0-9A-Za-z_-]{20,}|sk_live_[0-9A-Za-z]+|ghp_[0-9A-Za-z]+)["'\'' :=]+[^"'\'' ,;<>]+' js_dump.txt \
  | sort -u >> js_secrets.txt 2>/dev/null
[ -s js_secrets.txt ] && echo "    [!] candidate secrets: $(wc -l < js_secrets.txt) (most client-side keys are FINE — verify)"

echo "[*] Probing for SOURCE MAPS (reconstruct original source!)..."
cat js_files.txt | sed 's/$/.map/' | { have httpx && httpx -mc 200 -silent 2>/dev/null; } > jsmaps.txt
if [ -s jsmaps.txt ]; then
  echo "    [!!] EXPOSED SOURCE MAPS: $(wc -l < jsmaps.txt)"
  cat jsmaps.txt
  echo "    Reconstruct with:  npx unwebpack-sourcemap <map_url> ./src   OR   sourcemapper -url <map> -output ./src"
fi

echo
echo "[+] Done. See js_out/: js_endpoints.txt  js_internal_hosts.txt  js_secrets.txt  jsmaps.txt"
echo "    Route endpoints -> API testing (guide §16); internal hosts -> SSRF list; maps -> read their code."
