#!/usr/bin/env bash
# js_harvest.sh — pull EVERY JS asset (live + historical) for a target into a local corpus.
# Authorized testing only. Usage: bash js_harvest.sh target.com out/js
set -u
T="${1:?usage: js_harvest.sh <domain> [outdir]}"
OUT="${2:-out/js}"
mkdir -p "$OUT"
URLS="$(mktemp)"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36'

have(){ command -v "$1" >/dev/null 2>&1; }

echo "[*] crawling live JS for $T"
if have katana;   then katana -u "https://$T" -d 3 -jc -kf all -silent 2>/dev/null | grep -Ei '\.js(\?|$)' >> "$URLS"; fi
if have hakrawler;then echo "https://$T" | hakrawler -d 3 2>/dev/null | grep -Ei '\.js(\?|$)' >> "$URLS"; fi

echo "[*] pulling historical JS (wayback/gau) — often holds rotated-but-live keys"
if have gau;         then echo "$T" | gau --subs 2>/dev/null | grep -Ei '\.js(\?|$)' >> "$URLS"; fi
if have waybackurls; then echo "$T" | waybackurls 2>/dev/null | grep -Ei '\.js(\?|$)' >> "$URLS"; fi

# fallback: scrape the homepage for <script src>
curl -s -A "$UA" "https://$T" 2>/dev/null \
  | grep -oiE 'src="[^"]+\.js[^"]*"' | sed -E 's/^src="//; s/"$//' \
  | sed -E "s#^/#https://$T/#" >> "$URLS"

sort -u "$URLS" -o "$URLS"
n=$(wc -l < "$URLS")
echo "[*] $n unique JS URLs; downloading to $OUT"

i=0
while read -r u; do
  [ -z "$u" ] && continue
  i=$((i+1))
  base="$(basename "${u%%\?*}")"
  f="$OUT/$(echo "$u" | md5sum | cut -c1-12)_${base}"
  curl -s -L --max-time 25 -A "$UA" "$u" -o "$f" 2>/dev/null
  # if a source map is referenced, grab it too
  smap=$(grep -aoE 'sourceMappingURL=[^ "'"'"']+' "$f" 2>/dev/null | head -1 | sed 's/sourceMappingURL=//')
  if [ -n "${smap:-}" ]; then
    case "$smap" in http*) murl="$smap";; /*) murl="https://$T$smap";; *) murl="$(dirname "$u")/$smap";; esac
    curl -s -L --max-time 25 -A "$UA" "$murl" -o "$f.map" 2>/dev/null
  fi
done < "$URLS"

echo "[*] inline scripts from homepage -> $OUT/_inline.js"
curl -s -A "$UA" "https://$T" 2>/dev/null | tr '\n' ' ' \
  | grep -oP '(?s)<script(?![^>]*src)[^>]*>.*?</script>' > "$OUT/_inline.js" 2>/dev/null || true

rm -f "$URLS"
echo "[done] corpus in $OUT  (downloaded ~$i files; .map files saved alongside)"
echo "       next: secret_scan.py / endpoints.py / dom_sinks.py / sourcemap_unpack.py"
