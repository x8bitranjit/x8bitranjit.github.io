#!/usr/bin/env bash
# monitor.sh — continuous recon: alert on NEW subdomains / exposures / takeovers (guide §27).
# The biggest expert edge: new assets have the least competition. Run on a cron; act within the hour.
#
# AUTHORIZED TESTING ONLY. In-scope assets; respect rate/automation rules (guide §29).
#
# Cron example (every 6h):
#   0 */6 * * *  /path/scripts/monitor.sh target.com >> /path/output/target.com/monitor.log 2>&1
#
# Alerts: configure `notify` (~/.config/notify/provider-config.yaml) for Slack/Discord/Telegram.
set -u
D="${1:-}"; [ -z "$D" ] && { echo "usage: $0 <domain>"; exit 1; }
have(){ command -v "$1" >/dev/null; }
# resolve script dir BEFORE cd so the shared key loader + config.env are found
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
[ -f "$SCRIPT_DIR/keys.sh" ] && . "$SCRIPT_DIR/keys.sh"   # sets SF_PC + exports keys (all optional)
SF_PC="${SF_PC:-}"
OUT="output/$D"; mkdir -p "$OUT"; cd "$OUT" || exit 1
export PATH="$PATH:$HOME/go/bin:$(go env GOPATH 2>/dev/null)/bin:/usr/local/bin"
exec </dev/null   # cron/background: PD tools block on an open stdin — close it
STAMP="$(date '+%F %T')"

alert(){ # send to notify if configured, else just print
  if have notify; then printf '%s\n' "$1" | notify -silent 2>/dev/null; fi
  echo "[$STAMP] $1"
}

echo "[$STAMP] monitor run for $D"

# 1) NEW subdomains (anew prints only new lines)
NEWSUBS=""
{ have subfinder && subfinder -d "$D" -all $SF_PC -silent 2>/dev/null; } > _now_subs.txt
curl -s "https://crt.sh/?q=%25.$D&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> _now_subs.txt
NEWSUBS="$(sort -u _now_subs.txt | anew subs_all.txt)"
if [ -n "$NEWSUBS" ]; then
  alert "🆕 NEW subdomains on $D:\n$NEWSUBS"
  # immediately probe + Tier-1 check the new ones (first-mover, guide §27)
  printf '%s\n' "$NEWSUBS" | { have httpx && httpx -sc -title -td -cname -silent 2>/dev/null; } | tee -a new_live.txt | while read -r l; do alert "   live: $l"; done
  if have nuclei; then
    printf '%s\n' "$NEWSUBS" | { have httpx && httpx -silent 2>/dev/null; } \
      | nuclei -t http/takeovers/ -t http/exposures/ -silent 2>/dev/null | while read -r f; do alert "⚠️  $f"; done
  fi
else
  echo "[$STAMP] no new subdomains."
fi

# 2) NEW takeover/exposure findings on the existing live set (configs change over time)
# use the CLEAN url list (recon.sh writes live_urls.txt); nuclei -l on httpx's
# annotated live.txt parses the whole line as a URL and scans nothing.
if have nuclei; then
  NL=live_urls.txt; [ -s "$NL" ] || { awk '{print $1}' live.txt 2>/dev/null > _nl.txt; NL=_nl.txt; }
  [ -s "$NL" ] && nuclei -l "$NL" -t http/takeovers/ -t http/exposures/ -silent 2>/dev/null \
    | anew _findings_seen.txt | while read -r f; do alert "⚠️  NEW finding on $D: $f"; done
fi

echo "[$STAMP] monitor done."
