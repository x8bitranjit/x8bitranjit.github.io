#!/usr/bin/env bash
# origin_ip.sh — find the REAL origin IP behind a CDN/WAF (Cloudflare/Akamai/Fastly/…).
# Bug-bounty impact: if the origin accepts direct traffic, you bypass the WAF entirely
# (and often rate-limits, bot-management, geo-blocks). Multi-source + CDN-filtered +
# VALIDATED (a reported origin actually serves the target's content → low false positives).
#
#   Sources:  SecurityTrails historical+current A · Shodan cert/hostname · VirusTotal
#             passive DNS · non-proxied resolved subdomains (dnsx) · direct apex/www
#   Filter :  drop known CDN/WAF ranges (Cloudflare fetched live + common CDN CIDRs)
#   Verify :  curl --resolve target:443:<ip> and compare <title> to the real site;
#             a match = CONFIRMED origin (the IP serves the target behind the CDN).
#
# AUTHORIZED TESTING ONLY. In-scope assets. Keys (optional) come from config.env via keys.sh.
# Usage:  ./origin_ip.sh <domain> [resolved_subs.txt]      (OUT=<dir> to set output dir)
set -u
D="${1:-}"; [ -z "$D" ] && { echo "usage: $0 <domain> [resolved_subs.txt]"; exit 1; }
SUBS="${2:-}"
have(){ command -v "$1" >/dev/null; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
export PATH="$PATH:$HOME/go/bin:$(go env GOPATH 2>/dev/null)/bin:/usr/local/bin"
[ -f "$SCRIPT_DIR/keys.sh" ] && . "$SCRIPT_DIR/keys.sh"
OUT="${OUT:-.}"; mkdir -p "$OUT"
exec </dev/null
log(){ echo -e "[\e[36m*\e[0m] $*"; }

CAND="$OUT/_origin_cand.txt"; : > "$CAND"
CONFIRMED="$OUT/origin_ips.txt"; : > "$CONFIRMED"
log "origin-IP discovery for $D (keys: securitytrails=$([ -n "${SECURITYTRAILS_API_KEY:-}" ] && echo on || echo -) shodan=$([ -n "${SHODAN_API_KEY:-}" ] && echo on || echo -) virustotal=$([ -n "${VIRUSTOTAL_API_KEY:-}" ] && echo on || echo -))"

# ── 1) SecurityTrails — historical + current A records (origin often leaked pre-CDN) ──
if [ -n "${SECURITYTRAILS_API_KEY:-}" ] && have jq; then
  curl -s -m 30 -H "APIKEY: $SECURITYTRAILS_API_KEY" \
    "https://api.securitytrails.com/v1/history/$D/dns/a" 2>/dev/null \
    | jq -r '.records[]?.values[]?.ip // empty' 2>/dev/null >> "$CAND"
  curl -s -m 30 -H "APIKEY: $SECURITYTRAILS_API_KEY" \
    "https://api.securitytrails.com/v1/domain/$D" 2>/dev/null \
    | jq -r '.current_dns.a.values[]?.ip // empty' 2>/dev/null >> "$CAND"
fi

# ── 2) Shodan — IPs presenting a cert / hostname for the domain (likely origin) ──
if [ -n "${SHODAN_API_KEY:-}" ] && have jq; then
  for q in "ssl.cert.subject.CN:\"$D\"" "ssl:\"$D\"" "hostname:\"$D\""; do
    curl -s -m 30 -G "https://api.shodan.io/shodan/host/search" \
      --data-urlencode "key=$SHODAN_API_KEY" --data-urlencode "query=$q" 2>/dev/null \
      | jq -r '.matches[]?.ip_str // empty' 2>/dev/null >> "$CAND"
  done
fi

# ── 3) VirusTotal — passive-DNS resolutions (historical IPs) ──
if [ -n "${VIRUSTOTAL_API_KEY:-}" ] && have jq; then
  curl -s -m 30 -H "x-apikey: $VIRUSTOTAL_API_KEY" \
    "https://www.virustotal.com/api/v3/domains/$D/resolutions?limit=40" 2>/dev/null \
    | jq -r '.data[]?.attributes.ip_address // empty' 2>/dev/null >> "$CAND"
fi

# ── 4) non-proxied resolved subdomains → their A records (mail/dev/origin often direct) ──
if [ -n "$SUBS" ] && [ -s "$SUBS" ] && have dnsx; then
  dnsx -l "$SUBS" -a -resp-only -silent 2>/dev/null >> "$CAND"
fi
{ have dnsx && printf '%s\n%s\n' "$D" "www.$D" | dnsx -a -resp-only -silent 2>/dev/null; } >> "$CAND"

# normalize → unique IPv4
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$CAND" 2>/dev/null | sort -u > "$CAND.u" && mv "$CAND.u" "$CAND"
log "raw IP candidates: $(wc -l < "$CAND")"

# ── 5) drop CDN/WAF ranges → only plausible origins remain ──
CFR="$OUT/_cdn_cidrs.txt"; : > "$CFR"
# Fetch live CDN ranges where the provider publishes them — so the filter is accurate for
# WHICHEVER CDN a target uses (not just Cloudflare). Each is best-effort; the hardcoded
# list below is the fallback. Generic across targets.
curl -s -m 20 https://www.cloudflare.com/ips-v4 2>/dev/null >> "$CFR"; echo >> "$CFR"   # Cloudflare
if have jq; then
  curl -s -m 20 https://api.fastly.com/public-ip-list 2>/dev/null | jq -r '.addresses[]? // empty' 2>/dev/null >> "$CFR"   # Fastly
  curl -s -m 25 https://ip-ranges.amazonaws.com/ip-ranges.json 2>/dev/null \
    | jq -r '.prefixes[]? | select(.service=="CLOUDFRONT") | .ip_prefix // empty' 2>/dev/null >> "$CFR"   # AWS CloudFront
fi
# hardcoded common CDN/WAF/edge ranges (Akamai/Fastly/Sucuri/StackPath + Cloudflare fallback)
cat >> "$CFR" <<'CIDR'
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
23.235.32.0/20
43.249.72.0/22
103.244.50.0/24
151.101.0.0/16
199.27.72.0/21
185.31.16.0/22
23.32.0.0/11
23.64.0.0/14
104.64.0.0/10
184.24.0.0/13
2.16.0.0/13
CIDR
ORIG="$OUT/origin_candidates.txt"
python3 - "$CAND" "$CFR" > "$ORIG" 2>/dev/null <<'PY'
import sys, ipaddress
ips = [l.strip() for l in open(sys.argv[1]) if l.strip()]
nets = []
for l in open(sys.argv[2]):
    l = l.strip()
    if "/" in l:
        try: nets.append(ipaddress.ip_network(l, strict=False))
        except Exception: pass
for ip in ips:
    try: a = ipaddress.ip_address(ip)
    except Exception: continue
    if not any(a in n for n in nets):
        print(ip)
PY
log "non-CDN origin candidates: $(wc -l < "$ORIG")"

# ── 6) VALIDATE — confirm which candidate actually IS the origin ──
# A CDN-fronted baseline is usually just a WAF challenge ("Just a moment...", "Attention
# Required"), so title-equality is unreliable. The strongest, low-FP signal is the TLS
# CERTIFICATE: an IP that presents a cert valid for the target (CN/SAN) is almost
# certainly the target's origin — a random shared/cloud IP won't. We also flag IPs that
# serve real (non-challenge) 200 content for the target's SNI.
norm(){ tr -d '\r' | tr -s ' ' | sed 's/^ *//; s/ *$//'; }
is_challenge(){ printf '%s' "$1" | grep -qiE 'just a moment|attention required|access denied|cloudflare|please wait|checking (if|your)|error 10[0-9][0-9]'; }
Dre=$(printf '%s' "$D" | sed 's/\./\\./g')
log "validating ${0##*/}: $(wc -l < "$ORIG") candidate(s) by TLS cert + live content"
while read -r ip; do
  [ -z "$ip" ] && continue
  # (a) cert the IP presents for the target's SNI (subject CN + SANs)
  cert=$(echo | timeout 12 openssl s_client -connect "$ip:443" -servername "$D" 2>/dev/null \
         | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null)
  # (b) live response forcing the target host onto this IP
  code=$(curl -s -m 10 -k -o /dev/null -w '%{http_code}' --resolve "$D:443:$ip" "https://$D/" 2>/dev/null)
  ct=$(curl -s -m 10 -k --resolve "$D:443:$ip" "https://$D/" 2>/dev/null | grep -oiE '<title>[^<]*' | head -1 | sed 's/<[^>]*>//I' | norm)
  if printf '%s' "$cert" | grep -qiE "(^|[^a-z0-9.])(\*\.)?${Dre}([^a-z0-9.]|$)"; then
    echo "$ip  [CONFIRMED origin — presents TLS cert for $D (HTTP $code${ct:+, title: $ct}) → direct/WAF-bypass]" >> "$CONFIRMED"
  elif [ "$code" = "200" ] && [ -n "$ct" ] && ! is_challenge "$ct"; then
    echo "$ip  [LIKELY origin — serves HTTP 200 real content for $D SNI (title: $ct) — verify]" >> "$CONFIRMED"
  fi
done < "$ORIG"

n=$(wc -l < "$CONFIRMED" 2>/dev/null)
if [ "${n:-0}" -gt 0 ]; then
  log "✔ origin IP(s) found → $CONFIRMED"; cat "$CONFIRMED"
else
  log "no origin confirmed (target may be fully CDN-locked). Candidates to probe manually: $ORIG"
fi
rm -f "$CFR" "$CAND" 2>/dev/null
