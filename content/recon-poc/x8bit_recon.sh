#!/usr/bin/env bash
# x8bit_recon — full recon pipeline: domain -> assets -> live -> urls -> JS ->
# Tier-1 -> active vuln leads -> routed QUEUE. The impact-first companion to
# x8bit-arsenal. Implements the Master Recon Sequence in RECON_GUIDE.md (§4-§24).
#
# AUTHORIZED TESTING ONLY. In-scope assets only. Respect program rate/automation rules (guide §29).
# Idempotent (anew): re-running surfaces only NEW lines -> feeds monitor.sh.
#
# Usage:  ./x8bit_recon.sh target.com
set -u

D="${1:-}"
[ -z "$D" ] && { echo "usage: $0 <domain>"; exit 1; }

cat <<'BANNER'
 _  _____ _    _ _     ___
 \ \/ ( _ ) |__(_) |_ | _ \___ __ ___ _ _
  >  <| _ \ '_ \ |  _||   / -_) _/ _ \ ' \
 /_/\_\___/_.__/_|\__||_|_\___\__\___/_||_|
   x8bit_recon · impact-first bug-bounty recon · routed QUEUE
BANNER

# Resolve this script's own dir BEFORE we cd into the output folder, so co-located
# resources (wordlists/) travel with the kit and are found regardless of cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
# Go-installed tools (puredns/gotator/massdns/PD tools) often land in ~/go/bin,
# which login shells don't always have on PATH — add it so `have` finds them.
export PATH="$PATH:$HOME/go/bin:$(go env GOPATH 2>/dev/null)/bin:/usr/local/bin"

# ---- API keys / config (shared loader; every key OPTIONAL) ----------------------
# Loads config.env + routes keys: sets CFG_LOADED, SF_PC, exports PDCP_API_KEY.
# Missing key -> that source is skipped (run still works); present -> deeper coverage.
. "$SCRIPT_DIR/keys.sh"

# Resolvers: env override -> /opt -> co-located list that ships with the kit.
RES="${RESOLVERS:-}"
for c in "$RES" /opt/resolvers.txt "$SCRIPT_DIR/wordlists/resolvers.txt"; do
  [ -n "$c" ] && [ -s "$c" ] && { RES="$c"; break; }
done
# Trusted resolvers: a small, rock-solid list puredns uses to VALIDATE every brute
# hit (kills false-positive subdomains that flaky public resolvers invent).
TRUSTED="${RESOLVERS_TRUSTED:-}"
for c in "$TRUSTED" /opt/resolvers-trusted.txt "$SCRIPT_DIR/wordlists/resolvers-trusted.txt"; do
  [ -n "$c" ] && [ -s "$c" ] && { TRUSTED="$c"; break; }
done
# SecLists: env override -> /opt -> Kali's apt location.
WL="${WORDLISTS:-}"
for c in "$WL" /opt/SecLists /usr/share/seclists; do
  [ -n "$c" ] && [ -d "$c" ] && { WL="$c"; break; }
done
# Permutation words for gotator: SecLists has none by default, so fall back to
# the curated list shipped with the kit.
PERMS=""
for c in "$WL/Discovery/DNS/dns-permutations.txt" "$SCRIPT_DIR/wordlists/permutations.txt"; do
  [ -s "$c" ] && { PERMS="$c"; break; }
done
RATE="${RATE:-150}"                 # be polite (guide §29)
PDRATE="${PUREDNS_RATE:-150}"       # puredns/massdns brute qps (low = WSL-conntrack-safe)
# PASSIVE_ONLY=1 → OSINT-only quiet mode for tight programs: skips the active DNS
# brute, port scan, and payload-sending phases (dalfox). Passive sources + live
# probe + URL/JS collection still run.
PASSIVE="${PASSIVE_ONLY:-0}"
# NO_SUBS=1 → single-target / app-focused mode: SKIP ALL subdomain enumeration
# (no passive sources, no brute, no permutations). Recon ONLY the given host plus any
# SEED_URLS. Use it when you want the URL/JS/exposure/origin/vuln recon on one host and
# NOT its whole subdomain surface.
NOSUBS="${NO_SUBS:-0}"
# SEED_URLS="https://h/path ..." → explicit URLs to fold into the live set + URL corpus
# (crawled, JS-mined, exposure/nuclei-probed) so an exact deep path is always covered.
SEED_URLS="${SEED_URLS:-}"
OUT="output/$D"; mkdir -p "$OUT"; cd "$OUT" || exit 1
have(){ command -v "$1" >/dev/null; }
log(){ echo -e "\n[\e[36m*\e[0m] $*"; }

# Close stdin for the whole pipeline. ProjectDiscovery tools (dnsx/httpx/naabu/
# nuclei/katana) read stdin by default and BLOCK waiting for EOF when invoked
# with -l/-u and stdin is left open (background job, cron, CI) — this is what
# wedged dnsx for 15+ min in testing. Internal `a | b` pipes still get their own
# stdin, so this is safe and makes the script non-interactive-proof.
exec </dev/null

log "config: resolvers=${RES:-<none>}  trusted=${TRUSTED:-<none>}  seclists=${WL:-<none>}  perms=${PERMS:-<none>}  rate=${RATE}/${PDRATE}"
_on(){ [ -n "${1:-}" ] && printf 'on' || printf '-'; }
log "keys (config=${CFG_LOADED}): pdcp/asnmap=$(_on "${PDCP_API_KEY:-}")  subfinder-osint=$([ -n "$SF_PC" ] && printf on || printf -)  github=$(_on "${GITHUB_TOKEN:-}")  — missing keys just skip that source, run still works"

if [ "$NOSUBS" = "1" ]; then
  log "PHASE 1 — SKIPPED (NO_SUBS=1): single-target mode — no subdomain enumeration"
  # Seed the host list with just the target + any SEED_URLS hosts. Everything after
  # (live probe, ports, origin-IP, URLs, JS, exposures, nuclei, dalfox) runs on these.
  { printf '%s\n' "$D"; for u in $SEED_URLS; do printf '%s\n' "$u" | sed -E 's#^[a-z]+://##; s#[/:?].*##'; done; } \
    | grep -E '[a-z]' | sort -u > subs_all.txt
  echo "    target host(s): $(tr '\n' ' ' < subs_all.txt)"
else
log "PHASE 1 — passive subdomains (§5)"
# Every passive source is time-bounded: amass enum -passive in particular can
# hang for 20+ min on slow data sources (observed), and crt.sh/subfinder can
# stall on network. A capped source just contributes fewer subs — it never
# wedges the pipeline. NOTE: dropped `-recursive` — on a large target it pushes
# subfinder past the 180s cap, gets killed, and yields ZERO (observed: whatnot
# returned 0 with -recursive, 225 without). Plain -all is fast and complete.
{ have subfinder && timeout -k 5 180 subfinder -d "$D" -all $SF_PC -silent; } 2>/dev/null | anew -q subs_all.txt
{ have amass && timeout -k 5 180 amass enum -passive -d "$D" -timeout 3 -silent 2>/dev/null; } | anew -q subs_all.txt
# chaos needs a PDCP/Chaos key; with none it blocks on a prompt — so gate it (graceful skip).
{ have chaos && [ -n "${CHAOS_KEY:-}${PDCP_API_KEY:-}" ] && CHAOS_KEY="${CHAOS_KEY:-${PDCP_API_KEY:-}}" timeout -k 5 120 chaos -d "$D" -silent 2>/dev/null; } | anew -q subs_all.txt
curl -s --max-time 60 "https://crt.sh/?q=%25.$D&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' | sort -u | anew -q subs_all.txt
echo "    subs so far: $(wc -l < subs_all.txt)"

log "PHASE 1 — active: resolve + brute + permutations (§6)"
if [ "$PASSIVE" = "1" ]; then
  echo "    (PASSIVE_ONLY=1 — skipping active resolve/brute/permutations)"
else
# A resolver list is REQUIRED for mass-resolution: puredns won't run without it,
# and `dnsx -r <missing-file>` STALLS instead of erroring. So gate on the file
# and only pass -r when it actually exists+non-empty; otherwise fall back to the
# system resolver (correct for the small passive set) — degrade, never hang.
RFLAG=""; [ -s "$RES" ] && RFLAG="-r $RES"
# Cap puredns/massdns query rate. massdns UDP at high qps fills the WSL2 NAT
# conntrack table and knocks out the host's network for minutes (observed: 1000
# qps still floods; reaping massdns restores it instantly). 150 qps keeps
# conntrack under the limit AND is polite. Override with PUREDNS_RATE= on a beefy
# native Linux box. The 110k brute at 150/s ~= 12 min — slow but safe.
RL="--rate-limit $PDRATE --rate-limit-trusted $PDRATE"   # PDRATE set at top
[ -s "$TRUSTED" ] && RL="$RL --resolvers-trusted $TRUSTED"   # validate hits -> no FP subs
if have puredns && [ -n "$RFLAG" ]; then
  puredns resolve subs_all.txt $RFLAG $RL -q --write resolved.txt 2>/dev/null
  [ -f "$WL/Discovery/DNS/subdomains-top1million-110000.txt" ] && \
    puredns bruteforce "$WL/Discovery/DNS/subdomains-top1million-110000.txt" "$D" $RFLAG $RL -q --write brute.txt 2>/dev/null
  cat resolved.txt brute.txt 2>/dev/null | anew -q subs_all.txt
  if have gotator && [ -n "$PERMS" ]; then
    gotator -sub resolved.txt -perm "$PERMS" -depth 1 -numbers 3 -silent 2>/dev/null \
      | puredns resolve $RFLAG $RL -q --write perm.txt 2>/dev/null
    cat perm.txt 2>/dev/null | anew -q subs_all.txt
  fi
elif have dnsx; then
  # explicit resolvers if present, else dnsx's default system resolver.
  # NEVER pass -r to a non-existent file (dnsx hangs on it).
  dnsx -l subs_all.txt -silent $RFLAG 2>/dev/null | anew -q subs_all.txt
else
  echo "    (no usable puredns/dnsx resolver path — keeping passive subs only)"
fi
  [ -z "$RFLAG" ] && echo "    note: no resolver file at \$RES ($RES) — active brute/permutation skipped (set RESOLVERS=...)"
fi
echo "    total subs: $(wc -l < subs_all.txt)"
fi

log "PHASE 2 — probe live hosts (§8)"
if have httpx; then
  httpx -l subs_all.txt -sc -title -td -cname -ip -rl "$RATE" \
        -p 80,443,8080,8443,8000,8888,3000,5000,9000 -silent -o live.txt 2>/dev/null
fi
# CLEAN url list (column 1 only). live.txt is httpx's annotated output
# (`URL [200] [title] [ip]`); tools that take -l/-i (nuclei, httpx -path, subjs)
# parse the WHOLE line as a URL and silently scan nothing if fed the annotated
# file. Always feed them live_urls.txt instead.
awk '{print $1}' live.txt 2>/dev/null | sort -u > live_urls.txt
# fold explicit SEED_URLS into the live set so the exact path you care about (e.g. a
# login URL) is crawled + JS-mined + exposure/nuclei-probed, not just the bare host.
for u in $SEED_URLS; do printf '%s\n' "$u"; done | anew -q live_urls.txt
# interesting = the hosts you actually spend manual time on (guide §24)
grep -Eai 'admin|login|dashboard|internal|dev|staging|test|uat|qa|api|swagger|graphql|jenkins|grafana|kibana|jira|git|vpn|portal|status|account|auth|sso|upload|file' live.txt 2>/dev/null \
  | tee interesting.txt >/dev/null
grep -E ' 40[13] ' live.txt 2>/dev/null > authwalls.txt
echo "    live: $(wc -l < live.txt 2>/dev/null)  interesting: $(wc -l < interesting.txt 2>/dev/null)"

log "PHASE 2 — ports (§9)"
# Scan UNIQUE resolved IPs, not every subdomain. The subs collapse to far fewer IPs
# (e.g. 676 subs -> 31 IPs behind shared CDN edges), so per-sub scanning is ~20x
# redundant. The old `-top-ports 1000 -rate 1000` over all subs saturated the WSL NAT
# (all traffic dropped to code=000) AND is loud/detectable. Dedupe to IPs, scan the
# common-100 ports at a WSL-safe, stealthier rate (override with PORT_RATE=), bounded.
if [ "$PASSIVE" != "1" ] && have naabu; then
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' live.txt 2>/dev/null | sort -u > _scan_ips.txt
  [ -s _scan_ips.txt ] || awk '{print $1}' subs_all.txt 2>/dev/null | sort -u > _scan_ips.txt
  PORTRATE="${PORT_RATE:-300}"
  [ -s _scan_ips.txt ] && timeout -k 5 600 naabu -l _scan_ips.txt -top-ports 100 -rate "$PORTRATE" -silent -o ports.txt 2>/dev/null
  [ -s ports.txt ] && echo "    open ports: $(wc -l < ports.txt) across $(wc -l < _scan_ips.txt) IPs"
fi

log "PHASE 2 — ASN / IP ranges (§7)"
# Map the org's ASN -> CIDR ranges: more assets the DNS path won't surface.
# RECON ONLY — verify a range is in scope before you ever port-scan it.
# asnmap now REQUIRES a free PDCP API key; with none configured it blocks forever on an
# interactive "Enter PDCP API Key" prompt (the real cause of the 37-min hang). So we only
# run it when a key exists — otherwise the phase is a 45s no-op that returns nothing.
# When we DO run it, timeout -k guarantees it can never stall the pipeline (SIGTERM at 45s,
# unignorable SIGKILL 5s later), and </dev/null prevents any residual prompt-blocking.
if have asnmap && { [ -n "${PDCP_API_KEY:-}" ] || [ -f "$HOME/.config/pdcp/credentials.yaml" ]; }; then
  timeout -k 5 45 asnmap -d "$D" -silent </dev/null 2>/dev/null | anew -q asn_ranges.txt
  [ -s asn_ranges.txt ] && echo "    ASN/CIDR ranges: $(wc -l < asn_ranges.txt) (confirm in scope before scanning)"
elif have asnmap; then
  echo "    [skip] asnmap needs a free PDCP API key — run 'asnmap -auth' (key from cloud.projectdiscovery.io) or set PDCP_API_KEY. Skipping ASN phase."
fi

log "PHASE 2 — origin IP discovery (un-CDN the target, §7b)"
# Find the REAL origin behind the CDN/WAF. A reachable origin = full WAF / rate-limit /
# bot-management / geo bypass (high impact). Multi-source (historical DNS, cert search,
# passive DNS, non-proxied subs) + CDN-filter + TLS-cert/content validation (low FP),
# generic across any CDN. Best-effort + bounded; finding none is fine (well-locked target).
if [ -f "$SCRIPT_DIR/origin_ip.sh" ]; then
  OUT="." timeout -k 5 300 bash "$SCRIPT_DIR/origin_ip.sh" "$D" \
    "$([ -s resolved.txt ] && printf resolved.txt || printf subs_all.txt)" 2>/dev/null
  [ -s origin_ips.txt ] && echo "    [!] origin IP lead(s): $(wc -l < origin_ips.txt) -> origin_ips.txt (WAF-bypass)"
fi

log "PHASE 2 — WAF fingerprint (§10)"
# Knowing the WAF (Cloudflare/Akamai/etc.) shapes payload + evasion choices later.
if have wafw00f; then
  { echo "https://$D"; head -20 live_urls.txt 2>/dev/null; } | sort -u \
    | while read -r h; do timeout -k 5 25 wafw00f "$h" 2>/dev/null | grep -Ei 'is behind|seems to be behind'; done \
    | sort -u > waf.txt
  [ -s waf.txt ] && echo "    WAF detections: $(wc -l < waf.txt)"
fi

log "PHASE 2 — screenshots (§8 — visual triage)"
# A screenshot of every live host is the fastest triage (logins/dashboards/default
# pages). gowitness v3's default chromedp driver needs a Chrome/Chromium BINARY in
# PATH — if none exists we skip with a note (visual triage is a nice-to-have, not
# required for impact) instead of silently producing zero. Install once, optional:
#   sudo apt install -y chromium
if have gowitness && [ -s live_urls.txt ]; then
  CHROME=""
  for b in chromium chromium-browser google-chrome google-chrome-stable chrome; do
    command -v "$b" >/dev/null 2>&1 && { CHROME="$(command -v "$b")"; break; }
  done
  if [ -n "$CHROME" ]; then
    mkdir -p screenshots
    head -200 live_urls.txt > _shot_in.txt
    # bound the whole pass (headless browser × up to 200 hosts can drag); support
    # both v3 (scan file) and v2 (file) syntaxes, pinning the discovered browser.
    { timeout -k 5 600 gowitness scan file -f _shot_in.txt --screenshot-path screenshots --chrome-path "$CHROME" --delay 2 --timeout 10 2>/dev/null \
      || timeout -k 5 600 gowitness file -f _shot_in.txt -P screenshots --chrome-path "$CHROME" 2>/dev/null; } || true
    shots=$(find screenshots -type f 2>/dev/null | wc -l)
    if [ "$shots" -gt 0 ]; then echo "    screenshots: $shots in screenshots/ (open to triage)"
    else echo "    [skip] gowitness ran but produced no screenshots (headless/browser issue) — non-critical."; fi
  else
    echo "    [skip] screenshots need a Chrome/Chromium binary (none found). Optional: sudo apt install -y chromium. Visual triage only — skipping."
  fi
fi

log "PHASE 3 — historical URLs + routing (§12/§23)"
LIVEHOSTS=$(awk '{print $1}' live.txt 2>/dev/null | sed -E 's#https?://##' )
for u in $SEED_URLS; do printf '%s\n' "$u"; done | anew -q urls_all.txt   # always include seeds
# --subs widens gau/wayback to *.$D (not just the apex) — big URL-coverage win.
# Both are time-bounded: gau in particular can stall on a slow provider.
{ have gau && timeout -k 5 300 gau --subs --threads 5 "$D" 2>/dev/null; } | anew -q urls_all.txt
{ have waybackurls && timeout -k 5 180 waybackurls "$D" 2>/dev/null; } | anew -q urls_all.txt
# crawl ALL live hosts (not just the apex) for current endpoints; fall back to apex.
# katana is the slowest phase on a wide target (observed 16min+ unbounded), so cap it:
# -ct = native crawl-duration (graceful exit + flush), -rl honors the politeness rate,
# and an outer timeout is the hard backstop. Override the cap with KATANA_CT=8m etc.
if have katana; then
  KSEED=live_urls.txt; [ -s "$KSEED" ] || { echo "https://$D" > _kseed.txt; KSEED=_kseed.txt; }
  KCT="${KATANA_CT:-5m}"
  timeout -k 5 480 katana -list "$KSEED" -jc -d 2 -kf all -ct "$KCT" -rl "$RATE" -timeout 10 -silent 2>/dev/null | anew -q urls_all.txt
fi
if have gf; then
  for p in xss ssrf redirect sqli idor lfi rce ssti; do
    cat urls_all.txt 2>/dev/null | gf "$p" 2>/dev/null | anew -q "cand_$p.txt"
  done
fi
cat urls_all.txt 2>/dev/null | grep -Ei '\.(json|xml|config|env|bak|sql|log|zip|tar|gz|ya?ml|swp|old)(\?|$)' | anew -q files_interesting.txt
cat urls_all.txt 2>/dev/null | unfurl keys 2>/dev/null | sort -u > param_names.txt

log "PHASE 3 — JS endpoints + secrets + source maps (§15)"
if have subjs; then
  subjs -i live_urls.txt 2>/dev/null | anew -q js_files.txt
  cat js_files.txt 2>/dev/null | sed 's/$/.map/' | { have httpx && httpx -mc 200 -silent 2>/dev/null; } | anew -q jsmaps.txt
  [ -s jsmaps.txt ] && echo "    [!] source maps exposed: $(wc -l < jsmaps.txt) — reconstruct source (guide §15.1)"
  if have trufflehog; then
    : > js_dump.txt; while read -r u; do curl -s "$u" >> js_dump.txt; echo >> js_dump.txt; done < js_files.txt
    trufflehog filesystem js_dump.txt --only-verified 2>/dev/null > js_secrets.txt
  fi
fi

log "PHASE 4 — Tier-1 high-value checks (§17/§20)"
# start these result files fresh each run: nuclei -o / subzy append, and we never
# want a previous run's content (or tool banner noise) to linger and mislead.
: > takeovers.txt; : > exposures.txt
# nuclei/probe target list: dedupe the live URLs to ONE canonical https host each.
# live_urls.txt is full of Cloudflare-fronted duplicates + :8080/:8443 variants (e.g.
# 571 URLs -> 168 unique hosts behind 31 IPs), so scanning it directly is ~3x wasteful
# and is what let the Tier-1 nuclei pass run for 2h+. Scan the deduped set instead.
NT=nuclei_targets.txt
sed -E 's#https?://##; s#:[0-9]+##' live_urls.txt 2>/dev/null | sort -u | sed 's#^#https://#' > "$NT"
[ -s "$NT" ] || cp live_urls.txt "$NT" 2>/dev/null
if have nuclei; then
  # takeovers: high-value, few templates, fast — bound + rate-limit.
  timeout -k 5 600 nuclei -l "$NT" -t http/takeovers/ -rl "$RATE" -timeout 8 -silent -o takeovers.txt 2>/dev/null
fi
# NOTE: the broad nuclei http/exposures + http/misconfiguration scan was REMOVED. On a
# CDN/WAF-fronted target it ran 2h+ unfiltered (4,400+ info FPs: cookies-without-secure on
# Cloudflare's own __cf_bm, azure-domain-tenant, ...) and even deduped to 168 hosts at
# medium+ it still hit a 10-min cap with ZERO actionable findings. Real exposures are
# found precisely + fast by the content-verified httpx probes below
# (.git/.env/actuator/swagger/openapi/graphql/.DS_Store), so this phase was pure cost.
# subzy prints its banner/config to STDOUT (not stderr), so `2>/dev/null` won't
# drop it and it pollutes takeovers.txt -> fake "takeover candidates" in QUEUE.md.
# Keep ONLY real hits: subzy marks them with the bracketed uppercase token
# `[ VULNERABLE ]`. (A loose match on "vulnerable" also catches the banner line
# "...potentially vulnerable subdomains (--hide_fails)", so anchor to the bracket.)
have subzy && timeout -k 5 300 subzy run --targets subs_all.txt --hide_fails 2>/dev/null \
  | grep -E '\[ *VULNERABLE' | anew -q takeovers.txt
# direct exposure probes:
if have httpx; then
  # NOTE: a bare 200 on these paths is FP-prone (SPA catch-all). -mc 200 plus a
  # content regex (-mr) keeps only responses that actually look like the artifact.
  for probe in \
    "/.git/config|\[core\]" "/.env|^[A-Z0-9_]+=" "/actuator/env|propertySources" \
    "/swagger.json|swagger|openapi" "/openapi.json|openapi" "/graphql|__schema|errors" \
    "/.DS_Store|Bud1"; do
    p="${probe%%|*}"; rx="${probe#*|}"
    timeout -k 5 180 httpx -l "$NT" -path "$p" -mc 200 -mr "$rx" -rl "$RATE" -timeout 8 -silent 2>/dev/null \
      | sed "s#\$# [$p]#" >> exposures.txt
  done
fi

log "PHASE 4b — active vuln leads: dalfox XSS + nuclei CVEs (§20)"
# SCOPE: only test the target's OWN domain. cand_*/url lists can include third-
# party URLs (CDNs, OAuth, fonts) that recon merely surfaced — never fuzz those.
D_RE=$(printf '%s' "$D" | sed 's/[.[\*^$(){}+?|]/\\&/g')
SCOPE_RE="^https?://([a-zA-Z0-9_-]+\.)*${D_RE}([/:?]|$)"
: > dalfox.txt; : > nuclei_cves.txt
# dalfox: reflected/DOM XSS on the gf xss candidates — scope-filtered, capped,
# polite (--delay), benign payloads. A LEAD: confirm the popup before reporting.
if [ "$PASSIVE" != "1" ] && have dalfox && [ -s cand_xss.txt ]; then
  grep -iE "$SCOPE_RE" cand_xss.txt | sort -u | head -300 > _xss_scope.txt
  if [ -s _xss_scope.txt ]; then
    dalfox file _xss_scope.txt --skip-bav --silence --no-color -w 30 --delay 100 \
      -o dalfox.txt 2>/dev/null
    [ -s dalfox.txt ] && echo "    [!] dalfox XSS leads: $(wc -l < dalfox.txt)"
  fi
fi
# nuclei CVEs: known-CVE templates (critical/high) over the live hosts.
if have nuclei; then
  # CVE scan of the deduped hosts. Capped at 10min + higher concurrency + shorter per-req
  # timeout: over a CDN-fronted target it otherwise burned ~20min for 0 hits (slow + noisy).
  timeout -k 5 600 nuclei -l "$NT" -tags cve -severity critical,high -rl "$RATE" -timeout 6 -c 50 -silent \
    -o nuclei_cves.txt 2>/dev/null
  [ -s nuclei_cves.txt ] && echo "    [!] nuclei CVE hits: $(wc -l < nuclei_cves.txt)"
fi

log "PHASE 5 — generate routed testing queue (§23/§24)"
{
  echo "# Routed Testing Queue — $D   ($(date))"
  echo
  echo "## TIER 1 — fast criticals"
  [ -s origin_ips.txt ]  && { echo "### Origin IP behind CDN/WAF (validated — hit it directly to bypass the WAF)"; sed 's/^/- [ ] /' origin_ips.txt; echo; }
  [ -s takeovers.txt ]   && { echo "### Subdomain takeover candidates"; sed 's/^/- [ ] /' takeovers.txt; echo; }
  [ -s nuclei_cves.txt ] && { echo "### Known CVEs (nuclei — confirm version, then exploit)"; sed 's/^/- [ ] /' nuclei_cves.txt; echo; }
  [ -s dalfox.txt ]      && { echo "### Reflected/DOM XSS (dalfox — confirm popup, then PoC)"; sed 's/^/- [ ] /' dalfox.txt; echo; }
  [ -s exposures.txt ]  && { echo "### Exposures (.git/.env/actuator/etc.)"; sort -u exposures.txt | sed 's/^/- [ ] /'; echo; }
  [ -s jsmaps.txt ]     && { echo "### Source maps exposed (reconstruct source)"; sed 's/^/- [ ] /' jsmaps.txt; echo; }
  [ -s js_secrets.txt ] && { echo "### Verified secrets in JS"; sed 's/^/- [ ] /' js_secrets.txt; echo; }
  echo "## TIER 2 — APIs / auth / authz (manual, the meat)"
  [ -s interesting.txt ] && { echo "### Interesting hosts (route per matrix §23)"; awk '{print "- [ ] "$0}' interesting.txt; echo; }
  [ -s authwalls.txt ]  && { echo "### Auth walls (try 403-bypass, then auth/JWT)"; sed 's/^/- [ ] /' authwalls.txt; echo; }
  for p in idor ssrf redirect sqli xss lfi; do
    [ -s "cand_$p.txt" ] && { echo "### $p candidates ($(wc -l < cand_$p.txt))"; head -15 "cand_$p.txt" | sed 's/^/- [ ] /'; echo; }
  done
  echo "## SKIP (coverage only, no manual time — guide §25): static/CDN hosts, info-disclosure noise."
} > QUEUE.md

log "DONE → output/$D/"
echo "    Start here: interesting.txt  +  QUEUE.md"
echo "    Then switch to the XSS / JWT / API exploitation guides."
echo "    Set monitoring: ./monitor.sh $D  (cron) for first-mover bugs (guide §27)."
