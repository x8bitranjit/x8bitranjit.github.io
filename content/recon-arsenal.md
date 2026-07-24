# Web Recon Arsenal — Copy-Paste One-Liners by Phase

> Companion to `RECON_GUIDE.md`. Run on **Kali/WSL**. Set `D=target.com` once. Stay in scope (guide §3/§29). Each block maps to a guide section. The goal is **routed attack surface**, not data — every block ends pointing at the next step.

```bash
D=target.com                       # the root domain
RES=/opt/resolvers.txt             # keep fresh!  (guide §1)
WL=/opt/SecLists                   # wordlists
mkdir -p $D && cd $D
```

---

## §4 — Org / ASN / acquisitions (what others miss)
*What & when:* the very first pass, and the one most hunters skip. Before touching subdomains, find **every root domain the company owns** — its bought-up companies (acquisitions), its spare TLDs, and its blocks of IP addresses (its **ASN**). Each new root you find here multiplies everything downstream, and this surface has the least competition. Run it only when the scope actually includes acquisitions/ASN (§3).
```bash
amass intel -org "Target Inc"                                  # ASN/org → IP ranges
amass intel -active -asn <ASN> -o org_domains.txt              # domains in the ASN
amass intel -whois -d $D                                        # reverse-whois siblings
whois <known_IP> | grep -iE 'origin|netname|orgname'           # find the ASN
# acquisitions: Crunchbase / Wikipedia / "Target acquires" / SEC EDGAR → add each root domain
# favicon pivot (also §10): Shodan  http.favicon.hash:<hash>  → sibling domains
```

## §5 — Passive subdomains (do first, do most)
*What & when:* always your first subdomain pass. **Passive** = build the list by querying *third-party databases* (CT logs, Chaos, GitHub) — **zero packets to the target**, so it's silent and can't get you blocked. Configure the API keys first (they roughly double your coverage). The final `grep` is the important habit: immediately skim the results for the juicy names (`admin`, `staging`, `internal`…) so you know where to focus.
```bash
subfinder -d $D -all -recursive -o subs_subfinder.txt
amass enum -passive -d $D -o subs_amass.txt
chaos -d $D -o subs_chaos.txt 2>/dev/null
curl -s "https://crt.sh/?q=%25.$D&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subs_crt.txt
# github-leaked subs:
github-subdomains -d $D -t $GITHUB_TOKEN >> subs_github.txt 2>/dev/null
cat subs_*.txt | sort -u | anew subs_passive.txt
# grep CT/passive for the JUICY ones immediately:
grep -Ei 'admin|internal|staging|dev|test|uat|qa|vpn|jenkins|jira|git|api|portal|dashboard|grafana|kibana' subs_passive.txt
```

## §6 — Active subdomains (resolve + brute + permutations)
*What & when:* after passive, to catch names no public database has. **Active** = you query DNS yourself (louder — mind rate rules). Three moves: **resolve** (keep only names that actually answer), **bruteforce** (try thousands of common prefixes), and **permutations** (mutate names you already have: `api`→`api-dev`/`api2`/`api-staging`). The permutation step is the under-used gold — it routinely finds the soft dev/staging hosts.
```bash
puredns resolve subs_passive.txt -r $RES --write subs_resolved.txt
puredns bruteforce $WL/Discovery/DNS/subdomains-top1million-110000.txt $D -r $RES --write subs_brute.txt
# permutations (high yield, under-used):
gotator -sub subs_resolved.txt -perm $WL/Discovery/DNS/dns-permutations.txt -depth 1 -numbers 3 -silent \
  | puredns resolve -r $RES --write subs_perm.txt
cat subs_resolved.txt subs_brute.txt subs_perm.txt | sort -u | anew subs_all.txt
```

## §7 — Extras others miss
```bash
# TLS SAN harvest from live IPs → more hostnames:
cat subs_all.txt | dnsx -a -resp-only -silent | sort -u > ips.txt
tlsx -l ips.txt -san -cn -silent | grep "$D" | sort -u | anew subs_all.txt
# recursive enum on an interesting sub:
subfinder -d corp.$D -all -silent | anew subs_all.txt
```

## §8 — Liveness & HTTP probe
*What & when:* the moment you have a subdomain list, before any deep work. **Probing** = knock on each name and record who answers and what it is (status code, page title, tech stack, CNAME). This turns a dumb list of names into a **ranked map of real services**. The `grep` for interesting titles/tech and the `40(1|3)` (auth-wall) and dangling-CNAME lines below are how you pull the high-value targets straight to the top of your queue.
```bash
httpx -l subs_all.txt -sc -title -td -server -cname -ip -location \
      -p 80,443,8080,8443,8000,8888,3000,5000,9000 -json -o httpx.json
httpx -l subs_all.txt -sc -title -td -cname -silent -o live.txt
# sort by interesting (route these first — guide §24):
grep -Ei 'admin|login|dashboard|internal|dev|staging|test|api|swagger|graphql|jenkins|grafana|kibana|jira|git|vpn|portal' live.txt
# auth walls worth a bypass:
grep -E ' 40(1|3) ' live.txt
# dangling CNAMEs (takeover candidates → §17):
httpx -l subs_all.txt -cname -silent | grep -Ei 's3|github|herokuapp|azure|fastly|netlify|shopify|cloudfront|surge|zendesk'
```

## §9 — Ports & origin-IP (WAF bypass)
*What & when:* use when a host looks interesting or is hiding behind a CDN. **Port scanning** finds side doors beyond 80/443 (a dev app on 8080, a database UI on 9200) — often unauthenticated wins (check the policy first; scanning is noisier). **Origin-IP hunting** finds the real server address behind a Cloudflare/WAF so you can hit it directly and *skip the firewall* — the trick that rescues "blocked" payloads.
```bash
naabu -l subs_resolved.txt -top-ports 1000 -rate 1000 -silent -o ports.txt
naabu -l subs_resolved.txt -top-ports 1000 -silent | httpx -sc -title -td -silent -o live_allports.txt
# origin IP behind Cloudflare: historical DNS (SecurityTrails), Shodan ssl.cert.subject.cn:"$D",
#   then verify:  curl -sk https://<origin_ip>/ -H "Host: $D" -o /dev/null -w "%{http_code}\n"
```

## §10 — Tech + favicon hash
```bash
httpx -l live.txt -td -server -silent -o tech.txt
# favicon hash for Shodan pivot:
curl -s https://$D/favicon.ico | python3 -c "import sys,mmh3,base64;print(mmh3.hash(base64.encodebytes(sys.stdin.buffer.read())))"
# → Shodan:  http.favicon.hash:<hash>   (finds all hosts/IPs running the same app, incl. no-DNS ones)
```

## §11 — vhost discovery
```bash
ffuf -w $WL/Discovery/DNS/subdomains-top1million-20000.txt \
     -u https://<TARGET_IP>/ -H "Host: FUZZ.$D" -fs <baseline> -mc all -s
```

## §12 — Historical URLs → routed to bug classes
*What & when:* run on the interesting hosts to dig up forgotten doors. Internet **archives** (Wayback) saved every URL the site ever exposed — including endpoints and parameters the company *deleted years ago* but never actually turned off. The `gf` step is the payoff: it auto-sorts thousands of old URLs into per-bug candidate lists (`cand_xss`, `cand_ssrf`…), turning history into a routed test plan.
```bash
gau --threads 5 $D | anew urls_all.txt
waybackurls $D | anew urls_all.txt
katana -u https://$D -jc -d 3 -kf all -silent | anew urls_all.txt
# route (guide §23):
for p in xss ssrf redirect sqli idor lfi rce; do cat urls_all.txt | gf $p 2>/dev/null | anew cand_$p.txt; done
# forgotten sensitive files:
cat urls_all.txt | grep -Ei '\.(json|xml|config|env|bak|sql|log|zip|tar|gz|ya?ml|txt|pdf|xls|swp|old)(\?|$)' | anew files_interesting.txt
# all param NAMES ever seen → reuse for param mining (§14):
cat urls_all.txt | unfurl keys 2>/dev/null | sort -u > param_names.txt
```

## §13 — content / dir discovery + 403 bypass
```bash
ffuf -w $WL/Discovery/Web-Content/raft-medium-directories.txt -u https://api.$D/FUZZ \
     -mc 200,201,204,301,302,307,401,403,405,500 -ac -e .json,.bak,.old,.config,.zip,.sql -o ffuf.json
# direct high-value probes:
for p in /.git/config /.env /config.json /appsettings.json /actuator/env /actuator/heapdump \
         /swagger.json /openapi.json /api-docs /graphql /server-status /.DS_Store /phpinfo.php; do
  httpx -l live.txt -path "$p" -mc 200,500 -silent; done
# 403 bypass quick set on /admin:
nuclei -l live.txt -t http/misconfiguration/ -tags 403 -o bypass403.txt
```

## §14 — parameter discovery
```bash
arjun -u "https://api.$D/v1/user" -m GET,POST -oT params.txt
# (Burp param-miner for headers/cookies/JSON — best for hidden ones)
```

## §15 — JS analysis + SOURCE MAPS (others miss)
*What & when:* one of the highest-yield deep passes, on any app-heavy host. The site's **JavaScript** is downloaded to you, so you can read it — it lists API routes, parameters, hidden features, sometimes secrets (the app's blueprint). **Source maps** (`.js.map`) go further: if exposed, they rebuild the *original readable source code* with the devs' own comments. Probe for `.map` files even when nothing links to them.
```bash
cat live.txt | katana -jc -d 2 -silent | grep -Ei '\.js(\?|$)' | sort -u > js_files.txt
subjs -i live.txt | anew js_files.txt
cat js_files.txt | while read u; do curl -s "$u"; echo; done > js_dump.txt
# endpoints + secrets:
cat js_files.txt | jsluice urls -R <(cat js_dump.txt) | jq -r '.url' 2>/dev/null | anew js_endpoints.txt
cat js_files.txt | jsluice secrets 2>/dev/null | anew js_secrets.txt
trufflehog filesystem js_dump.txt --only-verified
# SOURCE MAPS — reconstruct original source:
cat js_files.txt | sed 's/$/.map/' | httpx -sc -mc 200 -silent -o jsmaps.txt
sourcemapper -url https://$D/static/app.js.map -output ./src_recovered 2>/dev/null
```

## §16 — API & GraphQL
```bash
# REST specs:
for p in /swagger.json /openapi.json /v2/api-docs /api-docs /swagger-ui.html /redoc; do
  httpx -l live.txt -path "$p" -mc 200 -silent; done
# GraphQL introspection:
curl -s https://$D/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq . | head
graphw00f -t https://$D/graphql           # fingerprint engine
# introspection off? recover schema:  clairvoyance -o schema.json https://$D/graphql
```

## §17 — subdomain takeover
*What & when:* a fast, high-severity, low-dupe pass to run early across the *whole* list (including dead subs). A **takeover** is when a subdomain's CNAME still points at a cancelled, now-unclaimed outside service (S3/Heroku/…) — you re-register that slot and control the subdomain. Always check the cookie `Domain` scope afterward: a `.target.com`-scoped cookie escalates a takeover from defacement to full **account takeover**.
```bash
nuclei -l live.txt -t http/takeovers/ -o takeovers.txt
subzy run --targets subs_all.txt --hide_fails
# confirm cookie scope to escalate to ATO (guide §17):  check Set-Cookie domain=.target.com
```

## §18 — secrets (GitHub / leaks)
*What & when:* run against the org's GitHub early — a live secret is often the fastest Critical of the whole engagement. **Dorks** are precise search queries that fish for leaked credentials (`.env` passwords, private keys, `.tfstate` infra secrets). Two rules: scan commit **history** (a secret deleted in the latest commit still lives in the log), and **verify** every hit before reporting (`--only-verified`) — most regex matches are dead/example keys.
```bash
trufflehog github --org=Target --only-verified
# dorks (GitHub web search):
#   "target.com" password   org:Target filename:.env   "target" AWS_SECRET_ACCESS_KEY   "target.com" api_key
#   filename:.tfstate target   filename:.npmrc _auth   path:.github/workflows target secret
gitleaks detect --no-git -s ./dumped_repo
```

## §19 — cloud buckets
```bash
cloud_enum -k target -k target-prod -k targetinc -k target-uploads -k target-backups
aws s3 ls s3://target-uploads --no-sign-request            # public LIST?
# write test (BENIGN file you delete; never overwrite real data):
echo poc > poc.txt && aws s3 cp poc.txt s3://target-uploads --no-sign-request
```

## §20 — exposed git/env/backups
```bash
nuclei -l live.txt -t http/exposures/ -t http/misconfiguration/ -o exposures.txt
httpx -l live.txt -path /.git/config -mc 200 -silent -o exposed_git.txt
cat exposed_git.txt | sed 's#/.git/config##' | while read u; do git-dumper "$u/.git/" "dump_$(echo $u|unfurl format %d)"; done
```

## §21 — CORS
```bash
cat urls_all.txt | head -300 | while read u; do
  acao=$(curl -s -I -H "Origin: https://evil.com" "$u" | grep -i '^access-control-allow-origin')
  echo "$acao" | grep -qi 'evil.com' && echo "[CORS] $u  -> $acao"; done
```

## §26 — full pipeline (see scripts/x8bit_recon.sh)
```bash
bash scripts/x8bit_recon.sh target.com
```

## §27 — monitoring (cron daily → alert on NEW)
*What & when:* set this up once and leave it running — it's the single biggest edge over the crowd. New assets are the least-tested, least-duped surface, so you want to be *alerted the moment one appears* and test it before anyone else. The magic is `anew`: it emits **only new lines**, so each daily run probes just the freshly-appeared hosts and pings you (Slack/Discord) on any new takeover/exposure — a standing first-mover advantage.
```bash
subfinder -d $D -all -silent | anew $D/subs.txt | httpx -silent \
  | nuclei -t http/takeovers/ -t http/exposures/ -silent | notify -silent
# 'anew' emits only NEW lines → only new assets get probed → first-mover (guide §27).
```

---

## §10c — Dorking & internet-scan pivots (find what DNS enum misses)
```
# Shodan (web or CLI) — assets with no DNS record, exposed panels, origin IPs:
ssl.cert.subject.CN:"target.com"            ssl:"Target Inc"            org:"Target Inc"
http.favicon.hash:<hash>                    http.title:"Target Admin"    http.html:"target.com"
hostname:"target.com"  product:"Jenkins"    port:9200 org:"Target Inc"   (exposed Elasticsearch)
# Censys: services.tls.certificates.leaf_data.subject.common_name: target.com  /  services.http... 
# FOFA:  domain="target.com" || cert="target.com" || title="Target"  ;  ZoomEye similar.
# Google dorks (exposed surface):
site:target.com inurl:admin|login|dashboard|api|swagger|graphql|debug
site:target.com ext:env|sql|bak|log|json|yml|config|txt|old
site:target.com intitle:"index of"   |   "target.com" "AWS_SECRET" -github
inurl:target.com & site:pastebin.com|trello.com|s3.amazonaws.com|github.com|gitlab.com
# GitHub dorks (beyond §18): org:Target "BEGIN RSA PRIVATE KEY" · "target.com" jdbc: · filename:.env DB_PASSWORD
#                            "target" filename:.kube/config · "target.com" authorization: bearer
# Cert transparency pivots: crt.sh "Target Inc" (org), censys cert search → new roots/subs (§4/§5).
```

## Real-world recon → critical wins (what to chase first) + references
```
□ Origin-IP behind Cloudflare (§9) → bypass WAF, hit the app directly (often unprotected) → everything is easier.
□ Exposed /.git, /.env, /actuator/{env,heapdump}, /swagger.json, /.DS_Store (§13/§20) → secrets/source → fast Critical.
□ Dangling CNAME (§8/§17) → subdomain takeover → cookie-scoped ATO / CORS-trust pivot / phishing.
□ Verified secret from JS/GitHub (§15/§18) → cloud key → RCE (JS-files kit §11 / SSRF kit §11).
□ GraphQL introspection on (§16) → full schema → IDOR/authz/mutation abuse map.
□ Forgotten staging/dev sub with no WAF + prod data (§5/§8) → same bugs, no defenses.
□ Public/writable cloud bucket (§19) → data exposure / supply-chain (overwrite a served asset).
```
> **References:** PortSwigger / OWASP WSTG (Information Gathering), ProjectDiscovery docs (subfinder/httpx/naabu/katana/
> nuclei), `tomnomnom`/`pdiscoveryio` tooling, PayloadsAllTheThings & HackTricks recon notes, Hackviser & PentesterLab
> recon modules, the Bug Bounty recon methodology references (TBHM, reconFTW).

---

### gf patterns (route URLs → bug classes, §23)
```bash
# install once:
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
git clone https://github.com/tomnomnom/gf && cp gf/examples/*.json ~/.gf
# use: cat urls_all.txt | gf <pattern>   where <pattern> ∈ {xss,ssrf,redirect,sqli,idor,lfi,rce,ssti,debug_logic,...}
```

> The reasoning for *which* output to chase first (impact-per-hour) and what to skip is in `RECON_GUIDE.md` §23–§25. Recon ends when you have a **ranked, routed testing queue** — then switch to the XSS / JWT / API exploitation guides.
