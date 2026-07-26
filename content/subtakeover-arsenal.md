# Subdomain Takeover — Arsenal (fingerprints, claim steps & commands)

**Author:** x8bitranjit

> Companion to `SUBDOMAIN_TAKEOVER_TESTING_GUIDE.md`. A fingerprint is a **lead**, not a finding — always confirm the
> service is **claimable** (guide §7), then **claim it and serve a benign marker** (§8), then chain the **trust** (§10–§13).
> The authoritative, continuously-updated per-service matrix is **`can-i-take-over-xyz`** (EdOverflow) — cross-check it.
> Replace `target.com`/`sub.target.com` with the real asset. **Authorized testing only; unpublish the claim after the PoC.**

---

## §0.0 — The whole attack in one sequence

*What & when:* the entire subdomain-takeover run on one screen — the **decision spine** every section below plugs into. The mantra: a dangling record is a **fingerprint**, the takeover is a **claim**, and the severity is **the trust the hostname carries**. Don't stop at "vulnerable to takeover" — *claim it benignly, then chain the trust to ATO.* Follow the arrows to the matching section.

```
# ── 1. RECON: enumerate + resolve EVERY record type (guide §3) ───────────
subfinder/amass/crt.sh → subs   →   dnsx -a -cname -ns -resp   (CNAME *and* NS/MX — the big ones hide in NS/MX)

# ── 2. FINGERPRINT: which are dangling? (guide §6) ───────────────────────
curl each → match the service "unclaimed" signature (GitHub "There isn't a GitHub Pages site here", S3 "NoSuchBucket", ...)
subzy / subjack / nuclei -tags takeover   (these output LEADS, not findings)

# ── 3. CLAIMABILITY: fingerprint ≠ takeover (guide §7) — the VALIDITY gate ─
cross-check can-i-take-over-xyz  →  CLAIMABLE? (GitHub Pages/S3/Heroku/... = yes · some CloudFront/Statuspage = NO = FP §16)

# ── 4. CLAIM benignly: prove control from sub.target.com (guide §8) ──────
register the dead resource IN YOUR OWN ACCOUNT (repo+CNAME file / bucket name / heroku app) → serve a BENIGN marker page
curl https://sub.target.com/ → your marker = takeover PROVEN

# ── 5. ESCALATE by the trust the hostname carries (guide §10–§13) ────────
cookie:  main app Set-Cookie Domain=.target.com (not __Host-)  → sub reads/sets session cookie → SESSION ATO ⭐
2nd-order: sub in main app's CSP script-src / <script src>     → serve JS → exec on MAIN app (XSS/mass session theft) ⭐
         sub in OAuth *.target.com redirect_uri allow-list     → receive victim's token → ATO (→ OAuth kit) ⭐
NS/MX:   NS takeover → full DNS control + valid TLS   ·   MX takeover → intercept reset/MFA email → ATO ⭐
else:    credential phishing on the real brand domain (Medium–High)

# ── 6. CLEAN UP + report (guide §19–§20) ─────────────────────────────────
screenshot marker + trust proof → UNPUBLISH the claim → report IMPACT → tell them to REMOVE the DNS record
```

> **Cash-out map (guide §17 severity):** claimable + benign marker = takeover **proven** → **cookie-scope/OAuth/CSP trust → session ATO / token theft / script-exec on the MAIN app** (Critical) · **NS/MX → DNS control / reset-mail interception → ATO** (Critical, the sleepers) · else **brand phishing** (Medium–High). Fingerprint you **can't** claim = **Info/FP** (§16). Full worked run: **guide Appendix D**.

---

## 1. Enumeration & resolution (find every subdomain + record)
> **What & when:** step one — build the full list of the target's signs and see where each points. Enumerate every subdomain (passive + CT logs + brute), then resolve *every* record type (CNAME **and** NS/MX/A), because the highest-value danglers (NS/MX) hide where CNAME-only tools never look.

```bash
# passive enum (CT logs + APIs + scraping)
subfinder -d target.com -all -silent | tee subs.txt
amass enum -passive -d target.com -o subs_amass.txt
assetfinder --subs-only target.com >> subs.txt
# cert transparency (dead hosts in CT are PRIME candidates)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u >> subs.txt

# resolve every record type
sort -u subs.txt | dnsx -silent -a -cname -ns -resp -o resolved.txt
dig CNAME sub.target.com +short
dig NS   sub.target.com +short
dig MX   sub.target.com +short
dig A    sub.target.com +short
# follow the WHOLE CNAME chain (danglers hide at the end)
dig +trace sub.target.com

# fingerprint at scale
subzy run --targets resolved.txt --hide_fails
subjack -w subs.txt -t 100 -timeout 30 -ssl -o subjack.txt
nuclei -l subs.txt -tags takeover -o takeover.txt
httpx -l subs.txt -silent -status-code -title -cdn -o httpx.txt
python3 poc/subtakeover_scan.py -l subs.txt
```

---

## 2. Per-service fingerprints (HTTP "not found" signatures) + claimability
> **What & when:** your lookup table for "is this booth empty, and can I rent it?" Match the provider's exact "not found" wording to identify the service, then read the **Claimable?** column — and always cross-check `can-i-take-over-xyz`, because a fingerprint on a *non*-claimable service (CloudFront, reserved names) is Info, not a bug.

> `claimable?` reflects the common state — **verify against `can-i-take-over-xyz`** (providers change policy). "Edge" = sometimes/region-dependent.

| Service | CNAME pattern | HTTP fingerprint (body) | Claimable? | Claim in short |
|---|---|---|---|---|
| **AWS S3** | `*.s3*.amazonaws.com`, `s3.amazonaws.com/<bucket>` | `NoSuchBucket` / `The specified bucket does not exist` | **Yes** | Create the exact bucket name (global namespace) in your account; enable static hosting. |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here.` | **Yes** | Create a repo/org page for that name; add `sub.target.com` as the custom domain (CNAME file). |
| **Heroku** | `*.herokuapp.com` | `No such app` / `herokucdn.com/error-pages/no-such-app.html` | **Yes** (edge) | Create an app, add `sub.target.com` as a custom domain. |
| **Fastly** | `*.fastly.net` | `Fastly error: unknown domain` | **Yes** (edge) | Add the domain to a Fastly service you control. |
| **Azure** | `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.trafficmanager.net`, `*.blob.core.windows.net` | `404 Web Site not found` / storage "resource does not exist" | **Yes** (edge) | Register the app/storage name; add the custom domain. |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable.` | **Edge** | Often needs the exact myshopify name; verify per `can-i-take-over-xyz`. |
| **Netlify** | `*.netlify.app` / `*.netlify.com` | `Not Found` (Netlify) | **Yes** (edge) | Create a site, add the custom domain. |
| **Surge.sh** | `*.surge.sh` | `project not found` | **Yes** | `surge` the domain. |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` | **Edge** | Register the Zendesk subdomain. |
| **Readme.io** | `*.readme.io` | `Project doesnt exist... yet!` | **Yes** | Claim the project name. |
| **Ghost** | `*.ghost.io` | `Domain error` / `Site unavailable` | **Edge** | Claim the Ghost publication. |
| **Cargo / Tumblr / Unbounce / Wufoo / Helpjuice / Pantheon / Tilda / Webflow / Bigcartel / Statuspage / Tave / Wishpond / Aftership / Uservoice / Campaign Monitor / Acquia / Anima / Simplebooklet** | various | provider-specific "not found" strings | **varies** | See `can-i-take-over-xyz` for each; many are claimable. |
| **AWS Elastic Beanstalk** | `*.elasticbeanstalk.com` | app not found | **Edge** | Region-locked; create the app in the same region. |
| **Bitbucket** | `*.bitbucket.io` | `Repository not found` | **Yes** | Create the repo/pages site. |
| **Desk / Freshdesk / Intercom** | various | provider help-desk "not found" | **varies** | Register the workspace. |

> **NOT (usually) claimable** — a fingerprint here is Info, not a takeover: `*.cloudfront.net` (often reserved), certain Fastly/Akamai edges, GitHub *user* pages already taken, and any service that verifies domain ownership before binding. **Always cross-check `can-i-take-over-xyz`.**

## 2.1 NS / MX / other-record signals

```
NS takeover:  dig NS sub.target.com  → points to ns*.provider.com whose DOMAIN is EXPIRED or on a claimable DNS host.
              Check registrability of the nameserver's base domain at a registrar; or claim the zone on the DNS provider.
              → you serve ALL DNS for sub.target.com (A/MX/TXT + DV TLS via DNS-01). CRITICAL (guide §11).
MX takeover:  dig MX sub.target.com  → mail routed to a SaaS where you can register that host → receive its email
              → intercept password-reset / verification mail → ATO. CRITICAL (guide §11).
SERVFAIL:     broken delegation → probe for NS takeover.
Dangling A:   dig A sub.target.com → an IP the target no longer holds (cloud elastic-IP churn / shared host). Harder; you'd
              need that exact IP or a shared-hosting vhost that answers. Lower yield.
TXT/SPF/CAA:  references to claimable third-party verification/anti-spam resources → email-spoofing / verification abuse.
```

---

## 3. Confirming the fingerprint (don't trust a bare 404)
> **What & when:** run this before you get excited — prove the booth is *actually empty and run by the mall*, not "the shop is open but has no page here." Match the provider's exact string, confirm the provider's own headers served it, and compare against a known-live sibling so a normal 404 doesn't fool you.

```bash
# does the CNAME target itself resolve? NXDOMAIN often == registrable
dig +short $(dig +short CNAME sub.target.com | tail -1)

# match the provider's EXACT "not found" string, served by the PROVIDER (check Server/Via/X-Served-By headers)
curl -sk https://sub.target.com/ -D - | sed -n '1,20p'
curl -sk https://sub.target.com/ | grep -iE 'NoSuchBucket|There isn.t a GitHub Pages|No such app|Fastly error: unknown domain|Web Site not found|currently unavailable|project not found|Repository not found'

# negative control: compare with a LIVE subdomain on the same provider so you don't mistake a normal 404 for a dangler.
```

---

## 4. The benign claim (per common provider) — serve proof, then UNPUBLISH
> **What & when:** the moment that turns a lead into a finding — rent the exact booth and hang your nameplate. Pick your provider's recipe, serve a single harmless marker, screenshot `sub.target.com` returning *your* content, then **immediately unpublish**. The screenshot is the proof; leaving the claim live is a safety violation.

**AWS S3 (CNAME → `<bucket>.s3.amazonaws.com`):**
```bash
aws s3 mb s3://<exact-bucket-name-from-the-cname>            # if the name is free → claimable
aws s3 website s3://<bucket> --index-document index.html
echo "subdomain-takeover PoC by <handle> for <program> - $(date -u)" > st-poc-<rand>.txt
aws s3 cp st-poc-<rand>.txt s3://<bucket>/st-poc-<rand>.txt --acl public-read
curl -s https://sub.target.com/st-poc-<rand>.txt            # returns YOUR marker → confirmed
# ... capture evidence, then: aws s3 rb s3://<bucket> --force   (UNPUBLISH)
```

**GitHub Pages (CNAME → `<name>.github.io`):**
```
1. Create repo <name>.github.io (or an org/project page) in your account.
2. Add a CNAME file containing: sub.target.com
3. Push an index/st-poc-<rand>.txt with your benign marker.
4. curl https://sub.target.com/st-poc-<rand>.txt → your content. Capture, then delete the repo.
```

**Heroku / Netlify / Fastly / Azure / Surge (custom-domain bind):**
```
1. Create the app/site/service with the exact name.
2. Add sub.target.com as a custom domain (the existing CNAME now resolves to YOUR resource).
3. Deploy a single benign page with a unique marker; fetch it via https://sub.target.com/<marker>.
4. Capture evidence → remove the custom domain / delete the resource (UNPUBLISH).
```

> **Every claim ends with UNPUBLISH.** Serve the marker only long enough to screenshot. In the report, ask them to **remove the DNS record** (re-creating the resource alone can re-dangle later).

---

## 5. Trust-chain escalation payloads (guide §10–§13)
> **What & when:** once you own the booth, these prove *what the trust unlocks* — the difference between Medium and Critical. Check the cookie `Domain` stamp (ATO), test OAuth/CSP/CORS allow-list membership (token theft / script-exec on the main app), or the NS/MX angle (certs/mail). Prove each with your own accounts and a benign marker.

**Cookie scope check (§10):**
```
# in the main app, inspect the session cookie:
Set-Cookie: session=...; Domain=.target.com; ...     ← DOMAIN-SCOPED → your subdomain can read/set it → ATO
Set-Cookie: session=...; Path=/; HttpOnly             ← host-only → your subdomain CANNOT read (still can SET .target.com cookies)
# proof page on the taken-over host (own account):
<script>document.title = 'ST-COOKIE-POC:' + document.cookie</script>   (benign; proves same-site read if not HttpOnly)
```

**OAuth redirect_uri (§13) — hand to the OAuth kit:**
```
https://idp/authorize?...&redirect_uri=https://sub.target.com/cb    (if sub is allow-listed → code/token to your host → ATO)
```

**CSP script-src / `<script src>` (§13) — hand to the XSS kit:**
```
# if the main app's CSP allows scripts from sub.target.com, or loads <script src="https://sub.target.com/app.js">:
# host a BENIGN proof at https://sub.target.com/app.js:
console.log('ST-CSP-POC: executing on ' + location.host);   (proves script-exec on the main app → XSS-equivalent)
```

**CORS ACAO (§13) — hand to the CORS kit:**
```
Origin: https://sub.target.com    → if the API returns Access-Control-Allow-Origin: https://sub.target.com + ACAC:true
                                     → your page reads the victim's credentialed responses cross-origin.
```

**NS/MX (§11):**
```
# NS: after claiming the zone, issue a DV cert (proves full control):
#   set the ACME DNS-01 TXT record in YOUR zone → get a valid cert for sub.target.com.
# MX: after claiming the mail resource, send a test email to <anything>@sub.target.com → you receive it.
```

---

## 6. Confirm-it checklist (don't submit before this)
> **What & when:** the final gate before you hit submit — every box must be ticked. If you can't tick "I claimed it and my marker served" and "here's the trust chain," you have a fingerprint or a bare claim, not an impactful takeover.

```
□ The record actually DANGLES (exact provider "not found" fingerprint, served by the provider — not a target 404).
□ The service is CLAIMABLE (cross-checked can-i-take-over-xyz; the exact name is free to register in your account).
□ You CLAIMED it and https://sub.target.com/<your-marker> returns YOUR content (screenshot + dig output).
□ You identified the TRUST chain: domain cookies (§10), OAuth/CSP/CORS allow-list (§13), or NS/MX (§11) — the impact.
□ It's the TARGET's own subdomain (in scope), not a third-party domain.
□ You UNPUBLISHED the claim after capturing evidence, and the report asks them to REMOVE the DNS record.
```
