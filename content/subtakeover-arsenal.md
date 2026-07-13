# Subdomain Takeover — Arsenal (fingerprints, claim steps & commands)

> Companion to `SUBDOMAIN_TAKEOVER_TESTING_GUIDE.md`. A fingerprint is a **lead**, not a finding — always confirm the
> service is **claimable** (guide §7), then **claim it and serve a benign marker** (§8), then chain the **trust** (§10–§13).
> The authoritative, continuously-updated per-service matrix is **`can-i-take-over-xyz`** (EdOverflow) — cross-check it.
> Replace `target.com`/`sub.target.com` with the real asset. **Authorized testing only; unpublish the claim after the PoC.**

---

## 1. Enumeration & resolution (find every subdomain + record)

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

**CSP script-src / <script src> (§13) — hand to the XSS kit:**
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

```
□ The record actually DANGLES (exact provider "not found" fingerprint, served by the provider — not a target 404).
□ The service is CLAIMABLE (cross-checked can-i-take-over-xyz; the exact name is free to register in your account).
□ You CLAIMED it and https://sub.target.com/<your-marker> returns YOUR content (screenshot + dig output).
□ You identified the TRUST chain: domain cookies (§10), OAuth/CSP/CORS allow-list (§13), or NS/MX (§11) — the impact.
□ It's the TARGET's own subdomain (in scope), not a third-party domain.
□ You UNPUBLISHED the claim after capturing evidence, and the report asks them to REMOVE the DNS record.
```
