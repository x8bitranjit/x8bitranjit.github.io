# Subdomain Takeover — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **Subdomain Takeover** — from "what is a dangling DNS record" to the
> chains that actually pay: **domain-cookie theft → session ATO**, **`NS`/`MX` takeover → DNS control / reset-email
> interception → ATO**, **second-order takeover of a host in the main app's OAuth / CSP / CORS / `<script src>` trust →
> token theft or script-exec on the primary application**, and **credential phishing on the real brand domain**. Q&A
> format, progressive difficulty. Covers enumeration, per-service fingerprints, **claimability**, the benign claim, every
> escalation, tooling, methodology, real-world patterns, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and your own labs. **Claim** in your own
> provider account, serve a **benign marker**, prove chains with **own accounts / own cert / own test email**,
> **unpublish immediately** after evidence, never intercept real users' mail/cookies/tokens, and ask the program to
> **remove the DNS record**.

**Canonical references** (cited throughout — real and worth reading):
- **`can-i-take-over-xyz`** (EdOverflow) — the per-service "is this fingerprint claimable?" matrix (the single most important reference)
- OWASP WSTG — *Test for Subdomain Takeover* (WSTG-CONF-10) · HackTricks — *Domain/Subdomain takeover*
- Detectify Labs — *Hostile subdomain takeover* (Frans Rosén, the class-defining series)
- CWE-350 · CWE-384 · CWE-79 · CWE-284
- Companion kit in this repo: `Web/SubdomainTakeover/` (guide + arsenal + checklist + report template + `poc/`); siblings `Web/Recon/`, `Web/OpenRedirect/`, `Web/OAuth/`, `Web/CORS/`, `Web/HostHeader/`, `Web/XSS/`.

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals (dangling records, why it pays)** (Q1–Q12)
- **Level 1 — Recon & baseline** (Q13–Q24)
- **Level 2 — Fingerprinting & claimability** (Q25–Q42)
- **Level 3 — Exploitation by impact (ATO, script-exec, DNS/mail)** (Q43–Q66)
- **Level 4 — Advanced chains** (Q67–Q78)
- **Tooling** (Q79–Q84)
- **Black-box methodology & checklist** (Q85–Q89)
- **Cheat sheets** (Q90–Q94)
- **Real-world patterns & references** (Q95–Q97)
- **Defense — preventing takeover** (Q98–Q102)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is a subdomain takeover in one breath?
A DNS record of the target (usually a `CNAME`) points a subdomain at a third-party resource (a cloud bucket, PaaS app, CDN, SaaS endpoint) that the target **no longer owns**. Because the provider lets anyone register that exact resource name, **you** claim it → `sub.target.com` now serves **your** content.

### Q2. What's a "dangling" DNS record?
A record left behind after the resource it points to was deleted/de-provisioned. The DNS entry still resolves toward the provider, but the specific bucket/app/page is gone — so it returns a provider "not found" page, `NXDOMAIN`, or `SERVFAIL`. That's the fingerprint.

### Q3. Why is a subdomain takeover valuable if I "just" serve a page?
Because `sub.target.com` is **inside the target's trust boundary**. It inherits the brand's reputation, domain-scoped cookies, CSP/CORS/OAuth allow-list membership, and user trust. That trust is the payload — it turns a leftover DNS record into cookie theft, phishing on the real domain, token theft, and script-exec on the main app.

### Q4. What's the single biggest reporting mistake?
Reporting the **fingerprint** ("the CNAME points to an unclaimed bucket — it 404s") without **claiming** it. A 404 is a lead, not a finding. You must actually register the resource and serve a benign marker from `sub.target.com`, or a triager can (rightly) close it as unconfirmed.

### Q5. Which record types can be taken over?
`CNAME` (the common case — dead SaaS/bucket), `A`/`AAAA` (an IP no longer owned — harder), **`NS`** (dangling delegation → full DNS control — Critical), **`MX`** (mail route → email interception — Critical), and `TXT`/SPF/CAA (verification/anti-spam references → spoofing/verification abuse).

### Q6. Why are `NS` and `MX` the sleeper Criticals?
A dangling **`NS`** you can claim = you serve **all** DNS for the subdomain → mint valid TLS certs, set MX, host anything → you own the subdomain outright. A dangling **`MX`** = you receive the target's **email** for that host → intercept password-reset/verification mail → account takeover. Both out-rank a typical CNAME-to-bucket.

### Q7. What's a "second-order" takeover?
A dead subdomain that's still **referenced by the main app** — in its CSP `script-src`, a `<script src>`, an OAuth `redirect_uri` allow-list, or a CORS allow-list. Claiming it gives you **script execution or token theft on the primary application**, not a standalone page. These pay the most.

### Q8. What's the difference between "dangling" and "claimable"?
Dangling = points at a dead resource (returns a fingerprint). Claimable = you can **actually register** that exact resource. Many dangling records point to services that **prevent re-registration** or require domain verification you can't pass → not takeover-able. `can-i-take-over-xyz` tracks which services are claimable.

### Q9. What CWE do I cite?
There's no perfect single CWE; **CWE-350** (reliance on untrusted external inputs / dangling DNS) is the usual anchor. Add **CWE-384** (session fixation, cookie chain), **CWE-79** (second-order script-exec), and **CWE-284** (access control) by outcome. Lead the report with the impact.

### Q10. How does a subdomain takeover become account takeover?
Three main paths: (1) domain-scoped cookies — your page on `sub.target.com` reads/sets the victim's `.target.com` session; (2) `MX` takeover — you intercept the victim's password-reset email; (3) second-order — the subdomain is in an OAuth `redirect_uri` allow-list, so the flow delivers the victim's token to your host.

### Q11. Is this a "recon bug" or a "web bug"?
Both — it's where **recon becomes a Critical**. The discovery is pure DNS/cloud recon (enumerate subs, resolve records, fingerprint danglers), but the exploitation and impact are web/auth (cookies, OAuth, CSP, phishing). That's why it lives in the Web kit but leans on the Recon kit's enumeration.

### Q12. What's the minimum I need to test subdomain takeover?
Subdomain enumeration (subfinder/amass + crt.sh), a resolver (dnsx/dig) to pull every record type, the per-service fingerprint matrix (`can-i-take-over-xyz` + this kit's Arsenal), and **a cloud/SaaS account you control** to actually claim the dangling resource for the benign PoC.

---

# LEVEL 1 — RECON & BASELINE

### Q13. Where do I get the subdomain list?
Passive: subfinder/amass/assetfinder pulling CT logs, APIs, and scraping; plus **crt.sh** and certspotter directly. Active: DNS brute (puredns/massdns + wordlist) and permutations (altdns/gotator). Historical: crt.sh and wayback — **dead hosts still in CT logs are prime candidates**.

### Q14. Why are certificate-transparency logs so useful here?
Because a subdomain that once had a TLS cert is in CT **forever**, even after it's decommissioned. So CT logs surface hostnames that no longer resolve or now return a provider 404 — exactly the dangling records you want. Diffing CT logs over time is a great continuous-monitoring signal.

### Q15. How do I resolve every record type at scale?
`dnsx -silent -a -cname -ns -resp` over the subdomain list, or `dig CNAME/NS/MX/A sub.target.com +short` per host. Don't just check CNAME — `NS` and `MX` danglers are the high-impact ones and are easy to miss if you only look at CNAME/A.

### Q16. What does "follow the CNAME chain" mean?
A subdomain may `CNAME` to another `CNAME` to another before hitting the dead resource. Resolve the **whole chain** (`dig +trace`) — the dangler often hides at the tail. A tool that only reads the first hop misses it.

### Q17. What's the baseline test to spot a dangler?
Resolve the subdomain; if the CNAME target is `NXDOMAIN`, it's likely registrable. If it resolves, fetch it over HTTP/HTTPS and look for a **provider "not found" page** (NoSuchBucket / no GitHub Pages site / Heroku "No such app" / Fastly "unknown domain" / etc.). Then check claimability.

### Q18. Is every `NXDOMAIN` a takeover?
No. `NXDOMAIN` on the CNAME target means the name doesn't resolve — but whether it's **registrable** depends on the provider/registrar. A lapsed domain you can buy = yes; a reserved provider namespace = no. Confirm registrability before claiming it a takeover.

### Q19. How do I avoid mistaking a normal 404 for a dangler?
Match the **exact provider signature** (the specific "not found" string) and confirm it's served by the **provider's** infrastructure (Server/Via/X-Served-By headers). Use a **negative control**: browse a known-live subdomain on the same provider and compare. A generic app 404 with no provider signature isn't a dangler.

### Q20. What's in scope — the target's subdomains only?
Yes. A dangling record on a **third-party** domain you discovered via the target is *their* vendor's problem, not the target's bug (usually out of scope). Only the target's own domains/subdomains count.

### Q21. Which candidates should I prioritize?
`NS`/`MX` danglers (Critical), subdomains referenced in the main app's CSP/CORS/OAuth/`<script src>` (second-order — script-exec/token theft), hosts that once served a login/portal (phishing muscle-memory), and staging/dev/CI hosts (privileged integrations).

### Q22. How do I know if a subdomain is referenced by the main app?
Grep the main app's HTML/JS for the hostname (CSP header, `<script src>`, `fetch`/XHR origins, OAuth config), check the response's `Content-Security-Policy` and any CORS `Access-Control-Allow-Origin` reflections. The JSFiles kit's JS-harvesting helps here.

### Q23. What's the deliverable after recon+baseline?
A shortlist of `(subdomain, record type, provider, fingerprint, claimable?)` candidates, with the high-impact ones (NS/MX/second-order) flagged. You then confirm claimability and claim them one by one.

### Q24. Can wildcard DNS hide danglers?
A live `*.target.com` catch-all can mask individual danglers (everything resolves to the catch-all). Conversely, a wildcard pointing at a dead resource is a broad takeover. Check whether resolution is a real per-host record or a wildcard catch-all before concluding.

---

# LEVEL 2 — FINGERPRINTING & CLAIMABILITY

### Q25. What exactly is a "fingerprint"?
The provider's specific "this resource doesn't exist / isn't claimed" response — a body string (e.g. `NoSuchBucket`), a status, and provider headers. Matching it confirms the resource behind the DNS record is dead, as opposed to an app that just returns 404 for `/`.

### Q26. Give the top fingerprints by memory.
S3: `NoSuchBucket` / `The specified bucket does not exist`. GitHub Pages: `There isn't a GitHub Pages site here.` Heroku: `No such app`. Fastly: `Fastly error: unknown domain`. Azure: `404 Web Site not found`. Shopify: `Sorry, this shop is currently unavailable.` Surge: `project not found`. (Full list in the Arsenal + `can-i-take-over-xyz`.)

### Q27. Why is `can-i-take-over-xyz` the key reference?
Because it tracks, per service, whether the fingerprint is **actually claimable** (providers change policy — some that were vulnerable are now fixed, and vice versa). It's the difference between a valid report and noise. Always cross-check it before claiming a takeover.

### Q28. Which common services are usually NOT claimable?
CloudFront (often reserved/edge), certain Fastly/Akamai edges, GitHub *user* pages already taken, and any service that verifies domain ownership before binding a custom domain. A fingerprint on a non-claimable service is Info, not a takeover.

### Q29. How do I confirm claimability for S3?
Try to create the exact bucket name (S3's namespace is global) in your own account. If it's free to create, it's claimable; if it's taken/reserved, it isn't. Match the region if the CNAME encodes one.

### Q30. How do I confirm claimability for GitHub Pages?
Check whether the repo/org username in the `*.github.io` target is free to create in your account, and whether you can add `sub.target.com` as the custom domain (via a CNAME file). GitHub binds on the CNAME without extra domain verification in the common case.

### Q31. What's the "custom-domain binding" gotcha?
Many services require you to **add `sub.target.com` as a custom domain** in your resource. If the provider then **verifies domain ownership** (a TXT record you can't set), you're blocked → not claimable. If it binds purely on the existing CNAME, you're in. This verification step is what makes some services safe.

### Q32. Does region/namespace matter?
Yes, for S3/Azure/Elastic Beanstalk — the resource may be region-locked, so you must create it in the **same region/namespace** the original used (often encoded in the CNAME target). Wrong region = the CNAME won't resolve to your resource.

### Q33. How do I confirm an `NS` takeover is claimable?
Check whether the delegated nameserver's **base domain is expired/registrable** at a registrar, or whether the DNS **zone is claimable** on the provider (e.g. a managed-DNS SaaS where you can add that zone). If you can register the nameserver domain or claim the zone, you control the subdomain's DNS.

### Q34. How do I confirm an `MX` takeover is claimable?
Check whether the mail SaaS the MX points at lets you **register that hostname/organization** and receive mail for it. If so, mail addressed to `<anything>@sub.target.com` (or the MX host) comes to you.

### Q35. What's the safest way to prove claimability without full exploitation?
For most: create the resource with the exact name and serve a benign marker (that *is* the claim). For NS/MX: claim the zone/mail resource and prove control with your **own** test cert / test email — don't catch real users' mail. Always minimal and benign.

### Q36. Can I take over an `A`-record dangler?
Rarely and with difficulty — you'd need the exact IP (cloud elastic-IP churn sometimes lets you re-allocate it) or a shared-hosting account that answers for the vhost. Lower yield than CNAME, but real in cloud environments where IPs recycle.

### Q37. What if the fingerprint matches but I can't create the resource?
Then it's **not claimable** — report as Info at most, or move on. Don't submit "vulnerable to takeover" based on a matched fingerprint alone; that's the #1 false positive.

### Q38. How do automated tools (subzy/subjack/nuclei) fit in?
They match fingerprints at scale and flag candidates — a **lead-generation** step. They don't confirm claimability or actually claim. Treat their "vulnerable" output as a to-verify list, then confirm claimability and claim by hand.

### Q39. Why do I need a negative control when fingerprinting?
To avoid false positives: a target's own app might return a 404 that superficially resembles a provider page. Comparing against a known-live subdomain on the same provider (and checking provider headers) confirms the response is the provider's generic not-found, not the target's.

### Q40. How current do fingerprints need to be?
Very — providers rename their error pages and change claimability. A fingerprint DB from two years ago will both miss new danglers and flag now-fixed services. Keep the Arsenal synced with `can-i-take-over-xyz` and re-verify before reporting.

### Q41. Can a subdomain be "half dangling"?
Yes — e.g. the CNAME resolves to a provider front-end that serves a generic page, but the specific resource is claimable. Or a service that's intermittently available. Confirm with repeated checks and the exact fingerprint, not a single request.

### Q42. What's the deliverable at the end of Level 2?
A **confirmed claimable** dangling record: you know the record type, you've matched the exact provider fingerprint (with a negative control), and you've verified the exact resource is free to register in your account. Now you claim it.

---

# LEVEL 3 — EXPLOITATION BY IMPACT

### Q43. What's the core PoC?
Register the dangling resource in your own account with the exact name, bind `sub.target.com` as the custom domain, and serve a **benign, uniquely-named marker** (`/st-poc-<rand>.txt` with your handle/program/timestamp). Fetch it via `https://sub.target.com/...` → your content → confirmed takeover. Screenshot, then unpublish.

### Q44. Is a bare claimed subdomain enough to report?
It's a valid (often Medium) finding on its own — you control content on a real brand subdomain. But to move it up, chain the **trust** the hostname carries: domain cookies, OAuth/CSP/CORS membership, or NS/MX control. The chain is where High–Critical lives.

### Q45. How does a takeover become cookie theft / session ATO?
If the app sets its session cookie with `Domain=.target.com` (domain-scoped), **every** subdomain — including your taken-over one — can read/set it. Your page runs `document.cookie` (same-site) → if the cookie isn't HttpOnly, you read the victim's session → hijack → ATO.

### Q46. What if the session cookie is HttpOnly?
You can't read it with JS, but you can still **set** `.target.com` cookies from your subdomain → **session fixation** (pin a known session), CSRF-token overwrite, cache/lang/feature-flag poisoning on the main app. HttpOnly blocks the read, not the write.

### Q47. How do I check the cookie scope?
Log into the main app, inspect the session cookie's `Domain` attribute in devtools/Burp. `Domain=.target.com` (or `target.com`) = domain-scoped → your subdomain can read/set it. `Domain=app.target.com` (host-only) = only that exact host → your subdomain can't read it (lower impact).

### Q48. Walk the `NS` takeover impact.
The subdomain is delegated (NS record) to a nameserver whose domain is expired or claimable. You register it → you answer **all** DNS for `sub.target.com`. Now you can serve any A/AAAA (host anything), mint a **valid DV TLS cert** (DNS-01, since you control DNS), set MX (catch mail), and set TXT (pass SPF/domain-verification). That's owning the subdomain outright — Critical.

### Q49. Why is a valid TLS cert such a big deal?
Because `https://sub.target.com` with a real padlock is **indistinguishable from the genuine service** — no cert warning, full user and filter trust. It maximizes phishing yield and makes every cookie/OAuth chain look legitimate. NS takeover gives you cert issuance for free (you control DNS validation).

### Q50. Walk the `MX` takeover impact.
The MX points at a mail SaaS you can register that host on. You claim it → you receive email addressed to that host. If any **password-reset / verification / invite** mail is routed there, you intercept the reset token → **account takeover**. You can also send spoofed mail as the domain.

### Q51. How do I prove an MX takeover safely?
Claim the mail resource and send **yourself** a test email to that host to prove you receive it. Don't sit and collect real users' reset emails — describe the reset-interception impact and prove control with your own test message. Unpublish after.

### Q52. What's a second-order takeover via CSP?
The main app's `Content-Security-Policy: script-src ... https://sub.target.com` trusts your (now-controlled) subdomain for scripts. You host a script there → it executes on the main app, **bypassing CSP** → effectively XSS on the primary application → session theft/ATO. This is one of the highest-impact takeovers.

### Q53. What's a second-order takeover via `<script src>`?
The main app loads `<script src="https://sub.target.com/app.js">`. You claim `sub.target.com` and serve malicious JS at that path → it runs on **every page** that includes it → XSS-equivalent, supply-chain style. Critical.

### Q54. What's a second-order takeover via OAuth `redirect_uri`?
The taken-over subdomain is a registered `redirect_uri` (or matches a wildcard). You run the OAuth flow with `redirect_uri=https://sub.target.com/cb` → the victim's `code`/`token` is delivered to your host → account takeover. Hand off to the OAuth kit for the flow specifics.

### Q55. What's a second-order takeover via CORS?
The API's CORS allow-list includes `https://sub.target.com` with credentials. Your page on that subdomain reads the victim's **authenticated** cross-origin API responses (session/PII/CSRF token) → secret theft → ATO. Hand off to the CORS kit.

### Q56. How do I prove second-order script-exec benignly?
Host a benign proof script — `console.log('ST-CSP-POC: '+location.host)` or a beacon to your own server — and show it executing in the main app's origin. Don't exfiltrate real data; the execution proof is enough.

### Q57. When there's no cookie/OAuth/CSP/NS/MX chain, is it worthless?
No — it's **credential phishing on the real brand domain** (High, context-dependent). A phishing page on the genuine `sub.target.com` (ideally with a valid cert via NS) beats any look-alike domain: users and URL-reputation filters trust it. Especially strong if the subdomain historically hosted a login.

### Q58. How do I PoC the phishing angle safely?
Do **not** host a live credential-harvesting page against real users. Prove control with a benign marker and **describe** the phishing impact (real domain + valid cert + historical login host). The takeover is the finding; the phishing potential is the impact narrative.

### Q59. Which chain gives the highest severity?
NS takeover (full DNS control), MX takeover routing reset mail (ATO), domain-cookie theft (session ATO), and second-order script-exec/token-theft on the main app — all Critical/High-Critical. Bare claimed host = Low–Medium.

### Q60. Do I need a victim for these?
Cookie theft, OAuth token theft, and MX reset-interception target a victim (their session/token/mail). NS/script-exec/phishing establish the capability; some need a victim to *realize* ATO. State the precondition in the report.

### Q61. Can staging/dev/CI takeovers be high-impact?
Yes — these hosts often had privileged integrations (internal APIs, webhooks, CI secrets baked into the old resource, SSO trust). A takeover there can reach internal systems or leak secrets, punching above a typical marketing-subdomain takeover.

### Q62. How does takeover interact with the Open-Redirect kit?
A controlled `*.target.com` is a **whitelisted redirect origin** — it defeats strict "must be `*.target.com`" redirect/`redirect_uri` allow-lists that you otherwise couldn't beat. The two kits are natural chain partners (guide §14, Open-Redirect §8/§11).

### Q63. Can I get domain-scoped cookies set on `.target.com` to persist?
Yes — from your subdomain you can set a `.target.com` cookie that the main app then reads (fixation, poisoning). Persistence depends on the app's cookie handling and whether it rotates sessions on login. Test the main app's behavior.

### Q64. What's the safest "stop point" for each chain?
Cookie: read the cookie **attribute** / your own session, don't harvest real ones. NS: issue your **own** benign cert. MX: send **yourself** a test email. Script-exec: benign `console.log`/beacon. OAuth/CORS: catch **your own** token. Prove capability, don't weaponize.

### Q65. How do I demonstrate full ATO without harming users?
Use your own two accounts (or one test account as victim). For MX/OAuth, run the reset/login flow against yourself and intercept **your own** token. For cookies, read **your own** session from the taken-over host. Own-account ATO proof is accepted.

### Q66. When do I stop escalating?
Once you've proven the highest safe chain (marker served + the specific trust demonstrated benignly). Then **unpublish the claim immediately**, capture evidence, and report — asking them to remove the DNS record. Don't leave the claim live.

---

# LEVEL 4 — ADVANCED CHAINS

### Q67. Give a full takeover → mass-XSS chain.
A dead `assets.target.com` is in the main app's CSP `script-src` and loaded via `<script src>`. You confirm it's a claimable S3 bucket, claim it, and serve `app.js` → your script executes on **every** page of the main app that includes it → mass session theft / ATO across the user base. Critical, supply-chain-flavored.

### Q68. Give a full NS-takeover → phishing chain.
`portal.target.com` has a dangling `NS` to an expired nameserver domain. You register the domain, claim the zone, issue a valid DV cert (DNS-01), and stand up a look-alike login on the **real** `portal.target.com` with a valid padlock → credential harvest indistinguishable from the genuine service. Critical for red-team.

### Q69. Give a full MX-takeover → ATO chain.
`mail.target.com` (or a subdomain used for transactional mail) has a dangling `MX` to a claimable mail SaaS. You claim it, then trigger a password reset for a target account whose reset mail routes through that host → you receive the reset token → set the password → account takeover.

### Q70. How does takeover defeat a strict OAuth `redirect_uri` allow-list?
If the allow-list is `https://*.target.com/cb` (or lists a now-dead subdomain), a subdomain takeover hands you a host **inside** the allow-list. You set `redirect_uri` to your controlled subdomain → the IdP validates it (it's `*.target.com`) → the `code`/`token` comes to you → ATO. You beat the allow-list by owning something in it.

### Q71. How does takeover defeat a CSP that only allows `self` + `*.target.com`?
By giving you a `*.target.com` host you control — you host your script there, and CSP allows it because it matches `*.target.com`. The CSP was only as strong as the assumption that every `*.target.com` is trustworthy; the takeover breaks that assumption.

### Q72. What's the cookie-jar / cookie-bomb angle?
From your subdomain you can set many/large `.target.com` cookies, overflowing the browser's per-domain cookie limit → the main app's requests break (headers too large) → a denial-of-service on the victim. Lower value than ATO but a real availability impact.

### Q73. How does takeover enable authenticated email spoofing?
With NS/MX/TXT control of the subdomain, you can set SPF/DKIM/DMARC-passing records → send mail **as** `sub.target.com` that passes email authentication → highly credible spoofed/phishing mail from the real domain.

### Q74. What's a "domain fronting"-adjacent abuse?
A taken-over CDN-backed subdomain can sometimes be used to route traffic through trusted infrastructure. More relevant to red-team C2/evasion than bounty, but worth noting as an impact of controlling a trusted host.

### Q75. Can takeover chain into the Host-Header / cache kits?
Yes — a trusted subdomain you control can seed cache-poisoning or host-header chains where the subdomain is trusted for routing/caching. Cross-ref the Host-Header and WebCache kits when the taken-over host participates in shared infrastructure.

### Q76. What's the "same-site" pivot?
Your taken-over `sub.target.com` is **same-site** to the main app, which helps satisfy `SameSite=Lax` cookie conditions and same-site `fetch`/`postMessage` assumptions in a larger chain — a supporting hop that enables CSRF/token-relay that a cross-site page couldn't.

### Q77. How do continuous-monitoring pipelines matter (offense and defense)?
Whoever watches CT logs + DNS churn first **claims the dangler**. Attackers automate "new subdomain appears / resource dies → auto-claim." Defenders automate "our DNS record now returns a takeover fingerprint → alert + remove." Same pipeline, opposite intent — build it either way.

### Q78. Give the highest-value single find.
A dead subdomain that is (a) in the main app's CSP `script-src` **and** (b) a claimable S3 bucket. One claim → script execution on the entire main application → mass ATO. That combination (second-order + easy claim) is the jackpot.

---

# TOOLING

### Q79. What does `poc/subtakeover_scan.py` do?
Takes a subdomain list, resolves each record (follows CNAME chains), probes HTTP for the provider "not found" body, matches it against the fingerprint DB (`fingerprints.py`), and **ranks** candidates by claimability + record type (NS/MX first). It flags leads to verify+claim by hand — it does **not** auto-claim.

### Q80. What does `poc/fingerprints.py` do?
It's the per-service signature database: CNAME pattern + HTTP fingerprint string + `claimable?` flag + a short claim note, importable by the scanner. Keep it synced with `can-i-take-over-xyz`.

### Q81. What does `poc/claim_proof.py` do?
After you've registered the resource, it fetches `https://sub.target.com/<your-marker>` and confirms your benign proof is being served (control confirmed), and re-checks the DNS record — the evidence-capture helper for the report.

### Q82. What existing tools complement the kit?
`subfinder`/`amass`/`assetfinder` (enum), `crt.sh`/`chaos` (CT/historical), `dnsx`/`massdns`/`dig` (resolve), `subzy`/`subjack`/`nuclei -tags takeover` (fingerprint at scale), `httpx` (probe), and `can-i-take-over-xyz` (the claimability matrix).

### Q83. How do I run a fast end-to-end sweep?
`subfinder -d target.com -all -silent | dnsx -silent -cname -resp | tee resolved.txt`, then `subzy run --targets resolved.txt --hide_fails` and `python3 poc/subtakeover_scan.py -l subs.txt`. Verify claimability + claim the top candidates by hand.

### Q84. Why not just trust `subzy`/`nuclei` output?
Because they match fingerprints, not claimability — they produce leads, some stale or non-claimable. Submitting their raw "vulnerable" output is the #1 way to get closed as unconfirmed. Always confirm claimability and claim it yourself.

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q85. Give the 5-phase method in one paragraph.
**Recon** all subdomains + every record (CT logs + historical + brute) → **baseline** which dangle (provider fingerprint) and are **claimable** → **fingerprint + confirm claimability** (cross-check `can-i-take-over-xyz`, negative control) → **claim benignly + escalate the trust** (cookies/NS/MX/OAuth/CSP/CORS) → **validate & report** impact-first, **unpublish**, ask them to remove the record.

### Q86. What's the one FP that gets reports closed?
A **fingerprint you didn't claim**, or a fingerprint on a **non-claimable** service. Always claim it and serve your marker, and confirm the service is genuinely claimable before you call it a takeover.

### Q87. How do I set severity honestly?
NS/MX → Critical; domain-cookie ATO / second-order script-exec or token-theft on the main app → High–Critical; credentialed CORS read → High; brand phishing → High (context); bare claimed host → Low–Medium; fingerprint-only/non-claimable → Info. Map to CVSS, anchor on CWE-350 + the chain CWE.

### Q88. What must be in the PoC before I submit?
The `dig` output (the dangling record), the provider fingerprint (before claim), and your **benign marker served from `sub.target.com`** (screenshot) — plus the trust-chain evidence (cookie attribute / CSP entry / issued cert / test email / caught own-token). And confirmation you unpublished.

### Q89. How do I make the report actionable?
Tell them to **remove the dangling DNS record** (not just re-create the resource — a new dangler can recur), and recommend DNS-cleanup-on-decommission + inventory/monitoring + minimal exact allow-lists. Lead the title with the impact + the provider.

---

# CHEAT SHEETS

### Q90. Fastest triage shortlist?
```
dig CNAME/NS/MX sub.target.com +short
curl -sk https://sub.target.com/ | grep -iE 'NoSuchBucket|GitHub Pages site|No such app|unknown domain|Web Site not found|currently unavailable'
# match -> check can-i-take-over-xyz (claimable?) -> claim -> serve marker -> chain trust -> UNPUBLISH
```

### Q91. Top fingerprints by memory?
```
S3:      NoSuchBucket
GHPages: There isn't a GitHub Pages site here.
Heroku:  No such app
Fastly:  Fastly error: unknown domain
Azure:   404 Web Site not found
Shopify: Sorry, this shop is currently unavailable.
Surge:   project not found
```

### Q92. Impact-to-CWE map?
```
bare takeover / phishing            → CWE-350 (+ context)
domain-cookie session ATO           → CWE-384 (+350)
second-order script-exec (CSP/src)  → CWE-79 (+350)
NS/MX (DNS/mail control)            → CWE-350 (+284)
```

### Q93. Escalation-in-one-line?
Claimed the host → NS?→DNS control/certs · MX?→reset-mail intercept · `.target.com` cookies?→session ATO · in CSP/OAuth/CORS?→script-exec/token on main app · else→brand phishing.

### Q94. Safe-PoC one-liner?
Claim in your own account → serve `/st-poc-<rand>.txt` benign marker → screenshot `https://sub.target.com/<marker>` → prove trust with own cert/email/token → **UNPUBLISH** → report + "remove the DNS record."

---

# REAL-WORLD PATTERNS & REFERENCES

### Q95. What are the classic real-world takeover patterns?
A marketing team spins up a Heroku/Shopify/GitHub-Pages site, points a CNAME at it, then kills the service without removing DNS; a decommissioned S3 static site left in DNS; an expired nameserver domain (NS takeover); a transactional-mail subdomain with a dangling MX; and a dead `assets`/`cdn` subdomain still in the main app's CSP/`<script src>` (second-order).

### Q96. Which references should I actually read?
`can-i-take-over-xyz` (the claimability matrix — read it fully), Detectify's *Hostile subdomain takeover* series (Frans Rosén), OWASP WSTG *Test for Subdomain Takeover*, and disclosed HackerOne reports for "subdomain takeover to account takeover" and "subdomain takeover CSP".

### Q97. Best disclosed-report search terms?
`subdomain takeover`, `NS takeover`, `MX takeover reset`, `subdomain takeover to account takeover`, `subdomain takeover CSP script-src`, `dangling CNAME`, `second-order subdomain takeover`.

---

# DEFENSE — PREVENTING TAKEOVER

### Q98. What's the single best fix?
**Remove the DNS record the moment a service/resource is decommissioned** — make DNS cleanup a mandatory step of de-provisioning. A subdomain takeover is impossible if no dangling record exists.

### Q99. How do I catch danglers I already have?
Maintain an **inventory of all DNS records** mapped to live resources, and run **continuous monitoring** that resolves every record and flags any that return a takeover fingerprint / NXDOMAIN / SERVFAIL. Diff CT logs + DNS daily and alert.

### Q100. How do I reduce the blast radius even if a takeover happens?
Scope cookies **host-only** (not `.target.com`) where feasible so a subdomain can't read the main session; keep OAuth `redirect_uri`, CSP `script-src`, and CORS allow-lists **exact and minimal** (avoid broad `*.target.com`) so a taken-over subdomain doesn't hand over the main app; and don't route reset/verification mail through decommissionable subdomains.

### Q101. Are there provider-side mitigations?
Prefer resources that **bind to your account** (so an arbitrary third party can't re-register the name), use provider domain-verification for custom domains, and for critical hosts avoid CNAMEs into shared third-party namespaces where a name can be silently claimed.

### Q102. What's the residual risk after fixing one record?
Recurrence — a new service+CNAME can re-dangle next quarter. And second-order trust: even after removing a record, audit that no CSP/CORS/OAuth/`<script src>` still references a host you no longer control. Takeover defense is a **continuous** inventory-and-monitoring discipline, not a one-time cleanup.

---

> **The one rule that pays:** a dangling DNS record is a fingerprint; a subdomain takeover is a **claim**. Confirm the
> service is genuinely **claimable**, register the dead resource, serve a **benign marker** from `sub.target.com`, and
> then chain the **trust** the hostname carries — domain cookies (session ATO), NS/MX (DNS control + reset-mail
> interception), or an OAuth/CSP/CORS/`<script src>` entry (token theft / script-exec on the main app). Prove it benignly,
> **unpublish immediately**, and tell them to **remove the record**.
