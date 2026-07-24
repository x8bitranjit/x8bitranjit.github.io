# Subdomain Takeover — Checklist

Expert per-attack **test-case matrix** for Subdomain Takeover — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*9 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SUBTKO-001 — Enumerate subs + resolve every record + trust context
**Test Category:** Recon · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** CNAME/A/AAAA/NS/MX/TXT per subdomain; CT logs; historical subs

**Test Steps:** 1. Passive enum (subfinder/amass/assetfinder + crt.sh + chaos/GitHub); pull HISTORICAL subs (dead hosts in CT are prime).<br>2. Resolve EVERY record type per sub (dnsx -a -cname -ns -resp); follow CNAME chains to the end (danglers hide at the tail).<br>3. Note trust context: is any sub referenced in the main app's JS/CSP/CORS/OAuth config (second-order)? Confirm each is the target's OWN sub (in scope).

**Expected Result:** A subdomain list with all records resolved and trust context flagged.

**Payload Example:**

```
subfinder -d $TARGET ; crt.sh %.$TARGET ; dig CNAME/NS/MX $SUB
```

**Impact:** Historical/CT dead hosts and NS/MX danglers are the highest-value and most-missed.

**Tools:** subfinder, amass, crt.sh, dnsx

**References:** CWE-350; OWASP: Subdomain Takeover

---

## SUBTKO-002 — Identify dangling / claimable records
**Test Category:** Baseline · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each subdomain's records

**Test Steps:** 1. Identify dangling records: provider 'not found' fingerprint / NXDOMAIN / SERVFAIL.<br>2. Filter to CLAIMABLE services (cross-check can-i-take-over-xyz).<br>3. Flag NS (DNS control) and MX (email interception) danglers as top-priority.

**Expected Result:** A list of dangling records classified by claimable service and record type.

**Payload Example:**

```
CNAME -> *.github.io 'There isn't a GitHub Pages site here.' ; NS dangling; MX dangling
```

**Impact:** The record type (CNAME/A/NS/MX) decides the ceiling; NS/MX are Critical.

**Tools:** subzy, subjack, nuclei -tags takeover

**References:** CWE-350; can-i-take-over-xyz (EdOverflow)

---

## SUBTKO-003 — Fingerprint service + confirm claimability
**Test Category:** Detect / Confirm · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Dangling CNAME/A candidates

**Test Steps:** 1. Fingerprint the service: exact provider 'not found' body, served by the provider (Server/Via/X-Served-By), with a NEGATIVE control vs a live sub.<br>2. Confirm claimability: the exact bucket/app/page/name is free to create in your account; no domain-verification block.<br>3. Cross-check can-i-take-over-xyz (providers change policy).

**Expected Result:** The exact resource is confirmed free to register in your account.

**Payload Example:**

```
S3 'NoSuchBucket' + bucket name globally free ; verify vs can-i-take-over-xyz
```

**Impact:** A fingerprint is a lead; confirmed claimability is the finding.

**Tools:** can-i-take-over-xyz, subzy

**References:** CWE-350; can-i-take-over-xyz (EdOverflow)

---

## SUBTKO-004 — Claim the resource + serve a benign marker
**Test Category:** Impact — Claim · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Confirmed-claimable CNAME/A dangling record

**Test Steps:** 1. Claim the resource in YOUR OWN account (e.g. create the S3 bucket / GitHub Pages repo + custom domain).<br>2. Serve a benign, unique marker: https://$SUB/&lt;marker&gt; returns YOUR content (screenshot + dig).<br>3. This proves control; then chain the trust; then UNPUBLISH.

**Expected Result:** https://$SUB/&lt;marker&gt; serves your content (proven claim).

**Payload Example:**

```
create bucket named after $SUB -> https://$SUB/x8bit-marker returns my page
```

**Impact:** Control of a target subdomain - Low/Medium alone; escalates via the trust chain.

**Tools:** aws cli / gh pages, dig

**References:** CWE-350; HackTricks: Domain/Subdomain takeover

---

## SUBTKO-005 — Cookie / session ATO (Domain=.target.com)
**Test Category:** Impact — ATO · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session cookie scoped Domain=.target.com

**Test Steps:** 1. If the session cookie is Domain=.$TARGET, your claimed sub page reads it (if not HttpOnly) or SETS it (fixation).<br>2. Read -&gt; session hijack; set -&gt; session fixation.<br>3. Confirm cross-scope on your own session.

**Expected Result:** The claimed subdomain reads or sets the domain-scoped session cookie.

**Payload Example:**

```
cookie Domain=.$TARGET -> my $SUB page reads document.cookie / sets a fixed session
```

**Impact:** Session hijack / fixation -&gt; account takeover - High/Critical.

**Tools:** browser

**References:** CWE-350; CWE-384; HackTricks: Domain/Subdomain takeover

---

## SUBTKO-006 — NS / MX takeover (DNS control / email interception)
**Test Category:** Impact — NS/MX · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dangling NS or MX records

**Test Steps:** 1. NS: the nameserver's base domain is expired/claimable -&gt; claim it -&gt; full DNS control of $SUB (A/MX/TXT + DV TLS via DNS-01).<br>2. MX: mail routed to a SaaS where you can register that host -&gt; receive its email -&gt; intercept password-reset/verification mail -&gt; ATO.<br>3. Benign proof (own DV cert / test email), then unpublish.

**Expected Result:** You control all DNS for the sub (NS) or receive its email (MX).

**Payload Example:**

```
NS base domain registerable -> serve all DNS for $SUB ; MX -> receive reset email -> ATO
```

**Impact:** Full DNS control / reset-mail interception -&gt; ATO - Critical.

**Tools:** dig, registrar

**References:** CWE-350; CWE-640; HackTricks: Domain/Subdomain takeover

---

## SUBTKO-007 — Second-order takeover (OAuth / CSP / CORS / &lt;script src&gt;)
**Test Category:** Impact — Second-Order · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** A claimed sub referenced in main-app OAuth redirect_uri / CSP script-src / &lt;script src&gt; / CORS allow-list

**Test Steps:** 1. If the claimed host is in an OAuth redirect_uri -&gt; catch the code/token on the MAIN app.<br>2. In CSP script-src / &lt;script src&gt; -&gt; serve JS that runs ON the main app (stored-XSS-equivalent).<br>3. In a CORS allow-list -&gt; credentialed cross-origin reads. Brand phishing via a claimed brand sub + valid TLS.

**Expected Result:** The claimed sub is trusted by the main app for tokens/scripts/CORS.

**Payload Example:**

```
$SUB in CSP script-src -> host malicious.js -> executes on $TARGET ; in redirect_uri -> token theft
```

**Impact:** Script-exec on the main app / token theft / credentialed reads - Critical.

**Tools:** browser, OAuth/CORS kits

**References:** CWE-350; CWE-79; HackTricks: Domain/Subdomain takeover

---

## SUBTKO-008 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: a fingerprint ONLY (you didn't claim + serve a marker); a service on the NON-claimable list; a generic 404 with no provider signature; a dangling record on a THIRD-PARTY domain (out of scope); a claimed host but cookies are host-only (Domain=app.x) reported as ATO without the domain-cookie chain; 'NXDOMAIN so takeover-able' without confirming registrability; a bare takeover with no impact narrative reported as Critical (Low-Medium alone).<br>2. REQUIRE: the claim (marker served) + the trust chain.

**Expected Result:** Only claimed + trust-chained candidates rate above Low.

**Payload Example:**

```
fingerprint-only = lead ; non-claimable = Info ; bare claim w/o trust = Low-Medium
```

**Impact:** Protects credibility; takeover is dense with fingerprint-only over-rated reports.

**Tools:** manual

**References:** CWE-350; can-i-take-over-xyz (EdOverflow)

---

## SUBTKO-009 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the highest-impact chain (NS/MX/second-order/cookie ATO &gt; brand phishing &gt; bare claim).<br>2. Provide the claim proof (marker + dig) AND the trust chain (which cookie/CSP/redirect_uri/CORS trusts it).<br>3. Set CVSS 3.1 + CWE-350 (+384/79/284 by outcome). Remediation: REMOVE the dangling DNS record (not just re-create the resource); adopt a decommissioning process; monitor CT/DNS.<br>4. Benign PoC, UNPUBLISH the claim after evidence, own accounts/cert/test email; de-dupe (one dangling record = one finding).

**Expected Result:** A reproducible, correctly-rated PoC with claim + trust chain and clear remediation.

**Payload Example:**

```
PoC: marker + dig (claim) + trust chain (cookie/CSP/redirect_uri) + CVSS + CWE-350 + 'remove the DNS record'.
```

**Impact:** Converts the claim + trust into a defensible High/Critical report.

**Tools:** CVSS calculator, SUBDOMAIN_TAKEOVER_REPORT_TEMPLATE.md

**References:** CWE-350; FIRST CVSS v3.1; OWASP: Subdomain Takeover  |  TOP REFERENCES: EdOverflow can-i-take-over-xyz; Frans Rosen/Detectify subdomain-takeover research; HackTricks; Patrik Hudak writeups

---
