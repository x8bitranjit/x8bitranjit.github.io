# Dependency Confusion — Checklist

Expert per-attack **test-case matrix** for Dependency Confusion — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*9 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## DEPCONF-001 — Harvest internal package names
**Test Category:** Recon · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** manifests (package.json/requirements.txt/composer.json/pom.xml/*.csproj), JS bundles/source maps, committed .npmrc/pip.conf

**Test Steps:** 1. Collect manifests exposed on the web / public repos / wayback.<br>2. Extract names from JS bundles / source maps (@scope/..., require(...)).<br>3. Find committed registry configs (.npmrc/pip.conf/nuget.config) PROVING private packages exist.<br>4. Classify names: scoped-unreserved / org-specific unscoped / internal - exclude well-known public packages.

**Expected Result:** A candidate list of internal package names (and proof a private store exists).

**Payload Example:**

```
grep '@acme/' package.json ; .npmrc: @acme:registry=https://npm.internal.acme.com/
```

**Impact:** You can't claim a name you've never seen; a committed .npmrc is a jackpot.

**Tools:** gau, GitHub dorks, jsluice

**References:** CWE-829; OWASP: Software Supply Chain Security

---

## DEPCONF-002 — Claimability check (public-registry 404 = unclaimed)
**Test Category:** Claimability · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each candidate name on npm/PyPI/RubyGems/NuGet

**Test Steps:** 1. Public-registry lookup: 404 = UNCLAIMED = you can claim it (read-only, safe at scale).<br>2. Check npm SCOPE reservation (@acme unreserved -&gt; ALL its scoped names confusable).<br>3. Confirm the target's resolver can reach the public registry (config evidence).

**Expected Result:** A name returns 404 on the public registry (claimable), ideally an unreserved scope.

**Payload Example:**

```
curl -o/dev/null -w '%{http_code}' https://registry.npmjs.org/@acme/config -> 404
```

**Impact:** Most of the bug's value is confirmed here read-only; an unreserved scope multiplies it.

**Tools:** poc/claimable_check.py, curl

**References:** CWE-829; HackTricks: Dependency Confusion

---

## DEPCONF-003 — Resolution — will the public copy win?
**Test Category:** Resolution · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The target's install tooling / registry policy

**Test Steps:** 1. Identify why the public copy would win: highest-version-wins / public-primary / pip --extra-index-url (highest across stores) / Artifactory-Nexus virtual-repo merge preferring remote.<br>2. Note lockfile/npm ci/--require-hashes status (pinned deps resist; unpinned/transitive still exposed).

**Expected Result:** A resolution path is identified where a high public version is preferred.

**Payload Example:**

```
publish version 99.99.99 -> highest-version-wins picks yours ; pip --extra-index-url
```

**Impact:** Claimable != exploitable; the tooling must actually choose your copy.

**Tools:** config review

**References:** CWE-829; Alex Birsan: Dependency Confusion (2021)

---

## DEPCONF-004 — Safe proof — benign beacon package + callback
**Test Category:** Impact — Proof · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** An authorized name in YOUR scope only

**Test Steps:** 1. Generate a BENIGN beacon package (install hook: preinstall/setup.py) that does exactly ONE thing: a DNS/HTTP callback to your OOB with a token + hostname. Nothing else.<br>2. Version pinned HIGH (99.99.99); publish for a name in YOUR scope only.<br>3. Callback received from the TARGET's build/CI/dev egress carrying your token = the proof. UNPUBLISH/yank immediately; correlate the source to the target (CI/corp ASN), not your machine/a scanner.

**Expected Result:** A callback arrives from the target's build carrying your unique token.

**Payload Example:**

```
package.json preinstall: node beacon.js -> DNS $token.$COLLAB from target CI
```

**Impact:** RCE in the target's CI/CD build pipeline - Critical.

**Tools:** poc/benign_callback_pkg.py, interactsh

**References:** CWE-829; CWE-494; Alex Birsan: Dependency Confusion (2021)

---

## DEPCONF-005 — Related supply-chain — repo-jacking / typosquat
**Test Category:** Supply-Chain Variants · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** go.mod / import URLs referencing deleted GitHub users; typo neighbours of real deps

**Test Steps:** 1. Repo-jacking: go.mod / import URL references a DELETED/renamed GitHub user -&gt; register it (namespaced ecosystems like Go where classic confusion doesn't apply).<br>2. Typosquat neighbours of real deps (benign proof).<br>3. Understand the install-hook path (where code exec fires); consider transitive internal deps.

**Expected Result:** A deleted-username import or typo neighbour is registrable and would be pulled.

**Payload Example:**

```
go.mod: github.com/deleted-user/lib -> register deleted-user -> serve the module
```

**Impact:** Supply-chain RCE via repo-jacking (high-value, easily missed) - Critical.

**Tools:** manual, GitHub

**References:** CWE-829; CWE-427; HackTricks: Dependency Confusion

---

## DEPCONF-006 — Impact — RCE in CI/CD (described, not exfiltrated)
**Test Category:** Impact · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** A confirmed build-time callback

**Test Steps:** 1. Establish the callback = RCE in CI/CD (or a dev machine).<br>2. DESCRIBE (do not exfiltrate) the reachable secrets (cloud/signing/CI keys, source) and downstream propagation to customers.<br>3. Never actually take the secrets.

**Expected Result:** The callback is shown to run inside the build pipeline holding keys/source.

**Payload Example:**

```
callback from CI runner -> describe reachable AWS/signing keys (not taken)
```

**Impact:** Critical CI/CD RCE with downstream supply-chain reach - Critical.

**Tools:** manual

**References:** CWE-829; Alex Birsan: Dependency Confusion (2021)

---

## DEPCONF-007 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: an internal name REFERENCED but already public / unclaimable; you PUBLISHED but got NO callback (no proof of a pull); a callback from YOUR machine / a scanner (not the target's build egress); everything lockfile-pinned with hashes + npm ci (no unpinned/transitive path); a full-path Go/Cargo namespaced module (that's repo-jacking - file as such).<br>2. REQUIRE: claimable (public 404) + a token-correlated callback from the target's build.

**Expected Result:** Only claimable + target-build-callback candidates survive.

**Payload Example:**

```
name already public = FP ; no callback = lead not finding ; own-machine callback = FP
```

**Impact:** Protects credibility; a lead (could claim) is not the finding (their build ran it).

**Tools:** manual

**References:** CWE-829; Alex Birsan: Dependency Confusion (2021)

---

## DEPCONF-008 — Client-facing impact &amp; responsible-disclosure package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact: RCE in the build pipeline (cloud/signing keys + customer shipment).<br>2. Provide the claimability proof (public 404), the token-correlated callback from the target's build, and the publish-&gt;unpublish window.<br>3. Set CVSS (9-10 CI RCE) + CWE-829 (+427/494). Remediation: reserve the name/scope on the public registry, pin + hash all deps (npm ci/--require-hashes), scope-lock the private registry, verify source of every package.<br>4. Benign beacon only, UNPUBLISHED, reported fast; de-dupe to one resolution root cause (e.g. unreserved scope), list the confusable names.

**Expected Result:** A reproducible, correctly-rated, responsibly-disclosed PoC with clear remediation.

**Payload Example:**

```
PoC: public 404 + target-build callback (token) + unpublish window + CVSS 9-10 + CWE-829 + reserve-the-name.
```

**Impact:** Converts the callback into a defensible Critical CI/CD-RCE report.

**Tools:** CVSS calculator, DEPENDENCY_CONFUSION_REPORT_TEMPLATE.md

**References:** CWE-829; CWE-494; FIRST CVSS v3.1; OWASP: Software Supply Chain Security  |  TOP REFERENCES: Alex Birsan 'Dependency Confusion' (2021); Assetnote supply-chain research; PortSwigger; OWASP supply-chain

---

## DEPCONF-009 — SBOM / component inventory &amp; n-day reachability mapping (A03:2025)
**Test Category:** Recon · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Client + server component fingerprinting for the software supply chain

**Test Steps:** 1. Build a component inventory (SBOM): server headers, framework tells, JS lib versions (retire.js), leaked package manifests (.npmrc/package-lock/pip.conf)<br>2. Map each component+version to known CVEs<br>3. Verify in-context reachability (don't just report a version banner)<br>4. Route reachable RCE classes to the right kit (Log4Shell-&gt;JNDI, gadgets-&gt;Deserialization, front-end libs-&gt;XSS/PP)

**Expected Result:** SBOM maintained; components patched/pinned with integrity/provenance; unused deps removed

**Payload Example:**

```
retire.js on all JS  |  grep package-lock.json for versions  |  map to CVE -> reachability proof
```

**Impact:** Outdated/vulnerable component inventory -&gt; ready-made n-day exploit (often RCE)

**Tools:** retire.js, Syft/Grype (SBOM), OWASP Dependency-Check, Recon kit

**References:** CWE-1104; CWE-1395; -&gt;[Dependency Confusion checklist](#/checklist/depconfusion); OWASP Top 10:2025 A03 (Software Supply Chain Failures)

---
