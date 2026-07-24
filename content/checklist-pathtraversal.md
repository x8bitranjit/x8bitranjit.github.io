# Path / Directory Traversal — Checklist

Expert per-attack **test-case matrix** for Path / Directory Traversal — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*13 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## PT-001 — Find READ/serve, static, archive &amp; write sinks
**Test Category:** Recon · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** download/export/attachment/view/avatar/PDF/backup; /static /assets; ZIP-import/restore; upload dest/save/log path

**Test Steps:** 1. Find READ/serve sinks (download/export/attachment/view/preview/avatar/PDF/backup).<br>2. Static routing (/static,/assets,/files,/media) for server-normalization; archive-extract sinks (ZIP import/restore/theme install) = Zip-Slip (top priority); upload filename/dest and save/export/log-path sinks.<br>3. Discover hidden file/path/name/dest/save params (Arjun); note absolute-path leaks in errors.

**Expected Result:** A list of read/serve/static/archive/write path sinks and any leaked base dir.

**Payload Example:**

```
?file= /download /static/<x> ZIP import ; upload filename ; error leaks base dir + OS
```

**Impact:** Archive-extract (Zip-Slip) and static-normalization sinks are the highest-value.

**Tools:** Burp, Arjun, Param Miner

**References:** CWE-22; OWASP Testing Guide: Path Traversal (WSTG-ATHZ-01)

---

## PT-002 — Baseline &amp; classify the sink (send ../ raw)
**Test Category:** Baseline · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each path sink

**Test Steps:** 1. Confirm the value IS the path (same-dir control vs traversal changes the response).<br>2. Send ../ RAW (curl --path-as-is / Burp), not collapsed client-side.<br>3. Classify: READ/serve / WRITE / INCLUDE-EXECUTE (-&gt; LFI kit) / absolute-path accepted (skip depth).

**Expected Result:** The sink is classified and ../ confirmed to be sent raw.

**Payload Example:**

```
curl --path-as-is $URL/download?file=../../../../etc/passwd ; classify READ vs WRITE
```

**Impact:** An include/execute sink is an LFI/RFI report, not this - classify first.

**Tools:** curl --path-as-is, Burp

**References:** CWE-22; PortSwigger Web Security Academy: File path traversal

---

## PT-003 — Read traversal — escape the base dir
**Test Category:** Read Traversal · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** READ/serve sinks

**Test Steps:** 1. Varying-depth ../, over-traverse, absolute path (/etc/passwd - CWE-36), ....// (strip-reform), Windows ..\.<br>2. file:///etc/passwd.<br>3. Confirm out-of-dir contents returned.

**Expected Result:** A file outside the base dir is served.

**Payload Example:**

```
../../../../etc/passwd ; /etc/passwd ; ....//....//etc/passwd ; ..\..\windows\win.ini
```

**Impact:** Out-of-dir read (Medium until escalated to secrets/cross-user).

**Tools:** curl --path-as-is

**References:** CWE-22; CWE-36; PortSwigger Web Security Academy: File path traversal

---

## PT-004 — Encoding &amp; filter bypass
**Test Category:** Read Traversal · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Sinks filtering ../

**Test Steps:** 1. ..%2f (url), %252e%252e%252f (double - beats decode-once/WAF), ..%c0%af (overlong UTF-8), unicode fullwidth %uff0e, ..%00 (legacy null).<br>2. ..;/ (Java/Tomcat segment), ....// (strip-and-reform).<br>3. Find the one that lands.

**Expected Result:** Traversal succeeds despite ../ filtering.

**Payload Example:**

```
..%252f..%252f..%252fetc%252fpasswd ; %uff0e%uff0e%u2215etc%u2215passwd
```

**Impact:** Bypasses naive traversal filters.

**Tools:** Burp Intruder

**References:** CWE-22; HackTricks: Path Traversal

---

## PT-005 — Prefix / suffix / allowlist bypass
**Test Category:** Read Traversal · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Sinks with base-dir prefix / forced suffix / allowed name

**Test Steps:** 1. Forced base dir prepended -&gt; just climb out.<br>2. Forced suffix appended -&gt; ../../etc/passwd%00.png (legacy) / target a file already ending in the suffix (../../../var/log/app.log if .log).<br>3. Allowlist 'must contain allowed name' -&gt; allowed.txt/../../../../etc/passwd.

**Expected Result:** The prefix/suffix/allowlist is satisfied and traversal still escapes.

**Payload Example:**

```
/base/../../../../etc/passwd ; allowed.txt/../../../etc/passwd ; passwd%00.png
```

**Impact:** Bypasses prefix/suffix/allowlist controls.

**Tools:** Burp Repeater

**References:** CWE-22; CWE-23; HackTricks: Path Traversal

---

## PT-006 — Server / framework normalization
**Test Category:** Server Normalization · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** /static, /assets, proxies (nginx/Tomcat/IIS)

**Test Steps:** 1. nginx alias off-by-slash: /static../../etc/passwd (location missing trailing slash).<br>2. Tomcat/Java semicolon: /app/..;/..;/WEB-INF/web.xml.<br>3. Encoded slash not decoded by proxy but by app: /api/%2e%2e%2f%2e%2e%2fWEB-INF/web.xml. Also /static../.git/config, /static../.env.

**Expected Result:** A server/proxy normalization flaw escapes the served dir.

**Payload Example:**

```
/static../../../etc/passwd (nginx alias) ; /..;/..;/WEB-INF/web.xml (Tomcat)
```

**Impact:** Source/config disclosure via infra normalization - High.

**Tools:** Burp

**References:** CWE-22; HackTricks: Path Traversal

---

## PT-007 — Language foot-gun — absolute path
**Test Category:** Read Traversal · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Python os.path.join / .NET Path.Combine / Java sinks

**Test Steps:** 1. A plain ABSOLUTE path often wins: os.path.join(base, '/etc/passwd') discards base in Python; Path.Combine likewise in .NET.<br>2. No ../ needed.<br>3. Test /etc/passwd and C:\Windows\win.ini directly.

**Expected Result:** An absolute path bypasses the base-dir join entirely.

**Payload Example:**

```
file=/etc/passwd (Python os.path.join discards base) ; file=C:\Windows\win.ini (.NET)
```

**Impact:** Trivial traversal via language path-join semantics - Medium/High.

**Tools:** curl --path-as-is

**References:** CWE-22; CWE-36; HackTricks: Path Traversal

---

## PT-008 — READ -&gt; secrets / source disclosure
**Test Category:** Impact — Read · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Confirmed out-of-dir read

**Test Steps:** 1. Climb from /etc/passwd to value: .env, config, keys, cloud-creds, source, /proc/self/environ, k8s token.<br>2. Windows: web.config, appsettings.json, .aspx source via ::$DATA.<br>3. Pivot the creds (SSRF/JWT); redact.

**Expected Result:** Secrets/source/cloud-creds are read from outside the base dir.

**Payload Example:**

```
.env ; ~/.aws/credentials ; /static../.git/config ; web.config
```

**Impact:** Secret/source disclosure -&gt; further compromise. High/Critical.

**Tools:** curl

**References:** CWE-22; CWE-73; HackTricks: Path Traversal

---

## PT-009 — READ -&gt; other users' / cross-tenant files
**Test Category:** Impact — Read · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Per-user/tenant file-serving sinks

**Test Steps:** 1. Traverse/swap to another (your OWN second) account's files / session-token files.<br>2. Confirm PII / session-token read -&gt; ATO.<br>3. Own second account as victim.

**Expected Result:** Another user's/tenant's private file is read.

**Payload Example:**

```
download?file=../<victim_id>/statement.pdf ; ../sessions/sess_<victim>
```

**Impact:** Cross-user PII / session-token read -&gt; ATO. High/Critical.

**Tools:** Burp Repeater

**References:** CWE-22; CWE-639; HackTricks: Path Traversal

---

## PT-010 — WRITE -&gt; Zip-Slip archive extraction
**Test Category:** Impact — Write · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Archive-extract sinks (ZIP/TAR import/restore/theme install)

**Test Steps:** 1. Craft an entry path that traverses out: ../../../../var/www/html/poc.php.<br>2. Extraction writes the benign marker OUTSIDE the extraction dir (show the path).<br>3. Webshell-in-webroot escalation described (FileUpload kit for executability).

**Expected Result:** Extraction writes a file outside the intended directory via a traversal entry.

**Payload Example:**

```
zip entry: ../../../../var/www/html/poc.php (benign marker) -> lands in webroot
```

**Impact:** Out-of-dir write -&gt; webshell/RCE. Critical.

**Tools:** poc/make_zipslip.py

**References:** CWE-22; CWE-434; HackTricks: Path Traversal

---

## PT-011 — WRITE -&gt; upload-path / save / export
**Test Category:** Impact — Write · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** upload filename/dest, save/export/log path sinks

**Test Steps:** 1. ../ in the filename/dest writes to webroot / overwrites a served file.<br>2. save/export overwrite (benign proof) of ~/.ssh/authorized_keys / cron / config location -&gt; RCE/persistence described.<br>3. Benign markers to safe paths only; never overwrite real files.

**Expected Result:** A write escapes the intended dir to a webroot/system path.

**Payload Example:**

```
filename=../../../../var/www/html/x.php ; export path=../../../home/user/.ssh/authorized_keys
```

**Impact:** Out-of-dir write -&gt; RCE/persistence. Critical.

**Tools:** Burp, FileUpload kit

**References:** CWE-22; CWE-59; HackTricks: Path Traversal

---

## PT-012 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: ../ changed the response but stayed INSIDE the base dir (no escape); /etc/passwd read reported as Critical (it's Medium - climb to secrets); ../ collapsed client-side (use --path-as-is); 'Zip-Slip' with no proof a file landed OUTSIDE; a write only inside your own upload dir; reading a file the app is supposed to serve; an include/execute sink (-&gt; LFI/RFI).<br>2. REQUIRE: out-of-dir escape + impact.

**Expected Result:** Only genuine out-of-dir escape with impact survives.

**Payload Example:**

```
in-base-dir change = not traversal ; passwd-only = Medium ; client-collapsed ../ = invalid
```

**Impact:** Protects credibility; traversal is dense with in-base-dir / passwd-only false positives.

**Tools:** manual

**References:** CWE-22; PortSwigger Web Security Academy: File path traversal

---

## PT-013 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact (out-of-dir write-&gt;RCE &gt; secret/cross-user read).<br>2. Provide the raw-../ request, the out-of-dir file contents (redacted) or the written marker's path, and the sink type.<br>3. Set CVSS 3.1 + CWE-22 (+36/23/434/59/73 by variant). Remediation: canonicalize and confine to a base dir (realpath prefix check), map user input to fixed identifiers, validate archive entry paths, never build paths by concatenation.<br>4. Read only enough (redact), write only benign markers to safe paths, no real file overwritten; de-dupe (read vs write separate; include/execute -&gt; LFI).

**Expected Result:** A reproducible, correctly-rated PoC with clear remediation.

**Payload Example:**

```
PoC: raw-../ request + out-of-dir contents/marker path + CVSS + CWE-22 + remediation.
```

**Impact:** Converts the escape+impact into a defensible High/Critical report.

**Tools:** CVSS calculator, PATH_TRAVERSAL_REPORT_TEMPLATE.md

**References:** CWE-22; CWE-36; FIRST CVSS v3.1; OWASP Testing Guide: Path Traversal (WSTG-ATHZ-01)  |  TOP REFERENCES: Orange Tsai reverse-proxy/path-confusion research (BlackHat); PortSwigger Academy; PayloadsAllTheThings; HackTricks; Snyk Zip Slip

---
