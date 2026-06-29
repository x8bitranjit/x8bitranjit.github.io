# LDAP-Injection Testing Checklist — tick per sink

> Companion to `LDAP_INJECTION_TESTING_GUIDE.md`. The finding is **altered filter logic with impact** (auth bypass /
> disclosure / blind extraction), not a reflected `*` or a lone 500. Work top-to-bottom **per LDAP sink**; stop and
> report only when you've proven the directory's answer changed in your favor.

## PHASE 0 — Recon & fingerprint (§3/§1)
- [ ] Found every LDAP-backed feature: **login** (corporate/SSO/VPN/appliance), **search/directory** ("find people/employees"), **group/role checks**, "forgot username/account", signup uniqueness checks.
- [ ] Grepped source/JS for `ldap_search`/`DirContext.search`/`DirectorySearcher`/`search_filter`/`ldapjs`.
- [ ] **Fingerprinted the backend:** Active Directory (`sAMAccountName`/`memberOf`/`DC=…`/`DSID` errors) vs OpenLDAP/389/etc (`uid`/`cn`/`inetOrgPerson`/`javax.naming` errors).
- [ ] **Second-order:** flagged stored profile fields (`displayName`/`description`/group name) later consumed by an admin search/sync.

## PHASE 1 — Baseline / classify (§4)
- [ ] Sent a **normal value**, then a single **`*`**, then a single **`(`** — recorded result-count / error / auth result / response length.
- [ ] Classified observability: **DATA-REFLECTED** (search results shown) / **AUTH-ORACLE** (login) / **ERROR-BASED** / **BLIND**.
- [ ] Determined **context**: AND `(&(fixed)(x=INPUT))` vs OR `(|(fixed)(x=INPUT))`; **filter** vs **DN**.
- [ ] Checked whether `*`/`(`/`)`/`\` are **escaped** (e.g. `\2a` shows in errors) → if so, plan DN/second-order/WAF-evasion.

## PHASE 2 — Detect (§5–§8)
- [ ] Special-char probes `* ( ) & | ! \ = %00` (each alone) → looked for result-count change / LDAP error / auth diff.
- [ ] Proved **logic change** (not reflection): `q=*)(objectClass=*)` returns the whole tree vs 1 row for a specific value.
- [ ] Determined **AND vs OR** breakout (§6): does `*)(objectClass=*)` widen? does `)(|(…` work (tolerant) or error (strict)?
- [ ] **Error-based** (§7): triggered an LDAP error with `(`/`\`; captured backend + base DN from the message.
- [ ] **Blind oracle** (§8): `…)(uid=alice)` vs `…)(uid=nobody999)` give a **stable, repeatable** different response.

## PHASE 3 — Impact (§9–§15)
- [ ] **Auth bypass (§9):** `admin)(&)` / `*)(uid=*))(|(uid=*` logs in → noted **which account** (admin → Critical).
- [ ] **Disclosure (§10):** `q=*)(objectClass=*)` → quantified extra entries; matched hidden attrs (`)(memberOf=*`, `)(userPassword=*`).
- [ ] **Authz/privesc (§11):** forced a group/role check always-true (`)(memberOf=*`, `)(&)`) → reached an admin-only feature.
- [ ] **Blind extraction (§12):** read a **few benign chars** of a benign attribute (your test user's `mail`/`objectClass`) via the oracle.
- [ ] **DN injection (§13):** if filter-escaped, tested DN metachars (`,` `+` `=` `\`) → changed OU/scope.
- [ ] **AD chains (§15, authorized):** enumerated non-preauth (`userAccountControl & 0x400000`) / SPN accounts as proof.
- [ ] Used **your own test account(s)**; **bounded** every read; **no** mass directory dump.

## PHASE 4 — Evade WAF/filter (§14)
- [ ] `*` blocked → `%2a` / `%252a` (double) / hex `\2a`.
- [ ] `(`/`)` blocked → encode (`%28`/`%29`) or use **absolute-true `(&)`** (needs only `&`).
- [ ] Trailing clauses block exploitation → **`%00`** truncation (C-backed servers).
- [ ] Attribute keyword blocked → alias/swap (`cn`/`objectCategory` instead of `objectClass`), AD case-insensitivity.

## PHASE 5 — Validate → report
- [ ] Proved the **directory's answer changed** (rows / auth result / stable oracle) — FP check §17.
- [ ] Re-tested blind oracles a few times to exclude noise/caching; tied the change to my specific payload.
- [ ] Confirmed any "extra rows" exceed the **intended** wildcard-search scope (not a legitimate feature).
- [ ] Confirmed on **production**; re-tested partial fixes (`*` escaped but not `(`/`)`; filter-escaped but DN-injectable).
- [ ] Set CVSS 3.1 + **CWE-90** (+ **CWE-287** auth-bypass / **CWE-285** authz) (§18).
- [ ] De-duped to one finding per sink; led with the highest impact (auth bypass over disclosure on the same filter) (§21).

## AUTO-REJECT (don't submit if…)
- [ ] A `*` merely **reflected** in the response (no change in which entries match).
- [ ] A **lone 500 / LDAP error** with no subsequent logic change (error-based is a *lead*, not the finding).
- [ ] A **built-in wildcard search** behaving as designed (you didn't exceed intended scope).
- [ ] **Username enumeration via error-message differences** (separate, lower bug — not filter injection).
- [ ] A **single** noisy response-length blip (could be caching/jitter — re-test for a stable oracle).
- [ ] A `${jndi:ldap://…}` callback (that's **Log4Shell/JNDI** RCE — report as its own bug).
- [ ] "Logged in with `*`" but it's a demo/guest account (not a real bypass).
- [ ] Self-DoS via a giant wildcard / malformed filter instead of a bounded, benign query.
