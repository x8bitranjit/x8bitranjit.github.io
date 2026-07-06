# XPath / XQuery Injection — Testing Checklist

**Author:** x8bitranjit
Baseline every probe against a control. Tick only what you reproduced. Impact = auth bypass / full dump / file / RCE.

## Phase 0 — Find & fingerprint
- [ ] XPath sink located (XML login, native XML DB, SAML, XML config, SOAP/XSLT)
- [ ] XPath version fingerprinted: 1.0 vs 2.0/3.0 (does `string-length`/`lower-case`/`doc` work?) vs XQuery (FLWOR)
- [ ] Injection context: single-quote / double-quote string / numeric / path
- [ ] Native XML DB identified if any (BaseX / eXist-db / MarkLogic / Sedna)

## Phase 1 — Detection
- [ ] Quote/error probe (`'`, `"`, `]`, `)`) — noted XPath/XML error leak
- [ ] Boolean TRUE (`' or '1'='1`) vs FALSE (`' or '1'='2`) differ (not just an error)
- [ ] Tried both `'` and `"` contexts
- [ ] Numeric/position context (`1 or 1=1`) where applicable

## Phase 2 — Authentication bypass
- [ ] `' or '1'='1` into username
- [ ] `admin' or '1'='1` (target admin)
- [ ] `' or ''='` / `'or'1'='1` variants
- [ ] Double-quote `" or "1"="1`
- [ ] Union breakout `']|//user|a['`
- [ ] **Confirmed: logged in with NO valid password, fresh session, expected/admin user**

## Phase 3 — Blind extraction (→ full dump)
- [ ] Boolean oracle established (login / record present / status / length)
- [ ] `count(//user)` record count
- [ ] `string-length((//user[1]/password))` length discovery
- [ ] `substring(...,i,1)='c'` char-by-char extraction works
- [ ] Codepoint binary-search (2.0) for speed
- [ ] Element-name discovery (`name()`)
- [ ] **Extracted a secret** (own record / marker → then whole store demonstrable)

## Phase 4 — Error-based & XPath 2.0/3.0 / XQuery
- [ ] Error-based extraction (verbose errors leak values)
- [ ] `doc('http://oob')` → SSRF/OOB fetch confirmed
- [ ] `doc()` → cloud metadata / internal (→ ../SSRF/)
- [ ] `unparsed-text('file:///...')` → file read
- [ ] XQuery extension fn (BaseX `proc:system` / MarkLogic `xdmp:*` / eXist `util:eval`) → RCE

## Phase 5 — Escalate & validate
- [ ] Concrete impact demonstrated (bypass / dump / file / RCE), repeatable
- [ ] Reach understood (whole XML store / admin)
- [ ] Chained where possible (SSRF/XXE/LDAP-NoSQLi engine/ATO)
- [ ] Severity + CWE-643 (or CWE-652 XQuery) mapped

## AUTO-REJECT (don't report alone)
- [ ] A lone `'`/error with no steered behavior change
- [ ] `' or '1'='1` returns 200 but no diff vs the `' or '1'='2` control
- [ ] Login "works" only in the same/your session
- [ ] Reflected `count()`/value with no oracle effect
- [ ] "App uses XML" with no injecting parameter

## SAFE-PoC
- [ ] Auth bypass proven into a test/own account; one screenshot; no roaming real data
- [ ] Blind extraction stopped after enough chars to prove; secrets redacted
- [ ] `doc()`/`unparsed-text()` = own OOB / benign file, one proof, no secret exfil
- [ ] XQuery RCE = one benign command then STOP; listeners torn down
- [ ] Blind loops throttled; no hammering prod
