# Insecure Deserialization Checklist — per sink

> Authorized testing only. **Confirm with a blind DNS gadget first**, prove RCE with **one benign command**, then STOP.
> No shells/persistence; delete uploaded artifacts; tear down OOB/JNDI servers. Payloads: `DESERIALIZATION_ARSENAL.md`.

## PHASE 0 — Find the sinks (§1)
- [ ] Cookies / session / auth tokens (base64 blob deserialized).
- [ ] **.NET `__VIEWSTATE`** hidden field (+ `__VIEWSTATEGENERATOR`).
- [ ] API bodies/params, hidden fields, "remember me"/state tokens.
- [ ] **File uploads** (serialized object / **phar** polyglot / pickle model `.pkl`/`.pt`).
- [ ] Message-queue / cache payloads; RMI/JMX/T3(WebLogic)/JNDI endpoints (red-team/internal).
- [ ] Grepped source/JS for deserializer calls + base64 blobs fed to them.

## PHASE 1 — Recognize the format/language (§2)
- [ ] Fingerprinted the blob (`poc/deser_detect.py`) — Java `rO0`/`AC ED` · PHP `O:`/`a:` · .NET `AAEAAAD`/ViewState · Python `\x80`/`!!python` · Ruby `\x04\x08`/`BAh` · Node `_$$ND_FUNC$$_` · JSON `@type`/`@class`.
- [ ] Identified the deserializer library where possible (ObjectInputStream/Jackson/Fastjson/BinaryFormatter/pickle/Marshal/node-serialize).

## PHASE 2 — Confirm deserialization SAFELY (§3)
- [ ] **Tamper test:** byte/field change → deserialization error/stack trace (confirms sink + language).
- [ ] **Blind DNS gadget** (Java **URLDNS**, or per-language callback) → DNS hit to your OOB = deserialization confirmed, **no RCE risk**.

## PHASE 3 — Exploit per language (§4–§9)
- [ ] **Java:** GadgetProbe classpath → matching `ysoserial` chain (CommonsCollections/Spring/…) → RCE. JSON libs (Fastjson `@type`/Jackson/SnakeYAML) → JNDI (marshalsec) → RCE.
- [ ] **PHP:** `phpggc <Framework>/RCE` into `unserialize()`; or **phar** upload + file-op trigger; object tampering for auth bypass; `__wakeup` count-bypass.
- [ ] **.NET:** `ysoserial.net` (BinaryFormatter/LosFormatter); **ViewState** (no MAC, or leaked machineKey) → RCE; Json.NET `$type`.
- [ ] **Python:** pickle `__reduce__` / PyYAML `!!python/object/apply` / jsonpickle; model-file pickle load.
- [ ] **Ruby:** Marshal/YAML universal gadget. **Node:** `node-serialize` `_$$ND_FUNC$$_`.

## PHASE 4 — Gadget-less & escalate (§10–§11)
- [ ] No chain? → **object tampering** (flip `isAdmin`/role/user) for **auth bypass/privesc**.
- [ ] No framework chain (PHP/Java)? → **custom POP chain from source**.
- [ ] Chained from another bug: **XXE/LFI → machineKey → ViewState RCE**; **upload → phar → RCE**.
- [ ] Reached **RCE / auth bypass**; benign proof captured.

## PHASE 5 — Validate & report (§12–§16)
- [ ] Passed **FP auto-reject** (real OOB/`sleep`/`id` proof — not just "it's a serialized blob"; not blocked by a MAC you lack).
- [ ] Severity set (CVSS + **CWE-502**); impact in business terms (unauth RCE / privesc).
- [ ] **SAFE-PoC honored:** OOB-first, ONE benign command, no shells/persistence/lateral movement, uploads deleted, OOB/JNDI servers torn down, no prod DoS.
- [ ] Distinguished from **Log4Shell/JNDI**, XXE, prototype pollution, SSTI (§15).

## AUTO-REJECT (not a finding by itself)
- [ ] "This base64 decodes to a serialized object" — with no tamper/callback/RCE proof.
- [ ] Deserialization **error** on tamper with no code-exec/callback demonstrated.
- [ ] Blob is **signed/MAC'd** and you don't have the key (not exploitable unless key is leaked/weak/default).
- [ ] URLDNS/DNS-only hit reported **as RCE** (it's confirmation of deser; report accordingly, escalate for Critical).
- [ ] A **safe** deserializer (allow-listed types / `yaml.safe_load` / `SafeLoader`) with no unsafe path.
