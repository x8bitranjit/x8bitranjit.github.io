# Insecure Deserialization Checklist — per sink

> Authorized testing only. **Confirm with a blind DNS gadget first**, prove RCE with **one benign command**, then STOP.
> No shells/persistence; delete uploaded artifacts; tear down OOB/JNDI servers. Payloads: `DESERIALIZATION_ARSENAL.md`.

## PHASE 0 — Find the sinks (§1)
*Why this matters:* you can't attack a deserializer you haven't found. The whole class lives wherever the app hands you
an object to hold and later takes it back — cookies, `__VIEWSTATE`, "remember me" tokens, file uploads. Cast wide here;
every later phase depends on having a real sink to poke.
- [ ] Cookies / session / auth tokens (base64 blob deserialized).
- [ ] **.NET `__VIEWSTATE`** hidden field (+ `__VIEWSTATEGENERATOR`).
- [ ] API bodies/params, hidden fields, "remember me"/state tokens.
- [ ] **File uploads** (serialized object / **phar** polyglot / pickle model `.pkl`/`.pt`).
- [ ] Message-queue / cache payloads; RMI/JMX/T3(WebLogic)/JNDI endpoints (red-team/internal).
- [ ] Grepped source/JS for deserializer calls + base64 blobs fed to them.

## PHASE 1 — Recognize the format/language (§2)
*Why this matters:* the language stamp picks everything downstream — tool, gadgets, magic methods. Two minutes reading
the prefix saves you from firing Java payloads at a PHP sink. Get this wrong and nothing else works.
- [ ] Fingerprinted the blob (`poc/deser_detect.py`) — Java `rO0`/`AC ED` · PHP `O:`/`a:` · .NET `AAEAAAD`/ViewState · Python `\x80`/`!!python` · Ruby `\x04\x08`/`BAh` · Node `_$$ND_FUNC$$_` · JSON `@type`/`@class`.
- [ ] Identified the deserializer library where possible (ObjectInputStream/Jackson/Fastjson/BinaryFormatter/pickle/Marshal/node-serialize).

## PHASE 2 — Confirm deserialization SAFELY (§3)
*Why this matters:* this is the safety gate that keeps you both accurate and ethical. Prove the sink is live with a
tamper-error and a **DNS doorbell** (URLDNS) *before* touching an RCE gadget — you confirm the bug with zero code
execution, and you never fire a live round at something you haven't verified deserializes your input.
- [ ] **Tamper test:** byte/field change → deserialization error/stack trace (confirms sink + language).
- [ ] **Blind DNS gadget** (Java **URLDNS**, or per-language callback) → DNS hit to your OOB = deserialization confirmed, **no RCE risk**.

## PHASE 3 — Exploit per language (§4–§9)
*Why this matters:* now you cash the confirmed sink into impact, using the tool that matches the language you fingerprinted.
Each row is a different door to the same room (RCE or auth bypass) — you only need one to open. Keep the payload a benign
marker; the goal is proof, not damage.
- [ ] **Java:** GadgetProbe classpath → matching `ysoserial` chain (CommonsCollections/Spring/…) → RCE. JSON libs (Fastjson `@type`/Jackson/SnakeYAML) → JNDI (marshalsec) → RCE.
- [ ] **PHP:** `phpggc <Framework>/RCE` into `unserialize()`; or **phar** upload + file-op trigger; object tampering for auth bypass; `__wakeup` count-bypass.
- [ ] **.NET:** `ysoserial.net` (BinaryFormatter/LosFormatter); **ViewState** (no MAC, or leaked machineKey) → RCE; Json.NET `$type`.
- [ ] **Python:** pickle `__reduce__` / PyYAML `!!python/object/apply` / jsonpickle; model-file pickle load.
- [ ] **Ruby:** Marshal/YAML universal gadget. **Node:** `node-serialize` `_$$ND_FUNC$$_`.

## PHASE 4 — Gadget-less & escalate (§10–§11)
*Why this matters:* "no ready RCE chain" is not the end. Editing an unsigned session object gives auth bypass with no
code exec; source access lets you hand-build a chain; and chaining from XXE/LFI (machineKey) or an upload (phar) turns
two mediums into a Critical. Don't walk away from a confirmed sink just because ysoserial didn't hand you a one-liner.
- [ ] No chain? → **object tampering** (flip `isAdmin`/role/user) for **auth bypass/privesc**.
- [ ] No framework chain (PHP/Java)? → **custom POP chain from source**.
- [ ] Chained from another bug: **XXE/LFI → machineKey → ViewState RCE**; **upload → phar → RCE**.
- [ ] Reached **RCE / auth bypass**; benign proof captured.

## PHASE 5 — Validate & report (§12–§16)
*Why this matters:* deserialization has a long false-positive list, and the fastest way to lose credibility is calling a
DNS ping "RCE" or reporting a MAC'd blob you can't forge. Lead with the command you ran or the callback you caught, set
CWE-502, and honor SAFE-PoC — one benign proof, listeners torn down. Honest severity is what gets paid.
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
