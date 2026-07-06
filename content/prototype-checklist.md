# Prototype Pollution — Testing Checklist

**Author:** x8bitranjit
**Source + Gadget = Impact.** Prove global pollution AND fire a gadget. Server-side pollution is global+persistent — benign markers, no prod DoS.

## Phase 0 — Environment & source
- [ ] Environment identified: Node server-side / browser client-side / both
- [ ] Candidate sources found (merge/extend/set/clone/query-parse) via JS review or behavior
- [ ] Input vectors mapped: JSON body · query string · form · hash · path/headers
- [ ] Loaded libraries enumerated (lodash/jQuery/minimist/EJS/Pug… + versions for known CVEs)

## Phase 1 — Detection (prove GLOBAL pollution)
- [ ] Client: `?__proto__[polluted]=yes` → `Object.prototype.polluted==='yes'`
- [ ] Client: `constructor[prototype][polluted]=yes` variant
- [ ] Client: fresh object carries it: `({}).polluted`
- [ ] Server SSPP: `{"__proto__":{"json spaces":10}}` → later JSON indented (baseline vs after)
- [ ] Server SSPP alt oracles: `status` / `exposedHeaders` / charset / `parameterLimit`
- [ ] Confirmed it's pollution (global), not mere reflection
- [ ] `__proto__` blocked? → `constructor.prototype` bypass works

## Phase 2 — Server-side exploitation
- [ ] Auth/logic: `{"__proto__":{"isAdmin":true}}` / `role:admin` → privilege change (gadget-free)
- [ ] child_process gadget: `NODE_OPTIONS`/`shell`/`env` → command execution
- [ ] Template gadget: EJS `outputFunctionName` / Pug `compileDebug` → RCE
- [ ] Other lib gadget matched to target deps
- [ ] Property-injection (no gadget): CORS `exposedHeaders` / redirect / cache
- [ ] **RCE proven** with one benign command / OOB callback

## Phase 3 — Client-side exploitation
- [ ] Client source confirmed
- [ ] Library gadget identified (jQuery/GA/analytics/sanitizer config)
- [ ] Polluted `src`/`html`/`srcdoc`/`url` reaches a sink
- [ ] **DOM-XSS fired** (alert/`document.domain`) and deliverable via URL to a victim

## Phase 4 — Escalate & validate
- [ ] Concrete impact demonstrated (RCE / DOM-XSS / admin / injected response), repeatable
- [ ] Reach understood (whole process / all users)
- [ ] Chained where possible (FileUpload for `--require`, CORS/redirect, XSS→ATO)
- [ ] Severity + CWE-1321 mapped; dependency CVE cited if applicable

## AUTO-REJECT (don't report alone)
- [ ] `__proto__` merely reflected in a response (not global)
- [ ] `?__proto__[x]=y` returns 200 with no proven global effect
- [ ] `Object.prototype.x` set but **no gadget / no impact** (primitive only) → keep hunting
- [ ] SSPP oracle blipped once, not repeatable
- [ ] "library X has a known gadget" but the sink never fires on this target
- [ ] `location.hash` pollution that only affects your own tab (self-XSS, not deliverable)

## SAFE-PoC (prototype pollution is dangerous)
- [ ] Server-side: benign markers only (`json spaces`, unique nonce prop); NO app-breaking property on prod (DoS)
- [ ] Auth-bypass proven against your OWN session; aware it may transiently affect others; prefer a lab on shared prod
- [ ] RCE = one benign command / OOB then STOP; don't re-pollute repeatedly
- [ ] Noted that server pollution persists until app RESTART (flag to program)
- [ ] Client PoC delivered to your OWN test victim; benign alert/beacon; not weaponized
- [ ] Secrets redacted; OOB torn down; prototype not left polluted longer than needed
