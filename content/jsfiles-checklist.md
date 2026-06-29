# JS-Files Testing Checklist — tick per application

> Companion to `JS_FILES_TESTING_GUIDE.md`. The goal is never "a regex match" — it's a **live + privileged secret**, a
> **firing DOM XSS**, or a **working unauthorized API call**. Stop and report only when you can demonstrate one.

## PHASE 0 — Harvest (§3)
- [ ] Pulled every **live** bundle + dynamically-loaded chunk (loaded all routes / read chunk manifest).
- [ ] Captured inline scripts, service workers (`/sw.js`), runtime config (`/config.js`, `/env.js`, `manifest.json`).
- [ ] Pulled **historical** JS (gau + waybackurls) — old bundles hold rotated-but-live keys & removed endpoints.
- [ ] Pulled across subdomains/CDN (each app has its own bundle).
- [ ] Looked for `//# sourceMappingURL=` and tried `<bundle>.js.map` even when not referenced.

## PHASE 1 — Beautify / structure (§4)
- [ ] Beautified/deobfuscated all files.
- [ ] Located the env/config object (base URLs, keys) and the SPA router table (all routes incl. admin).

## PHASE 2 — Extract the four veins (§5–§8)
- [ ] **Secrets:** ran entropy-gated regexes + trufflehog/gitleaks; separated HIGH-value from public client keys.
- [ ] **Endpoints/params:** extracted all API paths, verbs, parameters, GraphQL ops, internal hosts.
- [ ] **Hidden surface:** roles, permissions, feature flags, client-only authz, hidden params (debug/isAdmin).
- [ ] **DOM sinks:** mapped source→sink flows (innerHTML/eval/postMessage/redirect/proto-pollution).

## PHASE 3 — Recover source (§9)
- [ ] Unpacked `.map` / `sourcesContent` → original source tree.
- [ ] Re-ran all extractors over the **recovered original** code (higher signal); read comments/dead admin code.

## PHASE 4 — Validate + impact (§10–§14)
- [ ] **Validated each HIGH secret live + privileged** with a minimal read-only call (sts get-caller-identity / /user / /balance).
- [ ] **Secret → RCE/shell (§11):** cloud key → cloud run-command; CI token → pipeline; admin key → code-exec feature; DB URI → reachable DB. (Own tenant/repo only.)
- [ ] **DOM sink → DOM XSS → ATO (§12):** confirmed the source→sink fires; proved session/token theft (own account).
- [ ] **Prototype pollution (§13):** confirmed `({}).polluted` + a gadget → DOM-XSS (client) / RCE (server).
- [ ] **Hidden endpoint (§14):** called admin/internal routes directly (authz) + other ids (IDOR) → unauthorized result.

## PHASE 5 — Validate → report
- [ ] The artifact is **attacker-usable** — live/privileged secret, firing sink, or reachable unauth endpoint (FP check §17).
- [ ] Killed public-key false positives (AIza / pk_live / Sentry DSN / unvalidated matches).
- [ ] Confirmed old-JS findings **still work on production**.
- [ ] Named the impact (cloud RCE / ATO / privilege escalation / data theft) and demonstrated it.
- [ ] Set CVSS 3.1 + correct CWE (798 / 79 / 1321 / 639 / 540) (§18).
- [ ] SAFE PoC: read-only validate, own-tenant code-exec, secrets redacted, PoC pages down (§20).
- [ ] De-duped to one finding per root cause; led with the highest-impact artifact (§21).

## AUTO-REJECT (don't submit if…)
- [ ] Google Maps/Firebase `AIza…` web key, Stripe `pk_live_…`, Sentry DSN, GA/reCAPTCHA key (public by design).
- [ ] A secret match you never validated (could be dead/rotated/placeholder).
- [ ] A bare endpoint list or "I found API routes" with no exploited bug.
- [ ] A DOM sink with no controllable source / unreachable code path.
- [ ] A `/admin` path merely *mentioned* in JS but authz is enforced server-side (you couldn't access it).
- [ ] localhost/test/example creds that don't work against production.
- [ ] Source map exposed with no sensitive content and the program doesn't rate it.
