# CORS Testing Checklist — tick per endpoint

> Companion to `CORS_TESTING_GUIDE.md`. Work top-to-bottom **per CORS-enabled endpoint**. The goal is never
> "a reflected header" — it's "**my attacker origin (or `null`) is trusted WITH credentials and I read another
> user's secret**." Stop and report only when you can say that (or honestly downgrade to Info).

## PHASE 0 — Recon (find the right endpoints)
- [ ] Enumerated every endpoint returning an `Access-Control-Allow-*` header (proxy history + `poc/cors_scan.py`).
- [ ] Tagged each: **authenticated?** **returns a secret** (token/API key/PII/CSRF token)? **cookie-auth?**
- [ ] Prioritised: `/api/me`, `/account`, `/api/keys`, `/oauth/token`, `/graphql`, `/api/csrf`, GraphQL.
- [ ] Listed subdomains/services (api., app., dev., staging., internal.) — each may have its own policy.
- [ ] Grepped JS for `withCredentials` / `credentials:'include'` / `fetch('/api...')` (JS-files kit / Recon §15).

## PHASE 1 — Baseline (read headers correctly)
- [ ] Sent `Origin: https://evil.com`; recorded `Access-Control-Allow-Origin` returned.
- [ ] Recorded `Access-Control-Allow-Credentials` (true / absent).
- [ ] Confirmed (logged in as a test account) the body **actually contains a secret**.
- [ ] Classified: reflect-any / null-allowed / allowlist / wildcard `*` / static-correct / no-ACAO.

## PHASE 2 — ACAO logic mapping (§5)
- [ ] Fired the origin battery (`evil.com`, `null`, `target.com.evil.com`, `eviltarget.com`, `sub.target.com`, backtick).
- [ ] Inferred the server rule (reflect / endsWith / startsWith / contains / regex / `*.target.com`).

## PHASE 3 — Bypass (get YOUR origin trusted + creds)
- [ ] Reflect-any → confirmed several random origins echoed (§6).
- [ ] `null` → confirmed `ACAO: null` + `ACAC:true` (§7); have sandboxed-iframe PoC.
- [ ] Allowlist weakness → registered/used a satisfying attacker origin (§8) and confirmed reflection.
- [ ] `*.target.com` only → identified a **subdomain takeover or XSS** to obtain a trusted origin (§9).
- [ ] End state: an origin **I control** is reflected into ACAO **with `ACAC:true`**.

## PHASE 3b — Preflight & response-header reach (§10.2)
- [ ] Tested the **preflight** (`OPTIONS` + `Access-Control-Request-Method/Headers`) → recorded `ACAM`/`ACAH`/`ACAO`/`ACAC`.
- [ ] If permissive → planned **custom-header reads** (Authorization/X-Api-Key) and **JSON/PUT/DELETE writes** that read the result.
- [ ] Checked `Access-Control-Expose-Headers` → can JS read a secret that lives in a **response header**?

## PHASE 4 — Impact (prove the read / climb to RCE)
- [ ] Built `poc/exfil.html` with my origin; read **test account A's** secret while A is logged in (§11).
- [ ] Secret = **session token / API key** → replayed it → confirmed **account takeover** (§12).
- [ ] Secret = **CSRF token** → completed a protected state change (email/pw) → ATO (§13).
- [ ] **Cross-origin WRITE (§13.2):** permissive preflight → credentialed JSON/PUT → changed state + read result.
- [ ] **CSWSH (§13.3):** WS endpoint cookie-authed + handshake **ignores Origin** → cross-origin authenticated WebSocket (read/act).
- [ ] **Cache poisoning (§10.4):** reflected ACAO + cacheable + **no `Vary: Origin`** → poisoned shared cache (mass theft / DoS).
- [ ] **Private Network Access (§10.5):** internal/localhost service returns `Access-Control-Allow-Private-Network: true` (+ permissive ACAO) → public page drives intranet (router/IoT/dev-admin); else pivot to DNS-rebinding (SSRF kit).
- [ ] **RCE/shell chain checked (§14.1):** is the leaked secret a **cloud cred / admin key / CI token**?
      → cloud "run command" / admin code-exec feature / CI pipeline → **shell** (validate read-only, own tenant).
- [ ] Non-credentialed `*` → confirmed sensitive **no-auth** data read cross-origin (§15) — if no creds path.

## PHASE 5 — Validate → report
- [ ] An **attacker-controlled** origin (or `null`) is trusted — not the app's own/static origin (FP check §17).
- [ ] **`ACAC:true`** present (or the data is sensitive & auth-less for the `*` case).
- [ ] Proved the cross-origin **read in a real browser** (not just curl) with my **own** accounts.
- [ ] Named the secret + its impact (ATO / data breach / CSRF chain / RCE chain).
- [ ] Set CVSS 3.1 + **CWE-942 / CWE-346** (+ outcome CWE) (§18).
- [ ] SAFE PoC: own 2 accounts, benign collector, secret redacted, exfil page taken down (§20).
- [ ] De-duped to one finding per policy/root cause; led with the highest-impact endpoint (§21).

## AUTO-REJECT (don't submit if…)
- [ ] `ACAO: *` on public/non-sensitive data, **no creds** → Info.
- [ ] Reflected origin **without** `ACAC:true` and the body has no sensitive/auth-less data → Low/Info.
- [ ] `ACAO:*` **and** `ACAC:true` together → browser ignores for creds → not exploitable.
- [ ] Static, correct ACAO (the real frontend) and you don't control that origin.
- [ ] "Vulnerable" proven only by curl with no browser read and no credentials.
