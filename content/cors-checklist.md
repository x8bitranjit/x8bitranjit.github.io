# CORS Testing Checklist — tick per endpoint

> Companion to `CORS_TESTING_GUIDE.md`. Work top-to-bottom **per CORS-enabled endpoint**. The goal is never
> "a reflected header" — it's "**my attacker origin (or `null`) is trusted WITH credentials and I read another
> user's secret**." Stop and report only when you can say that (or honestly downgrade to Info).

## PHASE 0 — Recon (find the right endpoints)
*Why this matters:* a CORS bug only pays when there's a **secret behind the door**, so the whole game is aimed at the *right* endpoints — authenticated, credentialed ones that return a token/key/PII/CSRF token (`/api/me`, `/graphql`, `/api/keys`). Reflecting your origin on a public marketing JSON is worthless; reflecting it on `/api/me` is account takeover. Recon is what separates those two.
- [ ] Enumerated every endpoint returning an `Access-Control-Allow-*` header (proxy history + `poc/cors_scan.py`).
- [ ] Tagged each: **authenticated?** **returns a secret** (token/API key/PII/CSRF token)? **cookie-auth?**
- [ ] Prioritised: `/api/me`, `/account`, `/api/keys`, `/oauth/token`, `/graphql`, `/api/csrf`, GraphQL.
- [ ] Listed subdomains/services (api., app., dev., staging., internal.) — each may have its own policy.
- [ ] Grepped JS for `withCredentials` / `credentials:'include'` / `fetch('/api...')` (JS-files kit / Recon §15).

## PHASE 1 — Baseline (read headers correctly)
*Why this matters:* CORS reports get closed more than any other class because people report the *condition* (a reflected header) instead of the *exploit*. This phase forces the three-part gate that keeps you honest: my origin trusted **AND** `ACAC:true` **AND** a real secret in the body. Miss any one and it's Info — knowing that here saves you filing a dud.
- [ ] Sent `Origin: https://evil.com`; recorded `Access-Control-Allow-Origin` returned.
- [ ] Recorded `Access-Control-Allow-Credentials` (true / absent).
- [ ] Confirmed (logged in as a test account) the body **actually contains a secret**.
- [ ] Classified: reflect-any / null-allowed / allowlist / wildcard `*` / static-correct / no-ACAO.

## PHASE 2 — ACAO logic mapping (§5)
*Why this matters:* you can't pick the right bypass until you know the server's rule. Firing a spread of origins and watching which come back reflected reverse-engineers the check (reflect-any needs no bypass; `endsWith` needs a registered domain; `*.target.com` needs a subdomain you control). Two minutes of mapping decides whether Phase 3 is one request or a subdomain-takeover chain.
- [ ] Fired the origin battery (`evil.com`, `null`, `target.com.evil.com`, `eviltarget.com`, `sub.target.com`, backtick).
- [ ] Inferred the server rule (reflect / endsWith / startsWith / contains / regex / `*.target.com`).

## PHASE 3 — Bypass (get YOUR origin trusted + creds)
*Why this matters:* the exploit requires an origin **you actually control** to be the one the server trusts — the whole point of a bypass is to satisfy the allowlist with a domain you own (or `null`, or a subdomain you take over). Until an origin you control is reflected *with credentials*, you have nothing to run the exfil from. This phase's end-state is the prerequisite for all of Phase 4.
- [ ] Reflect-any → confirmed several random origins echoed (§6).
- [ ] `null` → confirmed `ACAO: null` + `ACAC:true` (§7); have sandboxed-iframe PoC.
- [ ] Allowlist weakness → registered/used a satisfying attacker origin (§8) and confirmed reflection.
- [ ] `*.target.com` only → identified a **subdomain takeover or XSS** to obtain a trusted origin (§9).
- [ ] End state: an origin **I control** is reflected into ACAO **with `ACAC:true`**.

## PHASE 3b — Preflight & response-header reach (§10.2)
*Why this matters:* the simple credentialed GET (the common theft) needs no preflight — but the *bigger* wins do: cross-origin **writes**, reads of **custom-header-gated** endpoints, and secrets hiding in **response headers**. Those are "non-simple," so a permissive preflight is what unlocks them. Checking it here is how a read-only CORS bug becomes full cross-origin read+write.
- [ ] Tested the **preflight** (`OPTIONS` + `Access-Control-Request-Method/Headers`) → recorded `ACAM`/`ACAH`/`ACAO`/`ACAC`.
- [ ] If permissive → planned **custom-header reads** (Authorization/X-Api-Key) and **JSON/PUT/DELETE writes** that read the result.
- [ ] Checked `Access-Control-Expose-Headers` → can JS read a secret that lives in a **response header**?

## PHASE 4 — Impact (prove the read / climb to RCE)
*Why this matters:* this is the phase a triager actually pays for — proving a **real browser** read another logged-in user's secret, then climbing as high as that secret allows (token→ATO, CSRF-token→state change, cloud/admin/CI cred→RCE). It also sweeps the adjacent classes others forget (CSWSH, cache poisoning, PNA) — the same misconfig mindset applied to WebSockets, caches, and the intranet. Always ask: *does this leaked value log me in, or run a command?*
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
*Why this matters:* CORS has a long false-positive list (bare `*`, reflection without creds, `*`+`ACAC` together, static-correct ACAO), and reporting any of them burns credibility. This phase is the gate: confirm an *attacker-controlled* origin is trusted *with credentials*, prove the read in a *real browser* with *your own* accounts (not curl), then lead with the impact and the right CWE. Clean, browser-proven, redacted evidence is what gets it paid instead of closed.
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
