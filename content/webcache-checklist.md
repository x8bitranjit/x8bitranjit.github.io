# Web Cache Poisoning & Deception — Testing Checklist

**Author:** x8bitranjit
**Use a cache-buster on every poisoning probe** so you land on YOUR key, never the shared prod cache (Guide §3/§20). Tick only
what you **reproduced**. The finding = the cache **re-serves** your influence to a **different request** (poisoning) or a
**victim's** response to you (deception) — never a lone reflected header.

## Phase 0 — Map the cache (§1–§2)
- [ ] Confirmed a cache exists on the target response (2nd request = HIT, or `Age` grows)
- [ ] Identified the layer (Cloudflare/Fastly/Akamai/CloudFront/Varnish/nginx/Vercel/Drupal…)
- [ ] Built a reliable **HIT/MISS oracle** (`X-Cache`/`CF-Cache-Status`/`Age`/timing/dynamic-marker)
- [ ] Noted the caching rule in play (extension / directory / `Cache-Control` / CDN page rule / heuristic)

## Phase 1 — Cache-buster + key discovery (§3–§4)  ← the make-or-break
- [ ] **Cache-buster confirmed KEYED** (each new value = a fresh MISS) — isolation established BEFORE any payload
- [ ] Canaried the high-yield **unkeyed headers** (`X-Forwarded-Host`/`X-Host`/`X-Forwarded-Scheme`/…)
- [ ] Ran **Param Miner** for custom unkeyed headers/params
- [ ] For each hit: **reflected** in the response AND **served to a request that DIDN'T send it** (unkeyed = poisonable)
- [ ] Noted **where** it reflects (script src / link / Location / canonical / raw HTML / JS config / header)

## Phase 2 — Poisoning (§5–§11)
- [ ] Unkeyed header → `<script src>`/`<link>` → **cached mass-XSS** (benign `alert(document.domain)` on YOUR key)
- [ ] Unkeyed header → `Location`/canonical → **cached open redirect** (→ OAuth token theft, `../OAuth/`)
- [ ] Unkeyed header → raw HTML → **cached reflected-XSS**
- [ ] **Resource poisoning:** a cached JS/CSS reflects your input → site-wide (§6)
- [ ] **Fat GET** (origin reads GET body, cache ignores) (§7)
- [ ] **Duplicate/array/cloaked params** (`;`/`%0a` delimiter split) (§7)
- [ ] **Key normalization/entanglement** (case/decoding/trailing differences cache-vs-origin) (§8)
- [ ] **DOM/multi-step/internal** (reflection lands in JS/JSON the client sinks) (§9)
- [ ] **CPDoS** (HHO/HMC/HMO) — error cached on YOUR key (**authorize first**) (§10)
- [ ] **Smuggling → shared cache** if desync-vulnerable (`../RequestSmuggling/`) (§11)
- [ ] **Proved the poisoned response is served to a SECOND request** on the same key ⭐

## Phase 2' — Deception (§12–§15)
- [ ] Walked the **path-confusion / delimiter matrix** on a sensitive endpoint (`.css/.js/;/%0a/%3f/%23/%2f/%2e/\`)
- [ ] Found a variant that **keeps your private content** AND **flips to a cache HIT**
- [ ] Understood the caching rule (extension/dir/`no-store` ignored) that stores it
- [ ] **Two-session confirm:** Session B (no cookie) retrieves Session A's benign marker from cache ⭐
- [ ] Graded the leaked body: token/reset/API-key = **Critical (ATO)**; CSRF/PII = **High**

## Phase 3 — Variants (§16)
- [ ] Browser cache / bfcache: sensitive page survives logout (no `no-store, private`)
- [ ] Cache-key injection (populate/predict a victim's key)

## Phase 4 — Validate → report (§17–§21)
- [ ] Reproduced the **"served to others"** (poison) / **cross-session** (deception) half — not just reflection
- [ ] Ruled out the FP list (§17): keyed input, not-cached, self-only, own-cookie-only
- [ ] Set **CVSS 3.1 + CWE-349 / CWE-524-525** (+ delivered CWE-79/601/400) (§18)
- [ ] SAFE-PoC: cache-buster + benign marker + **own accounts**; did **not** harm real users; recommended a **purge** (§20)
- [ ] De-duped to one **root cause** per report; led with the highest impact (mass-XSS > redirect) (§21)

## AUTO-REJECT (don't submit if…)
- [ ] A header/param is **reflected** but the response is **not cached** (self-XSS / plain reflection)
- [ ] The input is **keyed** (a request without it loses your canary)
- [ ] `Cache-Control: public` present but **no actual HIT** on a sensitive response
- [ ] Deception "works" but **only with your own cookie** (you fetched your own page)
- [ ] `CF-Cache-Status: DYNAMIC` / `Age: 0` on **every** variant (nothing cached)
- [ ] "Param Miner said unkeyed" with **no** reflection + served-to-others + concrete impact
- [ ] An open redirect that is **not cached** (that's a separate, lower bug)
- [ ] CPDoS "shown" by only erroring the **origin** (the error was never **cached**)

## SAFE-PoC (every time)
- [ ] **Cache-buster on every poisoning probe** — payload lands on YOUR key, never the shared prod entry
- [ ] Benign marker only (`alert(document.domain)` on your key / redirect to your own domain / a canary)
- [ ] Deception = **two of your OWN accounts** + a benign private marker; one cross-session proof, then STOP
- [ ] CPDoS/DoS = **explicit authorization**; prove cacheability on your key/staging; never outage real users
- [ ] Throttle; redact any real data seen; recommend a **cache purge** in the report
