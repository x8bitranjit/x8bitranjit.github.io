# Request-Smuggling Testing Checklist — tick per host

> Companion to `REQUEST_SMUGGLING_TESTING_GUIDE.md`. The finding is a **deterministic, controllable desync + a concrete
> cross-user impact** — never a timing blip. **DO NO HARM:** timing first, own connections, benign markers. Work
> top-to-bottom; stop and report only when impact (or a reliable capability) is proven safely.

## PHASE 0 — Recon (§3)
*Why this matters:* smuggling needs **two servers in a row sharing a reused pipe** — no chain, nothing to desync. So first confirm there's a front-end (CDN/proxy) in front of the origin and that connections are kept alive. You also scout the endpoints you'll later aim the smuggle at (a "saves my input" page for capture, a blocked `/admin` for bypass, a cacheable page for poisoning) — the desync is just the door; these are the rooms behind it.
- [ ] Confirmed a **front-end + back-end** chain (CDN/LB/proxy → origin) via Server/Via/X-Cache/CF-RAY headers.
- [ ] Confirmed keep-alive (HTTP/1.1) or HTTP/2; mapped protocol to you vs to the origin (downgrade surface).
- [ ] Located a **reflection/store** endpoint, **restricted/WAF-blocked** paths, and **cacheable** pages.

## PHASE 1 — Baseline: SAFE detection (§4)
*Why this matters:* this is the safety-critical step. Timing detection makes a disagreeing server *stall* without leaving any leftover in the shared pipe, so you find the desync **without risking real users' traffic** — always do it before a real smuggle. Then a deterministic differential on **your own** connection turns a "maybe it's just lag" hint into proof, which is the difference between a real finding and a rejected timing blip.
- [ ] Ran **timing-based** detection first (no socket poisoning) — CL.TE and TE.CL probes, repeated vs baseline.
- [ ] Confirmed with a **deterministic differential** on a connection **I control** (my follow-up gets the smuggled prefix's response).

## PHASE 2 — Technique (§5–§7)
*Why this matters:* the timing test told you the two servers disagree; now you pin down *which way* they disagree, because that decides how you build the smuggle. Don't stop at the classics — if CL.TE/TE.CL are patched, the modern variants (HTTP/2 downgrade, CL.0, connection-state) hit many "safe-looking" targets, and testing them is where most present-day smuggling bugs are found.
- [ ] Identified the class: **CL.TE / TE.CL** (§5), **TE.TE** obfuscation (§6), or **HTTP/2 downgrade** (H2.CL/H2.TE/CRLF) (§7).
- [ ] **Modern variants (§7.1–§7.3):** **CL.0 / 0.CL** (body-as-next-request on static/redirect endpoints) · **client-side desync** (browser-powered, no front-end) · **connection-state** attacks (first-request **routing** / **validation** on a reused connection).
- [ ] **2022–2024 wave (§7.4):** **TE.0** (chunked-as-next on body-less endpoints) · **CL.CL** (duplicate/ambiguous Content-Length) · **request tunnelling** (read an internal-only response inside your own connection — blind-SSRF-grade) · **pause-based desync** (streaming/timeout-induced).
- [ ] Tuned `Content-Length`/chunk sizes byte-exact (used Burp raw / Turbo Intruder, auto-CL disabled).

## PHASE 3 — Confirm (§8)
*Why this matters:* a desync you can only trigger *sometimes* is worthless to a triager and dangerous to exploit. Proving your prefix lands on a follow-up **predictably** (and knowing how often) is what makes the bug both reportable and safe to weaponize on your own connection.
- [ ] Proved the prefix attaches to a **follow-up** request predictably; measured reliability across trials.

## PHASE 4 — Impact (§9–§13) — benign, own connections
*Why this matters:* the desync is only the door — the payday is what you do through it, and severity is decided entirely here. Pick the exploit the target actually offers (a save-my-input page → session capture; a blocked path → WAF bypass; a cache → mass poisoning). Prove the **capability** on your own session/connection/unique key, then describe the cross-user impact — never demonstrate by harming real users.
- [ ] **Request capture (§9):** stored/reflected the **next** request; proved capture with my **own** second session → ATO.
- [ ] **WAF/auth bypass (§10):** reached a blocked/internal/admin path the front-end disallows.
- [ ] **Cache poisoning (§11):** poisoned a **benign/unique** cache key (described shared-cache mass impact).
- [ ] **Response-queue poisoning (§12):** demonstrated on my **own** traffic only.
- [ ] **Internal → RCE/cloud (§13):** reached a back-end code-exec/SSRF/metadata endpoint → handed off to SSRF/SSTI/cmdi kit (own tenant, read-only creds).

## PHASE 5 — Validate → report
*Why this matters:* smuggling is the class most often reported at the wrong severity and the one most likely to break the site, so this phase protects both the users and your credibility. Confirm you have a *deterministic desync + a real exploit*, keep the PoC benign and on your own connections, tag it correctly, and note the do-no-harm discipline — a genuine Critical with a reckless or unproven write-up gets downgraded or rejected.
- [ ] Showed a **deterministic, controllable** desync + a **concrete** exploit (or reliable cross-connection capability) — FP check §15.
- [ ] Used **benign** prefixes, **own** sessions/connections; did **not** harvest real users' data or poison shared entries.
- [ ] Restored connection state; kept volume low; confirmed reproducibility.
- [ ] Set CVSS 3.1 + **CWE-444** (+ outcome CWE: 79/384/918/94) (§16).
- [ ] De-duped to one finding per desync primitive; led with the highest-impact exploit (§19).

## AUTO-REJECT (don't submit if…)
*Why this matters:* every line here is a **non-finding that looks like a finding** — the trap that makes beginners file rejected reports. A single slow response is lag; a scanner flag is a guess; a 400 error is the server correctly *defending itself*; a self-only or non-reproducible effect isn't a security bug. If any box below is true, keep working until you have a deterministic desync with real cross-user impact — or don't submit.
- [ ] A single slow/odd response (load/jitter) with no deterministic differential.
- [ ] "smuggler.py / the extension flagged it" with no manual confirmation.
- [ ] A desync you can't make **deterministic/reproducible**.
- [ ] 400/errors from malformed requests (the server **rejecting** bad framing = correct).
- [ ] A confirmed desync reported as **Critical with no exploit** (that's ~Medium).
- [ ] Self-only effects (your request to yourself, no cross-user impact).
