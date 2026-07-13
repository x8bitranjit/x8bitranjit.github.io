# Open Redirect — Checklist (tick per app)

> Companion to `OPEN_REDIRECT_TESTING_GUIDE.md`. The finding is the **escalation** (ATO / DOM-XSS / SSRF-internal /
> credible phishing), never a bare "it redirects." Work top-to-bottom; stop and report only when you've proven an impact
> (or an honest phishing PoC). A server-side URL **fetch** is SSRF, not open redirect — don't mislabel it.

## PHASE 0 — Recon (§3)
- [ ] Harvested URLs (gau/waybackurls/katana/hakrawler) and grepped the **redirect param name-set** (`gf redirect`).
- [ ] Found the **login / logout / SSO** `redirect_uri` / `returnUrl` / `RelayState` (the #1 place + the OAuth chain §11).
- [ ] Discovered **hidden** redirect params (Arjun / Param Miner) on login/checkout/share/download/preview endpoints.
- [ ] Located the **sink type** per candidate: `Location` header, `<meta http-equiv=refresh>`, or JS (`location=`/`href`/`assign`/`replace`/`window.open`).
- [ ] Noted **email/verify/invite** "continue to" links and any **fragment-driven** (`location.hash`) client redirects.
- [ ] Flagged any **server-side URL fetchers** (link preview / webhook / image-by-URL) → test as **SSRF** (§12), not open redirect.

## PHASE 1 — Baseline (§4)
- [ ] Plain absolute `?p=https://evil.example` → lands off-origin?
- [ ] Protocol-relative `?p=//evil.example` → off-origin? (the most common win)
- [ ] Backslash `/\evil.example`, `https:/\evil.example` → off-origin?
- [ ] Classified: confirmed off-origin / blocked-needs-bypass / same-origin-only / OAuth `redirect_uri` / JS sink / server-fetch(SSRF).

## PHASE 2 — Sink + bypass (§5–§9)
- [ ] Confirmed **redirect vs reflect** (auto-navigation vs an href you must click) (§6).
- [ ] Walked the **parser-gap matrix**: `//`, `/\`, `https:/\`, `@`-userinfo, `evil/target.com`, `target.com.evil` (§7).
- [ ] Beat the **whitelist**: substring (`evil/target.com`), prefix (`target.com@evil`), host allow-list (own a subdomain / chain an allowed open redirect) (§8).
- [ ] Tried **encoding/CRLF**: `%2f%2f`, double-encode, `%09`/`%00`, unicode dot, and `%0d%0a` → response splitting (§9).

## PHASE 3 — Impact (§10–§14)
- [ ] **DOM-XSS (§10):** JS sink accepts `javascript:`/`data:` → `alert(document.domain)` fires → XSS (a tier above redirect).
- [ ] **OAuth/SSO (§11):** loose `redirect_uri` **or** open-redirect-on-allowed-client bounces the `code`/`access_token` to my host → **ATO** (caught my own token).
- [ ] **SSRF bypass (§12):** an allow-list-locked SSRF + an open redirect on an allowed host → follows to `169.254.169.254`/internal (read-only proof).
- [ ] **Token/session leak (§13):** reset/verify/session token in the URL/fragment/Referer walks off-origin → **ATO**.
- [ ] **Phishing/chain (§14):** a real `target.com` link auto-redirects to my page (credible phishing), or bounces to a sister-subdomain XSS (domain cookies).

## PHASE 4 — Validate → report
- [ ] Proved the **escalation** (caught token / fired script / internal fetch), not just the hop (FP check §16).
- [ ] Used my **own marker host**, **own account**, caught my **own token**; read-only for metadata; benign XSS marker.
- [ ] Confirmed on **production**; re-tested partial fixes (blocked `https://evil` but not `//evil`/`\/\/evil`/`@` = fresh finding).
- [ ] Set CVSS 3.1 + **CWE-601** (+ CWE-79 / CWE-918 / CWE-113 / CWE-287 by outcome) (§17).
- [ ] De-duped to one finding per root cause; led with the highest-impact escalation (§20).

## AUTO-REJECT (don't submit if…)
- [ ] **Same-origin** redirect only (`?next=/path`, leading `/` enforced, no `//`/`\`/`@` bypass reaches off-origin).
- [ ] Redirect to a **fixed/allow-listed partner** you can't steer to your host.
- [ ] A **bare** off-origin redirect reported as High/Critical with nothing riding along (it's Low–Medium).
- [ ] A server-side **URL fetch** reported as "open redirect" (it's **SSRF** — report it as that, usually higher).
- [ ] `javascript:` in a **`Location` response header** claimed as XSS (browsers ignore it there; only client-JS sinks execute).
- [ ] Requires the victim to **hand-edit/paste** the URL (not a realistic single-link delivery).
- [ ] A **third-party/out-of-scope** domain reached via the target (wrong asset).
