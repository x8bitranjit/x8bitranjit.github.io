# Web Cache Poisoning & Deception — PoC Scripts

Runnable, **benign-by-default** proof-of-concept helpers that back the Web Cache kit — one per phase. **Click a script
to open it on its own page.** *Authorized testing only:* **every poisoning probe uses a cache-buster** so your payload
lands on your **own** cache key and never touches the shared production entry real users hit; deception uses **your own
two sessions** + a benign marker. These tools detect and prove — they never weaponize, DoS, or harvest real users.

| Script | What it does |
|---|---|
| [`cache_detect.py`](#/webcache/poc/cache_detect) | Is the URL **cached**? Sends it twice on the same cache-buster (MISS→HIT / `Age` growth / speed-up), once with a different buster to prove the **buster is keyed** (safe isolation), and **fingerprints the cache layer** (Cloudflare / Fastly / Akamai / CloudFront / Varnish / Vercel …). Read-only. |
| [`poison_probe.py`](#/webcache/poc/poison_probe) | **Cache-buster-safe** unkeyed-input finder: for each header it sends a benign canary **with** it (reflected?), then the **same key without** it (still served = **unkeyed / poisonable**), and classifies the sink — `script src` → mass-XSS, `Location` → cached redirect, raw HTML. Low false-positive. |
| [`deception_probe.py`](#/webcache/poc/deception_probe) | **Two-request** cross-session confirmer with a **cold public-content control**: COLD (no cookie — is the page already public? → false-positive guard), request A (your cookie → private marker), request B (no cookie → your marker served from cache = **deception**). Auto-builds the path / delimiter / extension matrix. |

## How they fit together

1. **Is there a cache, and is it safe to probe?** — `cache_detect.py` confirms the response is cached and that your cache-buster is *keyed*, so you can poison only your own key.
2. **Find the unkeyed input** — `poison_probe.py` walks the request headers to find one that is reflected into the response **but is not part of the cache key**, then names the sink it lands in (script src / redirect / HTML).
3. **Or steal a page via deception** — `deception_probe.py` proves a static-looking URL caches your *authenticated* page, so a second, unauthenticated request retrieves it.

> Read the **Testing Guide** for the full detection → poisoning → deception order and the **cache-buster safety
> discipline**, and the **Checklist** for the per-endpoint sequence. Confirm impact manually and recommend a **cache
> purge** in the report.
