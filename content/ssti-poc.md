# SSTI — PoC Scripts

Runnable, **benign-by-default** proof-of-concept tooling that backs the SSTI kit. **Click a script to open it on its own
page.** *Authorized testing only:* the finding is **server-side evaluation → RCE** (or sandboxed file-read/secret),
never a lone `{{7*7}}=49`. Use benign markers and clean up.

| Script | What it does |
|---|---|
| [`ssti_detect.py`](#/ssti/poc/ssti_detect) | **Differential** detector with FP-gating: sends `{{1337*1338}}` (non-round) + `{{7*'7'}}`, verifies the **server** computed it (not CSTI/reflection), and fingerprints the engine across `{{ }}/${ }/#{ }/<%= %>/{ }`. |
| [`ssti_rce.py`](#/ssti/poc/ssti_rce) | Print the **engine-specific RCE payload** (Jinja2/Twig/Freemarker/SpEL/ERB/Smarty/EJS/Pug/Nunjucks/Mako/Tornado) for a given command. |

## How they fit together

1. **Confirm server-side eval + engine** — `ssti_detect.py` kills the `{{7*7}}=49` false positive (`1337*1338`=`1788906`, `7*'7'`=`7777777`).
2. **Get the engine's RCE payload** — `ssti_rce.py --engine jinja2 --cmd id` and fire a single benign marker.
3. **Sandboxed?** Fall back to secrets/file read (`{{config}}` / `{{config['SECRET_KEY']}}` → forge Flask sessions).
4. Remember: a client-side `{{}}` (Angular/Vue) is **XSS**, not SSTI — use the XSS kit.

> Read the **Testing Guide §4–§15** for engine fingerprints and per-engine RCE, and the **Zero to Expert (Q&A)** for
> sandbox escapes.
