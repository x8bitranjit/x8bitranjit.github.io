# Prototype Pollution — PoC Scripts

Tooling for the Prototype Pollution kit. *Authorized testing only.* **Source + Gadget = Impact.** The finding is proven **global pollution** (a fresh object carries the property / an SSPP oracle flips) **plus** a fired gadget (RCE / DOM-XSS / admin) — not "`?__proto__[x]=y` returned 200". **Server-side pollution is process-global and persists until the app restarts** — benign markers only, never an app-breaking property on prod. **Click a script to open its source.**

| Script | What it does |
|---|---|
| [`pp_probe.py`](#/prototype/poc/pp_probe) | **Server-side (SSPP) detector.** POSTs a benign pollution (`json spaces` / `status` / `exposedHeaders` / charset) to a source endpoint, re-reads an observe endpoint, and diffs against a baseline to confirm blind server-side pollution. `--root constructor` for the filter-bypass path. |
| [`pp_payloads.py`](#/prototype/poc/pp_payloads) | **Payload-matrix generator** for a `prop=value`: JSON `__proto__` / `constructor.prototype`, query bracket/dot, form, hash, and filter-bypass variants. Auto-types `true`/`false`/int for JSON. |
| [`gadgets_cheat.md`](#/prototype/poc/gadgets_cheat) | The **gadget catalog**: server-side RCE (child_process `NODE_OPTIONS`/shell, **EJS** `outputFunctionName`, **Pug**), gadget-free auth-bypass, property-injection, and client-side **DOM-XSS** library gadgets + a sink reference. |

## Typical flow
1. **Generate** the right-shaped payloads for what you want to set (`pp_payloads.py --prop isAdmin --value true`).
2. **Confirm** blind server-side pollution with the benign `json spaces` oracle (`pp_probe.py`).
3. **Client-side:** pollute via URL, confirm in console (`Object.prototype.x`), then match a loaded-library gadget.
4. **Match a gadget** from `gadgets_cheat.md` to the target's deps and fire **one** benign proof (`id` / `alert(document.domain)`), then stop.

> Prove **global** pollution (fresh object / oracle flip), then land a gadget for real impact. Benign markers only server-side; no app-breaking property on shared prod (DoS); note the pollution persists until restart; deliver client PoCs to your **own** test victim.
