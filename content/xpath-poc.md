# XPath Injection — PoC Scripts

Tooling for the XPath kit. *Authorized testing only.* The finding is a **steered, repeatable change in query behaviour** — you logged in without a password, extracted data, read a file, or ran code — **not** a lone quote error. Baseline every probe against a control; **XPath 1.0 has no comments** so payloads are quote-balanced. Extract only enough to prove it, then stop. **Click a script to open its source.**

| Script | What it does |
|---|---|
| [`xpath_fuzz.py`](#/xpath/poc/xpath_fuzz) | **Control-baselined** detector + **auth-bypass** tester. LOGIN mode fires the canonical `' or '1'='1` payloads (single/double-quote, union) and decides "bypassed" vs a learned wrong-creds baseline (or a success/fail marker, or a good-login baseline). DETECT mode does the TRUE-vs-FALSE + error differential on one param. Low false-positive. |
| [`xpath_blind.py`](#/xpath/poc/xpath_blind) | **Blind char-by-char extraction** via `string-length()`/`substring()` with an auto-calibrated (`1=1` / `1=2`) TRUE/FALSE oracle. Discovers length, then extracts a `--target` node (e.g. `//user[1]/password`). Same engine as the LDAP/NoSQLi blind extractors. |
| [`xcat_cheat.md`](#/xpath/poc/xcat_cheat) | **xcat** (the reference tool) + a manual workflow + XPath 2.0 `doc()`/`unparsed-text()` OOB/file-read + native-XML-DB (XQuery) RCE functions (BaseX / MarkLogic / eXist). |

## Typical flow
1. **Auth bypass** — `xpath_fuzz.py` in LOGIN mode (learn success from your own good login = most reliable).
2. **Boolean oracle?** Extract a secret from **your own** record (`xpath_blind.py --max-chars 8`) to prove full-store disclosure.
3. **Search param** — `xpath_fuzz.py --param` for the boolean/error differential.
4. **Full automated extraction / OOB / file read** — `xcat` (see the cheat).

> A finding = a **steered** TRUE/FALSE (login without a password / data out / file read / code run), not a lone error. Own/test accounts, one benign proof, redact secrets. This injects into the **query**; injecting a `<!DOCTYPE>` into the XML *input* is **XXE** — a different kit.
