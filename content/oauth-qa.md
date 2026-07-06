# OAuth / OIDC / SAML — Zero to Expert (100 Q&A)

**Author:** x8bitranjit
Study companion + field reference for the federated-auth / SSO attack class. Advanced guide — pair with PortSwigger Academy, HackTricks, RFC 9700/6749, OIDC Core, and the SAML papers. Impact ceiling = **account takeover**.

---

## Level 0 — Fundamentals

**Q1. What problem does OAuth 2.0 solve?** Delegated **authorization** — letting App A access resources on Service B on a user's behalf **without** giving A the user's B password. It issues *access tokens*, not identities.

**Q2. OAuth vs OpenID Connect (OIDC)?** OAuth = authorization (access tokens). OIDC is an **identity layer on top of OAuth** that adds an **`id_token`** (a signed JWT proving *who* the user is) and the `openid` scope. "Login with Google" is OIDC.

**Q3. OAuth vs SAML?** Both do SSO/federation. SAML is older, XML-based, uses **signed XML assertions** posted to an ACS URL. OAuth/OIDC is JSON/JWT + HTTP redirects. Same mental model: IdP asserts identity → SP trusts it → local session.

**Q4. Define the roles.** *Resource Owner* (user), *Client* (the app requesting access), *Authorization Server / IdP* (issues codes/tokens/assertions), *Resource Server* (holds the API/data). In SAML: *Identity Provider (IdP)* and *Service Provider (SP)*.

**Q5. What's the authorization code flow, in one breath?** Client redirects user to IdP `/authorize` → user consents → IdP redirects back to `redirect_uri` with a short-lived `code` → client exchanges `code` at `/token` (server-side, with client auth) for `access_token`(+`id_token`) → client creates a session.

**Q6. Why is the code exchanged server-side instead of getting a token directly?** So the token never touches the browser/URL. The code is single-use, short-lived, and useless without the client's credentials (or PKCE verifier) — limits the damage of a leaked code.

**Q7. What is `state`?** A client-generated, session-bound, random value echoed through the flow. It's the **CSRF token** for OAuth — it ties the callback to the browser/session that started the flow.

**Q8. What is `nonce` (OIDC)?** A client value placed in the authorization request and echoed **inside the id_token**, binding the token to a specific request → prevents **id_token replay**.

**Q9. What is PKCE and why?** Proof Key for Code Exchange. The client sends `code_challenge` (hash of a secret `code_verifier`) at `/authorize` and the raw `code_verifier` at `/token`. A stolen code is useless without the verifier → protects **public** clients (SPAs, mobile) that can't keep a secret.

**Q10. What's a `redirect_uri` and why is it security-critical?** The callback the IdP sends the code/token to. If an attacker can steer it to their host, they steal the credential → it must be validated by **exact match** against pre-registered values.

---

## Level 1 — Flow mapping & recon

**Q11. How do you fingerprint which SSO protocol is in use?** Look for `client_id/redirect_uri/response_type` + `/authorize` (OAuth/OIDC), `scope=openid`+`id_token` (OIDC), `SAMLRequest/SAMLResponse/RelayState`+`<saml:Assertion>` (SAML).

**Q12. What does `/.well-known/openid-configuration` give you?** The OIDC discovery doc: `authorization_endpoint`, `token_endpoint`, `jwks_uri` (signing keys), `userinfo_endpoint`, supported `response_types`, `scopes_supported`, and `code_challenge_methods_supported` (does it support PKCE?).

**Q13. Why grab `jwks_uri` early?** It holds the public keys the SP should verify id_tokens against — you need it to reason about `kid`/`jku`/key-confusion attacks and to know what a correct signature looks like.

**Q14. Which grant types exist and which are leakiest?** Auth-code (safest), auth-code+PKCE, implicit (token in URL fragment — leaky, deprecated), hybrid, device code, client-credentials. Implicit and anything putting the credential in a URL/fragment leaks most.

**Q15. SP-initiated vs IdP-initiated SAML — why does it matter for attacks?** IdP-initiated sends an **unsolicited** SAMLResponse with **no `InResponseTo`** → no request/response binding, so replay and injection are easier.

**Q16. How do you decode a SAMLRequest in a redirect URL vs a POST?** Redirect binding = base64 + **raw DEFLATE** (`zlib.decompress(data, -15)`). POST binding = plain base64. Then pretty-print the XML.

**Q17. What parameters must you always capture before attacking?** `client_id, redirect_uri, response_type, response_mode, scope, state, nonce, code_challenge, code_challenge_method, prompt` — and the full SAMLRequest/Response/RelayState.

**Q18. What's `prompt=none`?** Silent authentication — no consent/login UI; used for token refresh in SPAs via a hidden iframe. Abused to grab tokens silently or test scope grants without consent.

**Q19. What's `response_mode`?** How the IdP delivers the result: `query`, `fragment`, `form_post`, or `web_message` (postMessage). Switching it can move a credential to a leakier channel.

**Q20. Where do you find the OAuth flow in a target?** JS bundles and HTML: grep for `client_id=`, `/authorize`, `/oauth`, `redirect_uri`, `SAMLRequest`, provider domains (`accounts.google.com`, `login.microsoftonline.com`). See [JavaScript Files](#/jsfiles/guide).

---

## Level 2 — redirect_uri attacks

**Q21. Why is `redirect_uri` the #1 OAuth bug?** It decides where the code/token is delivered. Any validation weakness = credential delivered to attacker = ATO. It's also the most commonly mis-implemented (startswith/contains instead of exact match).

**Q22. List validation bypasses for `redirect_uri`.** Suffix (`app.com.evil.com`), substring (`evil.com?x=app.com`), subdomain/wildcard too loose, `@`-userinfo (`app.com@evil.com`), fragment (`evil.com#app.com`), backslash/encoded-traversal parser diffs, path traversal to a reflecting endpoint, `localhost`, empty value, parameter pollution (two `redirect_uri`s).

**Q23. The exact-match is strict — how do you still steal the code?** Pivot to an **open redirect or reflecting endpoint on the allowed origin**. The code lands on the legit host, which then forwards it (Location/Referer) to you. Also XSS on the callback page.

**Q24. How does a Referer leak steal a code?** If the callback page loads any third-party resource *before* stripping `?code=` from the URL, the full URL (with the code) is sent in the `Referer` header to that third party.

**Q25. Why is the implicit flow (`response_type=token`) especially leaky?** The token is in the **URL fragment** (`#access_token=`), which survives redirects and is visible to any script/redirect on the page → open-redirect-preserving-fragment = token theft.

**Q26. What is `redirect_uri` parameter pollution?** Sending two `redirect_uri` values so the *validator* checks one and the *token issuer* uses the other (parser differential). Also mixing encoded `&`.

**Q27. Does stealing a `code` always give ATO?** Not if you can't redeem it (confidential client with a secret you lack, or PKCE that binds it). It's ATO when the client is **public/PKCE-less** or the token endpoint doesn't bind the code to client/verifier.

**Q28. How do you turn "redirect_uri accepts localhost" into a finding?** Run a listener on that port; the IdP delivers the code/token to `http://localhost:port` in the victim's browser — but you need to receive it, so combine with a local-app or a scenario where your app is the one registered. Often used against native/mobile clients with loopback redirects.

**Q29. What's the RFC 9700 stance on `redirect_uri`?** Exact string matching, no wildcards; and the `redirect_uri` at `/token` must match the one at `/authorize`. Also mandates PKCE for code flows and forbids the implicit flow.

**Q30. `redirect_uri` reflected in an error page — finding or not?** Not by itself (auto-reject). Only a finding if the IdP actually **issues the credential** to your host or a working redirect exists.

---

## Level 3 — state / CSRF

**Q31. What does a missing/weak `state` enable?** OAuth CSRF: forced login (session fixation) and — critically — **account-linking CSRF** where the attacker links their identity to the victim's account → ATO.

**Q32. Walk through the account-linking CSRF ATO.** Attacker starts the "link social account" flow, captures their own `code` but doesn't complete it. They send the victim (logged into their own account) a pre-baked callback URL with the attacker's `code`. The victim's browser completes the link → attacker's social identity is now linked to the victim's account → attacker logs in via social → inside the victim's account.

**Q33. How do you test `state` validation?** (1) omit it entirely, (2) use a constant, (3) reuse user A's `state` in user B's callback, (4) check predictability. If login still succeeds, it's not properly bound.

**Q34. Is "state is missing" a reportable bug on its own?** Low/Info only. You must demonstrate a real CSRF/ATO (e.g., forced link or forced login with impact). Report the *exploit*, not the missing parameter.

**Q35. What's session fixation via OAuth?** Attacker fixes the victim's post-login session to an attacker-known value or logs the victim into an attacker-controlled IdP account, capturing the victim's subsequent actions/data.

**Q36. Difference between `state` and `nonce`?** `state` protects the *request/response* (CSRF, client-side, any OAuth). `nonce` protects the *id_token* (replay, inside the token, OIDC only). You need both.

**Q37. How can `state` leak?** Via Referer (if the callback loads third-party content) or logs — but `state` leaking matters less than `code`; the concern is `state` being *absent/unvalidated*, not secret.

**Q38. Can CSRF exist even with `state`?** If `state` isn't bound to the user's session (e.g., globally valid, or validated only for format), yes. Always test cross-user reuse.

**Q39. What's "login CSRF"?** Forcing a victim to log in as the *attacker* (not the reverse) — then the victim enters data (payment card, notes) into the attacker's account, which the attacker later reads.

**Q40. Best evidence for a `state` finding?** Two-account demo: attacker link-code + victim click → screenshot of attacker's identity now able to log into victim's account, plus the exact callback URL used.

---

## Level 4 — code, PKCE, response_type

**Q41. How do you test authorization-code replay?** Exchange the code at `/token`, then exchange it again. RFC requires single-use; a second success = replay. Also try after the victim used it.

**Q42. What is `redirect_uri` binding at the token endpoint?** The `redirect_uri` sent to `/token` must equal the one from `/authorize`. Omitting/changing it and still getting tokens = a validation gap (enables some code-injection variants).

**Q43. How do you test for PKCE downgrade?** Remove `code_challenge` from `/authorize` (is PKCE optional?), or set `code_challenge_method=plain` (challenge==verifier, so knowing the request reveals the verifier), or send a wrong `code_verifier` at `/token` (is it checked?).

**Q44. Why does PKCE omission matter if there's already a client secret?** For **public** clients there is no secret, so PKCE is the *only* thing binding the code. If it's optional, a stolen code = ATO. For confidential clients PKCE is defense-in-depth.

**Q45. What's a `response_type` downgrade attack?** Changing `response_type=code` to `token`/`id_token token`. If the IdP honors it, the credential now rides in the URL fragment (much easier to leak). Works when multiple response types are registered/allowed.

**Q46. What's the `web_message` response mode risk?** The token is delivered via `postMessage`. If the client's `message` listener doesn't verify `event.origin`, an attacker page (opener/iframe) receives the token — combine with `prompt=none` for a silent grab.

**Q47. What's code injection / cross-session code?** Injecting an attacker-obtained code into a victim's session (pairs with missing `state`) so the victim's SP session binds to the attacker's IdP identity, or the attacker's session gets the victim's code.

**Q48. Can you redeem a code issued for client A as client B?** Test it — if the token endpoint doesn't bind the code to the issuing `client_id`, that's a confused-deputy/token-endpoint flaw.

**Q49. What is scope escalation?** Requesting broader scopes (`admin`, `offline_access`, extra APIs) than consented, and having them granted — especially silently on refresh or via `prompt=none`.

**Q50. What is `offline_access`?** The scope that grants a **refresh token** (long-lived). Silently obtaining it is worse than a short access token — persistent access.

---

## Level 5 — OIDC id_token forgery

**Q51. What must an SP validate on an id_token?** Signature (against `jwks_uri`), `iss`, `aud`==its `client_id`, `exp`/`iat`, `nonce`, and `azp` in multi-client cases — plus `email_verified` before trusting `email`.

**Q52. `alg:none` on an id_token — impact?** If the SP accepts an unsigned token, you forge any `sub`/`email` → log in as anyone → ATO. Same class as the JWT `alg:none` bug (see [JWT](#/jwt/guide)).

**Q53. What's an audience-confusion / token-substitution attack?** Present an id_token that's validly signed but issued for a **different client** (one you control). If the SP doesn't pin `aud` to *its* `client_id`, it accepts it → ATO. This is the "leaked token from another app works here" bug.

**Q54. How does `iss` confusion work?** If the SP doesn't verify the issuer, you mint a token from *your* IdP (or a multi-tenant issuer) carrying the victim's `sub`/`email`.

**Q55. How do `kid`/`jku`/`x5u` enable id_token forgery?** They tell the verifier which key/where to fetch it. If attacker-controllable, point the SP at *your* JWKS and sign with your key → forged token validates. Full technique in the JWT kit.

**Q56. Why is `nonce` critical for id_tokens?** Without it, a previously issued/leaked id_token can be **replayed** into a new session. The SP must bind the token's `nonce` to the session that requested it.

**Q57. The "Sign in with Apple" 2020 bug — what was it?** Apple's endpoint would issue a valid JWT for **any email** the attacker requested (JWT signed by Apple), and SPs trusted it → full ATO on any account. Root cause = unverified email / over-trusted issuer. ($100k bounty.)

**Q58. How do you test id_token signature verification quickly?** Tamper a claim and flip `alg` to `none` (or resign with a wrong key) and submit. If the SP accepts it, verification is broken. Use `poc/idtoken_tamper.py`.

**Q59. What's `azp` and its confusion case?** "Authorized party" — in multi-audience tokens it names the client the token was issued to. If ignored, a token meant for another party is accepted.

**Q60. If the SP verifies the signature correctly, is OIDC login safe?** No — it can still fail on `aud`/`iss`/`nonce`/`email_verified`, or on **account linking** (Level 6), which is where most modern OIDC ATOs actually live.

---

## Level 6 — trust, email linking, mix-up (the money bugs)

**Q61. What's the single most common modern SSO ATO?** **Account linking on an unverified email.** The SP matches/links accounts by the IdP's `email` claim; if you can assert an arbitrary/victim email (custom IdP, `email_verified:false` ignored, provider that lets you own any email), you land in the victim's account.

**Q62. Explain pre-account-takeover.** Attacker registers on the SP with the victim's email (via password) **before** the victim signs up. Later the victim "Sign in with Google" using that email; the SP merges by email into the attacker-seeded account → both share it, attacker's password persists → **zero-click, persistent ATO**.

**Q63. What's the reverse (post-registration) linking variant?** Attacker signs up via social first; victim later registers via password with the same email; SP merges → shared account.

**Q64. Why is `email_verified` the crux?** If the SP treats a claimed `email` as trusted without checking `email_verified:true`, any IdP (or attacker-controlled tenant) that lets you set an email hands you that account.

**Q65. What is the IdP mix-up attack?** On multi-IdP clients, the attacker makes the client believe a response from IdP-B (attacker's) belongs to the IdP-A flow the victim chose. The client sends the victim's code to the attacker's token endpoint. Mitigation = the `iss` response parameter; test whether the client checks it.

**Q66. What's a confused deputy in OAuth?** A credential (token/code) valid for one party is accepted by another because audience/client binding is missing (see `aud`, Q53). The "deputy" (SP) is confused into acting on the wrong principal's authority.

**Q67. How does open dynamic client registration get abused?** Register a client with `redirect_uri=evil.com`, or a `logo_uri`/`jwks_uri` you control → SSRF (server fetches logo/jwks), stored-XSS via client name on the consent screen, or a rogue "trusted" client.

**Q68. Same-email across two IdPs — attack?** Link via a weakly-verified IdP-A, then log in via IdP-B (or password) that trusts the linked email → identity confusion → ATO.

**Q69. How do you safely PoC a pre-account-takeover?** Use two **emails you own**. Seed the "victim" (own) account by password, then complete social login as that email, and show the attacker password still works inside the merged account. Never target a real user.

**Q70. Why do email-linking ATOs often bypass MFA?** SSO replaces the password step; if MFA was enforced on the password login but not re-checked on the SSO/link path, the attacker enters without it. Call this out — it raises severity.

---

## Level 7 — SAML signature attacks

**Q71. What secures a SAML assertion?** An **XML digital signature** (`<ds:Signature>`) over the assertion (and/or response). Break the *verification* and you forge identities. The signature must cover the **Assertion**, not just the Response.

**Q72. What is XML Signature Wrapping (XSW)?** You keep the validly-signed element so the signature check passes, but inject a second, forged element (different `NameID`) that the *application logic* actually reads. "Signature valid" and "app reads my forgery" are simultaneously true.

**Q73. How many canonical XSW patterns are there and why test all?** Eight (XSW1–8). Different SP libraries resolve "which element is signed vs read" differently, so a target may fall to one pattern and resist others. SAML Raider applies all eight.

**Q74. What's signature exclusion/stripping?** Removing `<ds:Signature>` entirely (or supplying an empty one) and submitting an unsigned assertion with an attacker `NameID`. SPs that only "validate if a signature is present" accept it → instant forge.

**Q75. Explain the SAML comment/canonicalization bug.** Some libraries return the text node differently than what was signed; inserting `<!---->` inside `NameID` (`admin@target.com<!---->.evil.com`) can make the app read `admin@target.com` while the signature validated the full string. This is the Duo/ruby-saml/OneLogin CVE family (2017–2018).

**Q76. What is cert faking / key confusion in SAML?** Re-sign the whole assertion with **your** key and swap `<ds:X509Certificate>` to your cert. If the SP validates against the embedded cert rather than a **pinned** IdP cert, it trusts your key → total forge.

**Q77. How do you test SAML signature validation from scratch?** Decode the Response, modify `NameID` to a victim, and try: (a) leaving the now-invalid signature, (b) stripping the signature, (c) XSW, (d) re-signing with your cert. Whichever the SP accepts reveals the flaw.

**Q78. Why is IdP-initiated SAML more dangerous?** Unsolicited assertions, no `InResponseTo` binding → the SP accepts an assertion not tied to any request it made, easing injection/replay.

**Q79. What is Golden SAML?** With the IdP's token-signing **private key** (e.g., from a compromised ADFS server), an attacker mints arbitrary valid assertions for any user at any federated SP — persistent, undetectable. Post-exploitation/red-team, not typical bounty.

**Q80. What XML parser bug pairs with SAML?** **XXE** — the SAMLResponse is attacker-supplied XML. Inject a DOCTYPE with external entities to read files or SSRF (see [XXE](#/xxe/guide)). Also billion-laughs DoS on weak parsers.

---

## Level 8 — SAML binding, replay, RelayState

**Q81. How do you test SAML assertion replay?** Capture a valid SAMLResponse and re-submit it in a **fresh** session / after logout. Accepted = missing one-time-use / `NotOnOrAfter` not enforced → re-login as that user.

**Q82. Which SAML conditions must the SP enforce?** `NotBefore`/`NotOnOrAfter` (validity window), `Audience` (this SP), `Recipient`/`Destination` (this ACS URL), `InResponseTo` (matches a request), and one-time-use. Missing any → replay/cross-SP attacks.

**Q83. What's a cross-SP assertion replay?** An assertion minted for SP-X is accepted at SP-Y because `Audience`/`Recipient` isn't checked → identity from one service reused at another.

**Q84. What is RelayState and how is it abused?** An opaque round-trip value, often used as the post-login return URL → **open redirect** (`RelayState=https://evil.com`) or reflected → **XSS**. Also a CSRF vector if it controls post-auth navigation.

**Q85. `InResponseTo` missing — what does it allow?** Injecting an unsolicited/attacker-crafted assertion into a victim's flow (no binding to a legitimate request), enabling forced login / assertion injection.

**Q86. How do you decode + re-encode a SAML POST for tampering?** `base64 -d` → edit XML → `base64 -w0`. For redirect binding, add the DEFLATE step. Burp + SAML Raider automates this.

**Q87. What signature-algorithm downgrades matter in SAML?** Accepting weak algs (RSA-SHA1) or, worse, an HMAC where the key is guessable/shared, or `Transforms` that strip content before signing. Check what `SignatureMethod`/`Transforms` the SP accepts.

**Q88. How is SSRF reached via SAML?** XXE external entities (`SYSTEM "http://169.254.169.254/..."`) in the parsed XML → server-side fetch → cloud metadata/IAM creds (chain to [SSRF](#/ssrf/guide)).

**Q89. What's the fastest SAML win to try first?** Signature **stripping** and a single **XSW** (via SAML Raider) with `NameID` changed to a test admin — many SPs fall immediately; it's the highest-impact/lowest-effort test.

**Q90. How do you keep SAML PoCs safe?** Forge to a `NameID` **you're authorized** to impersonate (your own test admin), one login proof, redact keys/certs, and never touch real users' assertions or data.

---

## Level 9 — Escalation, chaining, severity

**Q91. Turn "redirect_uri accepts my host" into maximum impact.** Capture the `code`/`token` at your listener → redeem (public/PKCE-less) or use the token → authenticate as the flow's user → screenshot the session. Argue Critical (pre-auth ATO, all users).

**Q92. Chain: strict redirect_uri but open redirect on the allowed origin.** Authorize with `redirect_uri` = the legit callback that internally forwards via a vulnerable `returnUrl` → the code lands on the legit host → it 302s/leaks to your host with the code intact → ATO. High/Critical.

**Q93. What chains amplify SSO bugs?** [JWT](#/jwt/guide) (id_token forgery, jku/kid), [XXE](#/xxe/guide) (SAML parser file-read/SSRF), [SSRF](#/ssrf/guide) (`request_uri` → metadata → IAM), open redirect (code exfil), [CORS](#/cors/guide) (readable token/userinfo endpoints), [CSRF](#/csrf/guide) (login/link CSRF).

**Q94. How do you justify Critical vs High for an SSO ATO?** Critical when it's zero/one-click, affects **any** account, and **bypasses MFA** (SSO usually does). High when it needs specific conditions/interaction or only affects a subset.

**Q95. What's the SSRF-from-IdP vector and its ceiling?** `request_uri`/`jku`/SAML-XXE make the **IdP/SP fetch attacker URLs** → internal services and cloud metadata → IAM credentials → potential account/infra compromise. High/Critical.

**Q96. What CVSS vector fits a typical pre-auth SSO ATO?** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` ≈ 9.1 (adjust `UI`/`AC` for interaction/conditions). MFA-bypass and full-account reach push it to Critical.

**Q97. What are the top false positives to auto-reject?** "state missing" with no exploit; reflected-not-delivered `redirect_uri`; readable id_token/visible SAML; server-**rejected** tampering; PKCE absent on confidential clients; SAMLResponse "replaying" in the same session. Report only when you can **authenticate as someone you shouldn't**.

**Q98. What's the SAFE-PoC rule for federated auth?** Two accounts you own (attacker+victim); exfiltrate only to your listener; one benign proof; never misuse stolen creds or forge a real admin; tear down OOB servers; delete seeded accounts; redact tokens/keys.

**Q99. Which specs do you cite to speed up triage?** RFC 9700 (OAuth Security BCP), RFC 6749/6819, OIDC Core §3.1.3, SAML 2.0 Profiles §4.1.4 (subject confirmation/conditions). Quote the exact clause the target violates.

**Q100. If you learn one thing about SSO testing, what is it?** *Follow the assertion.* Every bug is stealing, forging, confusing, or replaying the identity assertion (code/token/id_token/SAMLResponse). Find where trust is granted without proof — a mis-matched `redirect_uri`, a missing `state`, an unverified `email`, an unsigned assertion — and you have an account takeover. **Report the ATO, not the missing parameter.**

---

## Defense quick-reference
- **redirect_uri:** exact match, no wildcards; bind at `/token`.
- **state:** random, session-bound, single-use, required.
- **PKCE:** `S256` required for public clients; verify `code_verifier`.
- **id_token:** verify sig vs `jwks_uri`; pin `iss`+`aud`; reject `alg:none`; enforce `nonce`; honor `email_verified`.
- **Account linking:** never auto-merge on unverified email; require re-verification.
- **SAML:** signed Assertion required; reject unsigned/stripped/XSW; pin IdP cert; enforce conditions + one-time-use; disable DTD/external entities; patched canonicalization.
- **request_uri/jku:** deny SSRF; allow-list.
- Adopt RFC 9700 end-to-end.
