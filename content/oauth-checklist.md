# OAuth / OIDC / SAML — Testing Checklist

**Author:** x8bitranjit
Two **own** test accounts (attacker + victim). Tick only what you actually reproduced. Impact = ATO.

## Phase 0 — Fingerprint
*Why this matters:* the attacks differ by protocol and grant, so you must first know *which ID-card system* you're facing and *which flow* it uses. Capturing every parameter now gives you the exact list of things to tamper with — you can't attack a handshake you haven't fully written down.
- [ ] Protocol identified: OAuth2 / OIDC / SAML (or which combination)
- [ ] Grant/flow: auth-code / +PKCE / implicit / hybrid / device / client-creds
- [ ] IdP identified (Google/MS/Okta/Auth0/Facebook/Apple/custom)
- [ ] SP-initiated vs IdP-initiated (SAML)
- [ ] OIDC discovery pulled (`/.well-known/openid-configuration`), `jwks_uri` saved
- [ ] All authz-request params captured (`client_id,redirect_uri,response_type,response_mode,scope,state,nonce,code_challenge,prompt`)
- [ ] Full SAMLRequest/SAMLResponse/RelayState captured & decoded

## Phase 1 — redirect_uri (code/token theft)
*Why this matters:* this is the #1 OAuth bug — "where does the IdP mail the ID card?" A sloppy check here mails the victim's login credential to you. The last box is the real test: reflection isn't enough — the code/token must actually be **delivered to a host you control**.
- [ ] Suffix / substring / prefix / subdomain bypass
- [ ] `@` userinfo, `#` fragment, backslash, encoded-traversal variants
- [ ] Path traversal → reflecting/open-redirect endpoint on allowed host
- [ ] localhost / 127.0.0.1 accepted
- [ ] Empty value / fallback-to-registered
- [ ] Parameter pollution (two `redirect_uri`)
- [ ] Exfil sink confirmed (Referer leak / open redirect / fragment / postMessage)
- [ ] **Code/token actually delivered to attacker host** (not just reflected)

## Phase 2 — state / CSRF
*Why this matters:* `state` is the "receipt number" that stops an attacker splicing their login into your session. Break it and the prize is the **account-linking silent ATO** (last box) — glue your identity onto a victim's account with one click from them.
- [ ] `state` missing accepted
- [ ] `state` not validated (constant/changed)
- [ ] `state` not bound to session (cross-user)
- [ ] `state` predictable
- [ ] **Account-linking CSRF → silent ATO** (if a link feature exists)

## Phase 3 — code / PKCE
- [ ] Code replay (redeem twice)
- [ ] `redirect_uri` mismatch/omission accepted at `/token`
- [ ] Code redeemable by a different `client_id`
- [ ] PKCE omission accepted (public client)
- [ ] `code_challenge_method=plain` downgrade
- [ ] `code_verifier` not verified

## Phase 4 — response_type / mode / scope
- [ ] `code` → `token`/`id_token token` downgrade honored
- [ ] `response_mode` switch to leakier channel
- [ ] `web_message`/postMessage listener missing origin check
- [ ] Scope escalation / silent grant via `prompt=none`

## Phase 5 — OIDC id_token
*Why this matters:* the `id_token` is the ID card itself. Each box is one verification the app might skip — signature, issuer, audience, nonce. Any skipped check lets you **forge or substitute** the card and log in as anyone.
- [ ] `alg:none` / unsigned accepted
- [ ] Signature not verified at all
- [ ] `iss` not checked
- [ ] `aud` not pinned (token substitution from another client)
- [ ] `azp` confusion
- [ ] `kid`/`jku`/`x5u` injection (→ ../JWT/)
- [ ] `nonce` missing/reused (replay)

## Phase 6 — trust & linking
*Why this matters:* the highest-value, no-crypto SSO bugs live here — the app trusting an email it shouldn't. **Pre-account-takeover** (seed the victim's email first, they SSO in, accounts merge) is frequently a zero-click Critical and the one most hunters miss.
- [ ] Unverified `email` / ignores `email_verified:false`
- [ ] **Pre-account-takeover** (attacker seeds account by victim email first)
- [ ] Same-email multi-IdP confusion
- [ ] IdP mix-up (`iss` response param not checked)
- [ ] Confused deputy (token audience not pinned)
- [ ] Open dynamic client registration abuse

## Phase 7 — request_uri / SSRF
- [ ] `request_uri` fetched server-side (OOB confirm)
- [ ] SSRF → internal / cloud metadata → IAM creds (→ ../SSRF/)

## Phase 8 — SAML
*Why this matters:* SAML's entire trust is the XML signature over the assertion, so these boxes are the ways to break or dodge that check — strip it, wrap it (XSW), comment-inject it, or re-sign with your own cert. Start with stripping + one XSW (`NameID`=test admin); many SPs fall immediately.
- [ ] Signature exclusion / stripping accepted
- [ ] Unsigned assertion inside signed Response trusted
- [ ] XSW1–8 (each — SAML Raider) — at least one accepted
- [ ] Comment / canonicalization injection in NameID
- [ ] Cert faking / key confusion (re-sign with own key)
- [ ] Algorithm downgrade / weak alg
- [ ] XXE in SAML parser (→ ../XXE/)
- [ ] Assertion replay (fresh session / after logout)
- [ ] `NotBefore`/`NotOnOrAfter` not enforced
- [ ] `Recipient`/`Destination`/`Audience` cross-SP replay
- [ ] `InResponseTo` missing/unbound (IdP-initiated injection)
- [ ] RelayState open redirect / XSS

## Phase 9 — Escalate & validate
- [ ] Proved **login as / privileges of** an identity you shouldn't have
- [ ] Confirmed reach (all users? admin?) and interaction (zero/one-click?)
- [ ] Confirmed MFA bypass (SSO ATO usually skips MFA — argue severity up)
- [ ] Chained where possible (JWT/XXE/SSRF/open-redirect)

## AUTO-REJECT (don't report these alone)
*Why this matters:* every line is the *observation* mistaken for the *exploit* — the trap that gets SSO reports closed as duplicate/informational. A readable token, a visible SAML blob, a missing parameter, or a tampered assertion the server **rejected** are not findings. Report only when you actually logged in as an identity you shouldn't have.
- [ ] "state missing" with **no** working CSRF/ATO → Info only
- [ ] `redirect_uri` **reflected** but code/token NOT delivered to you
- [ ] id_token readable / SAML base64-visible (that's normal)
- [ ] Tampered assertion that the server **rejected**
- [ ] PKCE absent on a **confidential** server-side client
- [ ] SAMLResponse "replays" only in the **same** browser session

## SAFE-PoC
*Why this matters:* these bugs take over real accounts, so the discipline keeps you legal — prove the mechanism on **two accounts you own**, land one benign proof, and stop. Never take over a real user, never misuse stolen creds, never forge a real admin; clean up after.
- [ ] Own attacker + victim accounts only; never a real user's account
- [ ] Exfil to own listener; one proof request; no misuse of stolen creds
- [ ] One benign SSRF/metadata request then STOP; no data exfil
- [ ] Seeded accounts deleted; OOB/listeners torn down; tokens/keys redacted in report
