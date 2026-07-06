# OAuth / OIDC / SAML — Testing Checklist

**Author:** x8bitranjit
Two **own** test accounts (attacker + victim). Tick only what you actually reproduced. Impact = ATO.

## Phase 0 — Fingerprint
- [ ] Protocol identified: OAuth2 / OIDC / SAML (or which combination)
- [ ] Grant/flow: auth-code / +PKCE / implicit / hybrid / device / client-creds
- [ ] IdP identified (Google/MS/Okta/Auth0/Facebook/Apple/custom)
- [ ] SP-initiated vs IdP-initiated (SAML)
- [ ] OIDC discovery pulled (`/.well-known/openid-configuration`), `jwks_uri` saved
- [ ] All authz-request params captured (`client_id,redirect_uri,response_type,response_mode,scope,state,nonce,code_challenge,prompt`)
- [ ] Full SAMLRequest/SAMLResponse/RelayState captured & decoded

## Phase 1 — redirect_uri (code/token theft)
- [ ] Suffix / substring / prefix / subdomain bypass
- [ ] `@` userinfo, `#` fragment, backslash, encoded-traversal variants
- [ ] Path traversal → reflecting/open-redirect endpoint on allowed host
- [ ] localhost / 127.0.0.1 accepted
- [ ] Empty value / fallback-to-registered
- [ ] Parameter pollution (two `redirect_uri`)
- [ ] Exfil sink confirmed (Referer leak / open redirect / fragment / postMessage)
- [ ] **Code/token actually delivered to attacker host** (not just reflected)

## Phase 2 — state / CSRF
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
- [ ] `alg:none` / unsigned accepted
- [ ] Signature not verified at all
- [ ] `iss` not checked
- [ ] `aud` not pinned (token substitution from another client)
- [ ] `azp` confusion
- [ ] `kid`/`jku`/`x5u` injection (→ ../JWT/)
- [ ] `nonce` missing/reused (replay)

## Phase 6 — trust & linking
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
- [ ] "state missing" with **no** working CSRF/ATO → Info only
- [ ] `redirect_uri` **reflected** but code/token NOT delivered to you
- [ ] id_token readable / SAML base64-visible (that's normal)
- [ ] Tampered assertion that the server **rejected**
- [ ] PKCE absent on a **confidential** server-side client
- [ ] SAMLResponse "replays" only in the **same** browser session

## SAFE-PoC
- [ ] Own attacker + victim accounts only; never a real user's account
- [ ] Exfil to own listener; one proof request; no misuse of stolen creds
- [ ] One benign SSRF/metadata request then STOP; no data exfil
- [ ] Seeded accounts deleted; OOB/listeners torn down; tokens/keys redacted in report
