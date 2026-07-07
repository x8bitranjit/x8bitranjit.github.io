# OAuth 2.0 / OIDC / SAML SSO — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** Federated authentication & Single Sign-On (OAuth 2.0, OpenID Connect, SAML 2.0)
**Impact ceiling:** **Full Account Takeover (ATO)** — pre-auth, one-click or zero-click, often on *every* account.
**Primary CWEs:** CWE-287 (Improper Authentication) · CWE-290 (Auth Bypass by Spoofing) · CWE-347 (Improper Verification of Cryptographic Signature) · CWE-352 (CSRF) · CWE-601 (Open Redirect) · CWE-918 (SSRF)

> ⚠️ **This is an advanced guide.** Before any section, read the fundamentals from **PortSwigger Web Security Academy (OAuth / OpenID / SAML labs)**, **HackTricks (OAuth to Account takeover, SAML Attacks)**, **OAuth 2.0 RFC 6749 + Security BCP RFC 9700**, **OIDC Core spec**, and **Cure53 / Compass Security SAML research**. This guide assumes you already know *what* an authorization code is — it teaches you how to *break the flow* and *report the impact*.

---

## Read this first — why SSO bugs are the highest-paying auth bugs

Federated auth is the front door to the whole account. A single flaw in the *handshake* — a mis-validated `redirect_uri`, a missing `state`, an unsigned SAML assertion, an unverified `email` claim — hands you **someone else's session without their password and without their MFA**. That is why these consistently pay **High–Critical**:

- You are not bypassing *one* control, you are bypassing **authentication itself**.
- The bug is usually **pre-authentication** (you attack the login flow) and **affects all users**, not one object (contrast IDOR).
- MFA/2FA usually sits *behind* the password, but SSO *replaces* the password — so an SSO takeover frequently **skips MFA entirely**.
- Fixes are protocol-level, so the same class recurs across every product a company ships.

**Report the impact, not the condition.** "The `state` parameter is missing" is a config note. "I can silently link my attacker identity to any victim's account and log in as them by getting them to click one link" is a **Critical ATO**. Always drive to: *whose account did I take over, with how much victim interaction, and does it bypass MFA?*

**The three technologies, one mental model.** All three are: *IdP asserts an identity → SP trusts the assertion → SP creates a local session.* Every bug is one of:
1. **Steal the assertion** (code/token/SAMLResponse) — via redirect/referrer/postMessage/logging.
2. **Forge or tamper the assertion** — unsigned/`alg:none`/XSW/unverified claim.
3. **Confuse the trust** — wrong audience, wrong IdP (mix-up), wrong client (confused deputy), unverified email → account linking.
4. **Replay the assertion** — no nonce/no NotOnOrAfter/no one-time-use.

---

## Master Testing Sequence (do it in this order)

1. **Fingerprint the flow.** Which protocol (OAuth2/OIDC/SAML)? Which grant (auth-code, implicit, hybrid, PKCE, client-credentials, device)? Who is the IdP (Google/Microsoft/Okta/Auth0/Facebook/Apple/custom)? SP-initiated or IdP-initiated?
2. **Capture every parameter** of the authorization request and the callback: `client_id, redirect_uri, response_type, response_mode, scope, state, nonce, code_challenge, prompt` — and for SAML the full `SAMLRequest`/`SAMLResponse`/`RelayState`.
3. **Attack the request → response leg** (redirect_uri, state/CSRF, response_type/mode switch, scope, PKCE).
4. **Attack the token/assertion itself** (ID-token signature/claims, SAML signature/XSW, replay).
5. **Attack the trust & linking logic** (unverified email → pre-account-takeover / account linking, confused deputy, IdP mix-up).
6. **Escalate to ATO** and chain (open redirect on client, SSRF via request_uri, XXE in SAML parser).
7. **Validate → severity → SAFE-PoC → report.**

---

# PART I — Fingerprint & map the flow

## 1.1 Identify the protocol

| Signal | Protocol |
|--------|----------|
| `response_type=code`/`token`/`id_token`, `client_id`, `redirect_uri`, `/authorize`, `/oauth/token` | **OAuth 2.0 / OIDC** |
| `scope=openid`, an `id_token` (JWT) returned, `/.well-known/openid-configuration` | **OpenID Connect** (OAuth + identity layer) |
| `SAMLRequest`/`SAMLResponse` (base64 XML), `RelayState`, `/saml/acs`, `/sso`, `AuthnRequest`, `<saml:Assertion>` | **SAML 2.0** |
| Provider-specific: `login.microsoftonline.com`, `accounts.google.com`, `appleid.apple.com`, `facebook.com/dialog/oauth` | branded IdP |

**OIDC discovery** (free recon): fetch `https://IDP/.well-known/openid-configuration` → gives `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, supported `response_type`s, `scopes_supported`, whether **PKCE** (`code_challenge_methods_supported`) is advertised. `jwks_uri` gives the signing keys — pull it for ID-token validation testing (see [JWT](#/jwt/guide)).

## 1.2 Which grant / flow?

- **Authorization Code** (`response_type=code`) — code returned to `redirect_uri`, exchanged server-side for tokens. Most common, most attack surface on the *code leg*.
- **Authorization Code + PKCE** (`code_challenge`, `code_verifier`) — public/mobile/SPA clients. Test for **PKCE downgrade/omission**.
- **Implicit** (`response_type=token`/`id_token token`) — token returned in the **URL fragment** (`#access_token=`). Legacy, leaky; deprecated by RFC 9700 but still shipped.
- **Hybrid** (`response_type=code id_token`, etc.) — mix; watch for the id_token being trusted without the code exchange.
- **Device Code** (`urn:ietf:params:oauth:grant-type:device_code`) — TV/CLI; phishing surface (user-code social-engineering).
- **Client Credentials** — machine-to-machine, no user; test for leaked client secret.

## 1.3 SP-initiated vs IdP-initiated (SAML especially)

- **SP-initiated:** you hit the SP → it redirects to IdP with a signed `AuthnRequest` → IdP posts a `SAMLResponse` back to the SP's ACS. Replay & `InResponseTo` binding matter.
- **IdP-initiated:** the IdP posts an *unsolicited* `SAMLResponse` to the ACS with **no `InResponseTo`**. This kills replay/CSRF protections and is a rich target — an unsolicited, forgeable, replayable assertion.

---

# PART II — OAuth 2.0 / OIDC attacks

## 2.1 `redirect_uri` validation — steal the code/token (the #1 OAuth bug)

The IdP sends the code/token to `redirect_uri`. If you can make it point at **your** host (or a page you control on the client), you steal the credential. Test **every** relaxation of the match:

```
# Baseline (legit):
redirect_uri=https://app.example.com/callback

# ── Weak allow-listing bypasses ──
redirect_uri=https://app.example.com.evil.com/callback      # suffix not anchored
redirect_uri=https://evil.com?x=app.example.com/callback     # substring match
redirect_uri=https://evilapp.example.com/callback            # prefix / subdomain wildcard too loose
redirect_uri=https://app.example.com@evil.com/callback       # userinfo confusion → host is evil.com
redirect_uri=https://evil.com#app.example.com/callback       # fragment
redirect_uri=https://evil.com\.app.example.com/callback      # backslash parser differential
redirect_uri=https://evil.com%2f%2eapp.example.com/          # encoded traversal

# ── Path / traversal within an allowed host ──
redirect_uri=https://app.example.com/callback/../../oauth/echo   # reach a reflecting/open-redirect endpoint
redirect_uri=https://app.example.com/callback/%2e%2e/redirect

# ── Registered but abusable values ──
redirect_uri=http://localhost:1337/                          # localhost allowed → run a listener
redirect_uri=https://app.example.com/oauth/callback?next=https://evil.com   # open redirect after landing

# ── Scheme / exotic ──
redirect_uri=javascript://app.example.com/%0aalert(document.domain)
redirect_uri=data:text/html,<script>...</script>
redirect_uri= (empty)          # some IdPs fall back to first registered / or reflect

# ── Parameter pollution (send TWO) — parser differential between validator and issuer ──
redirect_uri=https://app.example.com/callback&redirect_uri=https://evil.com/
```

**If the exact-match is strict:** pivot to an **open redirect or reflected-page on the *allowed* origin** (see [SSRF](#/ssrf/guide) and open-redirect testing). `redirect_uri=https://app.example.com/valid/callback` where `/valid/callback?returnUrl=` bounces to your host → the code lands on the allowed host, then the app forwards it (in `Location` or `Referer`) to you. This is the single most common way strict `redirect_uri` gets broken in the wild.

**Code/token exfiltration once it lands on a host you influence:**
- **Referer leak:** if the callback page loads any third-party resource (analytics, an `<img>`, an ad) *before* stripping the code from the URL, the full URL (with `?code=`) leaks in the `Referer` header to that third party.
- **Fragment leak (implicit):** `#access_token=` survives redirects; an open redirect that preserves the fragment ships the token to you.
- **Browser history / logs / proxy** if over a non-HTTPS hop.

→ **Impact:** steal `code` → exchange at `/token` (if you also have/guessed the client auth, or the client is public/PKCE-less) → victim's tokens → **ATO**. Steal `access_token`/`id_token` directly (implicit) → **ATO**.

## 2.2 `state` — CSRF on the OAuth flow / forced login (login CSRF → stealthy ATO)

`state` is the OAuth CSRF token binding the callback to the user who started the flow. Test:

1. **Missing entirely?** Start a flow, delete `state` from the authorization request and the callback — does login still succeed? → **CSRF vulnerable.**
2. **Not validated?** Change `state` to a constant/`state=x` on the callback — accepted? → not bound.
3. **Not tied to session?** Use user A's `state` value to complete user B's callback → accepted? → replayable.
4. **Predictable?** `state=1`, timestamp, sequential → forgeable.

**The classic exploit — account-linking CSRF (silent ATO):**
> On a site that lets you *link* a social login to an existing account, capture **your own** attacker `code` (from the "link Google" flow) but **don't** complete it. Craft a callback URL with *your* `code` and send it to the victim (they're logged into their own account). Their browser completes the link → **your Google identity is now linked to the victim's account** → you log in via Google → you're in **their** account. No `state` = this works. This is the highest-value `state` finding.

→ **Impact:** with account linking present → **full ATO** (attacker-interaction: one click). Without linking → forced login / session fixation (lower, but real).

## 2.3 Authorization-code flaws

- **Code reuse / replay:** exchange a `code` at `/token`, then exchange it **again**. RFC says single-use; if the second exchange also returns tokens → replay. Also try the code after the victim already used it.
- **Code fixation / injection:** inject an attacker-obtained `code` into the victim's session (pairs with missing `state`) → victim's SP session bound to attacker's IdP identity, or vice-versa.
- **Code for a different client:** get a `code` for `client_id=A`, try to redeem it while authenticating as `client_id=B` (confused deputy at the token endpoint).
- **Cross-`redirect_uri` redemption:** RFC 9700 requires the `redirect_uri` at `/token` to match the one at `/authorize`. Omit or change it at `/token` — accepted? → validation gap.
- **Code leakage via Referer/logs:** see 2.1.

## 2.4 PKCE — downgrade & omission (public clients)

PKCE binds the `code` to a secret (`code_verifier`) the client holds, so a stolen code is useless. Attacks:

- **PKCE omission accepted:** the client normally sends `code_challenge`; try the flow **without** it — if `/token` issues tokens without a `code_verifier`, PKCE is optional → a stolen code is fully usable.
- **`code_challenge_method=plain` downgrade:** force `plain` (challenge == verifier) so knowing the challenge (it's in the request) == knowing the verifier.
- **Verifier not checked:** send any `code_verifier` at `/token` → if accepted, PKCE is theater.
- **Challenge/verifier confusion across sessions.**

→ Pairs with 2.1: strict `redirect_uri` + PKCE is the modern defense; break *either* and code theft becomes ATO again.

## 2.5 `response_type` / `response_mode` switching

- **Downgrade to implicit:** if `response_type=code`, try `response_type=token` or `id_token token` — if the IdP honors it, the **token now rides in the URL fragment** (far easier to leak via 2.1). Many IdPs allow multiple registered response types.
- **`response_mode=form_post` → `query`/`fragment`:** switch where the credential is delivered to land it somewhere leakier (query → Referer/logs).
- **`response_mode=web_message` (postMessage):** the token is delivered via `postMessage`. If the client's message listener doesn't verify `event.origin`, a page you control (opened as the opener/iframe) **receives the token**. Test the silent-auth iframe flow (`prompt=none`) for missing origin checks.

## 2.6 Scope manipulation & consent bypass

- **Scope escalation:** add `scope=... admin`/`offline_access`/extra API scopes — granted without re-consent?
- **Scope-upgrade on refresh:** request broader scopes when refreshing than originally consented.
- **Consent bypass via `prompt=none`:** silently obtain tokens without the consent screen (fine if already consented; a problem if it grants *new* scopes silently).

## 2.7 OIDC ID-token validation (forge the identity)

The `id_token` is a JWT the SP must verify (signature + `iss` + `aud` + `exp` + `nonce`). Every JWT attack applies — see **[JWT](#/jwt/guide)** — plus OIDC-specific claim checks:

- **`alg:none`** — strip the signature; SP accepts an unsigned id_token → forge any `sub`/`email` → ATO.
- **Signature not verified** at all (SP just base64-decodes the JWT) → forge freely.
- **`iss` not checked** — mint a token from *your* IdP with the victim's `sub`.
- **`aud` not checked** — a **token-substitution / audience-confusion** attack: take a valid id_token issued for a *different* client (that you control) and present it to this SP. If `aud` isn't pinned to *this* `client_id`, it's accepted → ATO. (This is the OAuth "leaked token from another app" class.)
- **`azp` (authorized party) confusion** in multi-client setups.
- **`kid`/`jku`/`x5u` injection** — point the SP at attacker-controlled keys (JWKS injection). See JWT kit.
- **`nonce` missing/reused** — replay a previously valid id_token; without a per-request `nonce` bound to the session, an old/leaked id_token is reusable.
- **`email`/`email_verified` trust** — see 2.9 (the account-linking killer).

## 2.8 `request_uri` / JAR / PAR — SSRF & injection

OIDC lets the client pass the request by reference: `request_uri=https://client/req.jwt`. The **IdP fetches that URL server-side** → **SSRF from the IdP** (`request_uri=http://169.254.169.254/latest/meta-data/...`, internal hosts, `file://`). Also test `request` (JWT-secured Authorization Request/JAR) for parameter injection. See **[SSRF](#/ssrf/guide)** for the metadata/cloud-creds escalation.

## 2.9 Account linking & unverified email → **pre-account-takeover** (the money bug)

Modern SSO ATO usually comes from **identity linking on an unverified attribute**, not crypto:

- **Unverified `email` linking:** SP links/logs-in by matching the IdP's `email` claim to a local account. If the IdP (or a self-hosted/custom IdP, or a provider that doesn't verify email like some SAML/OIDC setups) lets you set an arbitrary `email`, register with the **victim's email** → SSO logs you into the victim's account. Always check `email_verified` handling: if the SP ignores `email_verified:false`, you win.
- **Pre-account takeover:**
  1. Attacker registers on the SP with `victim@email` **via password** (or via a social login the SP doesn't verify) *before* the victim signs up.
  2. Victim later "Sign in with Google" using `victim@email`.
  3. SP **merges** by email into the pre-existing attacker-seeded account → both now share it → attacker keeps their password → **persistent ATO**.
  - Reverse variant: attacker signs up via social first, victim registers via password, accounts merge.
- **Provider that lets you own any email:** "Sign in with Apple" hide-my-email, custom IdPs, or IdPs where you control the mail domain → assert `victim@target.com`.
- **Same email, multiple IdPs:** link via IdP-A (weakly verified), log in via IdP-B — trust confusion.

→ **Impact:** **full, persistent ATO**, often **zero victim interaction** (attacker seeds first). This is frequently Critical.

## 2.10 IdP mix-up & confused deputy

- **IdP mix-up (RFC 9700 §4.4):** on multi-IdP clients, start a flow choosing IdP-A but have the response come from IdP-B (attacker-controlled). If the client doesn't track *which* IdP a response belongs to (no `iss` in the response, no per-IdP `state`), it sends the code to A's token endpoint → attacker's IdP learns the victim's code. Mitigation is the `iss` response param — test whether the client checks it.
- **Confused deputy:** a token/code valid for one client used to authenticate at another; audience not pinned (see 2.7 `aud`).
- **Cross-account request forgery / cuckoo's token:** attacker's valid token injected into victim's session.

## 2.11 Dynamic client registration & other endpoints

- **Open dynamic registration** (`/register`): register a client with `redirect_uri=https://evil.com` and a `logo_uri`/`jwks_uri` you control → SSRF (server fetches logo/jwks), stored-XSS via client name on the consent screen, or a rogue trusted client.
- **`logout`/RP-initiated logout** `post_logout_redirect_uri` → open redirect.
- **Token endpoint auth:** try `client_secret` = empty/`none`/leaked-from-JS; public client accepting confidential-only grants.

---

# PART III — SAML 2.0 attacks

SAML's security rests entirely on the **XML signature** over the assertion. Break the signature verification and you forge identities. Decode `SAMLResponse` (base64, sometimes DEFLATE for redirect-binding) → pretty-print the XML → locate `<ds:Signature>`, what it references (`Reference URI="#..."`), and whether the **Assertion** (not just the Response) is signed.

## 3.1 XML Signature Wrapping (XSW) — the flagship SAML attack

The verifier checks the signature over the *original* element, but the application reads a *different, injected* element. You wrap/relocate nodes so both "the signature is valid" and "the app reads my forged assertion" are true. **All 8 canonical XSW patterns** (per Somorovsky et al. / the SAML Raider tool):

- **XSW1–2:** operate on the **Response** signature — add a second (forged) Response/Assertion as a sibling; the signature still references the original, the app processes the forged one.
- **XSW3–4:** forged Assertion as a sibling of the original signed Assertion (forged before/after).
- **XSW5–6:** copy the signature into the forged assertion / move the original assertion into an unusual location.
- **XSW7–8:** abuse `Extensions` / a wrapper element to hide the original signed assertion while the app reads the injected one.

Automate with **SAML Raider** (Burp) — it applies all 8 and re-signs; test each because different SP libraries fall to different patterns. Change `NameID`/attributes to the victim (`admin@target.com`) in the forged copy.

## 3.2 Signature exclusion / stripping

- **Remove `<ds:Signature>` entirely** and submit an unsigned assertion with your chosen `NameID`. Poorly configured SPs (or ones that only *validate if present*) accept it → **instant forge**.
- **Sign nothing but claim it's signed:** empty/garbage signature accepted.
- **Unsigned assertion inside a signed Response** (or vice-versa) — SP validates the Response signature but trusts an *unsigned Assertion* it contains.

## 3.3 XML canonicalization / comment injection (the "\<!--\-->" ATO)

Signature covers a *canonicalized* form; some libraries return a *different* string to the app than what was signed, exploitable via comments:

```
<saml:NameID>admin@target.com<!---->.evil.com</saml:NameID>
```
Depending on how the SP extracts text nodes after canonicalization, it may read `admin@target.com` (before the comment) while the signature validated over the full string. This is the **Duo/Duo-Labs SAML comment bug** class (CVE-2018-0489 family, affected many libraries). Test comment insertion inside `NameID`/attribute values around the username boundary.

## 3.4 Signature algorithm / key attacks

- **`alg` downgrade / weak alg** — accepted RSA-SHA1, or HMAC where key is guessable.
- **Certificate faking / self-signed acceptance:** re-sign the whole assertion with **your own** cert/key and swap the `<ds:X509Certificate>` to yours. If the SP trusts *any* cert in the message instead of a pinned IdP cert, it validates against your key → total forge (**"Key Confusion / cert injection"**).
- **XML signature over the wrong element** (`Reference URI=""` or pointing at an element you control).

## 3.5 XXE & SSRF in the SAML parser

`SAMLResponse` is attacker-supplied XML → a prime **XXE** target. Inject a DOCTYPE with external entities to read files / SSRF / blind-OOB — full technique in **[XXE](#/xxe/guide)**:

```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
... <saml:NameID>&xxe;</saml:NameID> ...
```
Also **SSRF** via entity URLs to cloud metadata → IAM creds → RCE-adjacent. Many SAML libs disable DTDs now — test anyway, especially older/custom parsers.

## 3.6 Replay & binding flaws

- **Assertion replay:** capture a valid `SAMLResponse` and submit it again — accepted after first use? Missing one-time-use / `NotOnOrAfter` not enforced → replay = re-login as that user.
- **`NotBefore`/`NotOnOrAfter` not enforced** — expired assertions accepted.
- **`Recipient`/`Destination`/`Audience` not checked** — an assertion minted for SP-X accepted at SP-Y (audience confusion / cross-SP replay).
- **`InResponseTo` missing/unbound** (IdP-initiated) — inject an unsolicited assertion into a victim's flow.
- **RelayState open redirect / injection** — `RelayState` is often used as the post-login return URL → open redirect, or reflected → XSS.

## 3.7 Golden SAML (post-exploitation / red-team)

If you obtain the IdP's **token-signing private key** (e.g., ADFS `AD FS` key from a compromised host), you can **mint arbitrary assertions for any user at any SP** indefinitely — the SAML analog of Golden Ticket. Out of scope for most bounty PoCs (requires key compromise) but the reason SAML key protection is Critical; note it in red-team engagements.

---

# PART IV — Escalate to ATO & chain

**"You found X → now do Y":**

| You found | Do this to prove ATO | Severity |
|-----------|----------------------|----------|
| `redirect_uri` accepts your host | Capture `code`/`token` → redeem → log in as the flow's user. If PKCE-less/public client, full ATO. | Critical/High |
| Strict `redirect_uri` **but** open redirect on the allowed origin | Chain: authorize → land on allowed host → it forwards `code` to you (Location/Referer). | High/Critical |
| Missing/unvalidated `state` + account-linking feature | Silent account-link CSRF → log in as victim (one victim click). | Critical |
| Unverified `email` / ignores `email_verified` | Register/assert `victim@email` → SSO into victim account (often zero-click via pre-ATO seeding). | Critical |
| `id_token` `alg:none` / sig-not-verified / `aud` unpinned | Forge/substitute id_token with victim `sub`/`email` → ATO. | Critical |
| SAML XSW / sig-strip / comment injection | Forge assertion with `NameID=admin@target` → admin session. | Critical |
| `request_uri` SSRF | Fetch cloud metadata → IAM creds → pivot (see SSRF kit). | High/Critical |
| SAML XXE | File read (`/etc/passwd`, app config, private keys) or blind OOB. | High/Critical |
| Implicit-flow token in fragment + any open redirect | Exfiltrate `access_token` → API access as victim. | High |

**Chaining map:** [JWT](#/jwt/guide) (id_token forgery, jku/kid) · [XXE](#/xxe/guide) (SAML parser) · [SSRF](#/ssrf/guide) (`request_uri`, metadata) · open-redirect on the client (code exfil) · [CSRF](#/csrf/guide) (login/link CSRF) · [CORS](#/cors/guide) (token endpoint / userinfo readable cross-origin).

---

# PART V — Validity, false positives, severity, reporting

## 5.1 False-positive auto-reject table

| Observation | Why it's NOT (yet) a finding | What would make it real |
|-------------|------------------------------|-------------------------|
| "`state` is missing" | Config note only | A working **login/link CSRF** that changes account state or logs you into another account |
| "`redirect_uri` reflects my value in an error page" | Reflection ≠ redirect | The IdP actually **issues the code/token to your host**, or a working redirect |
| "id_token is a JWT with readable claims" | JWTs are meant to be read | The **SP accepts a token you tampered/forged** (sig not verified) |
| "SAML assertion is base64/plaintext-visible" | That's normal | A **modified** assertion (XSW/strip/comment) is **accepted** |
| "access_token appears in the URL" (implicit) | By design for implicit | You can **exfiltrate** it to a third party (open redirect/Referer/postMessage) |
| "consent screen shows my app name" | Expected | Silent scope grant, or stored-XSS via app name |
| "PKCE not present" | Confidential server-side clients don't need it | A **public** client where a stolen code is redeemable without a verifier |
| "SAMLResponse replays in my own browser session" | Same session re-post | Replay in a **fresh/other** session, or after logout, still authenticates |
| Redirect to `login.microsoftonline.com`/IdP | That's the flow | — |

**Golden rule:** a federated-auth finding is real only when you can **authenticate as (or gain privileges of) an identity you shouldn't**, or **steal a credential that lets you**. Tampering that the server *rejects* is not a finding.

## 5.2 Severity calibration (CVSS + CWE)

| Scenario | Typical severity | CWE |
|----------|------------------|-----|
| Zero/one-click **full ATO** on any account (email-linking, XSW, id_token forge, code theft → redeem) | **Critical (9.0–10)** | CWE-287/290/347 |
| ATO requiring victim interaction + specific conditions | **High (7–8.9)** | CWE-352/601/347 |
| SSRF from IdP via `request_uri` → cloud metadata | **High/Critical** | CWE-918 |
| SAML XXE file read | **High** | CWE-611 |
| Token/code leak via Referer/open-redirect (needs a leak sink) | **High/Medium** | CWE-601/200 |
| Scope escalation without ATO | **Medium** | CWE-269 |
| Missing `state`/PKCE with **no** demonstrated exploit | **Low/Info** | CWE-352 |
| Verbose OAuth error disclosure | **Low/Info** | CWE-200 |

Justify with reach (all users?), interaction (zero/one-click?), and **MFA bypass** (SSO ATO usually skips MFA → argue up).

## 5.3 SAFE-PoC discipline (mandatory)

- Use **your own two test accounts** (attacker + victim) that **you own**. Never take over a real user's account.
- For account-linking/pre-ATO: seed and take over **your own** victim test account; screenshot the attacker session inside it.
- For token/code theft: exfiltrate to **your own** listener; capture **one** request proving the credential arrived; **do not** use stolen creds beyond proving login as your own test victim.
- For SAML forgery: forge to your own controlled `NameID`; if you must demo `admin`, use a **test admin you're authorized** for — never a real admin.
- For `request_uri` SSRF: hit **your own** OOB host / a benign internal marker; **one** metadata request to prove creds, then STOP — do not exfiltrate customer data.
- **No** brute force of `state`/`code`, no spraying real users, no persistence, tear down listeners/OOB servers, delete any seeded artifacts.
- Redact real tokens/codes/keys in the report (show enough to prove, mask the rest).

## 5.4 Reporting

Lead with **impact + reproduction**, exactly which validation failed, and the fix. Use the report template. Include: the full authorization request + callback, the tampered value, the accepted response, and the resulting authenticated session (screenshot/`whoami`-equivalent). Map to the OAuth Security BCP (RFC 9700) / OIDC spec clause that's violated — reviewers act faster when you cite the exact requirement.

## 5.5 References & further reading

**Always-on core:**
- **PortSwigger Web Security Academy** — OAuth authentication, OpenID Connect, SAML labs (do them all) · **PortSwigger Research** (OAuth/OIDC deep-dives).
- **HackTricks** — "OAuth to Account takeover", "SAML Attacks" · **The Hacker Recipes** — OAuth / SAML.
- **PayloadsAllTheThings** — OAuth · SAML Injection · **OWASP** — WSTG (OAuth/SAML testing) + SAML-Security & OAuth Cheat Sheets · **PentesterLab** — OAuth/OIDC/SAML badges.
- **RFC 9700** (OAuth 2.0 Security BCP — the canonical control list to cite) · **RFC 6749 / 6819** · **OIDC Core** · **SAML 2.0** spec.

**Class-specific research & tooling:**
- **Frans Rosén (Detectify)** — "Account hijacking using 'dirty dancing' in sign-in OAuth-flows" (2022) — the modern OAuth response-manipulation/ATO research (read this).
- **Salt Labs** — OAuth-implementation ATO series (Grammarly / Vidio / Bukalapak) · **Michael Stepankin (PortSwigger)** OAuth research.
- **Somorovsky et al.** — "On Breaking SAML: Be Whoever You Want to Be" (USENIX 2012) — the foundational XSW paper · **SAML Raider** (Burp) · **Cure53 / Compass Security** SAML audits.
- **Egor Homakov** — classic OAuth-CSRF / `redirect_uri` disclosures (Facebook/Google) · **Sam Curry / Bhavuk Jain** SSO-ATO write-ups.

**CVEs & real-world ATO:**
- **"Sign in with Apple" ATO** — Bhavuk Jain, 2020 ($100k) — Apple issued a valid JWT for any requested email; SPs trusted it → any-account ATO.
- **SAML comment/canonicalization** — CVE-2018-0489 (ruby-saml), CVE-2017-11427/11428 (python/ruby OneLogin), Duo Labs "SAML vulnerabilities" family (2018).
- **Microsoft / Auth0 / Okta** OAuth ATO advisories; countless HackerOne `redirect_uri` + account-linking-CSRF reports.

**Standards & scoring:** CWE-287 / 290 / 347 / 352 / 601 / 918 · CVSS 3.1 calculator (first.org/cvss/calculator/3.1).

---

## Companion files
- **[Attack Arsenal](#/oauth/arsenal)** — every payload + tool command.
- **[Testing Checklist](#/oauth/checklist)** — phase-by-phase test list + auto-reject.
- **the report template** — report skeleton.
- **[Zero to Expert (Q&A)](#/oauth/qa)** — 100-question study + field reference.
- **[PoC Scripts](#/oauth/poc)** — `oauth_redirect_fuzz.py` · `saml_xsw.py` · `oauth_flow_audit.py` · `idtoken_tamper.py`.
