# OAuth / OIDC / SAML — PoC Scripts

Tooling for the OAuth/SSO/SAML kit. *Authorized testing only.* The finding is **authenticating as an identity you shouldn't** (ATO) — not "state is missing" or "this decodes to an assertion". Prove it with **two accounts you own** (attacker + victim), one benign proof, then STOP. **Click a script to open its source.**

| Script | What it does |
|---|---|
| [`oauth_flow_audit.py`](#/oauth/poc/oauth_flow_audit) | **Passive** audit of a captured `/authorize` URL (+ optional OIDC discovery): flags missing/weak `state`, missing `nonce`, no PKCE, implicit/leaky `response_type`/`response_mode`, and whether the IdP *advertises* PKCE/implicit. Start here — the leads it surfaces are what the other scripts confirm. |
| [`oauth_redirect_fuzz.py`](#/oauth/poc/oauth_redirect_fuzz) | Enumerates **`redirect_uri` bypass** candidates from a real authorize URL; with `--send`, probes which variants the IdP does **not** reject — **without following redirects or completing any flow**. Baselines against the legit value to cut false positives. |
| [`idtoken_tamper.py`](#/oauth/poc/idtoken_tamper) | Crafts **OIDC id_token** test variants — `alg:none`, claim-swap keeping the original (now-invalid) signature, and both — to test SP-side signature / `aud` / `iss` / `email_verified` validation. |
| [`saml_xsw.py`](#/oauth/poc/saml_xsw) | Decodes a captured **SAMLResponse** and emits tampered variants: **signature-stripped**, **comment/canonicalization** injection, NameID-swap, and an **XSW3 scaffold** (forged unsigned assertion). |

## Typical flow
1. **Passive first** — `oauth_flow_audit.py` on a captured authorize request → what's weak in the flow.
2. **redirect_uri theft surface** — `oauth_redirect_fuzz.py --send` with **your** host; confirm the code/token actually reaches you.
3. **id_token trust** — `idtoken_tamper.py` → submit where the SP consumes the token; if it logs you in as the tampered identity, verification is broken.
4. **SAML** — `saml_xsw.py` variants via Repeater / SAML Raider; if a forged/stripped/wrapped assertion is accepted → Critical ATO.

> Two accounts **you own**; exfil only to **your** listener; one benign proof; never a real admin `NameID`; tear down OOB servers; redact tokens/keys. For `kid`/`jku` id_token forgery use the **JWT** kit's PoC.
