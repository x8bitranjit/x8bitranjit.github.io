#!/usr/bin/env python3
"""
oauth_flow_audit.py - passive audit of an OAuth/OIDC authorization request (+ optional discovery doc). Authorized only.

Reads a captured /authorize URL and reports weaknesses that ENABLE the real attacks (it does not exploit anything):
missing/weak `state` (CSRF/login-CSRF), missing `nonce` (id_token replay), no PKCE `code_challenge` (code theft ->
usable), implicit/leaky `response_type`/`response_mode`, and (with --discovery) whether the IdP advertises PKCE and
whether implicit is allowed. No network traffic unless you pass a discovery URL to --discovery. Findings here are LEADS
- confirm the actual exploit before reporting.

Usage:
  python3 oauth_flow_audit.py --url "https://idp/authorize?client_id=x&redirect_uri=https://app/cb&response_type=code&scope=openid&state=abc&nonce=n&code_challenge=..&code_challenge_method=S256"
  python3 oauth_flow_audit.py --url "<authorize url>" --discovery https://idp/.well-known/openid-configuration
  python3 oauth_flow_audit.py --url "<authorize url>" --discovery ./openid-configuration.json
"""
import argparse, json, sys, urllib.parse, urllib.request

OK, WARN, BAD = "[ok]", "[warn]", "[FLAG]"


def _get(params, key):
    v = params.get(key)
    return v[0] if v else None


def audit_request(url):
    q = urllib.parse.urlparse(url)
    p = urllib.parse.parse_qs(q.query, keep_blank_values=True)
    rt = (_get(p, "response_type") or "").strip()
    rm = (_get(p, "response_mode") or "").strip()
    state = _get(p, "state")
    nonce = _get(p, "nonce")
    cc = _get(p, "code_challenge")
    ccm = (_get(p, "code_challenge_method") or "").strip()
    scope = (_get(p, "scope") or "").strip()
    ru = _get(p, "redirect_uri")
    cid = _get(p, "client_id")
    prompt = (_get(p, "prompt") or "").strip()

    print(f"\n=== authorization request audit ===")
    print(f"  endpoint      : {q.scheme}://{q.netloc}{q.path}")
    print(f"  client_id     : {cid}")
    print(f"  redirect_uri  : {ru}")
    print(f"  response_type : {rt or '(none)'}")
    print(f"  scope         : {scope or '(none)'}")

    findings = []
    # response_type / implicit
    tokens = set(rt.split())
    if "token" in tokens:
        findings.append((BAD, "response_type includes 'token' -> IMPLICIT flow: access_token rides in the URL fragment "
                              "(leaky). Test open-redirect / Referer / postMessage exfil (2.1, 2.5)."))
    if rt and "code" in tokens and len(tokens) > 1:
        findings.append((WARN, f"hybrid response_type '{rt}': check the id_token is not trusted without the code exchange."))
    if rt == "code":
        findings.append((WARN, "response_type=code: TRY downgrading to 'token'/'id_token token' - if honored, the "
                               "credential moves to the fragment (easier to steal)."))
    # response_mode
    if rm in ("query", "fragment") and "code" in tokens:
        findings.append((WARN, f"response_mode={rm} for a code flow: credential in URL (Referer/log leak surface)."))
    if rm == "web_message":
        findings.append((BAD, "response_mode=web_message (postMessage): test the client's message listener for a missing "
                              "event.origin check (silent token theft with prompt=none) (2.5)."))
    # state (CSRF)
    if state is None:
        findings.append((BAD, "NO 'state' parameter: OAuth-CSRF surface. If an account-LINK feature exists this is a "
                              "silent-ATO primitive (2.2). Confirm login/link CSRF to make it a finding."))
    elif len(state) < 8 or state.isdigit() or state in ("state", "1", "test", "x"):
        findings.append((WARN, f"weak/guessable state='{state}': check it is random AND session-bound AND single-use."))
    else:
        findings.append((OK, "state present - still verify it is session-bound (cross-user reuse) and single-use."))
    # nonce (OIDC replay)
    is_oidc = "openid" in scope.split() or "id_token" in tokens
    if is_oidc and nonce is None:
        findings.append((BAD, "OIDC flow with NO 'nonce': id_token replay surface - a leaked/old id_token may be reusable (2.7)."))
    elif is_oidc:
        findings.append((OK, "nonce present - verify the SP binds it to the session and rejects mismatches."))
    # PKCE
    if cc is None:
        findings.append((BAD, "NO PKCE 'code_challenge': if this is a public/SPA/mobile client, a stolen code is directly "
                              "redeemable -> code theft = ATO. TRY the flow without PKCE and see if /token still issues (2.4)."))
    elif ccm.lower() == "plain":
        findings.append((BAD, "PKCE code_challenge_method=plain: challenge==verifier -> knowing the request reveals the "
                              "verifier. Downgrade attack surface (2.4)."))
    else:
        findings.append((OK, f"PKCE present (method={ccm or 'unspecified'}) - verify /token actually checks the verifier "
                             "and that omitting PKCE is rejected."))
    # redirect_uri quick reminder
    if ru:
        findings.append((WARN, "redirect_uri present: run oauth_redirect_fuzz.py for validation bypasses (2.1)."))
    if prompt == "none":
        findings.append((WARN, "prompt=none (silent auth): check whether NEW scopes can be granted without consent (2.6)."))

    for tag, msg in findings:
        print(f"  {tag} {msg}")
    return findings


def audit_discovery(src):
    print(f"\n=== OIDC discovery audit ===")
    try:
        if src.startswith("http://") or src.startswith("https://"):
            with urllib.request.urlopen(src, timeout=15) as r:
                doc = json.load(r)
        else:
            with open(src, "r", encoding="utf-8") as f:
                doc = json.load(f)
    except Exception as e:
        print(f"  {WARN} could not load discovery doc: {e}")
        return
    rts = doc.get("response_types_supported", [])
    ccm = doc.get("code_challenge_methods_supported")
    print(f"  authorization_endpoint : {doc.get('authorization_endpoint')}")
    print(f"  token_endpoint         : {doc.get('token_endpoint')}")
    print(f"  jwks_uri               : {doc.get('jwks_uri')}  (pull it for id_token sig / kid / jku tests)")
    print(f"  response_types_supported: {rts}")
    if any("token" in rt for rt in rts):
        print(f"  {WARN} implicit/hybrid response types advertised -> response_type downgrade is likely honored (2.5).")
    if not ccm:
        print(f"  {BAD} discovery does NOT advertise PKCE (code_challenge_methods_supported) -> PKCE may be optional (2.4).")
    elif "plain" in [m.lower() for m in ccm]:
        print(f"  {WARN} PKCE 'plain' method advertised -> downgrade surface. methods={ccm}")
    else:
        print(f"  {OK} PKCE methods={ccm}")
    if "none" in [a.lower() for a in doc.get("token_endpoint_auth_methods_supported", [])]:
        print(f"  {WARN} token endpoint allows auth_method 'none' (public clients) - pair with weak PKCE/redirect_uri.")


def main():
    ap = argparse.ArgumentParser(description="Passive OAuth/OIDC authorization-request auditor (authorized only).")
    ap.add_argument("--url", required=True, help="captured /authorize request URL (quote it)")
    ap.add_argument("--discovery", help="OIDC discovery URL or local JSON file (optional; only this fetches network)")
    a = ap.parse_args()
    audit_request(a.url)
    if a.discovery:
        audit_discovery(a.discovery)
    print("\n[i] These are LEADS. Confirm the actual exploit (ATO / token theft) with two accounts you own before reporting.")


if __name__ == "__main__":
    sys.exit(main())
