#!/usr/bin/env python3
"""
deser_detect.py — fingerprint a serialized blob's language / deserializer (authorized recon).

Give it a value (a cookie, a __VIEWSTATE, an API field, a token) and it tells you whether it's Java/PHP/.NET/Python/
Ruby/Node/JSON-gadget serialized data and which tool to reach for. Handles raw text, base64, and gzip+base64.

Recognizing the format is step 1 (§2) — it decides your whole approach. This does NOT exploit anything; it classifies.

Usage:
  python3 deser_detect.py 'rO0ABXNyAB...'
  python3 deser_detect.py --cookie "$SESSION"
  python3 deser_detect.py --file blob.bin
"""
import argparse, base64, gzip, re, sys


def as_bytes_candidates(s):
    """Yield (label, bytes) candidates: raw, base64-decoded, gzip(base64)-decoded."""
    raw = s.encode("latin1", "ignore") if isinstance(s, str) else s
    yield ("raw", raw)
    stripped = re.sub(r"\s+", "", s) if isinstance(s, str) else s.decode("latin1", "ignore")
    # url-decode common %XX and +/ variants lightly, then try base64 (std + urlsafe)
    for b64 in (stripped, stripped.replace("-", "+").replace("_", "/")):
        try:
            dec = base64.b64decode(b64 + "===", validate=False)
            if dec and len(dec) >= 2:
                yield ("base64", dec)
                if dec[:2] == b"\x1f\x8b":
                    try:
                        yield ("gzip+base64", gzip.decompress(dec))
                    except Exception:
                        pass
        except Exception:
            pass


def classify(s):
    hits = []
    text = s if isinstance(s, str) else s.decode("latin1", "ignore")

    # text-format serializers (no base64 needed)
    if re.match(r'^\s*[Oa]:\d+:', text) or re.search(r'[abOs]:\d+:[{"]', text):
        hits.append(("PHP serialize()", "PHPGGC (framework POP chain) / object tampering / phar", "text: O:/a:/s: pattern"))
    if "__HALT_COMPILER" in text or text[:4] in ("PK\x03\x04",):
        hits.append(("PHP phar archive", "phpggc -p phar → file-op on phar:// triggers deserialize", "phar/zip magic"))
    if "_$$ND_FUNC$$_" in text:
        hits.append(("Node node-serialize", "IIFE payload {\"rce\":\"_$$ND_FUNC$$_function(){...}()\"}", "_$$ND_FUNC$$_ marker"))
    if "!!python/object" in text:
        hits.append(("Python PyYAML (unsafe)", "!!python/object/apply:os.system [\"id\"]", "!!python/object tag"))
    if '"@type"' in text:
        hits.append(("Java Fastjson", "@type JdbcRowSetImpl → JNDI (marshalsec)", '"@type" key'))
    if '"@class"' in text:
        hits.append(("Java Jackson (polymorphic)", "@class gadget → JNDI/SpEL", '"@class" key'))
    if '"$type"' in text:
        hits.append((".NET Json.NET (TypeNameHandling)", "$type ObjectDataProvider gadget", '"$type" key'))
    if re.search(r"!ruby/object|!ruby/hash", text):
        hits.append(("Ruby YAML (Psych)", "!ruby/object gadget → RCE", "!ruby/object tag"))

    # binary-signature serializers (raw / base64 / gzip)
    for label, b in as_bytes_candidates(s):
        if b[:4] == b"\xac\xed\x00\x05":
            hits.append(("Java ObjectInputStream", "ysoserial (URLDNS first, then a classpath chain)", f"{label}: AC ED 00 05"))
        if b[:9] == b"\x00\x01\x00\x00\x00\xff\xff\xff\xff":
            hits.append((".NET BinaryFormatter", "ysoserial.net -f BinaryFormatter", f"{label}: 00 01 00 00 00 FF FF FF FF"))
        if b[:1] == b"\x80" and len(b) > 1 and b[1] in (2, 3, 4, 5):
            hits.append(("Python pickle", "pickle __reduce__ (poc/pickle_poc.py)", f"{label}: \\x80 proto{b[1]}"))
        if b[:2] == b"(d" or b[:2] == b"(l" or b[:3] == b"(dp":
            hits.append(("Python pickle (proto 0 text)", "pickle __reduce__ (poc/pickle_poc.py)", f"{label}: proto-0 opcodes"))
        if b[:2] == b"\x04\x08":
            hits.append(("Ruby Marshal", "Marshal universal gadget", f"{label}: 04 08"))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("value", nargs="?", help="the serialized value / token / cookie value")
    ap.add_argument("--cookie", help="a cookie value to classify")
    ap.add_argument("--file", help="read the blob from a file (binary ok)")
    a = ap.parse_args()

    if a.file:
        with open(a.file, "rb") as f:
            s = f.read().decode("latin1", "ignore")
    else:
        s = a.value or a.cookie
    if not s:
        ap.error("provide a value, --cookie, or --file")

    hits = classify(s)
    if not hits:
        print("[-] no known serialization signature matched.")
        print("    (still could be deserialized — try a tamper test + a blind DNS gadget; check for base64/url-encoding layers.)")
        return
    print(f"[+] {len(hits)} signature match(es):")
    seen = set()
    for name, tool, why in hits:
        key = (name, why)
        if key in seen:
            continue
        seen.add(key)
        print(f"   - {name:32} | {why}")
        print(f"     -> {tool}")
    print("\n[!] Confirm with a tamper test + a BLIND DNS gadget (Java URLDNS / a per-language callback) before any RCE. "
          "Recognition is a lead, not a finding (§12).")


if __name__ == "__main__":
    main()
