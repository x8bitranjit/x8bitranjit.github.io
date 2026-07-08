#!/usr/bin/env python3
"""
reset_token_analyzer.py - score password-reset (or OTP/session) tokens for predictability (authorized only).

Collect a series of reset tokens for YOUR OWN account (trigger several resets, copy each token) into a file, one per
line; this scores them for the weaknesses that enable forging a VICTIM's token: low entropy, sequential/timestamp
structure, short length, reuse, and decodable embedded data (userid/email/timestamp). Pure local analysis - no network,
no target contact. (ACCOUNT_TAKEOVER_TESTING_GUIDE.md §4.)

Usage:
  python3 reset_token_analyzer.py --file tokens.txt
  printf '%s\n' tok1 tok2 tok3 | python3 reset_token_analyzer.py
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, base64, binascii, math, re, statistics


def shannon_bits_per_char(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def charset_of(tokens):
    joined = "".join(tokens)
    if re.fullmatch(r"[0-9]+", joined):
        return "digits"
    if re.fullmatch(r"[0-9a-fA-F]+", joined):
        return "hex"
    if all(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", t) for t in tokens):
        return "uuid"
    if re.fullmatch(r"[A-Za-z0-9_\-+/=]+", joined):
        return "base64/url-safe"
    return "mixed/other"


def try_decode(tok):
    """Return decoded printable content if the token base64/hex-decodes to mostly-printable text."""
    for name, fn in (("base64", lambda t: base64.b64decode(t + "=" * (-len(t) % 4), validate=False)),
                     ("base64url", lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))),
                     ("hex", lambda t: binascii.unhexlify(t if len(t) % 2 == 0 else t[:-1]))):
        try:
            raw = fn(tok)
        except (binascii.Error, ValueError):
            continue
        if not raw:
            continue
        printable = sum(32 <= b < 127 for b in raw)
        if printable / len(raw) >= 0.7:
            return name, raw.decode("latin-1")
    return None, None


EPOCH_RE = re.compile(r"1[6-9]\d{8}")  # 10-digit unix epoch ~2020-2033


def numeric_sequential(tokens, base):
    vals = []
    for t in tokens:
        try:
            vals.append(int(t, base))
        except ValueError:
            return False, None
    if len(vals) < 3:
        return False, None
    vals.sort()
    deltas = [b - a for a, b in zip(vals, vals[1:])]
    if not deltas:
        return False, None
    med = statistics.median(deltas)
    constant = len(set(deltas)) == 1
    # Sequential/clustered (forgeable) if deltas are constant (arithmetic), OR the whole set spans a
    # NARROW band relative to the token magnitude - values packed together like a counter/timestamp.
    # Comparing SPREAD to magnitude (not an absolute delta) avoids a false "sequential" on a small
    # numeric keyspace: random 6-digit codes span most of their range, so spread ~= magnitude there.
    spread = vals[-1] - vals[0]
    clustered = vals[-1] > 0 and spread <= vals[-1] * 0.01
    return (constant or clustered), med


def main():
    ap = argparse.ArgumentParser(description="Score reset/OTP tokens for predictability (own tokens; authorized only).")
    ap.add_argument("--file", help="file of tokens, one per line (default: stdin)")
    a = ap.parse_args()
    raw = open(a.file, encoding="utf-8", errors="replace").read() if a.file else sys.stdin.read()
    tokens = [t.strip() for t in raw.splitlines() if t.strip()]
    if len(tokens) < 2:
        sys.exit("[!] give at least 2 tokens (more = better signal). Collect several resets of YOUR OWN account.")

    print("== reset-token analysis ==")
    print(f"[i] {len(tokens)} tokens; sample: {tokens[0][:40]}{'...' if len(tokens[0]) > 40 else ''}")

    flags = []  # (severity, message)

    # length
    lens = {len(t) for t in tokens}
    minlen = min(lens)
    print(f"[i] length: {'uniform ' + str(minlen) if len(lens) == 1 else 'varies ' + str(sorted(lens))}")
    if minlen < 16:
        flags.append(("HIGH", f"short tokens ({minlen} chars) - small keyspace, brute/forge feasible"))

    # charset + entropy
    cs = charset_of(tokens)
    bpc = shannon_bits_per_char("".join(tokens))
    eff_bits = minlen * bpc
    print(f"[i] charset: {cs}   entropy: {bpc:.2f} bits/char   ~{eff_bits:.0f} bits/token")
    if eff_bits < 64:
        flags.append(("HIGH", f"low effective entropy (~{eff_bits:.0f} bits) - guessable/forgeable"))
    if cs == "digits":
        flags.append(("MED", "digits-only token - much smaller keyspace than hex/base64"))

    # reuse / duplicates
    if len(tokens) != len(set(tokens)):
        flags.append(("HIGH", "DUPLICATE tokens issued - token reuse / not-single-use"))

    # sequential
    base = 16 if cs == "hex" else (10 if cs == "digits" else None)
    if base:
        seq, med = numeric_sequential(tokens, base)
        if seq:
            flags.append(("CRIT", f"SEQUENTIAL / near-arithmetic tokens (median delta {med}) - forge the victim's token directly"))

    # decodable embedded structure (userid / timestamp)
    embedded = 0
    ts_seen = False
    for t in tokens[:20]:
        name, dec = try_decode(t)
        if dec:
            embedded += 1
            if EPOCH_RE.search(dec) or EPOCH_RE.search(t):
                ts_seen = True
    if embedded >= max(1, len(tokens[:20]) // 2):
        flags.append(("HIGH", "tokens DECODE to printable data (base64/hex) - likely embed userid/email/timestamp -> predictable"))
    if ts_seen or any(EPOCH_RE.search(t) for t in tokens):
        flags.append(("HIGH", "a unix TIMESTAMP is embedded - tokens are time-correlated -> narrow the search to forge"))

    print()
    if not flags:
        print("[+] no predictability signals: tokens look high-entropy, unique, non-sequential, opaque.")
        print("    (still verify single-use + expiry + user-binding by REPLAY tests - guide §4.)")
        return 0
    order = {"CRIT": 0, "HIGH": 1, "MED": 2}
    for sev, msg in sorted(flags, key=lambda f: order[f[0]]):
        print(f"  [{sev}] {msg}")
    worst = min(flags, key=lambda f: order[f[0]])[0]
    verdict = {"CRIT": "CRITICAL - forge the victim's reset token", "HIGH": "WEAK - likely forgeable/guessable",
               "MED": "MODERATE - reduced keyspace"}[worst]
    print(f"\n[verdict] {verdict}. Confirm end-to-end: forge/guess B's token -> reset B -> log in as B (guide §4/§18).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
