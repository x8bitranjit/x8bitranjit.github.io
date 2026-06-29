#!/usr/bin/env python3
"""
ws_client.py — benign WebSocket client for testing: connect with a chosen Origin/Cookie, send a
frame, and print the reply. Use it as the CSWSH CLI oracle (foreign Origin + victim cookie →
still authenticated?), for IDOR-over-WS (A's cookie + B's id), and for frame tampering.

Authorized testing only. Your own accounts. The CLI ignores the browser Same-Origin Policy, so a
connect here is NOT proof of CSWSH by itself — it's an oracle; prove CSWSH in a REAL BROWSER with
cswsh_poc.html (guide §15). For IDOR, use two of your own accounts (A reaches B).
"""
import argparse, asyncio, sys
try:
    import websockets
except ImportError:
    sys.exit("pip install websockets")


async def run(args):
    headers = {}
    if args.origin:
        headers["Origin"] = args.origin
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.header:
        for h in args.header:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    print(f"[*] connecting {args.url}  (Origin={args.origin or '-'}, cookie={'yes' if args.cookie else 'no'})")
    try:
        async with websockets.connect(args.url, extra_headers=headers,
                                      subprotocols=args.subprotocol or None, open_timeout=15) as ws:
            print("[+] connected (handshake accepted). NOTE: CLI ignores SOP — confirm CSWSH in a real browser.")
            for msg in (args.send or []):
                await ws.send(msg)
                print(f"[>] {msg}")
            # read replies for a few seconds
            try:
                while True:
                    reply = await asyncio.wait_for(ws.recv(), timeout=args.wait)
                    print(f"[<] {reply}")
            except asyncio.TimeoutError:
                print("[*] no more messages (timeout).")
    except Exception as e:
        print(f"[!] connect/handshake failed: {e}  (Origin may be validated, or auth is a token not a cookie)")


def main():
    p = argparse.ArgumentParser(description="Benign WebSocket test client (authorized testing only).")
    p.add_argument("--url", required=True, help="wss://target/ws")
    p.add_argument("--origin", help="Origin header to send (foreign = CSWSH oracle)")
    p.add_argument("--cookie", help="Cookie header (e.g. 'session=<victim>')")
    p.add_argument("--header", action="append", help="extra header 'Name: value' (repeatable)")
    p.add_argument("--subprotocol", action="append", help="Sec-WebSocket-Protocol value (repeatable)")
    p.add_argument("--send", action="append", help="a frame to send (repeatable) — e.g. '{\"type\":\"getMessages\"}'")
    p.add_argument("--wait", type=float, default=5.0, help="seconds to wait for replies (default 5)")
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    main()
