# WebSocket — PoC Scripts

**Author:** x8bitranjit

Three benign, authorized-testing-only helpers for WebSocket security testing. Together they cover the three high-impact WebSocket attack chains: cross-site hijacking (CSWSH), IDOR-over-WS / frame tampering, and rate-limit bypass over a WebSocket channel.

| Script | What it does |
|--------|-------------|
| [cswsh_poc.html](#/websocket/poc/cswsh_poc) | Cross-Site WebSocket Hijacking proof-of-concept — connects from an attacker origin in a real browser, reads the victim's data, and optionally fires a benign state change |
| [ws_client.py](#/websocket/poc/ws_client) | Scriptable WebSocket client — connect with a chosen Origin/Cookie, send frames, read replies; the CSWSH CLI oracle and IDOR-over-WS frame-tamper helper |
| [ws_ratelimit_test.py](#/websocket/poc/ws_ratelimit_test) | Rate-limit bypass measurement — fires a bounded number of attempts on one socket and reports how many were processed/accepted (proves the per-request cap is bypassed) |

## How they fit together

1. **Reconnaissance and baseline** — use `ws_client.py` as the CLI oracle: connect with the victim's cookie and a foreign `Origin`; if the handshake is accepted authenticated, CSWSH is viable. Also use it to send IDOR-over-WS frames (A's cookie + B's id) and to map which message types are accepted.
2. **CSWSH real-browser proof** — serve `cswsh_poc.html` from a different origin; open it in the same browser where your victim test account is logged in. The page connects to the target WebSocket using the victim's cookie, reads their data, and exfiltrates it to your server. This is the validity proof — CLI oracle results alone are not sufficient.
3. **Rate-limit bypass measurement** — run `ws_ratelimit_test.py` to fire N login/OTP frames on a single socket and count how many were processed. A count exceeding the documented per-request HTTP cap proves the bypass and shows the ATO chain — without actually cracking a real account.

> **Authorized testing only.** All scripts use your own test accounts. CSWSH PoC exfiltrates to your server only. `ws_ratelimit_test.py` hard-limits to 200 attempts — the point is the measured count, not a real brute. Two accounts (A/B) for IDOR-over-WS. Revert any state changes after testing.

**Contact:** [LinkedIn](https://in.linkedin.com/in/x8bitranjit)
