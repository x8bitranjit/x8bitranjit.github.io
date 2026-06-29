# RFI — PoC Scripts

Runnable, **benign-by-default** proof-of-concept tooling that backs the RFI kit. **Click a script to open it on its own
page.** *Authorized testing only:* RFI means **your code executes** on the target (RCE = Critical) — a mere fetch is
**SSRF**. Prove execution with the computed marker, use benign markers, and clean up.

| Script | What it does |
|---|---|
| [`payload_host.py`](#/rfi/poc/payload_host) | Tiny HTTP server that serves your PHP payloads as **text/plain** (so they don't run on your box) and **logs every include hit** with source IP — your evidence. Built-in `/shell.txt`, `/cmd.txt`, `/blind.txt`, `/sleep.txt`. |
| [`rfi_probe.py`](#/rfi/poc/rfi_probe) | Sprays remote-include payloads (schemes + `?`/`#`/null suffix-defeats) **and** the `data://` equivalent; confirms **execution** via the `RFI-EXEC-343` marker (7×7×7) — separating RFI/RCE from an SSRF fetch. |

## How they fit together

1. **Stand up the payload host** — `payload_host.py` on a public IP / ngrok / cloudflared the target can reach.
2. **Probe the sink** — `rfi_probe.py` while watching the payload host's log for the include hit.
3. **If `http://` is blocked**, try the no-host `data://` equivalents, or (Windows targets) host SMB/WebDAV and include a UNC path (capture NetNTLMv2 with Responder).
4. **Confirmed execution?** Swap to `/cmd.txt?&c=id`, run a single benign command, then STOP and clean up.

> Read the **Testing Guide §4–§10** for the scheme/suffix matrix and the Windows UNC/NTLM path, and the
> **Zero to Expert (Q&A)** for the RFI-vs-SSRF distinction.
