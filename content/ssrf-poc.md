# SSRF — PoC Scripts

Runnable tooling for the bypass and exploitation phases of the SSRF kit. **Click a script to open it on its own page.**
*Authorized testing only:* **prove, don't pillage** — confirm metadata creds with read-only `aws sts
get-caller-identity` and stop; for internal services prove control with a benign marker, not destruction.

| Script | What it does |
|---|---|
| [`ip_encoder.py`](#/ssrf/poc/ip_encoder) | Print every IP-obfuscation form (decimal/hex/octal/short/IPv6/mapped) of a target — allowlist/blocklist bypass. |
| [`redirect_server.py`](#/ssrf/poc/redirect_server) | HTTP server that 302-redirects to an internal/metadata URL (allowlist bypass via open redirect). |
| [`gopher_redis.py`](#/ssrf/poc/gopher_redis) | Build a `gopher://` URL of Redis commands (benign default: SET marker + INFO). |
| [`ssrf_probe.sh`](#/ssrf/poc/ssrf_probe) | Fire the metadata/internal/bypass matrix at a sink; watch your OOB host. |

## How they fit together

1. **Confirm SSRF** — point the sink at your interactsh host; check the **source IP**.
2. **Reach metadata** directly, or generate obfuscated forms with `ip_encoder.py` if filtered.
3. **If an allowlist blocks internal**, host `redirect_server.py` to metadata and feed *that* URL to the sink.
4. **If gopher is accepted + Redis reachable**, build a benign proof payload with `gopher_redis.py`.
5. **Or sweep** a matrix with `ssrf_probe.sh`, then prove impact safely (`get-caller-identity` / benign marker / `/etc/hostname`).

> Read the **Testing Guide §5/§6/§8/§11/§13** for the bypass and protocol-smuggling matrix and the
> **Zero to Expert (Q&A)** for SSRF→cloud-cred→RCE chains.
