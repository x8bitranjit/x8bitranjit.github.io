#!/usr/bin/env bash
# setup.sh — install the core recon toolchain + wordlists + fresh resolvers (guide §1).
# Authorized testing only. Run on Kali/WSL. Re-run anytime to refresh resolvers.
set -u

echo "[*] Installing ProjectDiscovery + tomnomnom tooling (needs Go in PATH)..."
if ! command -v go >/dev/null; then
  echo "[!] Go not found. Install Go first: https://go.dev/dl/  (then re-run)"; exit 1
fi

PD="subfinder dnsx httpx naabu katana nuclei tlsx asnmap"
for t in $PD; do
  command -v "$t" >/dev/null || go install "github.com/projectdiscovery/$t/cmd/$t@latest"
done
command -v notify    >/dev/null || go install github.com/projectdiscovery/notify/cmd/notify@latest
command -v chaos     >/dev/null || go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
command -v gowitness >/dev/null || go install github.com/sensepost/gowitness@latest   # screenshots

for t in waybackurls anew unfurl qsreplace gf; do
  command -v "$t" >/dev/null || go install "github.com/tomnomnom/$t@latest"
done
command -v gau    >/dev/null || go install github.com/lc/gau/v2/cmd/gau@latest
command -v subjs  >/dev/null || go install github.com/lc/subjs@latest
command -v ffuf   >/dev/null || go install github.com/ffuf/ffuf/v2@latest
command -v dalfox >/dev/null || go install github.com/hahwul/dalfox/v2@latest
command -v amass  >/dev/null || go install github.com/owasp-amass/amass/v4/...@master
command -v gotator>/dev/null || go install github.com/Josue87/gotator@latest
command -v subzy  >/dev/null || go install github.com/PentestPad/subzy@latest

echo "[*] Python tools..."
pipx install arjun 2>/dev/null || pip install arjun 2>/dev/null || true
pipx install wafw00f 2>/dev/null || pip install wafw00f 2>/dev/null || true   # WAF fingerprint
pip install mmh3 2>/dev/null || true   # favicon hashing

echo "[*] Secret scanners..."
command -v trufflehog >/dev/null || go install github.com/trufflesecurity/trufflehog@latest
command -v git-dumper >/dev/null || pipx install git-dumper 2>/dev/null || true

echo "[*] Optional: headless browser for gowitness screenshots (skip if no apt/sudo)..."
command -v chromium >/dev/null || command -v google-chrome >/dev/null \
  || sudo apt-get install -y chromium 2>/dev/null || sudo apt-get install -y chromium-browser 2>/dev/null \
  || echo "    [i] chromium not installed — screenshots will be skipped (non-critical)."

echo "[*] Wordlists + gf patterns + resolvers..."
[ -d /opt/SecLists ] || sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists
mkdir -p ~/.gf
[ -d /tmp/Gf-Patterns ] || git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/Gf-Patterns
cp -n /tmp/Gf-Patterns/*.json ~/.gf/ 2>/dev/null || true
git clone --depth 1 https://github.com/tomnomnom/gf /tmp/gf 2>/dev/null && cp -n /tmp/gf/examples/*.json ~/.gf/ 2>/dev/null || true

echo "[*] Fetching fresh resolvers (keep these current!)..."
mkdir -p /opt
wget -qO /opt/resolvers.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
  && echo "[+] /opt/resolvers.txt updated ($(wc -l < /opt/resolvers.txt) resolvers)"

echo
echo "[+] Setup done."
echo "    API keys (all optional): cp config.env.example config.env  and fill in what you have"
echo "    -> PDCP key enables asnmap+chaos; VT/SecurityTrails/Shodan/Censys/GitHub add subfinder sources."
echo "    Then: ./x8bit_recon.sh <domain>"
