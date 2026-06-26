#!/usr/bin/env bash
# setup-recon-env.sh — wire the DNS brute/permutation phase of recon.sh.
# Installs puredns + gotator + massdns into ~/go/bin (NO sudo) and refreshes the
# co-located resolvers list. recon.sh adds ~/go/bin to its own PATH and finds the
# wordlists shipped beside it, so after this runs the active phase "just works".
#
# Run on each machine once (it's idempotent — safe to re-run):  bash setup-recon-env.sh
set -uo pipefail

c_g="\033[1;32m"; c_y="\033[1;33m"; c_c="\033[1;36m"; c_r="\033[1;31m"; c_0="\033[0m"
ok(){ echo -e "  ${c_g}OK${c_0} $1"; }
inf(){ echo -e "  ${c_c}->${c_0} $1"; }
wrn(){ echo -e "  ${c_y}!!${c_0} $1"; }
err(){ echo -e "  ${c_r}xx${c_0} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
WLD="$SCRIPT_DIR/wordlists"; mkdir -p "$WLD"
export PATH="$PATH:$HOME/go/bin:$(go env GOPATH 2>/dev/null)/bin"

echo -e "${c_c}=== recon env setup (no sudo) ===${c_0}"

# ── Go-based tools -> ~/go/bin ────────────────────────────────────────────────
if command -v go >/dev/null 2>&1; then
  goinst(){ # bin pkg
    if command -v "$1" >/dev/null 2>&1; then ok "$1 present"; return; fi
    inf "installing $1"; GOBIN="$HOME/go/bin" go install "$2" >/dev/null 2>&1 \
      && ok "$1 installed" || err "$1 failed"
  }
  goinst puredns github.com/d3mondev/puredns/v2@latest
  goinst gotator github.com/Josue87/gotator@latest
else
  err "Go not installed (sudo apt install golang-go) — puredns/gotator skipped"
fi

# ── massdns (puredns engine) — build from source, no sudo ─────────────────────
if command -v massdns >/dev/null 2>&1 || [ -x "$HOME/go/bin/massdns" ]; then
  ok "massdns present"
else
  inf "building massdns"
  if rm -rf /tmp/massdns && git clone --depth 1 https://github.com/blechschmidt/massdns /tmp/massdns >/dev/null 2>&1 \
     && make -C /tmp/massdns >/dev/null 2>&1 && cp /tmp/massdns/bin/massdns "$HOME/go/bin/massdns"; then
    ok "massdns built -> ~/go/bin"
  else
    err "massdns build failed (need git + make + gcc: sudo apt install build-essential git)"
  fi
fi

# ── resolvers list (co-located so it travels with the kit) ────────────────────
if [ -s "$WLD/resolvers.txt" ]; then
  ok "resolvers present ($(wc -l < "$WLD/resolvers.txt") lines) — delete to force refresh"
else
  inf "downloading trickest resolvers"
  curl -s --max-time 60 -o "$WLD/resolvers.txt" \
    https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    && ok "resolvers -> $WLD/resolvers.txt ($(wc -l < "$WLD/resolvers.txt") lines)" \
    || err "resolver download failed (check network)"
fi
[ -s "$WLD/permutations.txt" ] && ok "permutations wordlist present" \
  || wrn "permutations.txt missing from $WLD (ships with the kit)"

# ── SecLists (brute wordlist) — apt package on Kali ───────────────────────────
if [ -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt ] \
   || [ -f /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt ]; then
  ok "SecLists DNS wordlist present"
else
  wrn "SecLists not found — install it:  sudo apt install seclists   (or clone to /opt/SecLists)"
fi

# ── verify ────────────────────────────────────────────────────────────────────
echo -e "\n${c_c}=== verify ===${c_0}"
for b in puredns gotator massdns; do
  command -v "$b" >/dev/null 2>&1 && ok "$b -> $(command -v $b)" || err "$b not on PATH (it is in ~/go/bin; recon.sh adds that itself)"
done
echo -e "\n${c_g}Done.${c_0} Now run:  ./x8bit_recon.sh <domain>   (active brute/permutation will run)"
