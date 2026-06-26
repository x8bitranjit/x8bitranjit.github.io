#!/usr/bin/env bash
# keys.sh — sourceable: load config.env + route API keys (shared by x8bit_recon.sh
# and monitor.sh so there's ONE implementation). All keys are OPTIONAL:
#   key MISSING  -> that source is skipped; the run still works (graceful degrade)
#   key PRESENT  -> picked up automatically for deeper coverage
#
# Sets in the caller's shell:  CFG_LOADED (path or "<none>"),  SF_PC ("-pc <tmp>" or ""),
# and exports PDCP_API_KEY when present. Builds a PRIVATE temp subfinder provider-config
# from any OSINT keys (never touches ~/.config/subfinder; auto-deleted on EXIT).
#
# Usage (caller must have SCRIPT_DIR set, or we resolve our own dir):
#   . "$SCRIPT_DIR/keys.sh"

# resolve config path: X8_CONFIG override -> caller's SCRIPT_DIR -> this file's dir
_KEYS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
CFG="${X8_CONFIG:-${SCRIPT_DIR:-$_KEYS_DIR}/config.env}"
CFG_LOADED="<none>"
# set -a so every assignment in config.env is exported to child tools; sed strips any
# Windows CRLF so a Notepad-edited file still sources cleanly.
[ -f "$CFG" ] && { set -a; . <(sed 's/\r$//' "$CFG" 2>/dev/null); set +a; CFG_LOADED="$CFG"; }

# PDCP key powers asnmap (ASN ranges) + chaos (passive subs).
[ -n "${PDCP_API_KEY:-}" ] && export PDCP_API_KEY

# Assemble a subfinder provider-config from whatever keys are set. Only providers with
# a non-empty key are written; subfinder's free sources run regardless, so subdomain
# discovery never depends on a key.
SF_PC=""
_PC_TMP="$(mktemp 2>/dev/null || echo "/tmp/.x8_sf_pc.$$")"
trap 'rm -f "$_PC_TMP" 2>/dev/null' EXIT
{
  _p(){ [ -n "${2:-}" ] && printf '%s:\n  - %s\n' "$1" "$2"; }
  _p virustotal     "${VIRUSTOTAL_API_KEY:-}"
  _p securitytrails "${SECURITYTRAILS_API_KEY:-}"
  _p shodan         "${SHODAN_API_KEY:-}"
  _p github         "${GITHUB_TOKEN:-}"
  _p bevigil        "${BEVIGIL_API_KEY:-}"
  _p binaryedge     "${BINARYEDGE_API_KEY:-}"
  _p fofa           "${FOFA_KEY:-}"
  _p whoisxmlapi    "${WHOISXML_API_KEY:-}"
  if [ -n "${CENSYS_API_ID:-}" ] && [ -n "${CENSYS_API_SECRET:-}" ]; then printf 'censys:\n  - %s:%s\n' "$CENSYS_API_ID" "$CENSYS_API_SECRET"
  elif [ -n "${CENSYS_API_ID:-}" ]; then printf 'censys:\n  - %s\n' "$CENSYS_API_ID"; fi
  [ -n "${CHAOS_KEY:-}${PDCP_API_KEY:-}" ] && printf 'chaos:\n  - %s\n' "${CHAOS_KEY:-${PDCP_API_KEY:-}}"
} > "$_PC_TMP" 2>/dev/null
[ -s "$_PC_TMP" ] && SF_PC="-pc $_PC_TMP"

# convenience: '-' / 'on' indicator for banners
keyon(){ [ -n "${1:-}" ] && printf 'on' || printf '-'; }
