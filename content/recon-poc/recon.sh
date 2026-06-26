#!/usr/bin/env bash
# recon.sh — backward-compatible alias. The tool was renamed to x8bit_recon.sh;
# this shim forwards all args so old habits/docs/cron entries keep working.
exec "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/x8bit_recon.sh" "$@"
