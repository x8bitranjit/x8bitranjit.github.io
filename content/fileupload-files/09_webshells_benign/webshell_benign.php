<?php
/*
  Safe PoC -> x8bitranjit
  BENIGN marker shell - proves code EXECUTION only (no commands accepted,
  nothing exfiltrated). Upload via 01_upload polyglots/config tricks.
  Real usage discipline: on an authorized target, replace the echo with a
  single id/php_uname() capture - never a general-purpose shell in bounty.
*/
header('Content-Type: text/plain');
echo "Safe PoC -> x8bitranjit\n";
echo "php " . PHP_VERSION . " | " . php_uname() . " | " . get_current_user() . "\n";
