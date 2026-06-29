<%-- BENIGN RCE PROOF (JSP). Authorized testing only. Prints a marker if executed. Not a backdoor. Delete after PoC. (guide §12) --%>
<%= "RCE-POC-" + java.net.InetAddress.getLocalHost().getHostName() %>
