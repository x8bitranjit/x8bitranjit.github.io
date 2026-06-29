<%@ Page Language="C#" %>
<%-- BENIGN RCE PROOF (ASPX). Authorized testing only. Prints a marker if executed. Not a backdoor. Delete after PoC. (guide §12) --%>
<%= "RCE-POC-" + System.Environment.MachineName %>
