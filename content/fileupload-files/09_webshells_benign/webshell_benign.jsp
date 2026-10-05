<%--
  Safe PoC -> x8bitranjit
  BENIGN marker shell - proves JSP execution only.
--%>
<%@ page contentType="text/plain" %>
<%
  out.println("Safe PoC -> x8bitranjit");
  out.println("jsp " + application.getServerInfo() + " | " + System.getProperty("os.name"));
%>
