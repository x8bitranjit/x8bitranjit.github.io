<%--
  Safe PoC -> x8bitranjit
  BENIGN marker shell - proves ASP.NET code execution only.
--%>
<%@ Page Language="C#" ContentType="text/plain" %>
<%
  Response.Write("Safe PoC -> x8bitranjit\n");
  Response.Write("asp.net " + System.Environment.Version + " | " + Environment.OSVersion + " | " + Environment.UserName);
%>
