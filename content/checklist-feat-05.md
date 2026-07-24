# 5. Payment & Checkout — Checklist

Feature-area security **test cases** for “5. Payment & Checkout”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*219 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## PAY-001 — Payment Amount Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Add items to cart 2. Proceed to checkout 3. Intercept payment request 4. Modify amount parameter 5. Complete payment

**Expected Result:** Application should reject modified payment amounts

**Payload Example:**

```
{"amount":0.01,currency:"USD",order_id:"12345"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman / OWASP ZAP

**References:** CWE-840; PortSwigger Business logic

---

## PAY-002 — Payment Currency Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate checkout in USD 2. Intercept payment request 3. Change currency to lower value currency 4. Complete payment

**Expected Result:** Currency should be validated server-side

**Payload Example:**

```
{"amount":100,currency:"VND"} instead of USD
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-003 — Negative Amount Payment
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate payment 2. Intercept request 3. Set negative amount 4. Check for credit/refund

**Expected Result:** Negative amounts should be rejected

**Payload Example:**

```
{"amount":-100.00,order_id:"12345"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-004 — Payment Gateway SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Identify callback/webhook URL parameter 2. Modify to internal URL 3. Trigger payment completion 4. Access internal services

**Expected Result:** Callback URLs should be validated against whitelist

**Payload Example:**

```
callback_url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap / Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## PAY-005 — Webhook Signature Bypass
**Test Category:** Authentication Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Capture legitimate webhook payload 2. Modify payment status to success 3. Send without valid signature 4. Check if order marked paid

**Expected Result:** Webhooks must verify cryptographic signatures

**Payload Example:**

```
Forged webhook without HMAC signature
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-006 — Webhook Replay Attack
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Capture successful payment webhook 2. Replay the same webhook multiple times 3. Check for duplicate credits

**Expected Result:** Webhooks should have replay protection via nonce

**Payload Example:**

```
Replay same webhook_id multiple times
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-007 — Payment Status Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate payment 2. Intercept status callback 3. Change status from failed to success 4. Complete order

**Expected Result:** Status should only come from verified gateway

**Payload Example:**

```
{"status":"success",payment_id:"123"} without signature
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-008 — Order ID Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Create order and initiate payment 2. Intercept request 3. Change order_id to higher value order 4. Pay less for expensive order

**Expected Result:** Order amount should be re-validated at payment

**Payload Example:**

```
{"order_id":"expensive_order",amount:1.00}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-009 — Gateway Credential Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Analyze JavaScript files 2. Check network requests 3. Look for exposed API keys 4. Test key validity

**Expected Result:** Gateway credentials should never be client-side

**Payload Example:**

```
API keys in JS: pk_live_xxx or secret_key in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools / GitLeaks

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-010 — Payment Request Tampering
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate checkout 2. Intercept all payment parameters 3. Modify merchant_id or account 4. Redirect payment to attacker

**Expected Result:** Payment parameters should be signed

**Payload Example:**

```
{"merchant_id":"attacker_merchant",amount:100}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-011 — 3DS Bypass Attempt
**Test Category:** Authentication Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate payment requiring 3DS 2. Intercept authentication request 3. Attempt to bypass 3DS flow 4. Complete payment without verification

**Expected Result:** 3DS should be mandatory when required

**Payload Example:**

```
Skip 3DS redirect or modify enrolled status
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-012 — Payment Token Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Generate payment token 2. Analyze token structure 3. Modify token to use different card 4. Process payment

**Expected Result:** Tokens should be cryptographically secure

**Payload Example:**

```
Modify card_token to reference another card
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / jwt_tool

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-013 — Gateway Error Information Disclosure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Send malformed payment request 2. Analyze error response 3. Extract sensitive information

**Expected Result:** Errors should not reveal internal details

**Payload Example:**

```
Verbose errors with gateway credentials or internal paths
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-014 — Payment Double Spending
**Test Category:** Race Condition · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate payment with same funds 2. Send concurrent payment requests 3. Spend more than available balance

**Expected Result:** Payment processing should be atomic

**Payload Example:**

```
Parallel payment requests using same card/wallet
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-015 — SSL/TLS Downgrade Attack
**Test Category:** Cryptographic Failures · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Intercept gateway communication 2. Attempt SSL stripping 3. Check for fallback to HTTP

**Expected Result:** All payment communication must use TLS 1.2+

**Payload Example:**

```
sslstrip or TLS downgrade attempt
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Burp Suite / sslstrip / testssl.sh

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## PAY-016 — Payment Confirmation Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Submit payment 2. Rapidly access order status 3. Access order before payment confirms 4. Get free items

**Expected Result:** Order access should wait for payment confirmation

**Payload Example:**

```
Race between payment and order delivery
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-017 — Idempotency Key Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Submit payment with idempotency key 2. Modify key and resubmit 3. Charge card multiple times

**Expected Result:** Idempotency should prevent duplicate charges

**Payload Example:**

```
Different idempotency_key for same order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-018 — Gateway Timeout Exploitation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate payment 2. Force timeout on server side 3. Payment completes at gateway but server unaware 4. Get free items

**Expected Result:** Timeout handling should verify final payment status

**Payload Example:**

```
Slow network causing timeout exploitation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Network Throttling

**References:** CWE-840; PortSwigger Business logic

---

## PAY-019 — PCI Data Exposure in Logs
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Complete payment transaction 2. Analyze application logs 3. Check for PAN or CVV logging

**Expected Result:** PCI data must never be logged

**Payload Example:**

```
grep for card numbers in logs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Log Analysis / Manual Review

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-020 — Payment Method Switching Exploit
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Select expensive payment method with discount 2. Switch to different method at last step 3. Keep original discount

**Expected Result:** Discounts should be recalculated on method change

**Payload Example:**

```
Switch from COD (with fee) to card (without fee) keeping total
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-021 — Disabled Payment Method Usage
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Identify disabled payment methods 2. Directly call payment API with disabled method 3. Process payment

**Expected Result:** Disabled methods should be rejected

**Payload Example:**

```
{"payment_method":"disabled_gateway",amount:100}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-022 — Payment Method IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Select own payment method 2. Intercept request 3. Change payment_method_id to another user's 4. Charge victim's card

**Expected Result:** Payment method ownership should be verified

**Payload Example:**

```
{"payment_method_id":"victim_saved_card_id"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-023 — Hidden Payment Method Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Enumerate payment method endpoints 2. Find internal/test methods 3. Use test gateway in production

**Expected Result:** Test payment methods should not exist in production

**Payload Example:**

```
payment_method=test_always_success
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / ffuf

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-024 — Payment Method Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Submit payment method selection 2. Inject SQL payload in method parameter 3. Extract data or bypass

**Expected Result:** Parameters should be parameterized

**Payload Example:**

```
payment_method=card'; DROP TABLE payments;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PAY-025 — Bank Transfer Reference Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Select bank transfer 2. Generate reference number 3. Manipulate reference 4. Match with another order

**Expected Result:** Reference numbers should be cryptographically random

**Payload Example:**

```
Predictable reference: ORD-2024-0001
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Sequencer

**References:** CWE-840; PortSwigger Business logic

---

## PAY-026 — COD to Prepaid Switch
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Place order with COD 2. Modify order to prepaid after placement 3. Receive item without payment

**Expected Result:** Order payment method should be locked after confirmation

**Payload Example:**

```
Change payment_type after order creation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-027 — Free Payment Method Exploit
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Find free payment options (gift card with zero) 2. Combine to cover full amount 3. Checkout for free

**Expected Result:** Total payment must match order total

**Payload Example:**

```
Multiple $0 gift cards to complete order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-028 — Payment Method Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Try different payment method IDs 2. Compare error responses 3. Enumerate valid methods for users

**Expected Result:** Errors should be generic

**Payload Example:**

```
Response difference for valid vs invalid method IDs
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## PAY-029 — Cryptocurrency Amount Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multiple Payment Methods

**Test Steps:** 1. Select crypto payment 2. Intercept conversion 3. Manipulate exchange rate or crypto amount

**Expected Result:** Conversion should be server-calculated and signed

**Payload Example:**

```
{"crypto_amount":0.001} instead of calculated 0.1
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-030 — Saved Card IDOR Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. View own saved cards 2. Modify user_id or card_id parameter 3. View another user's cards

**Expected Result:** Card access should verify ownership

**Payload Example:**

```
GET /api/users/victim_id/cards or /api/cards/victim_card_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-031 — Saved Card IDOR Deletion
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Delete own card 2. Modify card_id parameter 3. Delete another user's saved card

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/cards/victim_card_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-032 — Saved Card IDOR Usage
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Use own saved card for payment 2. Modify card_id to victim's card 3. Charge victim's card

**Expected Result:** Card usage should verify ownership

**Payload Example:**

```
{"card_id":"victim_card_123",amount:1000}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-033 — Card Token Enumeration
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Analyze card token format 2. Generate sequential tokens 3. Access other users' card data

**Expected Result:** Tokens should be unpredictable

**Payload Example:**

```
card_token_1 to card_token_10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## PAY-034 — Full Card Number Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Add and save card 2. View saved cards 3. Check if full PAN exposed

**Expected Result:** Only last 4 digits should be visible

**Payload Example:**

```
API returning full card number
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-035 — CVV Storage Detection
**Test Category:** PCI Compliance · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Save card with CVV 2. Analyze storage and API responses 3. Check if CVV is stored

**Expected Result:** CVV must never be stored post-authorization

**Payload Example:**

```
CVV in response or evidence of storage
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Database Review

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PAY-036 — Card Update Without Verification
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Update saved card details 2. Check if verification required 3. Modify without CVV/password

**Expected Result:** Card updates should require re-authentication

**Payload Example:**

```
PUT /api/cards/123 without password or CVV
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-037 — Expired Card Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Save card 2. Wait for expiration 3. Use expired card for payment

**Expected Result:** Expired cards should be rejected

**Payload Example:**

```
Use card with past expiration date
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-038 — Default Card Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Set card as default 2. Modify user_id 3. Set attacker's card as victim's default

**Expected Result:** Default card setting should verify ownership

**Payload Example:**

```
{"card_id":"attacker_card",user_id:"victim_id",is_default:true}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-039 — Card Fingerprint Collision
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Analyze card fingerprint generation 2. Find collision vulnerability 3. Link cards incorrectly

**Expected Result:** Fingerprints should be unique per card

**Payload Example:**

```
Duplicate fingerprint for different cards
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## PAY-040 — Payment Method XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Add card with XSS in nickname field 2. View saved cards 3. XSS executes

**Expected Result:** Card nicknames should be sanitized

**Payload Example:**

```
card_nickname=<script>stealToken()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PAY-041 — Mass Assignment Card Attributes
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Add new card 2. Include extra parameters 3. Modify restricted attributes

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"card_number":"...",verified:true,limit:999999}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## PAY-042 — Card Verification Bypass
**Test Category:** Authentication Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Add card requiring verification 2. Skip verification step 3. Use unverified card

**Expected Result:** Unverified cards should not be usable

**Payload Example:**

```
Use card before completing micro-deposit verification
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-043 — CSRF on Card Addition
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Create malicious page 2. Auto-submit card addition form 3. Add attacker's card to victim account

**Expected Result:** Card operations should require CSRF token

**Payload Example:**

```
<form action="/cards/add" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## PAY-044 — Card Data in URL Parameters
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Saved Cards / Payment Methods

**Test Steps:** 1. Analyze card-related URLs 2. Check for sensitive data in parameters 3. Check browser history exposure

**Expected Result:** Card data should never be in URLs

**Payload Example:**

```
/verify?card_number=4111111111111111&cvv=123
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser History

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-045 — Wallet Balance Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. View wallet balance 2. Intercept balance request 3. Modify balance response 4. Use inflated balance

**Expected Result:** Balance should be server-side validated

**Payload Example:**

```
{"balance":999999.99} in response modification
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-046 — Negative Wallet Transaction
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Initiate wallet transaction 2. Set negative amount 3. Credit wallet instead of debit

**Expected Result:** Amounts should be positive and validated

**Payload Example:**

```
{"transaction_type":"debit",amount:-100}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-047 — Wallet Transfer IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Transfer from own wallet 2. Modify source wallet ID 3. Transfer from victim's wallet

**Expected Result:** Transfers should verify source ownership

**Payload Example:**

```
{"from_wallet":"victim_id",to_wallet:"attacker_id",amount:1000}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-048 — Wallet Double Spending
**Test Category:** Race Condition · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Check wallet balance 2. Initiate multiple concurrent transactions 3. Spend more than balance

**Expected Result:** Wallet transactions should be atomic

**Payload Example:**

```
10 parallel $100 purchases with $100 balance
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-049 — Wallet Topup Amount Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Initiate wallet topup 2. Intercept payment callback 3. Modify credited amount

**Expected Result:** Topup amount should match payment

**Payload Example:**

```
Pay $10 but modify callback to credit $1000
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-050 — Promotional Credit Exploitation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Identify promotional credit rules 2. Create multiple accounts 3. Transfer/consolidate credits

**Expected Result:** Promotional credits should have restrictions

**Payload Example:**

```
Signup bonus abuse via multiple accounts
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Accounts

**References:** CWE-840; PortSwigger Business logic

---

## PAY-051 — Wallet Currency Conversion Exploit
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Convert wallet currency 2. Manipulate exchange rate 3. Profit from rate difference

**Expected Result:** Conversion rates should be server-side

**Payload Example:**

```
Convert repeatedly with favorable rounding
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-052 — Expired Credits Usage
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Receive credits with expiry 2. Wait for expiration 3. Attempt to use expired credits

**Expected Result:** Expired credits should be rejected

**Payload Example:**

```
Use credits after expiration timestamp
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-053 — Wallet Transaction History IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. View own transaction history 2. Modify user_id parameter 3. View victim's transactions

**Expected Result:** History should verify ownership

**Payload Example:**

```
GET /api/wallets/victim_id/transactions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-054 — Wallet SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Search wallet transactions 2. Inject SQL payload 3. Extract transaction data

**Expected Result:** Queries should be parameterized

**Payload Example:**

```
/transactions?search=' UNION SELECT * FROM wallets--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PAY-055 — Credit Refund Loop
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Purchase with wallet 2. Request refund 3. Receive original payment + wallet credit 4. Repeat

**Expected Result:** Refunds should go to original payment source

**Payload Example:**

```
Refund to different method than payment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-056 — Wallet Integer Overflow
**Test Category:** Input Validation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Add extremely large amount to wallet 2. Cause integer overflow 3. Manipulate balance

**Expected Result:** Amounts should have reasonable limits

**Payload Example:**

```
{"amount":9999999999999999999999}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## PAY-057 — Wallet Withdrawal to External Account
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Request withdrawal 2. Modify destination account 3. Withdraw to attacker account

**Expected Result:** Withdrawals should verify linked accounts

**Payload Example:**

```
{"destination":"attacker_bank_account"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-058 — Gift Card to Wallet Balance
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Redeem gift card to wallet 2. Manipulate gift card value 3. Get inflated wallet balance

**Expected Result:** Gift card value should be validated

**Payload Example:**

```
Modify gift_card_value parameter
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-059 — Cashback Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Wallet / Credits System

**Test Steps:** 1. Complete qualifying purchase 2. Intercept cashback calculation 3. Inflate cashback amount

**Expected Result:** Cashback should be server-calculated

**Payload Example:**

```
{"cashback_percent":100} or {"cashback":999}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-060 — Split Amount Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Initiate split payment 2. Modify individual split amounts 3. Total splits less than order

**Expected Result:** Split total should equal order total

**Payload Example:**

```
{"splits":[{"method":"card",amount:1},{"method":"wallet",amount:0}]} for $100 order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-061 — Split Payment Method Injection
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Configure split payment 2. Add unauthorized payment method 3. Use test gateway in split

**Expected Result:** All split methods should be validated

**Payload Example:**

```
{"splits":[{"method":"test_success",amount:50}]}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-062 — Split Payment IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Create split with own cards 2. Modify card_id in one split 3. Use victim's card in split

**Expected Result:** All payment sources should be owned

**Payload Example:**

```
{"splits":[{"card_id":"victim_card",amount:50}]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-063 — Split Payment Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Initiate split payment 2. Modify splits during processing 3. Reduce total paid

**Expected Result:** Split configuration should be locked during processing

**Payload Example:**

```
Modify splits between validation and charge
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-064 — Partial Payment Completion Exploit
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Initiate split with multiple methods 2. Let one payment fail 3. Receive goods with partial payment

**Expected Result:** Order should require all splits to succeed

**Payload Example:**

```
First split succeeds but second fails deliberately
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-065 — Split Refund Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Complete split payment 2. Request partial refund 3. Refund more than paid per method

**Expected Result:** Refund should not exceed method amount

**Payload Example:**

```
Refund $100 to card that only paid $50
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-066 — Gift Card + Card Split Abuse
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Apply partial gift card 2. Modify remaining card amount 3. Pay less on card

**Expected Result:** Card amount should auto-calculate correctly

**Payload Example:**

```
{"gift_card":10,card_amount:0} for $50 order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-067 — Split Limit Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Check maximum split methods 2. Exceed split count 3. Create invalid payment state

**Expected Result:** Split count should be limited

**Payload Example:**

```
{"splits":[...50 different methods...]}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-068 — Zero Amount Split
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Create split with zero amount method 2. Mark it as paid 3. Reduce total payment

**Expected Result:** Zero amount splits should be rejected

**Payload Example:**

```
{"splits":[{"method":"card",amount:0}]}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-069 — Split Payment Decimal Exploit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Split Payments

**Test Steps:** 1. Create splits with many decimals 2. Exploit rounding errors 3. Pay less total

**Expected Result:** Decimal handling should be consistent

**Payload Example:**

```
{"splits":[{"amount":33.333333333}]} x3 for $100
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-070 — EMI Amount Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Select EMI option 2. Intercept EMI calculation 3. Modify installment amount

**Expected Result:** EMI amounts should be server-calculated

**Payload Example:**

```
{"emi_amount":1.00,tenure:12} for expensive item
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-071 — EMI Interest Rate Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Choose EMI plan 2. Modify interest rate parameter 3. Get zero or negative interest

**Expected Result:** Interest rates should be predefined server-side

**Payload Example:**

```
{"interest_rate":0} or {"interest_rate":-5}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-072 — EMI Tenure Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Select EMI tenure 2. Modify to unauthorized tenure 3. Get better terms

**Expected Result:** Available tenures should be validated

**Payload Example:**

```
{"tenure":120} when max is 24 months
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-073 — No-Cost EMI Fraud
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Identify no-cost EMI products 2. Apply to ineligible products 3. Get interest-free installments

**Expected Result:** No-cost EMI should validate product eligibility

**Payload Example:**

```
Apply no_cost_emi=true to ineligible product
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-074 — EMI Cancellation After Delivery
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Order with EMI 2. Receive product 3. Cancel EMI plan 4. Keep product

**Expected Result:** EMI cancellation should trigger return

**Payload Example:**

```
Cancel EMI without returning product
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-075 — Downpayment Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Select EMI requiring downpayment 2. Intercept request 3. Set downpayment to zero

**Expected Result:** Downpayment should be enforced server-side

**Payload Example:**

```
{"downpayment":0} when required is 20%
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-076 — EMI Eligibility Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Check EMI eligibility criteria 2. Modify eligibility check 3. Get EMI for ineligible purchase

**Expected Result:** Eligibility should be server-validated

**Payload Example:**

```
Bypass minimum order amount for EMI
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-077 — Processing Fee Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Accept EMI with processing fee 2. Modify fee amount 3. Reduce or eliminate fee

**Expected Result:** Processing fees should be fixed server-side

**Payload Example:**

```
{"processing_fee":0}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-078 — EMI Credit Limit Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Check available EMI limit 2. Place order exceeding limit 3. Get EMI above limit

**Expected Result:** Credit limit should be enforced

**Payload Example:**

```
Order $10000 with $5000 EMI limit
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-079 — Bank EMI Offer Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** EMI / Installments

**Test Steps:** 1. Find bank-specific EMI offers 2. Apply with different bank card 3. Get unauthorized discounts

**Expected Result:** Offers should validate card BIN

**Payload Example:**

```
Apply HDFC offer with ICICI card
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-080 — Invoice IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Access own invoice 2. Modify invoice_id parameter 3. Access other users' invoices

**Expected Result:** Invoice access should verify ownership

**Payload Example:**

```
GET /invoices/victim_invoice_id or /invoices/123456.pdf
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-081 — Invoice Number Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Analyze invoice number pattern 2. Enumerate sequential numbers 3. Access all invoices

**Expected Result:** Invoice numbers should be unpredictable

**Payload Example:**

```
INV-2024-0001 to INV-2024-9999
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## PAY-082 — Invoice Amount Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Generate invoice 2. Intercept request 3. Modify invoice amount 4. Send to client

**Expected Result:** Invoice amounts should be server-generated

**Payload Example:**

```
{"invoice_amount":0.01,original:1000}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-083 — Invoice PDF XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Find user-controlled data in invoice 2. Insert XSS payload 3. Generate and view PDF

**Expected Result:** PDF generation should sanitize inputs

**Payload Example:**

```
<script>alert('XSS')</script> in product name
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / PDF Reader

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PAY-084 — Invoice SSRF via Logo
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Find company logo URL in invoice 2. Modify to internal URL 3. Generate invoice

**Expected Result:** URLs should be validated

**Payload Example:**

```
logo_url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## PAY-085 — Invoice Template Injection
**Test Category:** Server-Side Template Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Identify template engine 2. Inject SSTI payload in invoice fields 3. Achieve code execution

**Expected Result:** User input should not be templated

**Payload Example:**

```
{{constructor.constructor('return this')()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## PAY-086 — Invoice Path Traversal
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Request invoice download 2. Modify file path 3. Access server files

**Expected Result:** File paths should be validated

**Payload Example:**

```
/invoices/download?file=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## PAY-087 — Fake Invoice Generation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Generate invoice for own order 2. Modify order_id 3. Generate invoice for non-purchased items

**Expected Result:** Invoices should only generate for valid orders

**Payload Example:**

```
Generate invoice without corresponding order
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-088 — Invoice Tax Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Generate invoice 2. Modify tax amount 3. Reduce total

**Expected Result:** Tax should be calculated server-side

**Payload Example:**

```
{"tax_amount":0} for taxable order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-089 — XML Invoice XXE
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Find XML invoice export 2. Inject XXE payload 3. Extract server files

**Expected Result:** XML parsing should disable external entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## PAY-090 — Invoice Status Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. View unpaid invoice 2. Modify status to paid 3. Mark order as complete

**Expected Result:** Invoice status should be system-controlled

**Payload Example:**

```
{"status":"paid"} without actual payment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-091 — Credit Note Fraud
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Invoice Generation

**Test Steps:** 1. Generate credit note 2. Manipulate credited amount 3. Get excess credit

**Expected Result:** Credit notes should match original transactions

**Payload Example:**

```
Credit note exceeding invoice amount
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-092 — Refund Amount Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Request refund 2. Intercept request 3. Modify refund amount 4. Get excess refund

**Expected Result:** Refund should not exceed payment amount

**Payload Example:**

```
{"refund_amount":1000} for $100 purchase
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-093 — Refund IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Request refund for own order 2. Modify order_id 3. Refund another user's order to your account

**Expected Result:** Refunds should verify order ownership

**Payload Example:**

```
POST /refunds {"order_id":"victim_order"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-094 — Double Refund Attack
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Request refund 2. Rapidly request same refund again 3. Get refunded twice

**Expected Result:** Refund should be idempotent

**Payload Example:**

```
Two concurrent refund requests for same order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-840; PortSwigger Business logic

---

## PAY-095 — Refund Without Return
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Request refund 2. Bypass return requirement 3. Keep product and money

**Expected Result:** Refund should require return verification

**Payload Example:**

```
Complete refund without return_tracking
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-096 — Refund to Different Account
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Pay with card A 2. Request refund 3. Modify destination to account B

**Expected Result:** Refund should go to original payment method

**Payload Example:**

```
{"refund_to":"attacker_bank_account"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-097 — Refund Currency Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Pay in one currency 2. Request refund 3. Change refund currency

**Expected Result:** Refund currency should match payment

**Payload Example:**

```
{"currency":"BTC"} for USD payment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-098 — Partial Refund Exploitation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Order multiple items 2. Request partial refund 3. Manipulate refund allocation

**Expected Result:** Partial refunds should be proportional

**Payload Example:**

```
Refund expensive item but return cheap one
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-099 — Refund Reason Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Submit refund request 2. Inject payload in reason field 3. Achieve XSS or SQLi

**Expected Result:** Reason field should be sanitized

**Payload Example:**

```
reason=<script>alert('XSS')</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PAY-100 — Gift Card Refund to Cash
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Purchase with gift card 2. Request cash refund 3. Convert gift card to cash

**Expected Result:** Refund should match payment method

**Payload Example:**

```
Refund to bank for gift card purchase
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-101 — Refund Timing Attack
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Return product 2. Intercept refund webhook 3. Modify timestamp 4. Get interest/compensation

**Expected Result:** Timing should be server-validated

**Payload Example:**

```
Modify refund_date to claim late refund penalty
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-102 — Chargeback Fraud Detection
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Complete purchase 2. Receive goods 3. File chargeback with bank 4. Keep goods

**Expected Result:** System should flag chargeback patterns

**Payload Example:**

```
Multiple chargebacks from same user
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing / Fraud Analysis

**References:** CWE-840; PortSwigger Business logic

---

## PAY-103 — Refund Approval Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Request refund requiring approval 2. Bypass approval workflow 3. Auto-approve refund

**Expected Result:** Approval workflow should be enforced

**Payload Example:**

```
{"status":"approved"} without admin
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-104 — Store Credit Refund Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Refund Processing

**Test Steps:** 1. Request store credit refund 2. Modify credit amount 3. Get excess credit

**Expected Result:** Store credit should equal refund amount

**Payload Example:**

```
{"store_credit":500} for $100 refund
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-105 — Subscription Price Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Subscribe to plan 2. Intercept recurring charge 3. Modify subscription amount

**Expected Result:** Subscription price should be fixed server-side

**Payload Example:**

```
{"subscription_price":0.01} for premium plan
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-106 — Subscription Plan Upgrade Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Subscribe to basic plan 2. Modify plan_id to premium 3. Get premium features at basic price

**Expected Result:** Plan access should match subscription

**Payload Example:**

```
{"plan_id":"premium"} while paying basic
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-107 — Subscription IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. View own subscription 2. Modify subscription_id 3. Access/modify other subscriptions

**Expected Result:** Subscription access should verify ownership

**Payload Example:**

```
GET /api/subscriptions/victim_sub_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-108 — Trial Period Extension
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Start free trial 2. Modify trial_end date 3. Extend trial indefinitely

**Expected Result:** Trial dates should be server-controlled

**Payload Example:**

```
{"trial_ends_at":"2099-12-31"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-109 — Subscription Cancellation Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Cancel subscription 2. Check if features still accessible 3. Use without paying

**Expected Result:** Cancellation should revoke access

**Payload Example:**

```
Access premium features after cancellation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-110 — Grandfathered Price Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Find legacy pricing 2. Apply old price to new subscription 3. Get discounted rate

**Expected Result:** Price should be current for new subscriptions

**Payload Example:**

```
{"price_id":"legacy_2019_price"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-111 — Subscription Webhook Bypass
**Test Category:** Authentication Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Capture subscription webhook 2. Forge renewal success 3. Extend without payment

**Expected Result:** Webhooks must be cryptographically verified

**Payload Example:**

```
Forged subscription.renewed webhook
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-112 — Family Plan Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Subscribe to family plan 2. Add users beyond limit 3. Share with unlimited users

**Expected Result:** Member limits should be enforced

**Payload Example:**

```
Add 100 members to 5-member family plan
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-113 — Subscription Transfer IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Transfer subscription 2. Modify recipient 3. Transfer to attacker

**Expected Result:** Transfers should verify both parties

**Payload Example:**

```
{"transfer_to":"attacker_id"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-114 — Billing Cycle Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Select monthly subscription 2. Modify to annual billing 3. Pay monthly price for year

**Expected Result:** Billing cycle should match price

**Payload Example:**

```
{"billing_cycle":"annual",amount:9.99}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-115 — Coupon on Recurring Payments
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Apply coupon to subscription 2. Check if applies to renewals 3. Get perpetual discount

**Expected Result:** Coupon terms should be enforced

**Payload Example:**

```
One-time coupon applying to every renewal
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-116 — Payment Method Update Timing
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Update payment method before charge 2. Use expired card 3. Get free month while updating

**Expected Result:** Failed payments should pause access

**Payload Example:**

```
Cycle through failed payment methods
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-117 — Subscription Sharing Token
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Generate sharing token 2. Analyze token structure 3. Generate tokens for other users

**Expected Result:** Tokens should be unpredictable

**Payload Example:**

```
Predictable share_token generation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-118 — Downgrade Refund Abuse
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Subscription / Recurring Payments

**Test Steps:** 1. Pay for annual premium 2. Downgrade to basic 3. Request prorated refund 4. Repeat

**Expected Result:** Downgrade should handle refunds correctly

**Payload Example:**

```
Downgrade/refund cycle for profit
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-119 — Tax Rate Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Add item to cart 2. Intercept tax calculation 3. Modify tax rate 4. Pay less tax

**Expected Result:** Tax should be calculated server-side

**Payload Example:**

```
{"tax_rate":0} or {"tax_rate":-10}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-120 — Tax Exemption Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Claim tax exemption 2. Bypass verification 3. Get tax-free purchase

**Expected Result:** Exemption should require verification

**Payload Example:**

```
{"tax_exempt":true} without certificate
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-121 — Tax-Free Region Abuse
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Enter tax-free shipping address 2. Complete payment 3. Change address to taxable region

**Expected Result:** Tax should be recalculated on address change

**Payload Example:**

```
Switch from Delaware to California post-payment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-122 — Tax Amount Parameter Tampering
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Proceed to checkout 2. Intercept request 3. Modify tax_amount parameter

**Expected Result:** Tax amount should be server-calculated

**Payload Example:**

```
{"tax_amount":0} for taxable order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-123 — VAT ID Validation Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Enter fake VAT ID 2. Bypass validation 3. Get B2B tax exemption

**Expected Result:** VAT IDs should be validated with authority

**Payload Example:**

```
Invalid VIES format accepted
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-124 — Tax Category Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Identify tax categories 2. Modify product category 3. Apply lower tax rate

**Expected Result:** Product categories should be server-controlled

**Payload Example:**

```
Change category from luxury (20%) to essential (5%)
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-125 — Digital Goods Tax Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Purchase digital goods 2. Modify location to tax-free jurisdiction 3. Avoid digital tax

**Expected Result:** Location should be verified

**Payload Example:**

```
IP from India but address in tax-free zone
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / VPN

**References:** CWE-840; PortSwigger Business logic

---

## PAY-126 — Tax Inclusive/Exclusive Exploit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Find tax calculation type 2. Manipulate inclusive/exclusive flag 3. Pay less

**Expected Result:** Tax mode should be fixed per region

**Payload Example:**

```
{"tax_inclusive":true} in exclusive region
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-127 — Multiple Tax Application
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Add items from different tax zones 2. Manipulate zone assignment 3. Apply lower taxes

**Expected Result:** Tax zone should be determined server-side

**Payload Example:**

```
Assign all items to lowest tax zone
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-128 — Tax Rounding Exploitation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Tax Calculation

**Test Steps:** 1. Calculate tax on many items 2. Exploit rounding errors 3. Pay less tax

**Expected Result:** Rounding should be consistent

**Payload Example:**

```
Many $0.01 items with favorable rounding
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## PAY-129 — Shipping Cost Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Select shipping method 2. Intercept request 3. Modify shipping cost 4. Get free shipping

**Expected Result:** Shipping cost should be server-calculated

**Payload Example:**

```
{"shipping_cost":0} for express shipping
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-130 — Shipping Method Injection
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Select shipping option 2. Modify to unauthorized method 3. Get free/discounted shipping

**Expected Result:** Available methods should be validated

**Payload Example:**

```
{"shipping_method":"internal_free_shipping"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-131 — Weight Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Add heavy items 2. Intercept weight calculation 3. Modify total weight

**Expected Result:** Weight should be server-calculated

**Payload Example:**

```
{"total_weight":0.1} for 50kg order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-132 — Dimension Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Order large items 2. Intercept dimension data 3. Reduce dimensions

**Expected Result:** Dimensions should be from product data

**Payload Example:**

```
{"dimensions":"1x1x1"} for large item
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-133 — Shipping Zone Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Enter distant address 2. Intercept zone calculation 3. Change to local zone

**Expected Result:** Zone should be calculated from address

**Payload Example:**

```
{"shipping_zone":"local"} for international
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-134 — Free Shipping Threshold Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Add items to reach free shipping 2. Remove items after calculation 3. Keep free shipping

**Expected Result:** Free shipping should recalculate on changes

**Payload Example:**

```
Remove items after free shipping applied
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-135 — Shipping Discount Stacking
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Apply shipping coupon 2. Apply promotional free shipping 3. Get shipping credit

**Expected Result:** Shipping discounts should not stack

**Payload Example:**

```
Multiple shipping discounts on one order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-136 — Expedited Shipping Swap
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Select standard shipping 2. Modify to expedited after payment 3. Get free upgrade

**Expected Result:** Shipping method should be locked at payment

**Payload Example:**

```
Change method in fulfillment request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-137 — Multi-Package Cost Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Order requiring multiple packages 2. Intercept package count 3. Reduce to single package cost

**Expected Result:** Package count should be calculated server-side

**Payload Example:**

```
{"package_count":1} for multi-package order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-138 — Store Pickup Delivery Fraud
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Shipping Cost Calculation

**Test Steps:** 1. Select free store pickup 2. Change to home delivery after order 3. Get free delivery

**Expected Result:** Fulfillment method should be locked

**Payload Example:**

```
Change from pickup to delivery post-order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-139 — Guest to Account Cart Hijack
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Add items as guest 2. Login to existing account 3. Steal guest cart items

**Expected Result:** Cart merge should be intentional

**Payload Example:**

```
Guest cart overwriting user cart items
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## PAY-140 — Guest Checkout Bypass Required Auth
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Identify products requiring account 2. Purchase via guest checkout 3. Bypass restrictions

**Expected Result:** Product restrictions should apply to guest

**Payload Example:**

```
Age-restricted items via guest checkout
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-141 — Guest Session Hijacking
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Get guest session token 2. Share with another browser 3. Hijack guest session

**Expected Result:** Guest sessions should be protected

**Payload Example:**

```
Predictable guest_session_id
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Session Analysis

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## PAY-142 — Guest Order IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Complete guest order 2. Receive order ID 3. Modify ID to access other orders

**Expected Result:** Guest orders should be access-controlled

**Payload Example:**

```
GET /orders/victim_order_id without auth
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-143 — Guest Email Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Start guest checkout 2. Enter existing user email 3. Observe different response

**Expected Result:** Response should be consistent

**Payload Example:**

```
Different messages for existing vs new email
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## PAY-144 — Guest Checkout Price Lock
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Add items to guest cart 2. Price increases 3. Check if old price applies

**Expected Result:** Prices should be current at checkout

**Payload Example:**

```
Use cart with outdated prices
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-145 — Guest Fraud Prevention Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Identify fraud checks for guests 2. Bypass velocity limits 3. Process fraudulent orders

**Expected Result:** Fraud checks should apply to guests

**Payload Example:**

```
Multiple orders with different guest identities
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Sessions

**References:** CWE-840; PortSwigger Business logic

---

## PAY-146 — Guest Address Validation Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Enter invalid shipping address 2. Bypass address validation 3. Complete order

**Expected Result:** Address should be validated

**Payload Example:**

```
Invalid or non-deliverable address accepted
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-147 — Guest Payment Limit Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Check guest payment limits 2. Exceed maximum order value 3. Complete large order

**Expected Result:** Transaction limits should apply

**Payload Example:**

```
Guest order exceeding $10000 limit
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-148 — Guest Promotion Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Guest Checkout

**Test Steps:** 1. Use guest promo code 2. Create new guest session 3. Reuse same promo

**Expected Result:** One-time promos should track usage

**Payload Example:**

```
Same promo code across guest sessions
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Sessions

**References:** CWE-840; PortSwigger Business logic

---

## PAY-149 — One-Click Without Re-auth
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Enable one-click checkout 2. Wait extended period 3. Purchase without re-authentication

**Expected Result:** High-risk actions should require re-auth

**Payload Example:**

```
One-click purchase after session age > 30min
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-150 — One-Click Payment Method Swap
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Configure one-click 2. Intercept one-click request 3. Change payment method to victim's

**Expected Result:** Payment method should be verified

**Payload Example:**

```
{"payment_method_id":"victim_card"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-151 — One-Click Address Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. One-click purchase 2. Intercept request 3. Change shipping address

**Expected Result:** Address should match saved default

**Payload Example:**

```
{"shipping_address":"attacker_address"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-152 — One-Click Price Tampering
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Initiate one-click 2. Intercept price parameter 3. Modify product price

**Expected Result:** Prices should be server-validated

**Payload Example:**

```
{"price":0.01} in one-click request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-153 — One-Click CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Create malicious page 2. Trigger victim's one-click 3. Force unwanted purchase

**Expected Result:** One-click should require CSRF protection

**Payload Example:**

```
<img src="/one-click-buy?product_id=expensive">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## PAY-154 — One-Click Clickjacking
**Test Category:** UI Redressing · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Frame one-click button 2. Overlay transparent UI 3. Trick victim to click

**Expected Result:** One-click pages should prevent framing

**Payload Example:**

```
Invisible iframe over one-click button
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## PAY-155 — One-Click Token Replay
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Capture one-click token 2. Replay for additional purchases 3. Unauthorized orders

**Expected Result:** Tokens should be single-use

**Payload Example:**

```
Replay one_click_token for multiple orders
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## PAY-156 — One-Click Session Fixation
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Create session 2. Send to victim 3. Victim configures one-click 4. Attacker uses it

**Expected Result:** Session should regenerate on configuration

**Payload Example:**

```
Session fixation before one-click setup
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## PAY-157 — One-Click Inventory Race
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Find limited stock item 2. Multiple concurrent one-clicks 3. Oversell inventory

**Expected Result:** One-click should check inventory atomically

**Payload Example:**

```
Parallel one-click purchases
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-158 — One-Click Timeout Exploit
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** One-Click Checkout

**Test Steps:** 1. Initiate one-click 2. Force timeout 3. Payment fails but order created

**Expected Result:** Timeout should cancel entire transaction

**Payload Example:**

```
Order completed despite payment timeout
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Network Throttling

**References:** CWE-840; PortSwigger Business logic

---

## PAY-159 — Retry Count Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Fail payment intentionally 2. Exceed retry limit 3. Continue retrying

**Expected Result:** Retry limits should be enforced

**Payload Example:**

```
Retry 100+ times after limit
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## PAY-160 — Failed Payment Order Completion
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Place order 2. Payment fails 3. Order marked complete anyway 4. Receive goods

**Expected Result:** Failed payments should cancel orders

**Payload Example:**

```
Order processing despite payment failure
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-161 — Payment Status Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Submit payment 2. Rapidly check order status 3. Access order before confirmation

**Expected Result:** Order status should wait for payment

**Payload Example:**

```
Race between payment and fulfillment
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-162 — Retry Different Amount
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Payment fails 2. Retry with modified amount 3. Pay less than order

**Expected Result:** Retry should use original amount

**Payload Example:**

```
{"amount":0.01} on retry
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-163 — Payment Failure Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Trigger various payment failures 2. Analyze error messages 3. Extract sensitive info

**Expected Result:** Errors should be generic

**Payload Example:**

```
Card declined reason revealing card type/bank
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-164 — Retry Token Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Get retry token 2. Modify token parameters 3. Retry with changed order

**Expected Result:** Retry should maintain original order

**Payload Example:**

```
Modify order_id in retry_token
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / jwt_tool

**References:** CWE-840; PortSwigger Business logic

---

## PAY-165 — Concurrent Retry Attack
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Initiate payment 2. Force failure 3. Concurrent retries 4. Multiple charges

**Expected Result:** Retry should be mutually exclusive

**Payload Example:**

```
Parallel retry requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-166 — Failure Callback Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Intercept failure callback 2. Change to success 3. Complete order without payment

**Expected Result:** Callbacks should be cryptographically signed

**Payload Example:**

```
Modify status in callback URL
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-167 — Pending Payment Timeout Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Start payment 2. Leave in pending 3. Use item/service during pending

**Expected Result:** Pending orders should not grant access

**Payload Example:**

```
Access subscription during pending payment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-168 — Grace Period Exploitation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Payment Retry / Failure Handling

**Test Steps:** 1. Payment fails 2. Grace period starts 3. Continue using service 4. Never pay

**Expected Result:** Grace periods should have limits

**Payload Example:**

```
Perpetual grace period extension
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-169 — Exchange Rate Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Select currency 2. Intercept conversion 3. Modify exchange rate

**Expected Result:** Rates should be server-provided

**Payload Example:**

```
{"exchange_rate":0.01} for USD to INR
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-170 — Currency Arbitrage Attack
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Check prices in multiple currencies 2. Find favorable conversion 3. Purchase in cheapest currency

**Expected Result:** Prices should be consistent across currencies

**Payload Example:**

```
Buy in currency with favorable rounding
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-171 — Dynamic Currency Conversion Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Opt out of DCC 2. Check if savings applied 3. Bypass DCC fees

**Expected Result:** DCC should be transparent

**Payload Example:**

```
Force local currency charge
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-172 — Refund Currency Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Pay in currency A 2. Request refund 3. Get refund in more valuable currency B

**Expected Result:** Refund should match payment currency

**Payload Example:**

```
{"refund_currency":"BTC"} for USD payment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-173 — Currency Code Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Enter currency code 2. Inject SQL/special characters 3. Exploit injection

**Expected Result:** Currency should be from predefined list

**Payload Example:**

```
currency=USD' OR '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PAY-174 — Invalid Currency Code
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Submit payment 2. Use invalid currency code 3. Check system behavior

**Expected Result:** Invalid currencies should be rejected

**Payload Example:**

```
{"currency":"FAKE"} or {"currency":""}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## PAY-175 — Conversion Rate Caching Exploit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Get price in currency 2. Wait for rate change 3. Use cached favorable rate

**Expected Result:** Rates should be recalculated at payment

**Payload Example:**

```
Use stale favorable exchange rate
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-176 — Multi-Currency Cart Exploit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Add items in different currencies 2. Manipulate conversion 3. Reduce total

**Expected Result:** Multi-currency should convert consistently

**Payload Example:**

```
Mix currencies to exploit rounding
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-177 — Cryptocurrency Conversion Race
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. Get crypto price 2. Rapid price change 3. Pay at old rate

**Expected Result:** Crypto prices should lock at payment

**Payload Example:**

```
Race between quote and payment
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-178 — Display vs Charge Currency Mismatch
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Currency Conversion

**Test Steps:** 1. View price in local currency 2. Check actual charge currency 3. Find mismatch

**Expected Result:** Displayed currency should match charge

**Payload Example:**

```
Display $100 but charge 100 EUR
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Bank Statement

**References:** CWE-840; PortSwigger Business logic

---

## PAY-179 — PAN Exposure in Logs
**Test Category:** PCI Compliance · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Complete payment 2. Access application logs 3. Search for card numbers

**Expected Result:** Card numbers must never be logged

**Payload Example:**

```
grep for 16-digit numbers in logs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Log Analysis / grep / SIEM

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-180 — CVV Transmission Security
**Test Category:** PCI Compliance · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Capture payment submission 2. Analyze CVV handling 3. Check encryption

**Expected Result:** CVV must be encrypted and not stored

**Payload Example:**

```
CVV in plaintext in request body
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Wireshark

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PAY-181 — Payment Page Content Injection
**Test Category:** Cross-Site Scripting · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Find user-controlled content on payment page 2. Inject XSS 3. Steal payment info

**Expected Result:** Payment pages should have strict CSP

**Payload Example:**

```
<script>sendCardToAttacker()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PAY-182 — Payment Form MITM
**Test Category:** Cryptographic Failures · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze payment form submission 2. Check for mixed content 3. Attempt SSL strip

**Expected Result:** All payment traffic must be HTTPS

**Payload Example:**

```
HTTP resources on HTTPS payment page
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Burp Suite / sslstrip / Wireshark

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## PAY-183 — Card Skimming via XSS
**Test Category:** Cross-Site Scripting · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Find XSS on payment page 2. Inject card skimmer 3. Capture card data

**Expected Result:** Payment pages should be XSS-free

**Payload Example:**

```
document.forms[0].addEventListener('submit'...)
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter / Magecart

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PAY-184 — Payment API Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze payment API 2. Remove/modify auth tokens 3. Process unauthorized payments

**Expected Result:** Payment APIs must require authentication

**Payload Example:**

```
API calls without authentication
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-185 — Insecure Payment Token Storage
**Test Category:** Insecure Storage · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze local storage 2. Check for payment tokens 3. Assess token security

**Expected Result:** Tokens should not be in localStorage

**Payload Example:**

```
payment_token in localStorage/sessionStorage
```

**Impact:** Insecure data storage -&gt; disclosure of credentials/PII/tokens at rest.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-922; OWASP Insecure Storage; WSTG-ATHN

---

## PAY-186 — Payment Confirmation Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Complete payment 2. Skip confirmation step 3. Process order without confirmation

**Expected Result:** All payment steps should be required

**Payload Example:**

```
Jump from payment to order completion
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-187 — Third-Party Payment Script Injection
**Test Category:** Supply Chain · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Identify third-party payment scripts 2. Analyze for tampering 3. Check SRI hashes

**Expected Result:** Third-party scripts should use SRI

**Payload Example:**

```
External scripts without integrity attribute
```

**Impact:** Supply-chain / dependency confusion -&gt; build &amp; CI compromise -&gt; RCE.

**Tools:** Browser DevTools / CSP Analysis

**References:** CWE-829; -&gt;[Dependency Confusion checklist](#/checklist/depconfusion); Alex Birsan Dependency Confusion

---

## PAY-188 — Payment Form Autocomplete
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze payment form HTML 2. Check autocomplete attributes 3. Assess data exposure

**Expected Result:** Sensitive fields should disable autocomplete

**Payload Example:**

```
autocomplete="on" for CVV field
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Browser DevTools / HTML Analysis

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PAY-189 — Concurrent Transaction Attack
**Test Category:** Race Condition · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Initiate multiple payments simultaneously 2. Exploit race conditions 3. Pay once for multiple orders

**Expected Result:** Transactions should be atomic

**Payload Example:**

```
Parallel payment submissions
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-190 — Payment Session Timeout
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Start payment flow 2. Wait for timeout 3. Complete with expired session

**Expected Result:** Expired sessions should restart flow

**Payload Example:**

```
Complete payment with expired session
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-191 — Payment Idempotency Failure
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Submit payment 2. Network issue 3. Retry submission 4. Double charge

**Expected Result:** Payments should be idempotent

**Payload Example:**

```
Same payment processed twice
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Network Simulation

**References:** CWE-840; PortSwigger Business logic

---

## PAY-192 — Checkout Step Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Map checkout workflow 2. Skip or reorder steps 3. Complete without payment

**Expected Result:** Workflow should enforce all steps

**Payload Example:**

```
Jump from cart to confirmation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-193 — Payment Notification Spoofing
**Test Category:** Authentication Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze IPN/webhook format 2. Send forged notification 3. Mark order as paid

**Expected Result:** Notifications must be cryptographically verified

**Payload Example:**

```
Forged PayPal/Stripe webhook
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman / Webhook Tester

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-194 — Card BIN Information Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Enter partial card number 2. Check response 3. Find BIN information exposure

**Expected Result:** BIN data should not be exposed

**Payload Example:**

```
Card type/bank revealed before submission
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-195 — Payment Method Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Enter different cards 2. Compare error messages 3. Determine card validity

**Expected Result:** Errors should be generic

**Payload Example:**

```
Different errors for invalid vs stolen cards
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## PAY-196 — Insufficient Payment Logging
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Complete transactions 2. Check audit logs 3. Assess log completeness

**Expected Result:** All payment events should be logged

**Payload Example:**

```
Missing logs for failed/suspicious payments
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Log Analysis / SIEM

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PAY-197 — Payment Gateway Credential Rotation
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Check for hardcoded credentials 2. Analyze credential management 3. Test old credentials

**Expected Result:** Credentials should be rotated regularly

**Payload Example:**

```
Old API keys still functional
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Code Review / Credential Testing

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PAY-198 — 3DS Implementation Flaws
**Test Category:** Authentication Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze 3DS implementation 2. Find bypass conditions 3. Skip authentication

**Expected Result:** 3DS should be properly implemented

**Payload Example:**

```
3DS skipped for high-risk transactions
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-199 — Tokenization Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze tokenization flow 2. Find way to access raw card data 3. Bypass tokenization

**Expected Result:** Raw card data should never be accessible

**Payload Example:**

```
Access card details instead of tokens
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-200 — Payment Link Tampering
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Generate payment link 2. Modify amount/details in link 3. Pay modified amount

**Expected Result:** Payment links should be signed

**Payload Example:**

```
Unsigned payment link parameters
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / URL Analysis

**References:** CWE-840; PortSwigger Business logic

---

## PAY-201 — Partial Capture Exploitation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Authorize full amount 2. Capture partial amount 3. Re-capture remaining

**Expected Result:** Capture total should not exceed auth

**Payload Example:**

```
Multiple captures exceeding authorization
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-202 — Void/Cancel Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Process payment 2. Simultaneously void 3. Check final state

**Expected Result:** Void should be atomic

**Payload Example:**

```
Race between capture and void
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PAY-203 — Test Card in Production
**Test Category:** Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Use test card numbers 2. Submit in production 3. Check if accepted

**Expected Result:** Test cards should fail in production

**Payload Example:**

```
4111111111111111 accepted in production
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PAY-204 — Payment Data in Browser History
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Complete payment 2. Check browser history 3. Find sensitive data in URLs

**Expected Result:** Sensitive data should not be in URLs

**Payload Example:**

```
Card details in GET parameters
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser History / URL Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PAY-205 — Insufficient Transaction Isolation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Start transaction 2. Access another user's transaction 3. Modify or view details

**Expected Result:** Transactions should be isolated

**Payload Example:**

```
View other users' transaction details
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-206 — Payment Confirmation Email Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Complete purchase 2. Inject headers in email field 3. Send spam

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
email=victim@test.com%0ABcc:spam@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PAY-207 — Mobile Payment Deep Link Hijacking
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze payment app deep links 2. Create malicious deep link 3. Hijack payment

**Expected Result:** Deep links should validate origin

**Payload Example:**

```
Malicious app handling payment://callback
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Mobile Testing / Deep Link Analysis

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-208 — QR Code Payment Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Generate payment QR 2. Analyze QR content 3. Modify payment details

**Expected Result:** QR codes should be signed

**Payload Example:**

```
Tampered QR code with different amount
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** QR Tools / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## PAY-209 — Biometric Payment Bypass
**Test Category:** Authentication Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Enable biometric payment 2. Find bypass mechanism 3. Pay without biometrics

**Expected Result:** Biometric should not have fallback bypass

**Payload Example:**

```
Bypass fingerprint with simple fallback
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Mobile Testing / Frida

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PAY-210 — Payment Widget Sandbox Escape
**Test Category:** Cross-Site Scripting · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze payment iframe/widget 2. Find XSS or sandbox escape 3. Access parent page

**Expected Result:** Payment widgets should be properly sandboxed

**Payload Example:**

```
XSS in payment iframe affecting parent
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PAY-211 — Inconsistent Decimal Handling
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Submit amounts with many decimals 2. Check rounding behavior 3. Exploit inconsistencies

**Expected Result:** Decimal handling should be consistent

**Payload Example:**

```
$99.999999 rounded differently across systems
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## PAY-212 — Payment Memo/Note Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Add payment note 2. Inject malicious content 3. Achieve XSS or SQLi

**Expected Result:** Notes should be sanitized

**Payload Example:**

```
note=<script>alert(1)</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PAY-213 — Order Amount vs Payment Mismatch
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Create order for $100 2. Pay $50 3. Check if order completes

**Expected Result:** Payment must match order amount

**Payload Example:**

```
Submit payment less than order total
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PAY-214 — Payment Method Downgrade
**Test Category:** Cryptographic Failures · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze available payment security 2. Force less secure method 3. Bypass security controls

**Expected Result:** Secure methods should be enforced

**Payload Example:**

```
Force fallback from chip to magnetic stripe
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## PAY-215 — International Card Fraud Indicators
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Use foreign card with local address 2. Check fraud detection 3. Bypass velocity limits

**Expected Result:** Fraud indicators should trigger review

**Payload Example:**

```
Multiple international cards same address
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Cards

**References:** CWE-840; PortSwigger Business logic

---

## PAY-216 — Digital Wallet Linking Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Link digital wallet 2. Bypass verification 3. Use unverified wallet

**Expected Result:** Wallet linking should require verification

**Payload Example:**

```
Skip wallet verification step
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Mobile Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-217 — Saved Payment Method Scope
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Save payment method for one merchant 2. Use across different merchants 3. Bypass merchant scope

**Expected Result:** Payment methods should be merchant-scoped

**Payload Example:**

```
Use Card saved on Site A for Site B
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PAY-218 — Payment Processor Failover Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Identify payment failover 2. Trigger primary failure 3. Exploit secondary processor

**Expected Result:** Failover should maintain security

**Payload Example:**

```
Less secure backup processor
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PAY-219 — Anti-Fraud Score Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Payment Security

**Test Steps:** 1. Analyze fraud scoring 2. Modify parameters to lower score 3. Bypass fraud detection

**Expected Result:** Fraud scoring should be tamper-proof

**Payload Example:**

```
Modify device_fingerprint or ip_address
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---
