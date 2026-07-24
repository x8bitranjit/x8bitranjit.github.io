# 19. Mobile & Device — Checklist

Feature-area security **test cases** for “19. Mobile & Device”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*30 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## MOB-001 — Mobile API BOLA/BFLA (proxy the app, swap identifiers)
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Mobile backend API — object IDs &amp; privileged methods behind the app

**Test Steps:** 1. Proxy the mobile app (Burp + device CA) to see the raw API<br>2. Swap object IDs / call admin-only methods as a normal user (two-account proof)<br>3. The app UI hiding a function != server enforcing it<br>4. Confirm cross-user data / privileged action

**Expected Result:** Mobile backend authorizes every object &amp; function server-side (UI is not a control)

**Payload Example:**

```
GET /api/v1/users/{other_id}  from the intercepted mobile session
```

**Impact:** Mobile backend BOLA/BFLA -&gt; cross-user data / privilege escalation

**Tools:** Burp Suite, mitmproxy, Frida

**References:** CWE-639; CWE-284; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP API Top 10 (BOLA/BFLA); OWASP MASVS/MASTG

---

## MOB-002 — Hardcoded secrets / API keys in the mobile binary
**Test Category:** Cryptography · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Decompiled APK/IPA — strings, resources, config

**Test Steps:** 1. Pull the APK/IPA; decompile (jadx/apktool / class-dump)<br>2. Grep for API keys, secrets, endpoints, cloud creds, signing keys<br>3. Validate a found secret against the live API<br>4. Confirm it grants access / cost abuse

**Expected Result:** No secrets in the client; keys are per-user, scoped, server-brokered, revocable

**Payload Example:**

```
jadx -> grep -Ri 'api_key|secret|AKIA|bearer' ;  test key against API
```

**Impact:** Hardcoded secret -&gt; direct API/cloud access or cost abuse

**Tools:** jadx, apktool, MobSF, trufflehog

**References:** CWE-798; -&gt;[JavaScript Files checklist](#/checklist/jsfiles); OWASP MASVS/MASTG (MASTG-CODE)

---

## MOB-003 — Certificate pinning bypass (intercept the mobile API)
**Test Category:** Cryptography · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** TLS pinning between app and backend

**Test Steps:** 1. Attempt intercept; if pinned, bypass with objection/Frida (unpinning) or patch the APK<br>2. Re-intercept the now-visible API traffic<br>3. Confirm you can read/modify requests<br>4. Proceed to server-side testing of the exposed API

**Expected Result:** Pinning present AND server-side controls independent of the client (pinning is not authz)

**Payload Example:**

```
objection -g <app> explore -> android sslpinning disable ;  frida CodeShare unpin
```

**Impact:** Pinning bypass -&gt; full visibility/tamper of mobile API -&gt; enables all backend testing

**Tools:** objection, Frida, apktool

**References:** CWE-295; OWASP MASVS/MASTG (MASTG-NETWORK); PortSwigger mobile

---

## MOB-004 — Insecure local storage of tokens / PII on device
**Test Category:** Cryptography · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** App sandbox — SharedPreferences/plist/SQLite/Keychain/Keystore

**Test Steps:** 1. Inspect app storage (adb / iMazing / objection) after login<br>2. Look for session tokens, passwords, PII stored in plaintext or world-readable<br>3. Check Keychain/Keystore usage vs plain files<br>4. Confirm a stolen-device or backup extraction yields creds

**Expected Result:** Secrets in Keychain/Keystore (hardware-backed); no plaintext tokens/PII at rest

**Payload Example:**

```
adb backup / objection -> ls sandbox -> read shared_prefs/*.xml, *.sqlite
```

**Impact:** Insecure at-rest storage -&gt; token/PII theft on device access or backup -&gt; ATO

**Tools:** objection, adb, iMazing, MobSF

**References:** CWE-922; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP MASVS/MASTG (MASTG-STORAGE)

---

## MOB-005 — Deep link / custom URL scheme hijacking
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** App-registered URL scheme / Android App Link / iOS Universal Link

**Test Steps:** 1. Enumerate registered schemes/links (manifest / Info.plist)<br>2. Check whether another app can claim the scheme (unverified) to intercept links<br>3. Send crafted deep links to trigger privileged in-app actions<br>4. Confirm hijack or unauthorized action

**Expected Result:** App Links/Universal Links verified (assetlinks/AASA); no sensitive action on unauthenticated deep link

**Payload Example:**

```
adb shell am start -a android.intent.action.VIEW -d 'app://transfer?to=attacker&amt=1000'
```

**Impact:** Deep-link hijack/injection -&gt; intercept tokens or trigger privileged actions

**Tools:** adb, Frida

**References:** CWE-939; CWE-926; OWASP MASVS/MASTG (MASTG-PLATFORM); Android App Links docs

---

## MOB-006 — WebView JS-bridge / native-method exposure
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebView addJavascriptInterface / message handlers loading remote content

**Test Steps:** 1. Find WebViews that expose native methods to JS (addJavascriptInterface / WKScriptMessageHandler)<br>2. Check whether remote/untrusted content can call those bridges<br>3. Inject JS (via MITM/open redirect/loaded URL) to invoke native functions<br>4. Confirm file access / native action / RCE-ish reach

**Expected Result:** Bridges exposed only to trusted origins; no untrusted content in privileged WebViews; JS disabled where unneeded

**Payload Example:**

```
window.AndroidBridge.readFile('/data/data/app/...')  from injected JS
```

**Impact:** WebView bridge abuse -&gt; native method invocation / local file theft

**Tools:** Frida, Burp, jadx

**References:** CWE-749; CWE-79; -&gt;[XSS checklist](#/checklist/xss); OWASP MASVS/MASTG (MASTG-PLATFORM)

---

## MOB-007 — Root / jailbreak detection bypass
**Test Category:** Security Misconfiguration · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Client-side root/JB detection guarding sensitive flows

**Test Steps:** 1. Trigger the root/JB check; note where it gates functionality<br>2. Bypass with objection/Frida (root-detection disable) or Magisk hide<br>3. Confirm the app runs its sensitive flow on a rooted device<br>4. Note that detection is defense-in-depth, not a server control

**Expected Result:** Detection is one signal only; server never relies on client integrity for security decisions

**Payload Example:**

```
objection -> android root disable ;  frida root-detection-bypass
```

**Impact:** Root/JB bypass -&gt; run instrumentation/tamper; server must not trust client integrity

**Tools:** objection, Frida, Magisk

**References:** CWE-693; OWASP MASVS/MASTG (MASTG-RESILIENCE)

---

## MOB-008 — Device binding / device-ID spoofing (session portability)
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Device-bound session / trusted-device feature

**Test Steps:** 1. Capture the device-identifier used to bind a session/trusted-device<br>2. Replay a victim session or spoof the device-ID from another device<br>3. Check whether the server ties the token to a verifiable device factor<br>4. Confirm session portability / trusted-device bypass

**Expected Result:** Sessions bound to a verifiable, non-spoofable device factor; re-auth on new device

**Payload Example:**

```
replay session token + spoofed X-Device-Id on attacker device
```

**Impact:** Device-binding bypass -&gt; port a victim session to attacker device -&gt; ATO

**Tools:** Burp, Frida

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP MASVS/MASTG (MASTG-AUTH)

---

## MOB-009 — Biometric auth bypass (client-side trust)
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Biometric gate protecting login/transactions

**Test Steps:** 1. Check whether biometric success is decided client-side (a boolean) vs a server-verified crypto object<br>2. Hook the biometric callback (Frida) to force success<br>3. Bypass without the biometric; reach the protected flow<br>4. Confirm no server-side cryptographic binding

**Expected Result:** Biometric unlocks a Keystore/SE crypto operation the server verifies; not a client boolean

**Payload Example:**

```
frida hook onAuthenticationSucceeded -> force callback
```

**Impact:** Biometric bypass -&gt; reach protected transactions without the factor

**Tools:** Frida, objection

**References:** CWE-287; OWASP MASVS/MASTG (MASTG-AUTH)

---

## MOB-010 — Cleartext traffic / weak transport (ATS/cleartextTrafficPermitted)
**Test Category:** Cryptography · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Network config — HTTP endpoints, weak TLS, disabled ATS

**Test Steps:** 1. Inspect network_security_config / ATS settings and observed traffic<br>2. Find any HTTP (cleartext) endpoints or downgrade paths<br>3. MITM the cleartext channel on a hostile network<br>4. Confirm token/PII interception

**Expected Result:** All traffic HTTPS with modern TLS; cleartext disabled; no user-added-CA trust in prod

**Payload Example:**

```
grep cleartextTrafficPermitted=true ;  MITM the http:// endpoint
```

**Impact:** Cleartext/weak transport -&gt; on-path token/PII interception -&gt; ATO

**Tools:** mitmproxy, Burp, MobSF

**References:** CWE-319; OWASP MASVS/MASTG (MASTG-NETWORK)

---

## MOB-011 — Client-side control bypass (mobile-only validation) on the backend
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Validation/limits enforced only in the app, not server-side

**Test Steps:** 1. Identify limits/validation the app enforces (price, quantity, role, feature flags)<br>2. Replay the API directly (proxy) without the client checks<br>3. Submit values the UI would block<br>4. Confirm the server accepts them

**Expected Result:** All validation/limits/authorization enforced server-side; client is convenience only

**Payload Example:**

```
POST /api/order {"price":0,"qty":-1}  directly, bypassing app validation
```

**Impact:** Client-side-only controls -&gt; business-logic/price/role bypass via direct API

**Tools:** Burp Suite

**References:** CWE-602; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP MASVS/MASTG (MASTG-CODE); OWASP WSTG-BUSL

---

## MOB-012 — SMS/OTP 2FA interception &amp; mobile push abuse
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SMS OTP / push-based MFA in mobile flows

**Test Steps:** 1. Test OTP delivery: SIM-swap exposure, OTP in notifications/logs, autofill leaks<br>2. Check OTP rate-limit / reuse / predictability<br>3. Abuse push MFA (fatigue) or device-token spoofing<br>4. Confirm 2FA bypass path

**Expected Result:** OTPs short-lived/single-use/rate-limited; push uses number-matching; no OTP in logs

**Payload Example:**

```
brute OTP (no limit)  |  read OTP from notification  |  MFA push fatigue
```

**Impact:** Mobile 2FA interception/fatigue -&gt; MFA bypass -&gt; ATO

**Tools:** Burp, Frida

**References:** CWE-287; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP MASVS/MASTG (MASTG-AUTH)

---

## MOB-013 — Exported Android component abuse (activity/service/receiver)
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Exported activities/services/broadcast receivers (AndroidManifest)

**Test Steps:** 1. Parse the manifest for exported=true components (or implicit intent-filters)<br>2. Invoke them from a malicious app / adb with crafted intents<br>3. Reach protected screens/actions or leak data without auth<br>4. Confirm unauthorized action

**Expected Result:** Components not exported unless required; exported ones enforce permissions + validate callers

**Payload Example:**

```
adb shell am start -n com.app/.AdminActivity --es token x   |   am broadcast -a com.app.SECRET
```

**Impact:** Exported-component abuse -&gt; unauthorized in-app action / data access

**Tools:** adb, Drozer, jadx

**References:** CWE-926; CWE-284; OWASP MASVS/MASTG (MASTG-PLATFORM)

---

## MOB-014 — Intent injection / redirection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Components that forward/execute attacker-controlled intents

**Test Steps:** 1. Find a component that reads an Intent extra and re-dispatches it (startActivity/serialized intent)<br>2. Inject a nested/redirected intent to reach an unexported/privileged component<br>3. Confirm the redirect grants access it shouldn't<br>4. Prove privileged reach

**Expected Result:** Intents validated; no forwarding of untrusted intents to privileged components

**Payload Example:**

```
Intent extra 'forward_intent' -> nested intent to com.app/.InternalActivity
```

**Impact:** Intent injection -&gt; reach privileged/internal components (confused deputy)

**Tools:** Drozer, jadx, Frida

**References:** CWE-926; OWASP MASVS/MASTG (MASTG-PLATFORM)

---

## MOB-015 — Insecure content provider (SQLi / path traversal)
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Exported ContentProvider query/openFile

**Test Steps:** 1. Enumerate exported content providers<br>2. Query with injection in the selection/URI; try ../ in openFile paths<br>3. Confirm SQLi in the provider or arbitrary file read via the provider<br>4. Extract data

**Expected Result:** Providers not exported unless needed; parameterized queries; no path traversal in openFile

**Payload Example:**

```
content://com.app.provider/users' OR '1'='1   |   content://com.app.provider/../../databases/app.db
```

**Impact:** Insecure provider -&gt; SQLi/arbitrary file read of app data

**Tools:** Drozer, adb

**References:** CWE-89; CWE-22; -&gt;[SQL Injection checklist](#/checklist/sqli); OWASP MASVS/MASTG (MASTG-PLATFORM)

---

## MOB-016 — PendingIntent hijacking
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Mutable/implicit PendingIntent handed to another app

**Test Steps:** 1. Find a mutable or implicit PendingIntent the app shares<br>2. Intercept and fill/redirect it to act with the app's identity/permissions<br>3. Confirm you can perform an action as the app<br>4. Prove privilege reuse

**Expected Result:** PendingIntents are immutable + explicit; least privilege

**Payload Example:**

```
capture mutable PendingIntent -> fill with attacker action, executed with app identity
```

**Impact:** PendingIntent hijack -&gt; perform actions with the app's identity/permissions

**Tools:** Frida, jadx

**References:** CWE-926; OWASP MASVS/MASTG (MASTG-PLATFORM)

---

## MOB-017 — Task hijacking (StrandHogg) / overlay
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** taskAffinity / recent-tasks + overlay

**Test Steps:** 1. Check taskAffinity/launchMode config enabling task-hijacking (StrandHogg 1/2)<br>2. Deploy a malicious app that inserts its activity into the target's task<br>3. Present a spoofed login/consent overlay<br>4. Capture credentials / approve actions

**Expected Result:** Harden taskAffinity/launchMode; detect overlays; FLAG_SECURE on sensitive screens

**Payload Example:**

```
malicious app with matching taskAffinity overlays a fake login on the target
```

**Impact:** Task hijack/overlay -&gt; credential capture / action spoofing

**Tools:** apktool, custom PoC app

**References:** CWE-1021; OWASP MASVS/MASTG (MASTG-PLATFORM)

---

## MOB-018 — Tapjacking (touch overlay)
**Test Category:** Client-Side · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Sensitive buttons without touch-filtering

**Test Steps:** 1. Check whether sensitive actions filter obscured touches (filterTouchesWhenObscured)<br>2. Overlay a transparent window over the target's confirm buttons<br>3. Trick the user into approving hidden actions<br>4. Confirm the action fires

**Expected Result:** Sensitive controls set filterTouchesWhenObscured / detect overlays

**Payload Example:**

```
SYSTEM_ALERT_WINDOW overlay over a 'Confirm transfer' button
```

**Impact:** Tapjacking -&gt; user unknowingly authorizes sensitive actions

**Tools:** custom overlay PoC

**References:** CWE-1021; OWASP MASVS/MASTG (MASTG-PLATFORM)

---

## MOB-019 — Android backup / allowBackup data extraction
**Test Category:** Cryptography · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** allowBackup=true / cloud backup of app data

**Test Steps:** 1. Check allowBackup in the manifest<br>2. adb backup the app; unpack the .ab<br>3. Look for tokens/PII/DB in the backup<br>4. Confirm at-rest data is extractable via backup

**Expected Result:** allowBackup=false for sensitive apps; no secrets in backed-up storage

**Payload Example:**

```
adb backup -f app.ab com.app ; abe unpack ; grep -Ri token
```

**Impact:** Backup extraction -&gt; offline theft of tokens/PII -&gt; ATO

**Tools:** adb, android-backup-extractor

**References:** CWE-922; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP MASVS/MASTG (MASTG-STORAGE)

---

## MOB-020 — Clipboard / pasteboard sensitive-data leakage
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Clipboard use for secrets (OTP/token/password)

**Test Steps:** 1. Perform flows that copy secrets to the clipboard (OTP autofill, copy token)<br>2. Read the clipboard from a background app<br>3. Confirm another app can harvest the secret<br>4. Note universal-pasteboard sync (iOS)

**Expected Result:** No secrets on the clipboard; sensitive fields flagged; auto-clear

**Payload Example:**

```
background app reads ClipboardManager after an OTP copy
```

**Impact:** Clipboard leakage -&gt; secret theft by any installed app

**Tools:** Frida, custom app

**References:** CWE-200; OWASP MASVS/MASTG (MASTG-STORAGE)

---

## MOB-021 — Screenshot / screen-recording leak (missing FLAG_SECURE)
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Sensitive screens captured in recents / screenshots

**Test Steps:** 1. Open a sensitive screen (payment/token/PII)<br>2. Trigger the app-switcher snapshot or a screenshot/recording<br>3. Confirm sensitive data is captured to recents/gallery<br>4. Note FLAG_SECURE / hidden-preview missing

**Expected Result:** FLAG_SECURE on sensitive screens; blank the app-switcher preview

**Payload Example:**

```
open card details -> recents snapshot retains full PAN
```

**Impact:** Screenshot/recents leak -&gt; sensitive data exposed on-device / in screenshots

**Tools:** manual, adb

**References:** CWE-200; OWASP MASVS/MASTG (MASTG-STORAGE)

---

## MOB-022 — Insecure logging (secrets in logcat / crash logs)
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** App/system logs &amp; crash reporting

**Test Steps:** 1. Exercise auth/payment flows while capturing logcat<br>2. Grep for tokens/passwords/PII/PAN in logs and crash reports<br>3. Confirm secrets are logged (readable pre-Android-M or via crash SDK)<br>4. Note third-party crash-SDK exfil

**Expected Result:** No secrets in logs; production logging minimized; crash reports scrubbed

**Payload Example:**

```
adb logcat | grep -Ei 'token|password|authorization|card'
```

**Impact:** Sensitive logging -&gt; secret disclosure via logs / crash-reporting SDKs

**Tools:** adb, MobSF

**References:** CWE-532; OWASP MASVS/MASTG (MASTG-STORAGE)

---

## MOB-023 — In-app purchase / receipt-validation bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Client-side purchase/receipt verification

**Test Steps:** 1. Complete or simulate a purchase; capture the receipt-validation call<br>2. Forge/replay a receipt, or unlock the entitlement client-side<br>3. Check whether the server validates the receipt with the store<br>4. Confirm free entitlement

**Expected Result:** Receipts validated server-to-store; entitlements server-granted; no client unlock

**Payload Example:**

```
replay/forge store receipt -> POST /iap/validate {"receipt":"forged"} -> premium unlocked
```

**Impact:** IAP/receipt bypass -&gt; unlock paid features for free (financial)

**Tools:** Burp, Frida

**References:** CWE-602; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP MASVS/MASTG (MASTG-CODE)

---

## MOB-024 — Third-party SDK / analytics data leakage
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Embedded SDKs (analytics/ads/attribution)

**Test Steps:** 1. Inventory embedded SDKs; observe their outbound traffic<br>2. Check what PII/identifiers/tokens they transmit and to where<br>3. Confirm over-collection or plaintext transmission of sensitive data<br>4. Assess third-party exposure

**Expected Result:** SDKs vetted, minimized, and sending no sensitive data; encrypted transport

**Payload Example:**

```
MITM SDK endpoints -> observe device-id/email/token exfil
```

**Impact:** SDK over-collection -&gt; user data leaked to third parties

**Tools:** MobSF, mitmproxy

**References:** CWE-359; OWASP MASVS/MASTG (MASTG-CODE)

---

## MOB-025 — Debuggable build / exposed debug endpoints
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** android:debuggable / dev menus / debug APIs

**Test Steps:** 1. Check android:debuggable and for hidden dev/QA menus or debug backend endpoints<br>2. Attach a debugger / run-as to inspect memory &amp; data<br>3. Reach debug-only APIs that bypass controls<br>4. Confirm elevated access

**Expected Result:** Production builds non-debuggable; no dev menus / debug endpoints shipped

**Payload Example:**

```
adb shell run-as com.app ;  hit /api/debug/impersonate
```

**Impact:** Debuggable build/debug endpoints -&gt; memory/data access &amp; control bypass

**Tools:** adb, jadx, Frida

**References:** CWE-489; OWASP MASVS/MASTG (MASTG-CODE)

---

## MOB-026 — Firebase / cloud backend misconfiguration (open datastore)
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Firebase/Firestore/S3/RTDB referenced by the app

**Test Steps:** 1. Extract backend URLs/keys from the app (Firebase config, bucket names)<br>2. Query the datastore unauthenticated (.json append, public bucket)<br>3. Confirm open read/write to other users' data<br>4. Quantify exposure

**Expected Result:** Backend rules enforce per-user auth; no public read/write; buckets locked down

**Payload Example:**

```
GET https://<proj>.firebaseio.com/users.json   |   aws s3 ls s3://<bucket> --no-sign-request
```

**Impact:** Open cloud backend -&gt; mass cross-user data read/write

**Tools:** Firebase tools, awscli, MobSF

**References:** CWE-284; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP MASVS/MASTG (MASTG-NETWORK)

---

## MOB-027 — Runtime memory secret extraction
**Test Category:** Cryptography · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Process memory holding tokens/keys

**Test Steps:** 1. Attach Frida/dump process memory after login<br>2. Search memory for tokens/keys/PINs<br>3. Confirm secrets persist unprotected in memory<br>4. Note absence of zeroization

**Expected Result:** Secrets minimized in memory + zeroized after use; hardware-backed keys never exported

**Payload Example:**

```
frida-dump / objection memory search 'Bearer '
```

**Impact:** Memory secret extraction -&gt; token/key theft on a compromised/rooted device

**Tools:** Frida, objection

**References:** CWE-316; OWASP MASVS/MASTG (MASTG-STORAGE)

---

## MOB-028 — Anti-tamper / repackaging &amp; integrity-check bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** App signature/integrity checks

**Test Steps:** 1. Decompile, patch (remove a check / change logic), repackage, re-sign<br>2. Check whether the app/server detects modification (signature/attestation)<br>3. Run the tampered app against production<br>4. Confirm no server-side attestation (Play Integrity/DeviceCheck)

**Expected Result:** Server verifies app integrity (Play Integrity/App Attest); tampered clients rejected

**Payload Example:**

```
apktool d -> patch smali -> apktool b -> sign -> run against prod
```

**Impact:** Repackaging bypass -&gt; run a tampered client; server must attest integrity

**Tools:** apktool, jadx, Frida

**References:** CWE-693; OWASP MASVS/MASTG (MASTG-RESILIENCE)

---

## MOB-029 — Offline / local DB tampering &amp; sync abuse
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Local SQLite/Realm cache synced to server

**Test Steps:** 1. Modify the local DB/cache (balances, entitlements, flags) on a rooted device<br>2. Trigger sync<br>3. Check whether the server trusts client-side state on sync<br>4. Confirm tampered state persists server-side

**Expected Result:** Server is source of truth; sync validates + reconciles; no trust of client state

**Payload Example:**

```
sqlite3 app.db 'UPDATE wallet SET balance=999999' -> sync
```

**Impact:** Local-state trust on sync -&gt; tamper balances/entitlements server-side

**Tools:** adb, sqlite3, objection

**References:** CWE-602; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP MASVS/MASTG (MASTG-STORAGE)

---

## MOB-030 — Geolocation spoofing for location-gated features
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Client-provided location for geo-gated logic

**Test Steps:** 1. Identify features gated on device location (pricing, availability, compliance, check-in)<br>2. Spoof GPS or send a forged location to the API<br>3. Confirm the server trusts client location<br>4. Bypass the geo-restriction

**Expected Result:** Location verified server-side (IP/geo-IP corroboration); client GPS not solely trusted

**Payload Example:**

```
mock-location app / POST /api {"lat":..,"lng":..} forged
```

**Impact:** Geo-spoofing -&gt; bypass location-based pricing/availability/compliance

**Tools:** mock-location, Burp

**References:** CWE-602; OWASP MASVS/MASTG (MASTG-CODE)

---
