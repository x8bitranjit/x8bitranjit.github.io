# OWASP Mobile Top 10 (2024) — Zero to Expert (Q&A, Bug-Bounty / Red-Team / Interview Edition)

> A complete study + field + **interview** reference for the **OWASP Mobile Top 10:2024**. **Organized in Mobile-Top-10
> order** — everything for **M1** (what it is → how to test → red-team escalation → interview questions → defense) is
> together, then **M2**, and so on through **M10**. This is the **umbrella** companion; the practical device work lives
> in the ADB tool kit (`Android/ADB/`) and the server-side cash-outs in the Web/API kits (`../Web/…`, `../API/…`). Learn
> the *risks* here; type the *commands* in the kits.
>
> ⚖️ **Authorized use only.** Test device-side findings on a device/emulator **you own** (rooted/jailbroken), and
> server-side findings with **your own accounts** + benign markers. Prove reachability + impact, clean up, never test
> what you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- **OWASP Mobile Top 10 (2024)**: https://owasp.org/www-project-mobile-top-10/
- **OWASP MASVS** (verification standard) + **MASTG** (the definitive testing guide): https://mas.owasp.org/
- HackTricks — Android/iOS pentesting · Frida (frida.re) · objection · MobSF · drozer · jadx/apktool
- Companion umbrella in this repo: `OWASP_MOBILE_TOP_10.md`. Practical base: `Android/ADB/` (ADB tool kit). Server-side cash-outs: `../Web/IDOR|AccountTakeover|JWT|OAuth|SQLi|XSS|PathTraversal/`, `../API/REST/`. Siblings: `../Web/OWASP_WEB_TOP_10.md`, `../API/OWASP_API_TOP_10.md`, `../AI/LLM/OWASP_LLM_TOP_10.md`.

---

## TABLE OF CONTENTS
- **§0 — The framework & mobile method** (Q1–Q12)
- **§M1 — Improper Credential Usage** (Q13–Q20)
- **§M2 — Inadequate Supply Chain Security** (Q21–Q27)
- **§M3 — Insecure Authentication / Authorization** (Q28–Q37)
- **§M4 — Insufficient Input / Output Validation** (Q38–Q45)
- **§M5 — Insecure Communication** (Q46–Q54)
- **§M6 — Inadequate Privacy Controls** (Q55–Q61)
- **§M7 — Insufficient Binary Protections** (Q62–Q69)
- **§M8 — Security Misconfiguration** (Q70–Q78)
- **§M9 — Insecure Data Storage** (Q79–Q87)
- **§M10 — Insufficient Cryptography** (Q88–Q94)
- **§XC — Cross-category chaining & reporting** (Q95–Q101)

> Each `§Mx` block runs in the same order: **Core → How to test → Red-team / escalation → Interview → Prevention.**

---

# §0 — THE FRAMEWORK & MOBILE METHOD

### Q1. What is the OWASP Mobile Top 10 and how does mobile testing differ from web?
> *Plain version:* it's the "top 10 mobile-app weaknesses" list. The thing to burn into your brain: **the attacker holds the phone.** They can open your app up like a book, read its files, and rewire it as it runs — so nothing hidden *inside* the app is truly hidden.

An **awareness list** of the top mobile-app risks (current: **2024**, superseding 2016). Mobile differs in one way that dominates everything: **the attacker often controls the client** — they own the device, decompile the app, hook it at runtime, and read its storage. So "it's only in the app" is never a defense; any shipped secret/logic is recoverable.

### Q2. Name the Mobile Top 10 (2024) in order.
M1 Improper Credential Usage · M2 Inadequate Supply Chain Security · M3 Insecure Authentication/Authorization · M4 Insufficient Input/Output Validation · M5 Insecure Communication · M6 Inadequate Privacy Controls · M7 Insufficient Binary Protections · M8 Security Misconfiguration · M9 Insecure Data Storage · M10 Insufficient Cryptography.

### Q3. What changed in the 2024 list vs 2016? (interview)
The 2024 list was **restructured** around a modern threat model. New/renamed entries include **M1 Improper Credential Usage**, **M2 Inadequate Supply Chain Security** (new — third-party SDKs/build), **M4 Insufficient Input/Output Validation**, and **M6 Inadequate Privacy Controls** (new emphasis). "Reverse Engineering" and "Extraneous Functionality" folded into **M7 Binary Protections** / **M8 Misconfiguration**. The spine shifted toward **credentials, supply chain, and privacy**.

### Q4. What's the single most important mobile-pentest insight?
> *Plain version:* the single most useful mobile-hacking fact — **your biggest wins are usually on the server, not the phone.** The app is just a map: crack it open to learn the server's secret addresses and shortcuts, then attack the server (where the real data lives).

**Most Critical mobile bugs are actually server-side, exposed by the client.** The app is a *map of the backend API* — decompile it to find hidden/privileged endpoints, auth flows, and parameters, then attack the **server** (BOLA/IDOR, auth bypass, injection). Half your best findings are server-side bugs the client revealed. → Web/API kits.

### Q5. What's the standard mobile testing method (the phases)?
0) **Get + decompile** the APK/IPA (jadx/apktool; read manifest, strings, endpoints, keys). 1) **Static** (hardcoded secrets M1, crypto M10, exported components M8, pinning M5, SDKs M2). 2) **Storage** (shared_prefs/DB/keychain/logs for tokens/PII — M9). 3) **Dynamic** (Frida/objection: bypass root/pinning, dump memory, tamper). 4) **Network** (proxy traffic M5, then attack the backend the app reveals — M3/M4). 5) **Validate** impact.

### Q6. Static vs dynamic analysis — what does each find?
**Static** (decompile, read code/manifest/resources): hardcoded secrets, crypto usage, exported components, pinning config, SDKs, logic — *what's in the binary*. **Dynamic** (run + hook with Frida/objection): runtime secrets in memory, pinning/root-detection bypass, live tampering, actual IPC/traffic — *what it does at runtime*. You need both.

### Q7. Which categories are device-side vs server-side?
**Device-side**: M1 (credential storage/use), M5 (comms), M6 (privacy), M7 (binary), M8 (config/IPC), M9 (storage), M10 (crypto). **Server-side (via the client)**: M3 (auth/authz → BOLA/ATO), M4 (input → forwarded injection). The Criticals often live in M3/M4's server side.

### Q8. What tools make up the mobile toolkit?
`adb` (base — pull APK, read storage, exercise components, logcat → `Android/ADB/` kit); **jadx/apktool/dex2jar** (decompile); **Frida/objection** (dynamic instrumentation, pinning/root bypass); **Burp + CA** (proxy); **MobSF** (automated static+dynamic first pass); **drozer** (IPC/attack-surface); class-dump/Ghidra (iOS/native).

### Q9. Why is "a decompiled string is not a finding" the mobile version of low-FP discipline?
Because the client is *designed* to be decompilable — finding an API endpoint or an obfuscated value proves nothing by itself. The finding is **what it reaches**: a token you steal and replay (ATO), an exported component you drive, a MITM you pull off, PII you read, or a server bug the client exposed. Always show reachability + impact.

### Q10. Android vs iOS — how does the same category differ?
Same risks, different mechanics: storage (Android `shared_prefs`/SQLite/Keystore vs iOS plist/Keychain), IPC (Android exported components/Intents vs iOS URL schemes/universal links/XPC), binary (smali/DEX vs Mach-O), pinning bypass (both via Frida/objection). MASTG documents both; this repo's tooling is Android-first (ADB).

### Q11. What is the Android manifest and why read it first?
`AndroidManifest.xml` declares **permissions, exported components (Activities/Services/Receivers/Providers), deep links, `debuggable`, `allowBackup`, and `networkSecurityConfig`**. It's the security blueprint of the app's attack surface (M8) — reading it first tells you what's reachable from another app or ADB without root.

### Q12. Which kits own the mobile work in this repo?
`Android/ADB/` (the ADB tool kit — connect, pull, read storage, exercise exported components, logcat, traffic plumbing) for the practical device side (M1/M5/M6/M8/M9); the **server-side cash-outs** in `../Web/IDOR|AccountTakeover|JWT|OAuth|SQLi|XSS|PathTraversal/` and `../API/REST/` for M3/M4. Planned tool kits: Frida, objection, apktool, jadx, drozer.

---

# §M1 — IMPROPER CREDENTIAL USAGE

**Core**

### Q13. What is M1 Improper Credential Usage?
Hardcoded credentials/API keys/secrets in the app, insecure transmission/storage of credentials, weak credential handling, or misuse of credentials — anything where the app manages secrets badly. Because the client is fully recoverable, **any embedded secret is effectively public**.

### Q14. Why is "the client can't keep secrets" the core M1 principle?
Because anyone can decompile the APK/IPA, read strings/resources/native libs, and hook memory — so a secret shipped in the app is retrievable by any user. Treating an API key as a *secret* (rather than a public identifier) is the fundamental M1 anti-pattern.

**How to test**

### Q15. How do you hunt credentials in an app?
Decompile (jadx/apktool) and **grep** strings/resources/assets/native `.so`/`BuildConfig` for keys/tokens/passwords/private keys/cloud creds/endpoints — e.g. `api[_-]?key|secret|password|BEGIN PRIVATE KEY|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}`. Then dump runtime memory with Frida for creds not in the binary. → `Android/ADB/` (logcat + pull), `../Web/JSFiles/` (secret-hunting method).

### Q16. You found an `AIza…`/`AKIA…` key. What proves it's a finding?
**Validate it** against the backend/cloud/third-party — does it actually work, and what does it unlock (data, billing, admin)? An unused/least-privilege/revoked key is low; a working **god-key** (broad scope) is High. The impact is *what the credential unlocks server-side*, not its mere presence.

**Red-team / escalation**

### Q17. How does a hardcoded key escalate?
A working cloud key (AWS/GCP/Firebase) → data access, billing abuse, or resource control; a hardcoded **admin/service** credential → privilege escalation; Firebase/S3 config from the app → test open rules / public buckets → data breach. Pull the key from the APK, confirm reach, and chain into the backend.

**Interview**

### Q18. "How should a mobile app handle API keys/secrets?"
Don't embed secrets in the client (it can't keep them). Fetch **scoped, short-lived tokens** from the backend at runtime; store anything that must be on-device in the **platform key store** (Android Keystore / iOS Keychain); scope + rotate + monitor keys; never log credentials. Design so a decompiled client reveals nothing usable.

### Q19. "An app has a hardcoded third-party API key. Is that always Critical?"
No — severity depends on **what the key unlocks and its scope**. A read-only key to public data is low; a key granting user-data access or paid-service billing or admin operations is High/Critical. Always validate the key and report the concrete access, not "a key was found."

**Prevention**

### Q20. Prevention + focus for M1?
No client-embedded secrets; runtime-fetched scoped/short-lived tokens; platform key stores for on-device secrets; scope/rotate/monitor keys; never log credentials; certificate-bound/attested tokens where possible. The mindset: assume the app is open-source to the attacker.

### Q20a. What can Frida do at runtime that static analysis can't (M1/M3/M5/M7)?
Frida hooks a *running* app to read/alter it live — the mobile red-team workhorse across categories: **dump secrets from memory** (keys/tokens decrypted at runtime that aren't in the binary — M1); **bypass root/emulator/debugger detection** (M7); **disable SSL pinning** (`objection android sslpinning disable` → intercept traffic — M5); **flip client-side auth** (hook `isAdmin()`/`isPremium()`/biometric callbacks → `true` — M3); **call internal methods** directly; and **trace crypto** (hook `Cipher`/`SecretKeySpec` to catch a hardcoded key — M10). Quick start: `objection -g <pkg> explore`, then `android hooking search classes <name>` / `android hooking watch class_method <m>`. It turns "the check lives in the app" into "the check is bypassed." → `Android/ADB/`.

---

# §M2 — INADEQUATE SUPPLY CHAIN SECURITY

**Core**

### Q21. What is M2 (new emphasis in 2024)?
Vulnerabilities from the mobile **supply chain** — third-party **SDKs/libraries**, the build pipeline, malicious/compromised dependencies, and untrusted bundled components. A malicious SDK runs with the **app's permissions and data access**.

### Q22. Why is a malicious SDK so dangerous on mobile?
Because it inherits the app's full **permissions** (location, contacts, storage, camera) and data — an ad/analytics/payment SDK can silently exfiltrate user data, inject behavior, or backdoor the app, and the user trusts the *app*, not the invisible SDK. It's the mobile twin of software supply-chain attacks.

**How to test**

### Q23. How do you test for M2?
Decompile → **inventory all SDKs/libraries** (package names, native libs) + versions; map versions to **known CVEs** (outdated OkHttp/WebView/OpenSSL/crypto); observe each SDK's **behavior/permissions** (what data does it access + where does it phone home? — proxy the traffic); flag unexpected/repackaged/typosquatted deps; verify build **signing/integrity**.

**Red-team / escalation**

### Q24. What's the escalation from an outdated bundled library?
Map the library version to a known CVE with a public exploit reachable in the client (e.g., an old WebView/OpenSSL/parser bug) → exploit in-context → data theft/RCE-ish on the client. Or a data-harvesting SDK → mass PII exfiltration. Confirm reachability, don't just cite the version.

**Interview**

### Q25. "How is M2 (mobile supply chain) different from M1?"
M1 is about the app's **own credentials** (hardcoded/misused secrets). M2 is about **third-party code** you bundle (SDKs/libs/build) that you don't fully control — its vulns and its behavior become yours. Different root: your secrets vs someone else's code.

### Q26. "How would you vet a third-party SDK before shipping it?"
Check reputation/maintenance/source; review its **permissions and network behavior** (does an analytics SDK really need contacts?); pin the version + track its CVEs (SBOM); minimize what data it can access; prefer well-maintained libraries; monitor its traffic in production. Treat SDKs as untrusted code with your users' data.

**Prevention**

### Q27. Prevention + CWEs for M2?
Vet + inventory + **pin** all SDKs/libraries (SBOM); patch known CVEs; minimize SDK permissions + monitor their network behavior; sign builds + protect the pipeline; remove unused dependencies. CWEs: CWE-1104 (unmaintained third-party), CWE-937, CWE-829.

---

# §M3 — INSECURE AUTHENTICATION / AUTHORIZATION

**Core**

### Q28. What is M3 and why is it frequently the Critical?
> *Plain version:* the app decides "you're allowed" on the **phone** (which you control) instead of on the server. So you flip the switch, or just call the server directly, and the guard is gone. It's the mobile bug that most often becomes a Critical — and it's really a server bug.

Weaknesses in how the app **authenticates users** and **authorizes actions** — client-side-only checks, weak session/token handling, authorization enforced in the app instead of the server, and **BOLA/IDOR on the backend the app fronts**. It's frequently Critical because the fixes (or the bugs) live **server-side**, where the real data is.

### Q29. Why is "client-side auth the server trusts" the classic mobile bug?
Because the attacker **controls the client** — any check done in the app (isAdmin, isLoggedIn, price, entitlement) can be tampered (Frida hook, patched binary, or by calling the API directly). If the server *trusts* that client-side decision, it's bypassable. Authorization must be re-checked server-side.

**How to test**

### Q30. What's the #1 M3 test?
**Call the API directly, bypassing the app**: proxy the traffic (Burp) or reconstruct the request from the decompiled code, then replay/craft backend requests without the client UI → is authorization re-checked server-side? A client-side gate (an `if(isAdmin)` in the app, a hidden screen) falls immediately. Then run the **two-account BOLA/IDOR** test on object IDs (`user_id`/`account_id`/`order_id`) and try **privileged endpoints** as a low-priv user (BFLA). This is where the mobile Critical usually lives — the app was just the map. → `../Web/IDOR/`, `../API/REST/`.

### Q31. How do you test token handling and local/biometric auth?
**Tokens**: how are session/refresh tokens issued, stored (M9), transmitted (M5), expired, rotated? JWT flaws (`alg:none`/weak secret) → `../Web/JWT/`. **Biometric/local auth**: does it gate only the **UI**, or actually protect the data/keys? Bypass by hooking the success callback (Frida) — if data is still reachable, the biometric was cosmetic.

### Q32. How do you test the auth/reset/2FA flows for M3?
Tamper responses (Frida) to flip `isLoggedIn`/`isAdmin`; skip steps; force-browse to post-auth screens; test login/reset/2FA server-side (no rate limit on OTP → brute; response-flip; delivery hijack). → `../Web/AccountTakeover/`, `../Web/OAuth/`.

**Red-team / escalation**

### Q33. How does a mobile M3 finding become mass ATO?
Client-enforced "admin" that the server trusts → call the admin API directly → privilege escalation. Or **BOLA** on the mobile backend → iterate object IDs → access *every* user's data → mass breach. Or a stealable/replayable session token (from M9 storage) → ATO. The mobile client is just the map; the server is the breach.

**Interview**

### Q34. "An app checks `isPremium` locally to unlock features. Problem?"
Yes if the **server trusts** that flag — the attacker flips it (Frida/patched binary/response tamper) and unlocks paid features, or worse if the same pattern gates data/authz. Client-side checks are UX only; entitlements and authorization must be enforced and re-validated **server-side**.

### Q35. "How is mobile BOLA different from web BOLA?"
Mechanically identical (swap an object ID → another user's data) — the difference is *discovery*: on mobile you find the endpoint/parameters by **decompiling the app** (there's no browser DevTools), then attack the same backend. The bug and fix are server-side; the app just revealed the API.

### Q36. "Where should authorization be enforced in a mobile app architecture?"
**Server-side, on every request, per-object and per-function** — never in the client. The client can display/hide UI for UX, but the backend must independently verify identity, ownership, and role for each action, because the client is attacker-controlled.

**Prevention**

### Q37. Prevention + CWEs for M3?
Enforce **all authN + authZ server-side**; per-object checks (defeat BOLA); strong, short-lived, rotated tokens bound to the session; secure token storage (Keystore/Keychain) + transport (TLS+pinning); server-side session invalidation; treat biometric/local auth as a UX gate backed by server-side + keystore-bound protection. CWEs: CWE-287, CWE-639 (BOLA), CWE-306 (missing auth), CWE-863.

### Q37a. How do you bypass biometric / local auth on a mobile app?
The bug: biometric/PIN gates the **UI**, not the **data/keys**. Test with **Frida/objection** — hook the auth callback and force success: objection `android biometrics bypass`, or a Frida script overriding `BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded` / (iOS) `LAContext.evaluatePolicy` to return `true`. If the protected screen/data is then reachable, the biometric was **cosmetic** (M3). The *correct* pattern binds a **hardware-Keystore key that requires biometric to unlock** (`setUserAuthenticationRequired(true)`), so the data is cryptographically gated — you can't hook past that. → `Android/ADB/`, `../Web/AccountTakeover/`.

---

# §M4 — INSUFFICIENT INPUT / OUTPUT VALIDATION

**Core**

### Q38. What is M4?
The app fails to validate/sanitize data from untrusted sources — **network responses, IPC/intents, deep links, files, QR codes, other apps** — leading to injection/memory-safety issues on the client, or passing malicious data through to the backend. Also output not encoded for its sink (e.g., into a WebView).

### Q39. What's the headline M4 impact on the client?
**WebView injection/XSS** (untrusted data into `loadUrl`/`loadData`/`addJavascriptInterface` → JS execution, and with a JS bridge → **native method access / RCE-ish**); local **SQLi**; **path traversal** in file handling; **intent/deep-link injection** driving internal behavior; **memory corruption** in native code. Plus forwarding unvalidated input to the server (server-side injection).

**How to test**

### Q40. How do you test WebViews for M4?
Check if the WebView loads untrusted URLs/HTML, whether JS is enabled + `addJavascriptInterface` exposes native methods, and whether `file://` access is on. Inject via a **deep link / intent extra / server response** → XSS or JS-bridge → native call. → `../Web/XSS/`, `Android/ADB/` (exercising components).

### Q41. How do you test deep links / intents / providers for M4?
Fuzz exported components + deep-link params (`adb am start ... -d "<uri>"`) → does malicious input drive sensitive actions, traversal, or injection? Test local SQLi (input → local DB query) and path traversal (filenames/paths from intents/downloads/content providers → `../` — → `../Web/PathTraversal/`). Ties to M8. → `Android/ADB/`.

**Red-team / escalation**

### Q42. What's the worst-case M4 chain?
`addJavascriptInterface` exposing a native method + a WebView that loads attacker-influenced content (via deep link or MITM'd server response) → JS calls the native bridge → **arbitrary native method execution** (file access, command exec) — effectively RCE on the client. Historically the `addJavascriptInterface` pre-4.2 RCE class, still exploitable via misuse.

**Interview**

### Q43. "Why is `addJavascriptInterface` dangerous?"
It exposes Java/Kotlin methods to JavaScript running in the WebView. If the WebView ever loads **untrusted content** (or is MITM'd without pinning), that JS can call the exposed native methods → data access / code execution. Safe only with `@JavascriptInterface` annotation + **trusted content only** + JS disabled where not needed.

### Q44. "A deep link takes a `url` param the app opens in a WebView. Risk?"
**M4** — an attacker crafts a malicious deep link (from a web page/another app) → the app loads attacker HTML/JS in the WebView → XSS, and if a JS bridge exists, native calls. Also possible `file://`/local-file theft. Validate + allow-list deep-link inputs and never load untrusted content into a privileged WebView.

**Prevention**

### Q45. Prevention + CWEs for M4?
Validate/sanitize all untrusted input (network, IPC, deep links, files); encode output for its sink; in WebViews disable JS if unused, avoid `addJavascriptInterface` (or restrict to `@JavascriptInterface` + trusted content), disable file access, load only trusted content; parameterize local SQL; canonicalize + confine file paths; memory-safe native code. CWEs: CWE-20, CWE-79 (WebView XSS), CWE-89, CWE-22, CWE-749 (exposed dangerous method).

---

# §M5 — INSECURE COMMUNICATION

**Core**

### Q46. What is M5?
> *Plain version:* the app's conversation with its server isn't properly sealed — no HTTPS, or an HTTPS lock that's easy to pop ("pinning" you can switch off with a tool). On the same Wi-Fi, an attacker reads your login token or edits the replies.

Weak or missing protection of data in transit: no TLS, TLS misconfiguration, accepting invalid/self-signed certs, **no certificate pinning (or bypassable pinning)**, cleartext traffic, and sensitive data over insecure channels. A network-positioned attacker reads or modifies the traffic.

### Q47. What's the impact and why is pinning central?
A network attacker (rogue Wi-Fi/MITM) can **read session tokens/credentials/PII** and **modify requests/responses** → ATO, data theft, request tampering, response manipulation (flip an auth/payment result). **Pinning** matters because without it, a user-installed CA (or malicious proxy) can intercept even TLS traffic; with bypassable pinning, a determined attacker still can.

**How to test**

### Q48. How do you intercept and test mobile traffic?
Proxy via **Burp + install the CA** (→ `Android/ADB/` traffic plumbing). Note **Android 7+ ignores user CAs by default** unless `networkSecurityConfig` allows them — so you may need a system CA (rooted) or to patch config. Check: does the app accept your proxy cert? send cleartext? validate hostnames? → `Android/ADB/`.

### Q49. How do you handle certificate pinning during a test?
If pinned, **bypass it** — objection `android sslpinning disable`, a Frida universal-unpinning script, or patch the check in smali + rebuild. A **bypassable pin is itself an M5 finding** (defense-in-depth, not a wall). If no pin, MITM is straightforward. Then intercept and test the backend it protects.

### Q50. How do you test cert validation and cleartext?
Look for custom `TrustManager`/`HostnameVerifier` that **trusts all certs** (accepts invalid/self-signed/hostname-mismatch — a common bug). Check for `http://` endpoints, `cleartextTrafficPermitted`, and sensitive data to third parties over insecure channels.

**Red-team / escalation**

### Q51. How does M5 become ATO or a business bypass?
MITM the traffic → **steal the session/refresh token** → replay against the backend → **ATO**. Or **modify responses** (flip `isPremium`/`authSuccess`/payment result) → unlock features / bypass checks (ties M3 client-trust). Show the intercepted/tampered sensitive traffic as proof.

**Interview**

### Q52. "What is certificate pinning and why use it?"
The app **hardcodes the expected server certificate/public key** and rejects any other — so even a valid CA-issued cert (from a malicious proxy or a user-installed CA) is refused, defeating MITM. It's defense-in-depth on top of TLS; assume a determined attacker with the device can still bypass it, so don't rely on it alone.

### Q53. "Android 7+ ignores user CAs — what does that mean for testing?"
By default (targetSdk ≥ 24), apps only trust **system** CAs, not user-installed ones — so simply installing Burp's CA as a user cert won't intercept unless the app's `networkSecurityConfig` opts in. Workarounds: install the CA as a **system** cert (rooted), use a debuggable build, or patch/override the network security config.

**Prevention**

### Q54. Prevention + CWEs for M5?
TLS everywhere (no cleartext); proper cert + hostname validation (never trust-all); **certificate/public-key pinning** (non-trivial to bypass); `networkSecurityConfig` (no user CAs, no cleartext); don't send sensitive data to third parties insecurely; re-validate security-critical decisions server-side (don't trust a tamperable response). CWEs: CWE-319 (cleartext), CWE-295 (improper cert validation), CWE-297.

### Q54a. What concrete certificate-validation bugs do you look for (M5)?
Decompile and grep for **trust-all** code that accepts any cert (trivial MITM even without pinning):
- A custom `X509TrustManager` whose `checkServerTrusted()` is **empty** (throws nothing).
- `HostnameVerifier` returning `true` for all hosts (`ALLOW_ALL_HOSTNAME_VERIFIER`).
- OkHttp/`SSLSocketFactory` wired to a trust-all manager; WebView `onReceivedSslError` calling `handler.proceed()` (ignoring cert errors).
- `android:usesCleartextTraffic="true"`, or a permissive `networkSecurityConfig` (`cleartextTrafficPermitted`, user CAs trusted).

Each = a network attacker reads/tampers traffic → session theft / response tampering (flip `isPremium`/`authSuccess`). → `../Web/HostHeader/`, `Android/ADB/`.

---

# §M6 — INADEQUATE PRIVACY CONTROLS

**Core**

### Q55. What is M6 and how does it differ from M9?
Mishandling of **PII/privacy-sensitive data** — excessive collection, insecure handling, over-broad permissions, leaking PII to logs/third parties/other apps, no consent, over-retention. It differs from **M9 (Insecure Data Storage)** in focus: M6 is about **privacy of PII specifically** (collection, sharing, consent), M9 is about **secure storage** of any sensitive data.

**How to test**

### Q56. How do you test for M6?
**Permissions audit** (does the app request more than it needs — location/contacts/SMS/mic?); **PII in logs** (logcat while using it — tokens/PII logged? — → `Android/ADB/` logcat); **PII to third parties** (proxy traffic — what goes to ad/analytics SDKs, with what consent?); **PII via IPC/broadcasts** (does it broadcast PII in Intents readable by other apps? export a provider with PII?); **clipboard/screenshots/backups** (`FLAG_SECURE`? `allowBackup`?); consent + retention.

### Q57. Why are logcat and IPC broadcasts classic M6 leaks?
On older Android, **logcat** was readable by other apps (and still via debug/adb) — PII/tokens written to logs leak. **IPC broadcasts** with PII in Intent extras can be read by any app registered for that action. Both leak sensitive data to co-located apps without the user's knowledge.

**Red-team / escalation**

### Q58. How does M6 become a reportable/bounty finding?
Demonstrate a **co-located malicious app (or logcat/backup) reading PII** it shouldn't — location, contacts, health, identity, tokens — or PII silently sent to a third-party SDK without consent. Impact = privacy breach + regulatory exposure (GDPR/CCPA/HIPAA), often in-scope for privacy bug-bounty programs.

**Interview**

### Q59. "What's the difference between M6 privacy and M9 storage?"
**M9** asks "is sensitive data stored *securely* (encrypted, keystore, not world-readable)?" **M6** asks "should the app *collect/share/expose* this PII at all, and with consent?" You can store PII perfectly (M9 fine) yet still over-collect it or leak it to an ad SDK (M6 fail). Related, different questions.

### Q60. "Name three ways an Android app leaks PII to other apps."
(1) Writing PII to **logcat**; (2) broadcasting PII in **Intent extras** readable by any registered app; (3) **exporting a ContentProvider** holding PII (or world-readable files / cloud+local **backups** / clipboard / un-`FLAG_SECURE` screenshots). Each hands PII to co-located apps or a device-access attacker.

**Prevention**

### Q61. Prevention + CWEs for M6?
Data minimization; explicit consent for PII + third-party sharing; keep PII out of logs/clipboard/screenshots (`FLAG_SECURE`, `allowBackup=false`); don't broadcast PII via IPC / don't export providers with PII; least-permission; encrypt PII at rest (ties M9); retention + deletion controls; vet SDK data flows (ties M2). CWEs: CWE-359 (private info exposure), CWE-532 (logs), CWE-200, CWE-921.

---

# §M7 — INSUFFICIENT BINARY PROTECTIONS

**Core**

### Q62. What is M7?
The app binary lacks protections against **reverse engineering, tampering, and repackaging** — no/weak obfuscation, no anti-tampering/integrity checks, no root/jailbreak/debugger/hook detection, no RASP. This makes it easy to analyze, modify, repackage, and abuse.

### Q63. Is M7 an "issue on its own" or an amplifier?
Primarily an **amplifier** (defense-in-depth): its absence lowers the bar for *everything else* — easy RE exposes secrets (M1) and endpoints; **repackaging** ships trojanized apps or bypasses client checks (M3); **no anti-hook** lets Frida bypass pinning (M5) and auth. It matters, but the real controls are server-side (M3) + not shipping secrets (M1).

**How to test**

### Q64. How do you test binary protections?
Reverse-engineer ease (jadx/apktool — is code obfuscated or fully readable?); **repackaging** (decompile → disable a check → rebuild + re-sign → does it run? no integrity check = yes); **root/jailbreak detection** (present? bypass with Frida/objection/Magisk hide — bypassable = finding); **anti-hook/anti-debug** (does Frida attach freely?); **runtime integrity** (does the app verify its own signature?).

**Red-team / escalation**

### Q65. What does defeating M7 unlock for an attacker?
Trojanized **repackaged** apps in third-party stores; game/finance **cheating/fraud** via patched binaries; trivial **root-detection bypass** so the app runs in a hostile environment; free **Frida hooking** to bypass pinning (M5) and auth (M3) and dump secrets (M1). M7's absence is what makes the whole dynamic-analysis chain easy.

**Interview**

### Q66. "If binary protections don't fix the real bug, why bother?"
Because they **raise the attacker's cost** and are defense-in-depth for scenarios where server-side controls can't help (offline logic, DRM, anti-cheat, anti-fraud). But you never *rely* on them: obfuscation/root-detection/RASP slow attackers; they don't replace server-side auth (M3) or not-shipping-secrets (M1). Both/and, not either/or.

### Q67. "How would you bypass root detection in an app?"
Hook the detection methods with **Frida/objection** (return false for root checks), use **Magisk Hide/DenyList**, or patch the check in smali + repackage. The ease of bypass demonstrates the M7 weakness — report it as "root detection present but trivially bypassable," not as a wall.

**Prevention**

### Q68. Prevention for M7?
Defense-in-depth: code obfuscation (R8/ProGuard/commercial), anti-tampering + runtime integrity/signature checks, root/jailbreak/debugger/emulator/hook detection (tamper-resistant), RASP for high-risk apps — **but never rely on client protections for security** (the real controls are server-side M3 + no secrets M1). Hardening raises cost; it doesn't replace server enforcement.

### Q69. CWEs for M7?
CWE-656 (reliance on obscurity), CWE-693 (protection mechanism failure), CWE-919, CWE-489 (active debug code).

---

# §M8 — SECURITY MISCONFIGURATION

**Core**

### Q70. What is M8 on mobile?
> *Plain version:* "misconfiguration" on a phone mostly means **doors left open to other apps.** An "exported" component is a door any other installed app can walk through — to poke your app's internals or read its private database — no hacking of the app itself required.

Insecure default/explicit configuration of the app and platform: **exported components** (Activities/Services/Receivers/ContentProviders) that shouldn't be exported, **debuggable** builds, **backup enabled**, permissive `networkSecurityConfig`, weak file permissions, exposed deep links, misconfigured WebViews, and insecure platform settings.

### Q71. Why are exported components the headline of M8?
Because an **exported component lets another app (or ADB, no root)** invoke internal Activities/Services, send Broadcasts, or **query/modify a ContentProvider's data** → read private data, provider SQLi, trigger internal actions → **privilege crossing, data theft, action injection** — concrete, no-root, on-device attack surface.

**How to test**

### Q72. How do you test exported components?
**Manifest audit**: list `exported=true` components (+ those with intent-filters = implicitly exported); which have no permission guard? Then: launch exported **Activities** (`adb am start`) → reach internal/post-auth screens; start/bind **Services** & send **Broadcasts** with crafted extras → trigger actions; query/insert/update/delete exported **ContentProviders** (`content://`) → read data, **provider SQLi**, path traversal via `openFile`. → `Android/ADB/`.

### Q73. How do you test `debuggable` and `allowBackup`?
`android:debuggable=true` in a release build → `run-as`/debugger access to app data as any user. `android:allowBackup=true` → `adb backup` → extract app data. Both let a device-access attacker pull private data with no root. Check the manifest and try the extraction.

**Red-team / escalation**

### Q74. Give a concrete M8 escalation.
An **exported ContentProvider** with no permission → another app queries `content://<authority>/users` → dumps private data, or injects into the provider's SQL (**provider SQLi** → `../Web/SQLi/`), or traverses via `openFile` (→ `../Web/PathTraversal/`). Or an exported **Activity** that skips the login check → launch it directly → reach post-auth screens (auth bypass).

**Interview**

### Q75. "What does `exported=true` mean and when is it dangerous?"
It means **other apps can invoke** the component. Dangerous when the component performs sensitive actions or exposes data **without a permission guard or input validation** — any installed app (or ADB) can drive it. Export only what must be, guard it with signature/custom permissions, and validate all incoming Intent data.

### Q76. "How can another app read your app's ContentProvider data?"
If the provider is **exported** (default `true` on older `targetSdk`, or explicitly) **without permissions**, any app calls `contentResolver.query(content://<authority>/…)` and reads it — and can inject SQL if the provider builds queries unsafely, or read arbitrary files via `openFile` path traversal. Fix: don't export, or require permissions + validate.

**Prevention**

### Q77. Prevention for M8?
Export only what must be; guard exported components with signature/custom permissions; never ship **debuggable** release builds; `allowBackup=false` for sensitive apps; least-privilege ContentProviders (or don't export); validate deep-link/Intent input (M4); strict `networkSecurityConfig`; secure file permissions; review the manifest as a security artifact.

### Q78. CWEs for M8?
CWE-926 (improper export of components), CWE-749 (exposed dangerous method), CWE-89 (provider SQLi), CWE-22 (provider traversal), CWE-16, CWE-489 (debuggable).

### Q78a. Give the concrete `adb` commands to exploit an exported component / ContentProvider.
```
# launch an exported Activity (reach a post-auth screen / bypass login)
adb shell am start -n com.target.app/.SecretActivity
# send a crafted Intent to an exported Service / Broadcast Receiver
adb shell am startservice -n com.target.app/.CmdService --es cmd "..."
adb shell am broadcast -a com.target.app.ACTION -e data "..."
# query an exported ContentProvider (read private data)
adb shell content query --uri content://com.target.app.provider/users
# provider SQL injection (unsanitized selection clause)
adb shell content query --uri content://.../users --where "1=1) UNION SELECT password FROM secrets--"
# path traversal via openFile
adb shell content read --uri content://.../files/../../databases/app.db
```
No root needed if the component is exported. **`drozer`** automates provider enumeration + injection. → `Android/ADB/`, `../Web/SQLi/`, `../Web/PathTraversal/`.

---

# §M9 — INSECURE DATA STORAGE

**Core**

### Q79. What is M9 and why is it the highest-frequency device-side High?
> *Plain version:* the app writes something sensitive — usually your **login token** — to the phone in plain readable form. Someone with a backup, a lost phone, or a sneaky co-installed app grabs it, replays it at the server, and they're you. The most common serious *phone-side* bug.

Sensitive data stored **insecurely on the device** — cleartext in `shared_prefs`/plists, unencrypted SQLite, files in world-readable/external storage, misused keychain/keystore, data in caches/logs/temp/backups. It's the highest-frequency device-side High because apps persist **session/refresh tokens or credentials** in readable places → **ATO** from a lost/shared/backed-up device or a co-located app.

**How to test**

### Q80. How do you test app storage?
Enumerate (rooted/`run-as`/emulator): `/data/data/<pkg>/shared_prefs`, `databases`, `files`, `cache`; external storage; iOS container + Keychain (→ `Android/ADB/` private-data read). Look for **session/refresh tokens, credentials, PII, PANs, keys** in cleartext or weak "encryption." Check caches/logs/backups (`adb backup`, WebView cache, logcat) and **data-at-rest after logout**.

### Q81. What's the "steal-and-replay" test and why is it the proof?
Take a **stored session/refresh token** off the device and **use it against the backend** — if it works, you've proven **ATO** from device access/backup/malicious app. That replay is the impact proof; a token sitting in `shared_prefs` is only a finding once you show it grants access.

**Red-team / escalation**

### Q82. How does M9 become ATO?
Cleartext session/refresh token in `shared_prefs`/SQLite/backup → recovered by a co-located malicious app (with storage access), a lost/shared device, or `adb backup` → **replay against the backend → account takeover**. Stored PANs/credentials/PII → direct breach. → `../Web/AccountTakeover/`, `../Web/JWT/` (token analysis).

**Interview**

### Q83. "Where should a mobile app store a session token?"
In the **platform secure store**: Android **Keystore**-backed encryption / **EncryptedSharedPreferences**; iOS **Keychain** with appropriate accessibility — with **hardware-backed keys**, never a hardcoded key. Not in plain `shared_prefs`/plist/SQLite/external storage, and wiped on logout.

### Q84. "Is storing data in the Android Keystore always safe?"
Safer, but not automatically — it's safe if the key is **hardware-backed** and the data is actually encrypted with it. Misuse (a **hardcoded** or derivable "encryption" key that only *looks* like protection — ties M10) defeats it. Also, on a rooted device an attacker with the running app can sometimes coerce keystore operations. Use hardware-backed keys + auth-bound keys for sensitive data.

### Q85. "What's the risk of `android:allowBackup=true`?"
`adb backup -f app.ab <pkg>` (or cloud backup) can **extract the app's private data** — including tokens/PII/credentials stored insecurely — to a device-access attacker, no root needed. Set `allowBackup=false` (or exclude sensitive data) for apps holding secrets.

**Red-team / escalation (cont.)**

### Q86. How do logs and caches feed M9?
Sensitive data written to **logcat**, **HTTP/WebView cache**, temp files, or **backups** persists in readable locations → recovered later via device access, another app, or a backup. Check what the app logs/caches during normal use, and whether it survives logout.

**Prevention**

### Q87. Prevention + CWEs for M9?
Don't store sensitive data unless necessary; use platform secure storage (Keystore-backed encryption / EncryptedSharedPreferences; iOS Keychain) with **hardware-backed keys** (never hardcoded); keep sensitive data out of external storage/logs/caches/backups (`allowBackup=false`, `FLAG_SECURE`); wipe on logout; encrypt at rest with keys the attacker can't recover. CWEs: CWE-312 (cleartext storage), CWE-522, CWE-200, CWE-921.

### Q87a. What exactly do you look for in app storage, and how do you prove ATO?
On a rooted/emulator/`run-as` device, pull and inspect: `/data/data/<pkg>/shared_prefs/*.xml` (grep for `token`/`auth`/`session`/`password`/`refresh`), `databases/*.db` (open with `sqlite3`, dump the tables), `files/`, `cache/`, WebView cache, and iOS Keychain/plist. **Prove ATO by steal-and-replay:** take a stored **session/refresh token**, drop it into a fresh Burp request to the backend (`Authorization: Bearer <token>`) — if it returns the victim's data, that's account takeover from device access/backup/co-located app. Also try **`adb backup -f app.ab <pkg>`** (if `allowBackup=true`) to extract the same data with no root. A token in `shared_prefs` is only a finding once you *replay* it. → `../Web/AccountTakeover/`, `Android/ADB/`.

---

# §M10 — INSUFFICIENT CRYPTOGRAPHY

**Core**

### Q88. What is M10?
Weak, broken, or misused cryptography: weak algorithms (MD5/SHA1/DES/RC4), **ECB mode**, **hardcoded/static keys**, weak key derivation, predictable IVs/nonces, custom "crypto," improper key management, or crypto that's present but implemented wrong. Often the reason M9's "encrypted" storage isn't actually protected.

**How to test**

### Q89. How do you test for M10?
Decompile + find crypto usage (grep `Cipher.getInstance`, `MessageDigest`, `AES/DES`, `ECB`, hardcoded `byte[]` keys, `SecretKeySpec` with a literal); check for **hardcoded/derivable keys** (recover → decrypt M9 data / forge tokens); flag **weak algorithms** (MD5/SHA1 for security, DES/3DES/RC4, ECB, static IV, weak/no KDF); check **randomness** (predictable IVs/nonces, `java.util.Random` for security values); check **key management** (Keystore/Keychain vs prefs/code).

**Red-team / escalation**

### Q90. How is M10 an escalation of M9?
A **hardcoded/derivable key** means the app's "encryption" is decryptable by anyone with the app → M9's "encrypted" stored token/data is **plaintext-equivalent**. Recover the key from the binary → decrypt the stored data / forge a signed token → ATO/breach. M10 is frequently *why* an M9 store isn't actually protected.

### Q91. What's the concrete "break it" proof for M10?
Recover the key/weakness → **decrypt the stored data or forge a signature/token** to demonstrate impact (using your own test data). "AES key hardcoded in `SecretKeySpec` → decrypted the stored session blob → recovered the token → replayed → ATO" is a complete M10→M9 proof.

**Interview**

### Q92. "Why is ECB mode insecure?"
ECB encrypts identical plaintext blocks to identical ciphertext blocks → it **leaks patterns** (the classic "ECB penguin") and enables block manipulation/forgery. It provides confidentiality of individual blocks but not of structure. Use authenticated modes like **AES-GCM** (unique IV per encryption) instead.

### Q93. "What's the right way to derive a key from a password, and store keys, on mobile?"
Derive with a **slow KDF** (Argon2/PBKDF2/scrypt) with a salt — never a raw hash or a hardcoded key. Store/generate keys in the **hardware-backed Keystore/Keychain** (keys never leave secure hardware), use `SecureRandom` for IVs/nonces (unique per op), and prefer **authenticated encryption (AES-GCM)**. Never roll your own crypto.

**Prevention**

### Q94. Prevention + CWEs for M10?
Strong standard algorithms (AES-GCM, SHA-256+, proper KDFs); never hardcode keys — derive/store in hardware-backed Keystore/Keychain; `SecureRandom`; unique IVs/nonces; authenticated encryption; proper key management + rotation; never roll your own; keep crypto libs updated. CWEs: CWE-327 (broken/risky crypto), CWE-328 (weak hash), CWE-321 (hardcoded key), CWE-326, CWE-330 (weak randomness).

---

# §XC — CROSS-CATEGORY CHAINING & REPORTING

### Q95. What's a canonical mobile kill chain across categories?
**M7** (no binary protection) → decompile freely → **M1** (hardcoded key) + map endpoints → **M5** (bypass pinning with Frida) → intercept traffic → **M3** (call API directly, BOLA/auth bypass) → server-side breach; *or* **M9** (steal a stored session token) → replay → **ATO**. Binary weakness enables recovery; recovery enables the server-side and storage attacks.

### Q96. Which mobile findings are device-side vs "carry to the server"?
**Device-side** (report in the mobile context): M1/M5/M6/M7/M8/M9/M10. **Carry to the server** (usually higher severity, report via Web/API kits): **M3** (auth/authz → BOLA/ATO → `../Web/IDOR|AccountTakeover|JWT|OAuth/`, `../API/REST/`) and **M4** (forwarded injection → `../Web/SQLi|XSS|PathTraversal/`). Half your best findings live server-side.

### Q97. How do you keep mobile findings low-FP and high-impact?
Prove **reachability + impact**, not artifacts: steal *and replay* a token (M9→ATO), *drive* an exported component (M8), *pull off* a MITM (M5), *read* PII off the device (M6), or *exploit the server bug* the client exposed (M3/M4). A decompiled string with no consequence is Info, not a finding.

### Q98. How do you rate and report a mobile finding?
Impact-first + reachability, then Mobile-ID + CWE: "Session token stored in cleartext `shared_prefs` → recovered from an `adb backup` → replayed → **account takeover** (**M9**, CWE-312)." Prove device-side on a device **you own**; server-side with **your own accounts** + benign markers. Carry server-side bugs into the Web/API kits (often higher severity).

### Q99. "What's the biggest mistake junior mobile testers make?"
Reporting **decompiled strings / hardcoded values / outdated libs with no reachability** as findings. The client is *designed* to be openable — the bug is what the artifact *reaches* (a token replayed, a component driven, a server bug exposed). Always demonstrate the consequence.

### Q100. "You have 30 minutes on an Android app — what do you do?"
Pull + decompile (jadx) → grep secrets (M1) + read the manifest for exported components/`debuggable`/`allowBackup` (M8); proxy traffic + bypass pinning (M5); **call the backend API directly** and run two-account BOLA/auth tests (M3 — the likely Critical); check `shared_prefs`/DB for stored tokens (M9). Prioritize M3 (server-side) and M9 (ATO) — that's where the impact is.

### Q101. The one meta-lesson of the Mobile Top 10?
> *Plain version:* one sentence for the whole list — **the phone can't be trusted and can't keep secrets, so do the real security on the server and store nothing sensitive in plain sight.** And remember: the client is a map to the server, where your best bugs hide.

**The attacker owns the client, so the client can't be trusted or keep secrets — enforce security server-side and store nothing sensitive in the clear.** Every device-side category is "assume it's recoverable"; the biggest wins are the **server-side bugs the client exposed** (M3/M4). Test the device *and* follow the client into the backend.
