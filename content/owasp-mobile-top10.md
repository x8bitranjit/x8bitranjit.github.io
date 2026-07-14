# OWASP Mobile Top 10 (2024) — In-Depth Testing Reference (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Native and hybrid mobile apps (Android + iOS) — the client binary, its local storage, its IPC/exported surface, its network comms, its crypto, its auth, and its backend integration. Covers both **app-side** flaws (what's in the APK/IPA and on the device) and the **client↔server** boundary.
**Standard:** OWASP **Mobile Top 10, 2024** edition (the current list; supersedes 2016). IDs are `M1` … `M10`.
**Platforms:** Android-first tooling here (this repo's `Mobile/Android/ADB/` kit); iOS notes included. Testing in Kali/WSL + a rooted/jailbroken or emulator device.

> **This is the mobile-surface reference, sibling of the Web/API/LLM Top 10 docs.** Mobile pentesting is different from web in one way that matters: **the attacker often controls the client** — they own the device, can decompile the app, hook it at runtime, read its storage, and drive its exported components. So "it's only in the app" is not a defense. The mistake testers make is reporting decompiled strings or a hardcoded value with no reachability. **The finding is what that flaw *reaches*:** a session token you can steal, an exported component you can drive, a MITM you can pull off, PII you can read off the device, or a server-side bug the mobile client exposes. Read the impact + cross-ref lines before you report.

---

> ### ⚡ READ THIS FIRST — how mobile bugs actually cash out
> 1. **The client is hostile territory, not a secret.** Any secret shipped in the app (API keys, crypto keys, endpoints, logic) is **recoverable** — decompile (`jadx`/`apktool`), hook (`frida`/`objection`), and read memory. So M1/M7/M10 findings are about *what the recovered secret unlocks*, not the recovery itself.
> 2. **Most Critical mobile bugs are actually server-side, exposed by the client.** The app is a map of the backend API. Decompile it → find hidden/privileged endpoints, auth flows, and parameters → attack the **server** (BOLA/IDOR, auth bypass, injection). Cross-ref the Web/API kits — that's where the real money often is.
> 3. **Local storage + logs leak the session.** Insecure data storage (M9) that holds a **session token, refresh token, or credentials** = account takeover from a shared/lost/backed-up device or a co-located malicious app. That's the highest-frequency device-side High.
> 4. **Exported components are the on-device attack surface.** Exported Activities/Services/Receivers/ContentProviders (M8) let *another app* (or ADB) invoke internal functionality, read provider data, or trigger deep links — privilege-crossing without root.
> 5. **Insecure communication (M5) is still everywhere.** No TLS, no cert pinning, or bypassable pinning = network attacker reads/modifies traffic → session theft, request tampering. Pinning-bypass via Frida is a standard step, not a wall.
>
> **Where the money is (memorize):** ① **auth/authz bypass exposed by the client → server BOLA/ATO (M3, → API/Web kits) — Critical** → ② **insecure data storage of session/creds → device-side ATO (M9) — High** → ③ **insecure comms / broken pinning → MITM → session theft (M5) — High** → ④ **exported-component / IPC abuse → privilege crossing (M8) — High** → ⑤ **hardcoded creds/keys → backend/third-party access (M1) — High** → ⑥ **weak/broken crypto (M10) — Medium–High** → ⑦ **binary/supply-chain/config/privacy/output-validation (M7/M2/M8/M6/M4) — context-dependent.**

---

## Table of Contents
- [How to use this list — the mobile testing method](#how-to-use-this-list--the-mobile-testing-method)
- [M1 — Improper Credential Usage](#m1--improper-credential-usage)
- [M2 — Inadequate Supply Chain Security](#m2--inadequate-supply-chain-security)
- [M3 — Insecure Authentication / Authorization](#m3--insecure-authentication--authorization)
- [M4 — Insufficient Input / Output Validation](#m4--insufficient-input--output-validation)
- [M5 — Insecure Communication](#m5--insecure-communication)
- [M6 — Inadequate Privacy Controls](#m6--inadequate-privacy-controls)
- [M7 — Insufficient Binary Protections](#m7--insufficient-binary-protections)
- [M8 — Security Misconfiguration](#m8--security-misconfiguration)
- [M9 — Insecure Data Storage](#m9--insecure-data-storage)
- [M10 — Insufficient Cryptography](#m10--insufficient-cryptography)
- [Tooling](#tooling)
- [Severity calibration & reporting](#severity-calibration--reporting)
- [References](#references)

---

# How to use this list — the mobile testing method

```
0. GET THE APP + DECOMPILE:  pull the APK (adb) / IPA; decompile (jadx/apktool for Android; class-dump/Hopper for iOS).
   Read the manifest (exported components, permissions, network config), strings, endpoints, keys, logic. (ADB kit)
1. STATIC (in the binary): hardcoded creds/keys (M1), crypto usage (M10), exported components + permissions (M8),
   network security config / pinning (M5), third-party SDKs (M2), obfuscation/anti-tamper (M7), privacy/PII (M6).
2. STORAGE (on the device): shared_prefs, SQLite DBs, files, keychain/keystore, cache, logs, backups — for
   session tokens / creds / PII stored insecurely (M9). (ADB kit: private-data read)
3. DYNAMIC (runtime): hook with Frida/objection — bypass root/jailbreak + pinning detection, dump secrets from memory,
   tamper logic, exercise exported components (M8), watch IPC.
4. NETWORK (client↔server): proxy the traffic (Burp + CA); test TLS/pinning (M5); then attack the BACKEND the app
   reveals — auth (M3), authz/BOLA, injection, business logic → the Web/API kits. THIS is often where the Criticals are.
5. VALIDATE: show reachability + impact (a stolen token, a driven component, a MITM, read PII, a server bug), not a
   decompiled string with no consequence.
```

**Golden rule:** a mobile app is a **rich client to a backend, running on hardware the attacker controls.** Half your findings are *device-side* (storage, IPC, crypto, comms) and half are *server-side bugs the client exposes* (auth, BOLA, injection). Test both; the client is your map to the server.

---

# M1 — Improper Credential Usage

**What it is.** Hardcoded credentials/API keys/secrets in the app, insecure transmission or storage of credentials, weak credential handling, or misuse of credentials — anything where the app manages secrets badly. Because the client is fully recoverable, any embedded secret is effectively public.

**Why it pays / impact.** A hardcoded **API key / cloud credential / third-party secret** → direct access to the backend, cloud resources, or a paid third-party service (billing abuse, data access). Hardcoded **admin/service creds** → privilege escalation. Insecurely handled **user credentials** → theft. The impact is *what the credential unlocks server-side*.

**Root causes.** Secrets baked into the APK/IPA (strings, resources, native libs, config); credentials in code/config assuming the client is trusted; keys not scoped/rotated; credentials logged or stored in cleartext; using API keys as if they were secrets when the client can't keep secrets.

**How to test.**
```
□ Decompile + grep for secrets: apktool/jadx → search strings, resources, assets, native .so, BuildConfig for
   API keys, tokens, passwords, private keys, cloud creds, endpoints. (grep -rE 'api[_-]?key|secret|password|BEGIN
   PRIVATE KEY|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}' ...)
□ Validate the key: does the recovered key actually work against the backend/cloud/third-party? (that's the impact).
□ Firebase/S3/backend from config: extract endpoints + keys → test for open Firebase rules / public buckets / open API.
□ Credential handling: are user creds stored/transmitted/logged insecurely? cached? in memory dumpable via Frida?
□ Key scope: is a leaked key least-privilege + revocable, or a god-key?
```

**Real-world / examples.** Hardcoded AWS/Google/Firebase keys in apps (mass-scanned by researchers); Twitter/API keys in binaries; open Firebase databases reachable via keys pulled from the APK; third-party SDK secrets abused for billing.

**Prevention.** Don't embed secrets in the client — the client can't keep secrets; fetch scoped, short-lived tokens from the backend at runtime; use platform key stores (Android Keystore / iOS Keychain) for anything that must be on-device; scope + rotate + monitor API keys; never log credentials; use certificate-bound / attested tokens where possible.

**Cross-refs.** `../Web/Recon/` + `../Web/JSFiles/` (secret-hunting methodology), `../Web/DependencyConfusion/`, and whatever backend the key unlocks (`../API/REST/`, cloud). ADB kit: `logcat` secret hunting, APK pull.

---

# M2 — Inadequate Supply Chain Security

**What it is.** Vulnerabilities from the mobile supply chain: third-party **SDKs/libraries**, the build pipeline, malicious or compromised dependencies, and untrusted components bundled into the app. A malicious SDK runs with the app's permissions and data access.

**Why it pays / impact.** A compromised/malicious **SDK** (ads, analytics, payment) can exfiltrate user data, inject behavior, or backdoor the app — with the app's full permissions. Outdated libraries carry known **CVEs** exploitable in the client. A poisoned **build pipeline** ships malware to every user. This is the mobile twin of software supply-chain attacks.

**Root causes.** Bundling SDKs/libraries without vetting; no dependency inventory/pinning; outdated components with known CVEs; over-permissioned third-party code; unsigned/unsafe build artifacts; typosquatted dependencies.

**How to test.**
```
□ Inventory SDKs/libraries: decompile → identify all third-party SDKs (package names, native libs) + versions.
□ Known CVEs: map library versions to known vulnerabilities (outdated OkHttp, WebView, crypto libs, etc.).
□ SDK behavior/permissions: what data does each SDK access + exfiltrate? excessive permissions? phones home where?
□ Malicious/typosquatted deps: unexpected libraries, repackaged SDKs, suspicious native code.
□ Build integrity: is the APK/IPA properly signed? repackaging protection (ties to M7)? build provenance?
```

**Real-world / examples.** Malicious analytics/ad SDKs harvesting data (documented repeatedly); the Joker/malware-SDK families; outdated WebView/OpenSSL CVEs in shipped apps; SDKs with silent data exfiltration.

**Prevention.** Vet + inventory + pin all third-party SDKs/libraries (SBOM); keep dependencies updated (patch known CVEs); minimize SDK permissions and monitor their network behavior; sign builds + protect the pipeline; prefer reputable, maintained SDKs; remove unused dependencies.

**Cross-refs.** `../Web/DependencyConfusion/` (supply-chain framing), M7 (binary protections / repackaging), component/CVE management.

---

# M3 — Insecure Authentication / Authorization

**What it is.** Weaknesses in how the app **authenticates users** (login, session, tokens, biometrics) and **authorizes actions** (what a user can do/access). Includes client-side-only auth checks, weak session management, insecure token handling, authorization enforced in the app instead of the server, and BOLA/IDOR on the backend the app fronts.

**Why it pays / impact.** This is frequently the **Critical** on mobile: **client-side auth/authz that the server trusts** → bypass it by tampering the client or calling the API directly (→ account takeover, privilege escalation, accessing other users' data). **BOLA/IDOR** on the mobile backend → mass data access. Weak session/token handling → session theft.

**Root causes.** Authorization decided in the app (which the attacker controls) and not re-checked server-side; the server trusting client-supplied identity/role; weak/predictable tokens; sessions that don't expire/rotate; auth bypassable by calling the API directly; insecure biometric/local-auth that gates only the UI, not the data.

**How to test.**
```
□ Call the API DIRECTLY (bypass the app): replay/craft backend requests without the client UI → is authz re-checked
   server-side? (client-side gate = bypassed). This is the #1 mobile-to-server test.
□ BOLA/IDOR: change object IDs (user_id, account_id, order_id) in API calls → other users' data. (→ IDOR kit)
□ Auth bypass: tamper responses (Frida) to flip isLoggedIn/isAdmin; skip steps; force-browse to post-auth screens;
   test the login/reset/2FA flows (→ AccountTakeover / OAuth / JWT kits).
□ Token handling: how are session/refresh tokens issued, stored (M9), transmitted (M5), expired, rotated? JWT flaws?
□ Local/biometric auth: does it gate only the UI, or actually protect the data/keys? bypass via hooking.
□ Session management: fixation, no server-side invalidation on logout, long-lived tokens.
```

**Real-world / examples.** Mobile apps enforcing "admin" client-side → direct-API privilege escalation; BOLA in mobile banking/social APIs (mass account access); JWT `alg:none`/weak-secret in mobile tokens; biometric prompts that only hide UI while data stays accessible.

**Prevention.** **Enforce all authentication + authorization server-side** — never trust the client for identity/role/permission; per-object authorization checks (defeat BOLA); strong, short-lived, rotated tokens bound to the session; secure token storage (Keystore/Keychain) + transport (TLS+pinning); server-side session invalidation; treat biometric/local auth as a UX gate that must be backed by server-side + keystore-bound protection.

**Cross-refs.** THE server-side money link — `../Web/IDOR/` (BOLA), `../Web/AccountTakeover/`, `../Web/JWT/`, `../Web/OAuth/`, `../API/REST/` (API1 BOLA / API2 broken auth / API5 BFLA). ADB kit: exercising exported auth components.

---

# M4 — Insufficient Input / Output Validation

**What it is.** The app fails to validate/sanitize data from untrusted sources — network responses, IPC/intents, deep links, files, QR codes, other apps — leading to injection and memory-safety issues on the client, or passing malicious data through to the backend. Also output not encoded for its sink (e.g. into a WebView).

**Why it pays / impact.** **WebView injection / XSS** (untrusted data into `loadUrl`/`loadData`/`addJavascriptInterface` → JS execution, and with a JS bridge → **native method access / RCE-ish**). **SQL injection** in local DBs. **Path traversal** in file handling. **Intent/deep-link injection** driving internal behavior. **Memory corruption** in native code. Plus the app forwarding unvalidated input to the server (server-side injection).

**Root causes.** Trusting data from IPC/intents/deep links/network/files; loading untrusted content into WebViews; `addJavascriptInterface` exposing native methods to web content; unsafe native code (buffer overflows); no output encoding for WebView/SQL/file sinks.

**How to test.**
```
□ WebView: does it load untrusted URLs/HTML? is JS enabled + addJavascriptInterface exposing native methods? file://
   access? → XSS/JS-bridge → native call. Inject via a deep link / intent extra / server response. (→ XSS kit)
□ Deep links / intents: fuzz exported components + deep-link params → does malicious input drive sensitive actions,
   traversal, or injection? (ties to M8). (ADB kit: exercising components)
□ Local SQLi: input into a local DB query → SQLi in the on-device database.
□ Path traversal: filenames/paths from intents/downloads/content providers → ../ read/write. (→ PathTraversal kit)
□ Native fuzzing: malformed input to native (JNI) code → crashes/memory corruption.
□ Server-forwarded input: does the app pass unvalidated input to the backend → server-side injection there?
```

**Real-world / examples.** `addJavascriptInterface` RCE (pre-4.2 and misuse since); WebView XSS in hybrid apps; deep-link parameter injection driving account actions; local SQLi in messaging apps; path traversal via content providers.

**Prevention.** Validate + sanitize all input from untrusted sources (network, IPC, deep links, files); encode output for its sink; in WebViews: disable JS if not needed, avoid `addJavascriptInterface` (or restrict to `@JavascriptInterface` + trusted content only), disable file access, load only trusted content; parameterize local SQL; canonicalize + confine file paths; memory-safe native code / bounds-checking.

**Cross-refs.** `../Web/XSS/` (WebView), `../Web/SQLi/`, `../Web/PathTraversal/`, `../Web/CommandInjection/`; M8 (exported components / deep links). ADB kit: exercising exported components + content providers.

---

# M5 — Insecure Communication

**What it is.** Weak or missing protection of data in transit: no TLS, TLS misconfiguration, accepting invalid/self-signed certs, no certificate pinning (or bypassable pinning), cleartext traffic, and sensitive data sent over insecure channels. A network-positioned attacker reads or modifies the traffic.

**Why it pays / impact.** A network attacker (rogue Wi-Fi, MITM) can **read session tokens/credentials/PII** and **modify requests/responses** → account takeover, data theft, request tampering, response manipulation (e.g. flip an auth/payment result). Missing/bypassable **pinning** means even TLS traffic is interceptable by a determined attacker (or a malicious proxy/CA).

**Root causes.** Cleartext HTTP; disabled/weak cert validation (accepting all certs, ignoring hostname); no certificate pinning; pinning implemented but trivially bypassable; sensitive data over non-HTTPS channels (analytics, third-party); mixed content; TLS downgrade.

**How to test.**
```
□ Proxy the traffic: Burp + install the CA (ADB kit: traffic-intercept plumbing). Does the app trust a user CA? send
   cleartext? accept your proxy cert? (Android 7+ ignores user CAs by default unless network_security_config allows.)
□ TLS validation: does it accept invalid/self-signed/hostname-mismatched certs? (custom TrustManager that trusts all).
□ Certificate pinning: is it pinned? If yes, BYPASS it (Frida/objection universal unpinning, or patch the check) —
   a bypassable pin = M5 finding. If no pin, MITM is straightforward.
□ Cleartext: any http:// endpoints? sensitive data to third parties over insecure channels? cleartextTrafficPermitted?
□ Response tampering: modify server responses (via MITM) to flip client decisions (isPremium, auth success) — ties to
   client-side-trust (M3).
□ Sensitive data in transit: what PII/creds/tokens ride the wire, and are they protected?
```

**Real-world / examples.** Apps with disabled cert validation (mass-scanned); banking/health apps without pinning; response-tampering to unlock premium; cleartext analytics leaking PII; the endless supply of "trust-all-certs" TrustManagers.

**Prevention.** TLS everywhere (no cleartext); proper cert + hostname validation (never trust-all); **certificate/public-key pinning** (and make it non-trivial to bypass — though assume a determined attacker can); Android `network_security_config` (no user CAs, no cleartext); don't send sensitive data to third parties insecurely; re-validate security-critical decisions server-side (don't trust a tamperable response).

**Cross-refs.** `../Web/HostHeader/` + `../Web/RequestSmuggling/` (backend transport), `../Web/AccountTakeover/` (stolen session). ADB kit: forward/reverse/proxy/CA plumbing. M3 (client trusting tamperable responses).

---

# M6 — Inadequate Privacy Controls

**What it is.** The app mishandles **personally identifiable information (PII)** and privacy-sensitive data — excessive collection, insecure handling, over-broad permissions, leaking PII to logs/third parties/other apps, no consent, and retaining/exposing data beyond need. Distinct from "data storage" (M9) in that it's about *privacy* of PII specifically.

**Why it pays / impact.** **PII exposure** (location, contacts, health, identity, financial) → privacy breach, regulatory exposure (GDPR/CCPA/HIPAA), user harm, and often a reportable bug in bug-bounty privacy scopes. Leaking PII to **third-party SDKs** or **logs** or **other apps** (via IPC/broadcasts) is the common finding. Over-permissioning enables mass data harvesting.

**Root causes.** Collecting more data than needed; sending PII to analytics/ad/third-party SDKs without consent; PII in logs (`logcat`), clipboard, screenshots/backups, or IPC broadcasts readable by other apps; excessive permissions; no data-minimization or retention controls.

**How to test.**
```
□ Permissions audit: does the app request more than it needs (location, contacts, SMS, camera, mic)? (manifest).
□ PII in logs: logcat while using the app → PII/tokens logged? (ADB kit: logcat secret hunting). Readable by other
   apps on older Android / via debug.
□ PII to third parties: proxy the traffic → what PII goes to analytics/ad/SDK endpoints, with what consent?
□ PII via IPC/broadcasts: does the app broadcast PII in Intents readable by other apps? export a provider with PII?
□ Clipboard / screenshots / backups: sensitive data copyable, screenshot-able (FLAG_SECURE?), in cloud/local backups?
□ Consent + retention: is there consent for collection? is data retained/deleted appropriately?
```

**Real-world / examples.** Apps leaking location/contacts to ad SDKs; PII in logcat readable by other apps; sensitive data in Android auto-backup; health/finance apps over-collecting; clipboard-sniffing exposure.

**Prevention.** Data minimization (collect only what's needed); explicit consent for PII + third-party sharing; keep PII out of logs/clipboard/screenshots (`FLAG_SECURE`, `android:allowBackup=false`); don't broadcast PII via IPC / don't export providers with PII; least-permission; encrypt PII at rest (ties M9); retention + deletion controls; vet SDK data flows (ties M2).

**Cross-refs.** M9 (secure storage of the PII), M2 (SDK data exfiltration), M8 (exported providers leaking PII). ADB kit: `logcat`, private-data read, provider queries.

---

# M7 — Insufficient Binary Protections

**What it is.** The app binary lacks protections against **reverse engineering, tampering, and repackaging** — no/weak obfuscation, no anti-tampering/integrity checks, no root/jailbreak or debugger/hook detection, no runtime application self-protection. This makes it easy to analyze, modify, repackage, and abuse the app.

**Why it pays / impact.** Enables/amplifies the other categories: easy reverse engineering exposes secrets (M1), logic, and endpoints; **repackaging** lets attackers ship trojanized versions or bypass client-side checks (M3); **no anti-hook** lets Frida bypass pinning (M5) and auth; **cheating/piracy/fraud** in games/finance. Note: binary protections are *defense-in-depth*, not a root fix — but their absence lowers the bar for everything.

**Root causes.** No code obfuscation; no integrity/anti-tamper checks; no root/jailbreak/emulator/debugger/Frida detection; no signature verification at runtime; secrets/logic in plaintext in the binary; RASP absent.

**How to test.**
```
□ Reverse-engineer ease: jadx/apktool → is code obfuscated or fully readable? are secrets/logic in the clear?
□ Repackaging: decompile → modify (e.g. disable a check) → rebuild + re-sign → does it run? (no integrity check = yes).
□ Root/jailbreak detection: present? bypass it (Frida/objection/Magisk hide) — bypassable detection = a finding.
□ Anti-hook/anti-debug: does Frida attach freely? can you hook freely (pinning/auth bypass)?
□ Runtime integrity: does the app verify its own signature/integrity at runtime?
```

**Real-world / examples.** Trojanized repackaged apps in third-party stores; game/finance cheating via patched binaries; trivially bypassed root detection; unobfuscated fintech apps exposing full logic.

**Prevention.** Apply defense-in-depth: code obfuscation (R8/ProGuard/commercial), anti-tampering + runtime integrity/signature checks, root/jailbreak/debugger/emulator/hook detection (with tamper-resistant implementation), RASP for high-risk apps; **but never rely on client protections for security** — the real controls are server-side (M3) and not shipping secrets (M1). Binary hardening raises the attacker's cost; it doesn't replace server-side enforcement.

**Cross-refs.** Amplifies M1 (secret recovery), M3 (client-check bypass), M5 (pinning bypass), M2 (repackaging). ADB kit: APK pull + analysis; Frida/objection (planned kits).

---

# M8 — Security Misconfiguration

**What it is.** Insecure default or explicit configuration of the app and its platform: **exported components** (Activities/Services/Broadcast Receivers/Content Providers) that shouldn't be exported, debuggable builds, backup enabled, permissive `network_security_config`, weak file permissions, exposed deep links, misconfigured WebViews, and insecure platform settings.

**Why it pays / impact.** **Exported components** = another app (or ADB, no root) can invoke internal Activities/Services, send Broadcasts, or **query/modify a Content Provider's data** (→ read private data, SQLi in the provider, trigger internal actions) → privilege crossing, data theft, action injection. `android:debuggable=true` in prod → `run-as`/debugger access to app data. `allowBackup=true` → extract app data via backup. These are concrete, no-root, on-device attack surfaces.

**Root causes.** Components exported without need (or by default for those with intent-filters); missing/weak permissions on exported components; debuggable/backup-enabled release builds; permissive network config (cleartext, user CAs); world-readable files; over-broad content-provider access; deep links without validation.

**How to test.**
```
□ Manifest audit: list exported=true components (+ those with intent-filters = implicitly exported). Which have no
   permission guard? (ADB kit: exercising exported components).
□ Exported Activities: launch them directly (adb am start) → reach internal/post-auth screens, bypass flows.
□ Exported Services/Receivers: bind/start/send-broadcast with crafted extras → trigger internal actions.
□ Content Providers: query/insert/update/delete an exported provider (content://) → read private data, provider SQLi,
   path traversal via openFile. (ADB kit: content-provider access)
□ debuggable/backup: is the release build debuggable (run-as any user)? allowBackup=true (adb backup → extract data)?
□ network_security_config: cleartext allowed? user CAs trusted? (ties M5).
□ Deep links: exported deep-link handlers → param injection / unauth actions (ties M4).
```

**Real-world / examples.** Exported content providers leaking private data / provider SQLi (a classic Android bug class); exported Activities bypassing login; debuggable production apps; `allowBackup` data extraction; broadcast-receiver action injection.

**Prevention.** Export only what must be exported; guard exported components with signature/custom permissions; never ship debuggable release builds; `android:allowBackup=false` for sensitive apps; least-privilege content providers (or don't export); validate deep-link/intent input (M4); strict `network_security_config`; secure file permissions; review the manifest as a security artifact.

**Cross-refs.** THE on-device attack surface — ADB kit (`ADB_GUIDE.md` exercising exported Activities/Services/Receivers/Content Providers, `run-as` debuggable). `../Web/SQLi/` (provider SQLi), `../Web/PathTraversal/` (provider openFile traversal), M4 (deep-link/intent input).

---

# M9 — Insecure Data Storage

**What it is.** Sensitive data stored **insecurely on the device**: cleartext in shared_preferences/plists, unencrypted SQLite DBs, files in world-readable/external storage, secrets in the keychain/keystore misused, data in caches/logs/temp/backups. Recoverable by a malicious co-located app, an attacker with device access, or via backup.

**Why it pays / impact.** Stored **session/refresh tokens or credentials** → **account takeover** from a lost/shared/backed-up device or a malicious app with storage access. Stored **PII/financial/health** data → breach. This is the highest-frequency *device-side* High: the app persists something that grants access, in a place the attacker can read.

**Root causes.** Storing secrets in cleartext (shared_prefs, SQLite, files); using external/shared storage for sensitive data; caching sensitive responses; sensitive data in logs/temp/screenshots/backups; misusing (or not using) Keystore/Keychain; hardcoded encryption keys "protecting" the storage (ties M10).

**How to test.**
```
□ Enumerate app storage (rooted / run-as / emulator): /data/data/<pkg>/shared_prefs, databases, files, cache;
   external storage; iOS app container + Keychain. (ADB kit: private-data read — shared_prefs/DB/sdcard).
□ Look for: session tokens, refresh tokens, credentials, PII, PANs, keys — stored in cleartext or weakly "encrypted".
□ Steal-and-replay: take a stored session token → use it against the backend (that's the ATO impact).
□ Keystore/Keychain: is sensitive data actually in the hardware-backed store, or just in prefs? is the "encryption"
   key hardcoded/derivable (M10)?
□ Caches/logs/backups: sensitive data in HTTP cache, WebView cache, logcat, temp files, adb backup, cloud backup?
□ Data-at-rest after logout: is sensitive data wiped on logout, or does it persist?
```

**Real-world / examples.** Session tokens in cleartext shared_prefs → ATO from a stolen/backed-up device; banking apps storing PANs unencrypted; credentials in SQLite; sensitive data in WebView cache / logcat; "encrypted" storage with a hardcoded key.

**Prevention.** Don't store sensitive data unless necessary; use platform secure storage (Android Keystore-backed encryption / EncryptedSharedPreferences; iOS Keychain with appropriate accessibility) with hardware-backed keys (never hardcoded); keep sensitive data out of external/shared storage, logs, caches, and backups (`allowBackup=false`, `FLAG_SECURE`); wipe on logout; encrypt at rest with keys the attacker can't recover.

**Cross-refs.** THE device-side ATO — `../Web/AccountTakeover/`, `../Web/JWT/` (stored token analysis), M10 (the crypto protecting it), M6 (PII). ADB kit: private-data read (shared_prefs/DB/`/sdcard`), `logcat`.

---

# M10 — Insufficient Cryptography

**What it is.** Weak, broken, or misused cryptography: weak algorithms (MD5, SHA1, DES, RC4), ECB mode, hardcoded/static keys, weak key derivation, predictable IVs/nonces, custom "crypto," improper key management, or crypto that's technically present but implemented wrong. Often the reason M9's "encrypted" storage isn't actually protected.

**Why it pays / impact.** **Recoverable/hardcoded keys** → the "encryption" is decryptable by anyone with the app (so M9 data is plaintext-equivalent). **Weak algorithms** → hashes cracked, ciphers broken. **Predictable IVs/ECB** → pattern leakage, forgery. The impact is *decryption/forgery of whatever the crypto was protecting* — tokens, stored data, signatures.

**Root causes.** Using deprecated/weak algorithms; hardcoded or derivable keys in the binary; keys not in hardware-backed store; ECB mode; static/predictable IVs/nonces; weak KDF (or none); rolling custom crypto; improper random (predictable PRNG); no key rotation.

**How to test.**
```
□ Decompile + find crypto usage: which algorithms/modes/keys? (grep for Cipher.getInstance, MessageDigest, AES/DES,
   ECB, hardcoded byte[] keys, SecretKeySpec with a literal).
□ Hardcoded keys: is the encryption/HMAC key in the binary or derivable? → recover it → decrypt M9 data / forge tokens.
□ Weak algorithms: MD5/SHA1 for security, DES/3DES/RC4, ECB mode, weak/no KDF, static IV.
□ Randomness: predictable IVs/nonces/tokens? non-crypto PRNG (java.util.Random) for security values?
□ Key management: keys in Keystore/Keychain (hardware-backed) or in prefs/code? rotated?
□ Break it: recover the key/weakness → decrypt stored data / forge a signature/token (that's the impact).
```

**Real-world / examples.** Apps "encrypting" storage with a hardcoded AES key (trivially decrypted); MD5/SHA1 password hashing; ECB-mode leakage; DES/RC4 in legacy apps; predictable token generation; custom broken crypto.

**Prevention.** Use strong, standard algorithms (AES-GCM, SHA-256+, proper KDFs like Argon2/PBKDF2/scrypt); never hardcode keys — derive/store in hardware-backed Keystore/Keychain; strong random (SecureRandom); unique IVs/nonces; authenticated encryption (GCM); proper key management + rotation; never roll your own crypto; keep crypto libraries updated.

**Cross-refs.** M9 (crypto protects stored data — a hardcoded key defeats it), M1 (key handling), `../Web/JWT/` (token crypto/signing weaknesses). 

---

# Tooling

| Tool | Job |
|------|-----|
| **adb** (`Mobile/Android/ADB/` kit) | Connect, pull APK, read private data, exercise exported components, logcat, traffic plumbing — the base kit. |
| **jadx / apktool / dex2jar** | Decompile Android (jadx = Java, apktool = smali/resources/manifest) for static analysis. |
| **Frida / objection** | Dynamic instrumentation — bypass root/pinning detection, dump secrets from memory, hook auth/crypto, tamper logic. |
| **Burp Suite + CA** | Proxy/intercept traffic (M5); then attack the backend the app reveals (the Web/API kits). |
| **MobSF** | Automated static + dynamic analysis (a fast first-pass across most categories). |
| **frida-based unpinning / objection `android sslpinning disable`** | Certificate-pinning bypass (M5). |
| **drozer** | Android IPC/attack-surface assessment — exported components, providers (M8). |
| **class-dump / Hopper / Ghidra** (iOS/native) | iOS + native binary analysis. |

```bash
# pull + decompile
adb shell pm path <pkg>; adb pull <apk-path>; jadx -d out app.apk; apktool d app.apk
# read private storage (rooted/run-as/emulator)
adb shell run-as <pkg> cat /data/data/<pkg>/shared_prefs/*.xml
# exercise an exported component / provider (M8)
adb shell am start -n <pkg>/<Activity>;  adb shell content query --uri content://<authority>/<path>
# bypass pinning + dump (M5/M9) — objection
objection -g <pkg> explore  # then: android sslpinning disable ; android keystore list
```

---

# Severity calibration & reporting

| Scenario | Typical | Notes |
|---|---|---|
| **Client-side auth/authz → server BOLA/ATO (M3)** | **Critical** | Rate as the server bug; call the API directly to prove. |
| **Insecure storage of session/creds → ATO (M9)** | **High** | Steal + replay the token to prove impact. |
| **Insecure comms / broken pinning → MITM → session theft (M5)** | **High** | Show the intercepted/tampered sensitive traffic. |
| **Exported component / provider → private data / action injection (M8)** | **High** | Another app / ADB drives it with no root. |
| **Hardcoded creds/keys → backend/cloud/3rd-party access (M1)** | **High** | Prove the key works; note least-privilege/scope. |
| **Weak/broken crypto → decrypt stored data / forge (M10)** | **Medium–High** | Recover the key → decrypt to prove. |
| **PII leakage (M6) / supply-chain SDK (M2) / binary (M7) / input-validation (M4)** | **Medium–High** | Rate by the data/reachability/downstream sink. |
| **Decompiled string / config with no reachability** | **Low/Info** | Not a finding without impact — find what it unlocks. |

**Reporting rules:** name the **impact + reachability**, not the artifact ("session token stored in cleartext shared_prefs → recovered from a device backup → account takeover," not "the app stores data in shared_prefs"). Prove device-side findings on a device **you own** (rooted/emulator) and server-side findings with **your own accounts** + benign markers. Half your best findings are **server-side bugs the client exposed** — carry them into the Web/API kits and report them there (usually higher severity). Map to the Mobile ID **plus** the underlying CWE/Web-kit where relevant.

---

# References

**Primary**
- **OWASP Mobile Top 10 (2024)**: https://owasp.org/www-project-mobile-top-10/
- **OWASP MASVS** (Mobile Application Security Verification Standard) — the requirements: https://mas.owasp.org/MASVS/
- **OWASP MASTG** (Mobile Application Security Testing Guide) — the how-to (the definitive testing manual): https://mas.owasp.org/MASTG/
- OWASP MAS project + MASWE (weakness enumeration): https://mas.owasp.org/

**Technique / platform**
- Android developer security guidance (network security config, Keystore, exported components) + iOS security guides.
- HackTricks — Android/iOS pentesting: https://book.hacktricks.xyz/mobile-pentesting
- Frida (https://frida.re/) · objection · MobSF · drozer docs.

**Companion kits in this repo**
- `Mobile/Android/ADB/` (the ADB tool kit — connect, pull, read storage, exercise components, logcat, traffic) — the practical base for M1/M6/M8/M9. Server-side cash-outs: `../Web/IDOR/`, `../Web/AccountTakeover/`, `../Web/JWT/`, `../Web/OAuth/`, `../Web/SQLi/`, `../Web/XSS/`, `../Web/PathTraversal/`, `../API/REST/`. Planned mobile tool kits: Frida · objection · apktool · jadx · drozer.

---

> **Final reminder — the one rule that pays:** on mobile the attacker owns the client, so a decompiled secret or a stored value is only a finding when you show **what it reaches** — a session token you steal and replay (ATO), an exported component you drive, a MITM you pull off, PII you read off the device, or (most often) a **server-side auth/BOLA/injection bug the client exposed.** Test the device side (M1/M5/M7/M9/M10/M6/M8) *and* follow the client into the backend (M3/M4 → the Web/API kits) — that's where the Criticals hide.
