# 11. Approval & Workflow — Checklist

Feature-area security **test cases** for “11. Approval & Workflow”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*24 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## WF-001 — Self-approval / maker=checker separation-of-duties bypass
**Test Category:** Business Logic (WSTG-BUSL-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Approval action where the requester can also be the approver

**Test Steps:** 1. Create a request (maker) as user A<br>2. Attempt to approve the same request as A (or as an account you control on both roles)<br>3. Confirm the workflow lets the same identity make + approve<br>4. Complete the privileged action with no independent review

**Expected Result:** Maker and checker must be distinct identities; server enforces segregation of duties

**Payload Example:**

```
POST /requests/123/approve  (Authorization: same user who created 123)
```

**Impact:** Separation-of-duties bypass -&gt; self-approve privileged/financial actions

**Tools:** Burp Suite

**References:** CWE-863; CWE-841; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSL-07

---

## WF-002 — Approve another user's request (BOLA on approval object)
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Approval endpoint — request/approval object identifier

**Test Steps:** 1. As low-priv A, enumerate approval/request IDs<br>2. Approve/reject a request that belongs to another tenant/user or a higher approval tier<br>3. Two-account proof: A actions B's pending item<br>4. Confirm the state changed

**Expected Result:** Approval endpoints authorize the object AND the approver's role/tier per request

**Payload Example:**

```
POST /approvals/{other_users_request_id}/approve  (A token)
```

**Impact:** BOLA on approvals -&gt; approve/deny others' requests -&gt; unauthorized state change

**Tools:** Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP WSTG-ATHZ-04

---

## WF-003 — Skip approval step / forced workflow-state transition
**Test Category:** Business Logic (WSTG-BUSL-06) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Workflow status field / state-transition endpoint

**Test Steps:** 1. Map the workflow states (draft-&gt;pending-&gt;approved-&gt;executed)<br>2. Try to jump straight to 'approved'/'executed' via a status param or a later-step endpoint<br>3. Force-browse the execute endpoint while status is still pending<br>4. Confirm the guarded step ran without approval

**Expected Result:** State transitions validated server-side; each step re-checks the prior state + authorization

**Payload Example:**

```
PATCH /requests/123 {"status":"approved"}  |  POST /requests/123/execute (while pending)
```

**Impact:** Workflow-state bypass -&gt; execute privileged action with no approval

**Tools:** Burp Suite

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSL-06

---

## WF-004 — Approval threshold bypass via transaction splitting
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Amount/quantity field vs approval-required threshold

**Test Steps:** 1. Find the value that triggers required approval (e.g. &gt; $10,000)<br>2. Split the action into multiple sub-threshold requests that each auto-approve<br>3. Or set an amount just under the limit then top-up post-approval<br>4. Confirm the aggregate exceeds the control with no approval

**Expected Result:** Thresholds evaluated on aggregate/velocity, not per-request; post-approval edits re-trigger review

**Payload Example:**

```
3 x POST /transfer {"amount":9999}  (each below the $10k approval gate)
```

**Impact:** Threshold split -&gt; move value above the approval limit unreviewed -&gt; financial

**Tools:** Burp Suite

**References:** CWE-840; PortSwigger Business logic; OWASP WSTG-BUSL-01

---

## WF-005 — TOCTOU: execute action before/while approval is pending (race)
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Gap between approval decision and action execution

**Test Steps:** 1. Submit a request needing approval<br>2. Fire the execute call concurrently with (or just before) the approval commit<br>3. Use parallel/single-packet requests to win the race<br>4. Confirm the action ran without a committed approval

**Expected Result:** Execution is gated on a committed approval inside one atomic transaction

**Payload Example:**

```
parallel: POST /requests/123/execute  x N  during the approval window
```

**Impact:** Approval TOCTOU -&gt; execute unapproved action -&gt; control bypass / financial

**Tools:** Turbo Intruder, Burp

**References:** CWE-367; CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle 'Smashing the State Machine'

---

## WF-006 — Approve-then-modify (edit request after approval)
**Test Category:** Business Logic (WSTG-BUSL-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Request object mutability after the approval decision

**Test Steps:** 1. Submit a benign request and get it approved<br>2. Modify the sensitive fields (amount/recipient/scope) after approval, before execution<br>3. Confirm the executed action uses the modified values, not the approved ones<br>4. Prove the approver reviewed different content

**Expected Result:** Approved payload is frozen/signed; any edit invalidates the approval

**Payload Example:**

```
PATCH /requests/123 {"recipient":"attacker"}  (status already 'approved')
```

**Impact:** Approve-then-modify TOCTOU -&gt; execute attacker-chosen action under a stale approval

**Tools:** Burp Suite

**References:** CWE-367; CWE-841; -&gt;[Race Condition checklist](#/checklist/racecondition); PortSwigger Business logic

---

## WF-007 — CSRF / replay on the approve action
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Approve/reject endpoint under cookie auth

**Test Steps:** 1. Capture an approve request; check for anti-CSRF token / custom header<br>2. Build a cross-site auto-submit (or replay a captured approval)<br>3. Fire at a logged-in approver<br>4. Confirm the approval executed cross-site / on replay

**Expected Result:** State-changing approvals require anti-CSRF token + are single-use (nonce)

**Payload Example:**

```
<form action=/approvals/123/approve method=POST>...</form> auto-submit at an approver
```

**Impact:** Approval CSRF/replay -&gt; forge or repeat approvals in the approver's session

**Tools:** Burp Suite

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF; OWASP WSTG-SESS-05

---

## WF-008 — Second-order BOLA: re-authorization dropped at later workflow steps
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-step workflow where step 1 authorizes but later steps don't re-check

**Test Steps:** 1. Start a workflow that authorizes the object at step 1<br>2. Confirm steps 2/3 (approve/execute) don't re-validate object ownership/tier<br>3. Swap in another tenant's object ID at a later step (A token)<br>4. Confirm cross-object action

**Expected Result:** Every workflow step independently re-authorizes the object and the actor

**Payload Example:**

```
POST /wf/step1 {obj:A} -> POST /wf/step3/execute {obj:B_id}  (A token)
```

**Impact:** Second-order BOLA in workflow -&gt; cross-user/tenant privileged action

**Tools:** Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); REST_API TESTING_GUIDE (multi-step BOLA)

---

## WF-009 — Fail-open approval (approval-service error defaults to approved)
**Test Category:** Business Logic (WSTG-BUSL-06) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Approval decision under an error/timeout of the approval service (A10:2025 / CWE-636)

**Test Steps:** 1. Force the approval/policy service to error or time out (malformed input, dependency down)<br>2. Observe whether the workflow defaults to APPROVED (fail-open) or blocks (fail-closed)<br>3. Confirm the guarded action proceeds on error<br>4. Report the fail-open decision

**Expected Result:** Approval fails CLOSED on any error; no auto-approve on exception/timeout

**Payload Example:**

```
make the policy call throw -> request auto-approves
```

**Impact:** Fail-open approval -&gt; unreviewed privileged action on service error (A10:2025)

**Tools:** Burp Suite

**References:** CWE-636; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Top 10:2025 A10; PortSwigger Business logic

---

## WF-010 — Multi-level approval collapse (one approval satisfies all tiers)
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-tier approval chain (L1/L2/L3)

**Test Steps:** 1. Map the required approval tiers<br>2. Provide one approval and check whether it auto-satisfies higher tiers<br>3. Or reuse the same approver identity across tiers meant to be distinct<br>4. Confirm the action executes with fewer distinct approvals than required

**Expected Result:** Each tier requires a distinct, authorized approver; server counts distinct identities

**Payload Example:**

```
L1 approve as A -> action executes though L2/L3 never approved
```

**Impact:** Approval-chain collapse -&gt; privileged action with insufficient authorization

**Tools:** Burp Suite

**References:** CWE-863; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Business logic; OWASP WSTG-BUSL-07

---

## WF-011 — Delegation / proxy-approval privilege abuse
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Approval-delegation feature (delegate approve rights)

**Test Steps:** 1. Delegate approval authority to an account you control (or to yourself)<br>2. Check whether delegation is validated against role/scope and time-boxed<br>3. Use the delegated right to approve out-of-scope requests<br>4. Confirm privilege gained via delegation

**Expected Result:** Delegation is authorized, scoped, time-boxed, and audited; no self-delegation of higher rights

**Payload Example:**

```
POST /approvals/delegate {"to":"attacker","scope":"*"}
```

**Impact:** Delegation abuse -&gt; acquire approval authority beyond role

**Tools:** Burp Suite

**References:** CWE-863; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP WSTG-ATHZ-02

---

## WF-012 — Audit-trail / notification gap on approval actions
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Audit log &amp; notifications for approve/reject/execute events

**Test Steps:** 1. Perform approve/reject/execute actions<br>2. Check whether each is logged with actor, object, before/after, timestamp<br>3. Check whether the request owner/approvers are notified<br>4. Confirm gaps that let approval abuse go undetected

**Expected Result:** All approval events are tamper-evident logged + stakeholders notified

**Payload Example:**

```
approve then verify no audit entry / no notification to the maker
```

**Impact:** Missing approval audit/alerts -&gt; approval abuse is undetectable (A09:2025)

**Tools:** Burp, log review

**References:** CWE-778; OWASP Top 10:2025 A09 (Logging &amp; Alerting Failures); OWASP WSTG-CONF-09

---

## WF-013 — Stored XSS via approval comment / rejection-reason field
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Approval comment/reason field rendered in the approver/requester dashboard

**Test Steps:** 1. Submit a request with an XSS payload in a free-text field (title/reason/comment)<br>2. Confirm it renders unescaped in the approver's queue or the audit view<br>3. Fire in the approver's authenticated context<br>4. Chain to approve-as-approver / token theft

**Expected Result:** All workflow free-text is context-encoded on output

**Payload Example:**

```
reason=<img src=x onerror=fetch('/approvals/123/approve',{method:'POST'})>
```

**Impact:** Stored XSS in approval UI -&gt; auto-approve or token theft in approver session

**Tools:** Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; OWASP WSTG-INPV-02

---

## WF-014 — IDOR on approval history / audit-trail read
**Test Category:** Information Disclosure (WSTG-ATHZ-04) · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Approval history / audit-log endpoint

**Test Steps:** 1. Access your approval history endpoint; note the ID scheme<br>2. Enumerate/swap IDs to read other users'/tenants' approval records<br>3. Confirm exposure of amounts, approvers, business data<br>4. Quantify scope

**Expected Result:** Approval/audit reads authorized per record + tenant

**Payload Example:**

```
GET /approvals/history?id={other}   or   GET /audit/approval/{id}
```

**Impact:** IDOR on approval audit -&gt; cross-user/tenant disclosure of sensitive workflow data

**Tools:** Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP WSTG-ATHZ-04

---

## WF-015 — Bulk / mass-approve abuse
**Test Category:** Business Logic (WSTG-BUSL-06) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk-approve endpoint / select-all action

**Test Steps:** 1. Find a bulk-approve action<br>2. Submit IDs beyond your scope (other tenants/tiers) in the batch<br>3. Check whether per-item authorization is applied in bulk<br>4. Confirm mass unauthorized approval

**Expected Result:** Bulk operations authorize every item individually server-side

**Payload Example:**

```
POST /approvals/bulk {"ids":[all_pending_including_others],"action":"approve"}
```

**Impact:** Bulk-approve authz gap -&gt; mass unauthorized state change

**Tools:** Burp Suite

**References:** CWE-639; CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP WSTG-BUSL-06

---

## WF-016 — Approval webhook / callback forgery (spoof 'approved' event)
**Test Category:** Business Logic (WSTG-BUSL-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** External approval callback / webhook that flips state

**Test Steps:** 1. Find a webhook/callback that marks a request approved (e-sign, external approver, IdP)<br>2. Check signature/HMAC verification and source validation<br>3. Forge/replay an 'approved' event<br>4. Confirm the request flips to approved

**Expected Result:** Callbacks are signed (HMAC), source-verified, single-use, and idempotent

**Payload Example:**

```
POST /webhooks/approval {"request":123,"status":"approved"}  (no/invalid signature)
```

**Impact:** Forged approval callback -&gt; approve without a real approver

**Tools:** Burp Suite

**References:** CWE-345; CWE-347; -&gt;[SSRF checklist](#/checklist/ssrf); OWASP WSTG-BUSL-07

---

## WF-017 — Auto-approve on SLA / timeout abuse
**Test Category:** Business Logic (WSTG-BUSL-06) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Escalation/timeout policy that auto-approves un-actioned requests

**Test Steps:** 1. Determine whether un-actioned requests auto-approve after a timeout/SLA<br>2. Submit a request and simply wait / suppress approver notification<br>3. Confirm it auto-approves without human review<br>4. Combine with notification suppression to hide it

**Expected Result:** Timeouts escalate to a human or fail-closed; never silent auto-approve of privileged actions

**Payload Example:**

```
submit request -> suppress notification -> wait for SLA auto-approve
```

**Impact:** SLA auto-approve -&gt; privileged action granted with zero review

**Tools:** Burp Suite

**References:** CWE-636; CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Top 10:2025 A10; WSTG-BUSL-06

---

## WF-018 — Predictable / reusable email approval link
**Test Category:** Broken Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email 'Approve' magic-link token

**Test Steps:** 1. Capture an email approve/reject link<br>2. Check token entropy, single-use, expiry, and account binding<br>3. Predict/replay the token, or use it after logout / from another account<br>4. Confirm approval without the approver

**Expected Result:** Approval links are high-entropy, single-use, short-lived, and bound to the approver session

**Payload Example:**

```
GET /approve?token=<predictable-or-replayed>
```

**Impact:** Weak approval link -&gt; approve as the approver without authentication

**Tools:** Burp Suite

**References:** CWE-640; CWE-330; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## WF-019 — Reviewer / approver self-assignment tampering
**Test Category:** Broken Access Control (WSTG-ATHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Reviewer-assignment field on the request

**Test Steps:** 1. Check whether the requester can set/influence who approves<br>2. Assign yourself (or a colluding account) as the approver<br>3. Approve your own request via the assigned approver<br>4. Confirm SoD defeated

**Expected Result:** Approver assignment is policy-driven server-side; requester cannot select their approver

**Payload Example:**

```
POST /requests {"amount":9000,"approver":"attacker_account"}
```

**Impact:** Approver self-assignment -&gt; route approval to a controlled account -&gt; SoD bypass

**Tools:** Burp Suite

**References:** CWE-863; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP WSTG-ATHZ-02

---

## WF-020 — 'approval_required' / conditional-gate flag tampering
**Test Category:** Business Logic (WSTG-BUSL-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Client-supplied flag that decides whether approval is needed

**Test Steps:** 1. Inspect the create/submit request for a flag like approval_required / needs_review / auto_approve<br>2. Flip it to skip the approval gate<br>3. Confirm the action executes without entering the workflow<br>4. Prove the gate is client-controlled

**Expected Result:** Whether approval is required is decided server-side by policy, never by a client field

**Payload Example:**

```
POST /requests {"amount":50000,"approval_required":false}
```

**Impact:** Conditional-gate tampering -&gt; skip approval entirely

**Tools:** Burp Suite

**References:** CWE-602; CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP WSTG-BUSL-07

---

## WF-021 — Change / deployment approval (CAB) bypass
**Test Category:** Broken Access Control (WSTG-ATHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CI/CD or change-management approval gate

**Test Steps:** 1. Identify the deploy/change gate requiring approval (CAB/change ticket)<br>2. Trigger the deploy/apply endpoint directly, or mark the change approved via API<br>3. Check whether the pipeline enforces the gate server-side<br>4. Confirm an unapproved change ships

**Expected Result:** Deploy/apply is gated on a verified approval in the pipeline; no direct-trigger bypass

**Payload Example:**

```
POST /deploy {"change":123,"env":"prod"}  (bypassing the CAB gate)
```

**Impact:** Change-approval bypass -&gt; unreviewed production change (supply-chain/integrity, A08)

**Tools:** Burp Suite, curl

**References:** CWE-840; -&gt;[Dependency Confusion checklist](#/checklist/depconfusion); OWASP Top 10:2025 A08; WSTG-ATHZ-04

---

## WF-022 — Access-request (JML) approval self-grant
**Test Category:** Broken Access Control (WSTG-ATHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Joiner-Mover-Leaver access-request approval

**Test Steps:** 1. Request elevated access/role/group for yourself<br>2. Attempt to approve or auto-grant it (self-approve, or exploit a missing approver check)<br>3. Confirm the entitlement is granted<br>4. Use the new access

**Expected Result:** Entitlement grants require an independent approver; no self-grant path

**Payload Example:**

```
POST /access-requests {"role":"admin"} -> POST /access-requests/{id}/approve (self)
```

**Impact:** Access-request self-grant -&gt; privilege escalation to elevated role

**Tools:** Burp Suite

**References:** CWE-863; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP WSTG-ATHZ-02

---

## WF-023 — Break-glass / emergency-override abuse
**Test Category:** Business Logic (WSTG-BUSL-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Emergency-approval / break-glass bypass path

**Test Steps:** 1. Locate any emergency/break-glass path that skips normal approval<br>2. Check whether invoking it is itself authorized, logged, and time-boxed<br>3. Invoke it to bypass the workflow<br>4. Confirm privileged action with no approval + weak accountability

**Expected Result:** Break-glass is tightly authorized, alarmed, fully logged, and auto-expiring

**Payload Example:**

```
POST /requests/123/emergency-approve {"reason":"x"}  as a normal user
```

**Impact:** Break-glass abuse -&gt; bypass approval controls under an emergency pretext

**Tools:** Burp Suite

**References:** CWE-863; CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP WSTG-BUSL-07

---

## WF-024 — Notification suppression / recall to hide approval abuse
**Test Category:** Logging &amp; Monitoring (WSTG-CONF-09) · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Notification settings / message-recall around approval events

**Test Steps:** 1. Perform an approval action, then suppress or recall the resulting notifications to stakeholders<br>2. Check whether owners/approvers can be kept unaware<br>3. Confirm the abuse is concealable<br>4. Tie to missing tamper-evident audit

**Expected Result:** Approval notifications are non-suppressible + audit is tamper-evident

**Payload Example:**

```
PATCH /notifications {"approval_events":"off"} then approve silently
```

**Impact:** Notification suppression -&gt; approval abuse goes unnoticed (A09:2025)

**Tools:** Burp Suite

**References:** CWE-778; OWASP Top 10:2025 A09; WSTG-CONF-09

---
