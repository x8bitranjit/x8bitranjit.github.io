// Cloudflare Worker — edge access gate for the static site (Workers Assets).
// Runs BEFORE any file is served (wrangler assets.run_worker_first = true), so an
// unauthenticated visitor never receives index.html / app.js / content — real
// security, unlike the old client-side boot.js gate.
//
// Required Worker environment variables (Settings -> Variables and Secrets, as "Secret"):
//   SITE_TOKEN      the access token you hand out (what people type to enter)
//   SESSION_SECRET  a DIFFERENT long random string; signs the session cookie
//
// Rotate the token      -> change SITE_TOKEN     (old token stops working)
// Log everyone out now   -> change SESSION_SECRET (all cookies become invalid)

const COOKIE = "x8session";
const MAX_AGE = 60 * 60 * 24 * 7; // 7 days

async function hmac(key, data) {
  const k = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function safeEqual(a, b) { // constant-time compare
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

async function makeSession(secret) {
  const exp = String(Date.now() + MAX_AGE * 1000);
  return `${exp}.${await hmac(secret, exp)}`;
}

async function validSession(secret, val) {
  if (!val) return false;
  const dot = val.lastIndexOf(".");
  if (dot < 1) return false;
  const exp = val.slice(0, dot), sig = val.slice(dot + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return safeEqual(sig, await hmac(secret, exp));
}

function getCookie(request, name) {
  const m = (request.headers.get("Cookie") || "")
    .match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}

function loginPage(msg) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>x8bitranjit &middot; Access</title>
<style>
:root{--bg:#0c1426;--panel:#12203c;--edge:#1a2949;--gold:#cdab46;--gold2:#e3c463;--link:#8ab4f8;--text:#dfe3ec}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 600px at 50% -10%,rgba(138,180,248,.07) 0,transparent 60%),var(--bg);color:var(--text);font-family:system-ui,Segoe UI,Roboto,sans-serif}
.card{width:min(92vw,360px);background:var(--panel);border:1px solid var(--edge);border-radius:16px;padding:2rem 1.7rem;box-shadow:0 20px 60px rgba(0,0,0,.45)}
h1{margin:.2rem 0 .1rem;font-size:1.25rem;color:var(--gold)}
.sub{margin:0 0 1.3rem;font-size:.86rem;color:#9fb0d0}
label{display:block;font-size:.8rem;color:#9fb0d0;margin:.2rem 0 .35rem}
input{width:100%;padding:.75rem .85rem;border-radius:10px;border:1px solid var(--edge);background:#0b1226;color:var(--text);font-size:1rem;outline:none}
input:focus{border-color:var(--link);box-shadow:0 0 0 3px rgba(138,180,248,.15)}
button{width:100%;margin-top:1rem;padding:.8rem;border:0;border-radius:10px;background:linear-gradient(180deg,var(--gold2),var(--gold));color:#231a02;font-weight:700;font-size:1rem;cursor:pointer}
button:hover{filter:brightness(1.06)}
.err{min-height:1.25em;margin:.5rem 0 0;color:#f56991;font-size:.85rem}
.foot{margin-top:1.2rem;font-size:.72rem;color:#6f80a0;text-align:center}
</style></head><body>
<form class="card" method="POST" action="/__auth" autocomplete="off">
  <h1>&#128274; Restricted</h1>
  <p class="sub">Enter your access token to continue.</p>
  <label for="t">Access token</label>
  <input id="t" name="token" type="password" autofocus autocomplete="off" spellcheck="false">
  <p class="err">${msg || ""}</p>
  <button type="submit">Enter</button>
  <p class="foot">x8bitranjit &middot; security knowledge base</p>
</form></body></html>`;
}

function htmlResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Fail-closed: no secrets configured -> nobody gets in.
    if (!env.SITE_TOKEN || !env.SESSION_SECRET) {
      return htmlResponse(loginPage("Access gate not configured yet."), 503);
    }

    // Don't serve the gate's own source files.
    if (url.pathname === "/gate-worker.js" || url.pathname === "/wrangler.jsonc") {
      return new Response("Not found", { status: 404 });
    }

    // 1) Token submission
    if (url.pathname === "/__auth" && request.method === "POST") {
      let token = "";
      try { token = (await request.formData()).get("token") || ""; } catch (_) {}
      const ok = safeEqual(
        await hmac(env.SESSION_SECRET, token),
        await hmac(env.SESSION_SECRET, env.SITE_TOKEN)
      );
      if (!ok) return htmlResponse(loginPage("Wrong token — try again."), 401);
      const session = await makeSession(env.SESSION_SECRET);
      return new Response(null, {
        status: 302,
        headers: {
          "Location": "/",
          "Cache-Control": "no-store",
          "Set-Cookie": `${COOKIE}=${encodeURIComponent(session)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`
        }
      });
    }

    // 2) Valid session -> serve the real (identical) static site
    if (await validSession(env.SESSION_SECRET, getCookie(request, COOKIE))) {
      return env.ASSETS.fetch(request);
    }

    // 3) Everything else -> the gate. No site bytes leak to the unauthenticated.
    return htmlResponse(loginPage(""), 401);
  }
};
