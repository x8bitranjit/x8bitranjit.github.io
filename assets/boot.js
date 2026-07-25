/* Pre-render loader. Verifies the access code and initializes the application. */
(function () {
  'use strict';

  var CACHE = 'x8_app_v2';          // per-tab cache of the decrypted app (clears on tab close)
  var ENC   = 'assets/app.enc';

  var enc = new TextEncoder();
  function b64ToBytes(s){ var bin = atob(s); var u = new Uint8Array(bin.length); for (var i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u; }

  /* Run the decrypted SPA. Indirect eval executes in global scope — exactly like the original external
     <script src=app.js> did — so its top-level functions/listeners bind the same way (CSP: 'unsafe-eval'). */
  function injectApp(src) {
    if (!document.body) {                       // boot.js runs in <head>; wait for <body> on the cached fast-path
      document.addEventListener('DOMContentLoaded', function () { injectApp(src); });
      return;
    }
    document.documentElement.classList.remove('nb-lock');
    (0, eval)(src);
  }

  /* Derive the AES key from the code and try to decrypt app.enc. Resolves with the plaintext source or rejects. */
  function decryptApp(code) {
    return fetch(ENC, { cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('enc fetch ' + r.status);
      return r.json();
    }).then(function (p) {
      var salt = b64ToBytes(p.salt), iv = b64ToBytes(p.iv), ct = b64ToBytes(p.ct);
      return crypto.subtle.importKey('raw', enc.encode(code), { name: 'PBKDF2' }, false, ['deriveKey'])
        .then(function (base) {
          return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: salt, iterations: p.iter, hash: 'SHA-256' },
            base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        })
        .then(function (key) { return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct); })
        .then(function (buf) { return new TextDecoder().decode(buf); });  // wrong code -> GCM throws here
    });
  }

  var AUTH_HTML =
    '<div class="nb-bar" aria-hidden="true"></div>' +
    '<div class="nb-wrap">' +
      '<div class="nb-seal-box">' +
        '<img class="nb-seal" src="image.webp" width="178" height="184" ' +
          'alt="Seal of the Federal Bureau of Investigation, U.S. Department of Justice">' +
      '</div>' +
      '<div class="nb-eyebrow">UNITED STATES DEPARTMENT OF JUSTICE &#183; FEDERAL BUREAU OF INVESTIGATION</div>' +
      '<h1 class="nb-title">THIS WEBSITE HAS BEEN SEIZED</h1>' +
      '<div class="nb-rule" aria-hidden="true"></div>' +
      '<p class="nb-lead">This domain has been seized by the Federal Bureau of Investigation pursuant to a ' +
        'seizure warrant issued by the United States District Court as part of a coordinated law enforcement operation.</p>' +
      '<p class="nb-legal">Access to this resource is restricted to authorized personnel. This system and all ' +
        'activity on it are monitored, logged, and may be used as evidence. Unauthorized access, use, or any attempt ' +
        'to circumvent these controls is prohibited under 18 U.S.C. &#167; 1030 and related statutes and may result ' +
        'in criminal prosecution.</p>' +
      '<div class="nb-auth">' +
        '<div class="nb-auth-h">AUTHORIZED ACCESS ONLY</div>' +
        '<label class="nb-auth-l" for="nbIn">Enter access authorization code</label>' +
        '<div class="nb-row">' +
          '<input id="nbIn" class="nb-input" type="password" autocomplete="off" autocapitalize="off" ' +
            'autocorrect="off" spellcheck="false" placeholder="Authorization code" aria-label="Access authorization code">' +
          '<button id="nbBtn" class="nb-btn" type="button">AUTHENTICATE</button>' +
        '</div>' +
        '<div id="nbMsg" class="nb-err" role="alert"></div>' +
      '</div>' +
      '<div class="nb-foot">FEDERAL BUREAU OF INVESTIGATION &#183; CYBER DIVISION &mdash; UNAUTHORIZED USE PROHIBITED</div>' +
    '</div>';

  var DECOY_HTML =
    '<div class="nb-bar" aria-hidden="true"></div>' +
    '<div class="nb-wrap">' +
      '<div class="nb-eyebrow">PRIVACY CHECKPOINT &#183; ACCESS NOT RECOGNIZED</div>' +
      '<h1 class="nb-title">NICE TRY &#128373;</h1>' +
      '<div class="nb-rule" aria-hidden="true"></div>' +
      '<img class="nb-decoy-img" src="image2.jpg" width="540" height="536" ' +
        'alt="The hacker who cannot see the password vs. the one who set it to eight asterisks">' +
      '<p class="nb-lead nb-joke">That&#39;s not the code &mdash; but relax. We take your privacy so seriously ' +
        'we won&#39;t even tell you what you got wrong.</p>' +
      '<p class="nb-legal nb-joke">This access attempt was securely logged straight to <code>/dev/null</code>, ' +
        'fully anonymized, encrypted with military-grade ROT13, and immediately forgotten. ' +
        'That&#39;s the x8bitranjit&#39;s privacy guarantee&#8482;.</p>' +
      '<p class="nb-legal nb-joke">The password is sixtynine asterisks. Good luck guessing which six.</p>' +
      '<button id="nbAgain" class="nb-again" type="button">&#8592; Fine, let me try again</button>' +
    '</div>';

  function showAuth(g) {
    g.innerHTML = AUTH_HTML;
    var input = document.getElementById('nbIn');
    var btn   = document.getElementById('nbBtn');
    var msg   = document.getElementById('nbMsg');

    var busy = false;
    function go() {
      if (busy) return;
      var v = (input.value || '').trim();
      if (!v) return;
      busy = true; btn.textContent = 'AUTHENTICATING…';
      decryptApp(v).then(function (src) {
        // success — cache for this tab, grant access
        try { sessionStorage.setItem(CACHE, src); } catch (e) {}
        msg.classList.add('ok', 'show');
        msg.textContent = 'AUTHORIZATION ACCEPTED — ACCESS GRANTED';
        setTimeout(function () {
          var ov = document.getElementById('nbOv');
          if (ov) { ov.classList.add('nb-off'); setTimeout(function () { ov.remove(); }, 600); }
          injectApp(src);
        }, 600);
      }).catch(function () {
        busy = false; btn.textContent = 'AUTHENTICATE';
        showDecoy(g);                                   // wrong code (GCM tag failed) or fetch error
      });
    }

    btn.addEventListener('click', go);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); go(); }
    });
    try { input.focus({ preventScroll: true }); } catch (e) { input.focus(); }
  }

  function showDecoy(g) {
    g.innerHTML = DECOY_HTML;
    try { g.scrollTop = 0; } catch (e) {}
    var again = document.getElementById('nbAgain');
    if (again) {
      again.addEventListener('click', function () { showAuth(g); });
      try { again.focus({ preventScroll: true }); } catch (e) {}
    }
  }

  function build() {
    if (document.getElementById('nbOv')) return;
    var g = document.createElement('div');
    g.id = 'nbOv';
    g.className = 'nb-ov';
    document.body.appendChild(g);
    showAuth(g);
  }

  // Decide in <head> so we can hide the skeleton before first paint, but only touch <body> once it exists.
  var cached = null;
  try { cached = sessionStorage.getItem(CACHE); } catch (e) {}
  if (!cached) { document.documentElement.classList.add('nb-lock'); }

  function start() { if (cached) { injectApp(cached); } else { build(); } }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
