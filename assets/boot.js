/* Pre-render init — runs before first paint. */
(function () {
  'use strict';

  var K = 'x8_v';
  var H = '7b6bda4bd020350b0cfbc0cebddaf255e4e39a4c9a219dc0a4ad6576513cacea';

  try { if (sessionStorage.getItem(K) === '1') return; } catch (e) {}

  document.documentElement.classList.add('nb-lock');

  function d(s) {
    var data = new TextEncoder().encode(s);
    return crypto.subtle.digest('SHA-256', data).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) {
        return ('0' + b.toString(16)).slice(-2);
      }).join('');
    });
  }

  function pass() {
    try { sessionStorage.setItem(K, '1'); } catch (e) {}
    document.documentElement.classList.remove('nb-lock');
    var g = document.getElementById('nbOv');
    if (g) { g.classList.add('nb-off'); setTimeout(function () { g.remove(); }, 600); }
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
        'That&#39;s the x8bit privacy guarantee&#8482;.</p>' +
      '<p class="nb-legal nb-joke">Pro tip: the password is eight asterisks. Good luck guessing which eight.</p>' +
      '<button id="nbAgain" class="nb-again" type="button">&#8592; Fine, let me try again</button>' +
    '</div>';

  function showAuth(g) {
    g.innerHTML = AUTH_HTML;
    var input = document.getElementById('nbIn');
    var btn   = document.getElementById('nbBtn');
    var msg   = document.getElementById('nbMsg');

    function ok() {
      msg.classList.add('ok', 'show');
      msg.textContent = 'AUTHORIZATION ACCEPTED — ACCESS GRANTED';
      setTimeout(pass, 650);
    }

    var busy = false;
    function go() {
      if (busy) return;
      var v = (input.value || '').trim();
      if (!v) return;
      busy = true;
      d(v).then(function (x) {
        busy = false;
        if (x === H) ok(); else showDecoy(g);   // only the exact code unlocks; anything else -> decoy
      }).catch(function () { busy = false; showDecoy(g); });
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

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', build);
  } else {
    build();
  }
})();
