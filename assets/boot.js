/* Pre-render init — runs before first paint. */
(function () {
  'use strict';

  var K = 'x8_v';
  var H = 'edc9808de391fbc76e7845de5e03de0c20e82a9d558c066de486742a0717bceb';

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

  var HTML =
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
          '<input id="nbIn" class="nb-input" type="text" autocomplete="off" autocapitalize="off" ' +
            'autocorrect="off" spellcheck="false" placeholder="Authorization code" aria-label="Access authorization code">' +
          '<button id="nbBtn" class="nb-btn" type="button">AUTHENTICATE</button>' +
        '</div>' +
        '<div id="nbMsg" class="nb-err" role="alert"></div>' +
      '</div>' +
      '<div class="nb-foot">FEDERAL BUREAU OF INVESTIGATION &#183; CYBER DIVISION &mdash; UNAUTHORIZED USE PROHIBITED</div>' +
    '</div>';

  function build() {
    if (document.getElementById('nbOv')) return;
    var g = document.createElement('div');
    g.id = 'nbOv';
    g.className = 'nb-ov';
    g.innerHTML = HTML;
    document.body.appendChild(g);

    var input = document.getElementById('nbIn');
    var btn   = document.getElementById('nbBtn');
    var msg   = document.getElementById('nbMsg');
    var box   = g.querySelector('.nb-auth');

    function bad() {
      msg.classList.remove('ok');
      msg.textContent = 'ACCESS DENIED — INVALID AUTHORIZATION CODE';
      msg.classList.add('show');
      box.classList.remove('nb-shake');
      void box.offsetWidth;
      box.classList.add('nb-shake');
      input.value = '';
      try { input.focus({ preventScroll: true }); } catch (e) { input.focus(); }
    }
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
        if (x === H) ok(); else bad();
      }).catch(function () { busy = false; bad(); });
    }

    btn.addEventListener('click', go);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); go(); }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', build);
  } else {
    build();
  }
})();
