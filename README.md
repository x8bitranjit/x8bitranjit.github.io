# x8bitranjit.github.io — security testing guides (site)

Static site that renders the markdown guides as web pages. **Sample: JWT kit is live.**

## Structure
```
site/
  index.html          # app shell (sidebar + content pane)
  .nojekyll           # tell GitHub Pages to serve files as-is
  assets/
    style.css         # theme
    app.js            # sidebar config + hash router + markdown renderer (edit DOCS/NAV to add kits)
  content/
    home.md           # landing page (your info — edit this)
    jwt-guide.md  jwt-arsenal.md  jwt-checklist.md  jwt-report.md  jwt-qa.md
```

## Preview locally
The pages load markdown with `fetch()`, which needs HTTP (not `file://`). Run a tiny server:
```powershell
cd site
python -m http.server 8080
# open http://localhost:8080
```

## Deploy to GitHub Pages (x8bitranjit.github.io)
The repo `x8bitranjit/x8bitranjit.github.io` serves from its **root**, so the contents of `site/` go at the repo root.
Once authenticated (`gh auth login` or a git credential), from the repo root:
```powershell
git add . && git commit -m "Add security guides site (JWT sample)" && git push
```
Then it's live at https://x8bitranjit.github.io

## Add another kit later
1. Copy its markdown into `content/` (e.g. `xss-guide.md`).
2. Add entries to `DOCS` and `NAV` in `assets/app.js`.
That's the whole change — no build step.

## Security of this site
It's a **static** site (no server, DB, login, or user input), so classic web vulns (SQLi/RCE/SSRF/auth/IDOR)
don't apply. The narrow risks specific to a *security-guides* site are handled:

- **Payloads can't execute on the site.** The guides contain live `<script>`/`<svg onload>` payloads. Markdown is
  rendered then run through **DOMPurify** before insertion, so a payload in the text can't run in a visitor's browser.
- **No third-party at runtime.** `marked`, `highlight.js`, `DOMPurify` are **vendored locally** in `assets/vendor/`
  (no CDN) — removes supply-chain/CDN-tampering risk and works offline.
- **Strict Content-Security-Policy** (meta tag in `index.html`): `default-src 'none'`, `script-src 'self'`,
  `style-src 'self'`, `connect-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'` (anti-clickjacking),
  `base-uri 'none'`. So even if a payload ever slipped past DOMPurify, the browser would still block it. No inline
  scripts/styles are used.
- **`referrer: no-referrer`** so outbound link clicks don't leak the page URL.

### Your part (account-level — this is the only realistic attack path)
A static site is only as safe as the account that publishes it:
- **Enable 2FA on GitHub** (a hardware key or TOTP). Repo takeover = your account, not the site.
- In the repo: **Settings → Pages → Enforce HTTPS** (on).
- **Never commit real secrets** — the PoC scripts and guides use placeholders only (`YOUR_IP`, `*.oast.fun`, `<REDACTED>`).
  Keep it that way; consider enabling GitHub **secret scanning / push protection**.
- Don't enable auto-merge of public PRs (you control what gets published).
- `frame-ancestors` is set via meta but is only enforced as an HTTP header; GitHub Pages can't add headers, so it's
  best-effort. Not a real risk for static content.

Net: there is no server to attack, payloads are neutralised two ways (DOMPurify + CSP), and dependencies are local.
The thing to protect is your **GitHub login** → turn on 2FA.
