# Dependency Confusion — Testing Checklist

**Author:** x8bitranjit
**Authorized + responsible-disclosure ONLY.** Detect widely (read-only); publish only a name in your **authorized scope**, prove
with a **benign beacon**, **unpublish immediately**, report. The finding is a **callback from the target's build** — not a leaked
name, and never a payload/secret dump.

## Phase 0 — Recon: harvest internal names (§1–§3)
*Why this matters:* you can't claim a name you've never seen, so everything starts by **learning the company's private package nicknames**. They leak in dependency-listing files (manifests), in the JavaScript your browser downloads, and in committed config. A committed `.npmrc`/`pip.conf` is a jackpot — it *proves* private packages exist, which turns every internal-looking name you find into a real candidate.
- [ ] Collected manifests exposed on the web / public repos / wayback (package.json, requirements.txt, composer.json, pom.xml, *.csproj…)
- [ ] Extracted names from JS bundles / source maps (`@scope/…`, `require(...)`) (→ `../JSFiles/`)
- [ ] Found committed registry configs (`.npmrc`/`pip.conf`/`nuget.config`) proving **private packages exist**
- [ ] Classified names: scoped-unreserved / org-specific unscoped / internal — excluded well-known public packages

## Phase 1 — Claimability (§4–§5)  ← the core detection
*Why this matters:* this is the make-or-break filter — "can I actually register this name?" A simple read-only lookup answers it: **404 = nobody owns it = you can claim it.** Most of the whole bug's value is confirmed right here, without publishing anything. The npm-**scope** check is the force-multiplier: an unreserved `@acme` shelf means *all* their `@acme/*` packages are confusable at once.
- [ ] For each candidate: **public-registry lookup → 404 = UNCLAIMED** (npm/PyPI/RubyGems/NuGet)  (`claimable_check.py`)
- [ ] npm **scope** reservation checked (`@acme` unreserved → all its scoped names confusable)
- [ ] Confirmed the target's resolver can **reach the public registry** (config evidence)

## Phase 2 — Resolution (§6)
*Why this matters:* claimable ≠ exploitable. The target's tooling still has to *choose* your public copy, and this phase is where you confirm it would — usually because it takes the **highest version number** across stores (so your `99.99.99` wins). The lockfile note is the reality check: if CI runs `npm ci` against hashed pins, the swap is blocked for pinned deps, so you look for the unpinned/transitive gap instead.
- [ ] Identified why the public copy would win: highest-version-wins / public-primary / pip `--extra-index-url` / virtual-repo policy
- [ ] Noted lockfile/`npm ci`/`--require-hashes` status (pinned deps resist; unpinned/transitive still exposed)

## Phase 3 — Safe proof (authorized name only) (§7–§8)
*Why this matters:* this is the only phase that writes to a real public store, so it's the one with rules. You publish a **harmless** package (a beacon that just phones home with a token + hostname), pinned high so resolution grabs it, then you **catch the callback and pull the package right back down**. The starred callback line is the entire finding; the unpublish + source-correlation lines are what keep it responsible and rejection-proof.
- [ ] Generated a **benign** beacon package (`benign_callback_pkg.py`) — DNS/HTTP callback + token + hostname, **nothing else**
- [ ] Version pinned **high** (`99.99.99`) so resolution prefers it
- [ ] (authorized) Published for a name in **my scope only**
- [ ] **Callback received from the TARGET's build/CI/dev egress** carrying my token  ← the proof ⭐
- [ ] **UNPUBLISHED / yanked immediately**; recorded the publish→unpublish window
- [ ] Correlated the callback source to the target (CI/corp ASN), not my own machine / a scanner

## Phase 4 — Related supply-chain (§9–§11)
*Why this matters:* when classic confusion doesn't apply — name already taken, or a namespace-strict ecosystem like Go — these cousins still reach the same RCE. **Repo-jacking** (claiming a deleted GitHub username a dependency still imports) is the high-value one here and easy to miss. Same benign-proof discipline throughout.
- [ ] Typosquat neighbours of real deps (hygiene, benign proof)
- [ ] **Repo-jacking**: `go.mod` / import URL references a **deleted/renamed** GitHub user → registerable
- [ ] Install-hook path understood (where the code exec fires); transitive internal deps considered

## Phase 5 — Impact (§12)
*Why this matters:* the callback proves *code ran*; this phase is where you turn that into *why it's Critical* — it ran inside the build pipeline that holds cloud keys, signing keys, and source, and whose output ships to customers. The crucial line is "**described**, not exfiltrated": you name what's reachable to establish impact, but you never actually take it.
- [ ] Established the callback = **RCE in CI/CD** (or dev machine)
- [ ] **Described** (not exfiltrated) the reachable secrets / downstream propagation

## Phase 6 — Validate → report (§13–§17)
*Why this matters:* the final quality gate before you hit submit. It forces you to prove the finding is real (claimable + a token-correlated callback), rule out the tempting-but-invalid look-alikes, score it correctly (CWE-829, ~9–10 for CI RCE), and package it responsibly. De-duping to one **root cause** keeps a hundred confusable names from becoming a hundred noisy reports.
- [ ] Proof = **claimable (public 404) + benign callback from the target's build**, token-correlated
- [ ] Ruled out the FP list (§13): name already public, no callback, own-machine callback, lockfile-pinned, secret-dump over-reach
- [ ] Set **CVSS (9–10 CI RCE) + CWE-829** (+ 427/494) (§14)
- [ ] **Responsible disclosure:** benign beacon only, **unpublished**, reported fast, recommended reserving the name/scope (§16)
- [ ] De-duped to one **resolution root cause** (e.g. unreserved scope); listed the confusable names (§17)

## AUTO-REJECT (don't submit if…)
*Why this matters:* every line here is a near-miss that *feels* like a win but will get your report closed — a name you can't claim, a publish with no callback, or a callback that came from your own machine. The recurring trap: mistaking a **lead** (found a name, could claim it) for the **finding** (their build actually ran your package). If any box is ticked, it's not a report yet.
- [ ] An internal name is **referenced** but is **already public** / **unclaimable**
- [ ] You **published** but got **no callback** (no proof of a pull)
- [ ] The callback came from **your** machine / a **scanner**, not the target's build egress
- [ ] Everything is **lockfile-pinned with hashes** and CI uses `npm ci` (no unpinned/transitive path)
- [ ] It's a **full-path Go/Cargo** module (namespaced) — that's **repo-jacking**, file it as such
- [ ] You dumped **CI secrets/source** to "prove" it (over-reach — a benign beacon is the accepted proof)

## RESPONSIBLE-DISCLOSURE GATE (must all be true before publishing)
*Why this matters:* this phase actually publishes to a public store the whole world can install from, so a mistake harms real people — a wrong name hits an unrelated org, a non-benign hook is a genuine attack, and leaving it up hands the door to the next attacker. All four boxes must be true *before* you type `npm publish`; treat them as a hard gate, not a suggestion.
- [ ] The name belongs to a target I am **authorized** to test (not an unrelated org)
- [ ] The package is **benign** (beacon + token + hostname; no exfil/shell/persistence/destructive hook)
- [ ] I will **unpublish immediately** after the callback and **report at once**
- [ ] I will recommend the org **reserve** the name/scope and fix resolution config
