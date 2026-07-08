# Dependency Confusion — Testing Checklist

**Author:** x8bitranjit
**Authorized + responsible-disclosure ONLY.** Detect widely (read-only); publish only a name in your **authorized scope**, prove
with a **benign beacon**, **unpublish immediately**, report. The finding is a **callback from the target's build** — not a leaked
name, and never a payload/secret dump.

## Phase 0 — Recon: harvest internal names (§1–§3)
- [ ] Collected manifests exposed on the web / public repos / wayback (package.json, requirements.txt, composer.json, pom.xml, *.csproj…)
- [ ] Extracted names from JS bundles / source maps (`@scope/…`, `require(...)`) (→ `../JSFiles/`)
- [ ] Found committed registry configs (`.npmrc`/`pip.conf`/`nuget.config`) proving **private packages exist**
- [ ] Classified names: scoped-unreserved / org-specific unscoped / internal — excluded well-known public packages

## Phase 1 — Claimability (§4–§5)  ← the core detection
- [ ] For each candidate: **public-registry lookup → 404 = UNCLAIMED** (npm/PyPI/RubyGems/NuGet)  (`claimable_check.py`)
- [ ] npm **scope** reservation checked (`@acme` unreserved → all its scoped names confusable)
- [ ] Confirmed the target's resolver can **reach the public registry** (config evidence)

## Phase 2 — Resolution (§6)
- [ ] Identified why the public copy would win: highest-version-wins / public-primary / pip `--extra-index-url` / virtual-repo policy
- [ ] Noted lockfile/`npm ci`/`--require-hashes` status (pinned deps resist; unpinned/transitive still exposed)

## Phase 3 — Safe proof (authorized name only) (§7–§8)
- [ ] Generated a **benign** beacon package (`benign_callback_pkg.py`) — DNS/HTTP callback + token + hostname, **nothing else**
- [ ] Version pinned **high** (`99.99.99`) so resolution prefers it
- [ ] (authorized) Published for a name in **my scope only**
- [ ] **Callback received from the TARGET's build/CI/dev egress** carrying my token  ← the proof ⭐
- [ ] **UNPUBLISHED / yanked immediately**; recorded the publish→unpublish window
- [ ] Correlated the callback source to the target (CI/corp ASN), not my own machine / a scanner

## Phase 4 — Related supply-chain (§9–§11)
- [ ] Typosquat neighbours of real deps (hygiene, benign proof)
- [ ] **Repo-jacking**: `go.mod` / import URL references a **deleted/renamed** GitHub user → registerable
- [ ] Install-hook path understood (where the code exec fires); transitive internal deps considered

## Phase 5 — Impact (§12)
- [ ] Established the callback = **RCE in CI/CD** (or dev machine)
- [ ] **Described** (not exfiltrated) the reachable secrets / downstream propagation

## Phase 6 — Validate → report (§13–§17)
- [ ] Proof = **claimable (public 404) + benign callback from the target's build**, token-correlated
- [ ] Ruled out the FP list (§13): name already public, no callback, own-machine callback, lockfile-pinned, secret-dump over-reach
- [ ] Set **CVSS (9–10 CI RCE) + CWE-829** (+ 427/494) (§14)
- [ ] **Responsible disclosure:** benign beacon only, **unpublished**, reported fast, recommended reserving the name/scope (§16)
- [ ] De-duped to one **resolution root cause** (e.g. unreserved scope); listed the confusable names (§17)

## AUTO-REJECT (don't submit if…)
- [ ] An internal name is **referenced** but is **already public** / **unclaimable**
- [ ] You **published** but got **no callback** (no proof of a pull)
- [ ] The callback came from **your** machine / a **scanner**, not the target's build egress
- [ ] Everything is **lockfile-pinned with hashes** and CI uses `npm ci` (no unpinned/transitive path)
- [ ] It's a **full-path Go/Cargo** module (namespaced) — that's **repo-jacking**, file it as such
- [ ] You dumped **CI secrets/source** to "prove" it (over-reach — a benign beacon is the accepted proof)

## RESPONSIBLE-DISCLOSURE GATE (must all be true before publishing)
- [ ] The name belongs to a target I am **authorized** to test (not an unrelated org)
- [ ] The package is **benign** (beacon + token + hostname; no exfil/shell/persistence/destructive hook)
- [ ] I will **unpublish immediately** after the callback and **report at once**
- [ ] I will recommend the org **reserve** the name/scope and fix resolution config
