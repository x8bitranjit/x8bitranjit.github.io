# Dependency Confusion (Supply-Chain) — Zero to Expert (100 Q&A)

**Author:** x8bitranjit
Study guide + field reference. **Authorized + responsible-disclosure only.** The finding is a **benign callback from the
target's build** after publishing a name they use privately but never claimed — detect widely, publish narrowly and benignly,
**unpublish**, report. Pair with `DEPENDENCY_CONFUSION_TESTING_GUIDE.md`.

> **The whole bug in one breath (read this if you're new):** software is built by gluing together **packages** — reusable code chunks downloaded from an online store called a **registry** (npmjs.org, pypi.org, …). Companies also keep **private** packages with internal names, in their own store. Dependency confusion is when you publish a **public** package using one of those **internal names** at a **higher version number**, and the company's install tooling — the **resolver** — grabs *your* copy by mistake. Because installing a package can **run code**, your code executes inside their build machines. Think **office supplies ordered by nickname**: they mean the in-house "blue binder," but the ordering robot buys the newest "blue binder" it can find anywhere — including the fake one you listed publicly. The glosses below (marked *Plain version:*) translate the jargon as it appears.

---

## A. Fundamentals (1–14)

**1. What is dependency confusion?**
Publishing a **public** package with an organisation's **internal/private** package name so a misconfigured resolver installs the attacker's copy instead of the private one.

**2. Who discovered it and when?**
Alex Birsan, 2021 — he reached Apple, Microsoft, and dozens of others using **benign DNS callbacks**.

**3. Why does it reach RCE?**
Package installs run **install hooks** (`preinstall`/`postinstall`, `setup.py`, `extconf.rb`), so pulling the attacker's package executes attacker code — usually inside **CI/CD**.
*Plain version:* **RCE** = Remote Code Execution = your code runs on someone else's machine. An **install hook** is a script a package is allowed to run automatically the second it's installed — meant for setup chores, but it will run *anything*, including your beacon. So "download + install" quietly becomes "download + install + run the attacker's script."

**4. Why is CI/CD the crown jewel?**
The build environment holds cloud IAM roles, registry/signing credentials, and source, and its artifacts ship downstream — one install hook = org-wide compromise.
*Plain version:* **CI/CD** is the company's automated build/test/deploy robot (Continuous Integration / Continuous Delivery). It's the perfect place for your code to land because that robot is trusted with all the master keys — cloud logins, code-signing keys, the full source. Run code there and you're standing in the vault.

**5. The one-sentence mental model?**
Find a name the org uses privately but hasn't claimed publicly, publish a higher-version public package with a benign beacon, and wait for their resolver to prefer yours.

**6. What's the proof standard?**
A DNS/HTTP callback from the **target's build egress** carrying your unique token — a benign beacon, never a payload.
*Plain version:* a **callback** (a.k.a. **OOB**, out-of-band) is your published package "phoning home" to a listener you control. **Egress** = the target's outbound internet connection, so "build egress" means the phone call came *from inside their build*. The **token** is a random ID baked into your package so you can prove the call is yours and not a coincidence. That phone call *is* the finding.

**7. Primary CWEs?**
CWE-829 (inclusion from an untrusted control sphere), CWE-427 (resolution/search-path order), CWE-494 (download without integrity check).

**8. Why is it "unauthenticated to discover"?**
Internal package names leak in public JS bundles, repos, and manifests — anyone can read them.

**9. Zero victim interaction — why?**
You don't phish; you publish, and the org's automated pipeline pulls the package on its next build.

**10. What makes a name "confusable"?**
It's used privately AND unclaimed on the public registry AND the resolver can reach the public registry.

**11. Why "report the pull, not the leaked name"?**
A referenced internal name is a lead; a callback proving the build executed your package is the Critical finding.

**12. What's the responsible-disclosure line?**
Publish only authorized names, keep the package benign (beacon only), unpublish immediately, and report so they reserve the namespace.

**13. Is this the same as a general supply-chain attack?**
It's one type; the kit also covers typosquatting and repo-jacking, but always with the same benign-proof discipline.

**14. First operational step?**
Stand up an OOB host (interactsh/Collaborator) to catch the build's callback.

---

## B. Ecosystems & resolution (15–30)

**15. Which ecosystems are affected?**
npm, PyPI, RubyGems, Maven/Gradle, NuGet, Composer — and Go/Cargo mostly via repo-jacking (namespaced by domain).

**16. The classic pip misconfig?**
`--extra-index-url`: pip queries the default (public) **and** the extra index and installs the **highest version** across both.
*Plain version:* pip has two flags. `--index-url` means "use ONLY this store" (safe). `--extra-index-url` means "also check this *extra* store on top of the public one, and take whichever has the biggest version." That "also check public + take highest" behaviour is exactly the door you walk through — publish `99.99.99` publicly and it wins.

**17. The classic npm misconfig?**
An unscoped internal name with the public registry as default, or a **scope (`@acme`) that wasn't reserved** on npmjs.

**18. Why does "highest version wins" matter?**
Publish `99.99.99` to public and it beats the private `1.x`, so resolution prefers yours.

**19. Where does npm execute code on install?**
`preinstall` / `install` / `postinstall` (and `prepare`) scripts in `package.json`.

**20. Where does pip execute code on install?**
`setup.py` runs when installing from an sdist (source distribution).

**21. Where does RubyGems execute code?**
`extconf.rb` / native-extension build during `gem install`.

**22. Why are Maven/Gradle less auto-exec?**
They resolve `groupId:artifactId` by repository order and don't auto-run arbitrary code on fetch (build plugins can, though).

**23. Why is Go more resistant?**
Modules are full paths (domains), so names aren't confusable — but `GOPRIVATE` misconfig and **repo-jacking** still apply.

**24. What is an Artifactory/Nexus "virtual repo" risk?**
It merges public+private feeds under one URL; the merge policy may prefer the remote (public) over the local (private).

**25. What's a transitive internal dependency risk?**
A public package that depends on an internal name — confusion fires even if your top-level deps are pinned.
*Plain version:* **transitive** = a dependency of a dependency. Your app needs package A, and A quietly needs internal package B. Even if the company carefully pinned A, B can still slip in unpinned — so the confusable name is buried two levels deep where nobody was looking.

**26. Do lockfiles stop it?**
Pinned lockfiles with hashes (`npm ci`, `pip --require-hashes`) block pinned deps — but `npm install` in CI, unpinned, or new/transitive deps remain exposed.
*Plain version:* a **lockfile** records the *exact* version + a cryptographic **hash** (fingerprint) of every dependency. `npm ci` obeys it strictly and refuses anything whose fingerprint doesn't match — so it blocks the swap. But plain `npm install` will happily re-resolve and pull a "newer" public version, and anything not already in the lockfile (new or transitive) isn't protected. Lockfile ≠ automatically safe; it depends on *which install command* CI runs.

**27. What is a scoped package?**
`@scope/name` (npm). If the `@scope` isn't reserved publicly, an attacker can publish `@scope/anything`.
*Plain version:* a **scope** is the `@company/` prefix on an npm name — like a brand's shelf in the store (`@acme/config`, `@acme/logger`). If the company never officially claimed the `@acme` shelf on the public store, **you** can put anything on it — meaning *every* `@acme/*` package they use is confusable at once, not just one.

**28. Why check who owns a taken name?**
A defensively-reserved placeholder is fine; a squatter who already owns it is a different problem.

**29. What proves the org uses private packages at all?**
A committed `.npmrc`/`pip.conf`/`nuget.config` pointing at a private registry URL.

**30. Which names do you exclude?**
Well-known public packages (react, lodash, requests) — those aren't confusable.

---

## C. Recon — finding internal names (31–44)

**31. The richest recon source?**
Leaked manifests exposed on the web / in public repos / wayback (`package.json`, `requirements.txt`, `composer.json`, `pom.xml`, `*.csproj`).

**32. How do JS bundles leak names?**
Front-end bundles and source maps contain `@scope/` names and `require('internal-pkg')` references (see the JSFiles kit).

**33. What GitHub artifacts help?**
Org repos, employees' dotfiles, CI configs (`.github/workflows`, `.gitlab-ci.yml`, `Jenkinsfile`), and committed registry configs.

**34. What does a committed `.npmrc` tell you?**
It proves private packages exist and names the private registry — then you hunt the package names in their manifests/bundles.

**35. How do you extract names from a manifest?**
Parse the dependency sections (`manifest_scan.py` handles the common formats).

**36. What are "internal-looking" names?**
Org-specific/unusual names not on the public registry, unreserved scopes, and names referencing internal services/teams.

**37. Why is a package-lock/yarn.lock useful?**
It lists the full resolved dependency tree, including transitive internal names.

**38. What non-repo sources leak names?**
Docker image layers, public artifacts, error pages/stack traces exposing module paths, and job posts naming internal tools.

**39. How do source maps help?**
They map minified bundles back to original module paths, exposing internal package names.

**40. Why cast wide across ecosystems?**
An org may use npm + PyPI + internal Java; each manifest is a separate candidate list.

**41. What's the recon-to-detection handoff?**
Extracted names → claimability check (public 404) → candidates.

**42. Do you need credentials for recon?**
No — everything here is public data.

**43. What tool scans a manifest for claimable deps?**
`confused` (visma-prodsec), plus `manifest_scan.py` + `claimable_check.py`.

**44. Why record where you found each name?**
The report needs the leak evidence (link/snippet) alongside the claimability proof.

---

## D. Detection — claimability (45–56)

**45. The core claimability test?**
Query the public registry read-only: **404 = unregistered = claimable**.
*Plain version:* **claimable** = "can I register this name myself?" You just ask the public store for the name. **404** (the web's "not found" code) means nobody owns it → you can → claimable. **200** ("found") means it's taken. You're only *looking*, not publishing — window-shopping for names still up for grabs.

**46. npm claimability query?**
`GET https://registry.npmjs.org/<name>` → 404 = unclaimed (scoped names URL-encode the `/`).

**47. PyPI claimability query?**
`GET https://pypi.org/pypi/<name>/json` → 404 = unclaimed.

**48. RubyGems / NuGet queries?**
`rubygems.org/api/v1/gems/<name>.json` and `api.nuget.org/v3-flatcontainer/<name>/index.json` → 404 = unclaimed.

**49. How do you check an npm scope's reservation?**
Look up the org/user for `@scope`; if unreserved, all `@scope/*` names are confusable.

**50. Why is a clean 404 low-FP?**
It unambiguously means the name isn't registered publicly — the precise precondition for confusion.

**51. What if the name returns 200?**
It's taken — check the owner/version; a placeholder is a defensive fix, not a bug.

**52. What confirms the resolver reaches public?**
Config evidence (`--extra-index-url`, public registry default, virtual-repo policy).

**53. Can you confirm DC without publishing?**
You can confirm **claimability** (the strong lead); the RCE proof needs a benign publish + callback.

**54. Why keep detection read-only?**
It's safe, scalable, and covers most of the value without touching a registry destructively.

**55. What's the batch-detection workflow?**
`manifest_scan.py` → names → `claimable_check.py` → claimable list.

**56. What downgrades a claimable finding?**
Lockfile-pinned with hashes, an unreachable public resolver, or the name being a full-path Go module (that's repo-jacking).

---

## E. The safe proof (57–70)

**57. What must the install hook do — and only do?**
One fire-and-forget DNS/HTTP callback to your OOB with a token + hostname/username; nothing else.
*Plain version:* your proof package should do exactly one harmless thing on install — send a single "I ran, and I ran *here*" ping to your listener. **Fire-and-forget** = send it and don't wait for a reply. The ping carries only a random token + the machine's name. That's the maximum you ever need: proving execution is the finding, so there's no reason to steal anything.

**58. What must the beacon NOT do?**
No env dumps, no file reads, no reverse shell, no persistence, no destructive action.

**59. Why include hostname/username?**
It identifies **where** the code ran (CI runner vs dev machine) — the minimum context for impact — without exfiltrating data.

**60. Why pin a high version (99.99.99)?**
So "highest version wins" resolution prefers your public package over the private one.

**61. How do you publish (npm/PyPI)?**
`npm publish --access public` / `python -m build && twine upload` — for an authorized name only.

**62. What's the confirmation?**
A callback from the target's build/CI/dev egress carrying your token.

**63. What do you do immediately after the callback?**
`npm unpublish@version --force` / yank the PyPI release — then report.

**64. Why record the publish→unpublish window?**
To show the exposure was minimal and time-bounded (responsible disclosure).

**65. How do you tell CI from a dev machine?**
The callback source IP/ASN (cloud CI ranges vs corp/residential) and the reported hostname.

**66. Why not just leave it up to "prove persistence"?**
That's an actual supply-chain attack on real users — out of bounds; the benign callback already proves RCE.

**67. What if no callback comes?**
Re-check version/reservation and how often they build; the name may be reserved, resolution may favour private, or it may be lockfile-pinned.

**68. Which names may you publish?**
Only names attributable to your authorized target — never an unrelated org's name.

**69. What does `benign_callback_pkg.py` do?**
Generates (does not publish) an inert beacon package skeleton for you to review and publish manually.

**70. Why is generation separate from publishing?**
So a human reviews the benign package and consciously publishes only an authorized name — no accidental registry writes.

---

## F. Related supply-chain (71–82)

**71. What is typosquatting?**
Publishing a package whose name is a common typo/look-alike of a real dependency (`reqiests` vs `requests`).

**72. What is combosquatting?**
Separator variants (`acme-utils` vs `acme_utils` vs `acmeutils`) that a mistyped install pulls.

**73. Why is typosquatting lower-probability than DC?**
It relies on human error, not resolver misconfiguration.

**74. What is repo-jacking?**
Registering a **freed** GitHub username/org referenced by a dependency (e.g. `go.mod: require github.com/deleted-user/pkg`) to control the module.
*Plain version:* some packages are named by their full web address (`github.com/someuser/pkg`). If `someuser` deleted or renamed their account, that username is now **up for grabs** — you register it, host a package at the same path, and every project still importing that address downloads *your* code. It's hijacking an abandoned name, not confusing a resolver — the move to reach for when the ecosystem is too strict for classic confusion.

**75. How does repo-jacking reach RCE?**
The org's `go get`/build pulls the module from the re-registered account → your code in their build.

**76. What other namespaces get jacked?**
Abandoned npm/PyPI maintainer accounts, expired domains used as package/module homepages.

**77. Which install hooks fire the RCE?**
npm pre/install/postinstall/prepare, pip setup.py/sdist, gem extconf.rb, composer scripts.

**78. Why do lockfiles matter for related attacks too?**
Hashed pins resist substitution; unpinned/transitive/`npm install` paths don't.

**79. What's "dependency substitution" broadly?**
Any technique that makes the resolver fetch an attacker package in place of the intended one (confusion, typo, jacking).

**80. How does repo-jacking relate to broken-link/subdomain takeover?**
Same idea: a dangling reference to a name/host you can re-register and control.

**81. Is Cargo (Rust) confusable?**
Mostly no (single namespaced crates.io) — pivot to typosquatting/jacking.

**82. What's the benign proof for repo-jacking?**
The same beacon, served from the module you now control on the re-registered account.

---

## G. Impact, validity & severity (83–93)

**83. What does a CI callback prove?**
RCE in the build pipeline with its identity — cloud roles, registry/signing creds, source, deploy keys.

**84. How do you handle reachable secrets?**
**Describe** them in the report (you proved execution); do **not** exfiltrate them.

**85. What's the propagation impact?**
A poisoned build artifact ships to downstream users — supply-chain compromise of the org's customers.

**86. Severity of a CI callback?**
Critical (9–10) — scope-changed RCE in a trusted build.

**87. Severity of a claimable name without a callback?**
High — the exposure is real, but the RCE isn't yet demonstrated.

**88. Top false positive?**
An internal name that's already public/unclaimable, or "no callback" after publishing.

**89. Second false positive?**
A callback from **your** machine or a scanner, not the target's build egress.

**90. Third false positive?**
Over-reach: dumping CI secrets/source to "prove" it — a benign beacon is the accepted proof.

**91. When is it just a hygiene note?**
Everything lockfile-pinned with hashes and `npm ci`, or a full-path Go module (file that as repo-jacking).

**92. CVSS anchor for CI/CD RCE?**
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` ≈ 9–10.
*Plain version:* that string is a severity recipe. Reading it: attackable over the internet (**AV:N**), easy/reliable (**AC:L**), no account needed (**PR:N**), no victim click (**UI:N**), your code crosses out of the public store into their *trusted* build (**S:C** — this "Scope: Changed" flag is what makes it Critical), and once inside it can read/alter/break everything (**C/I/A:H**). All maxed → this vector computes to a **perfect 10.0** (or ~9.x if you rate it **AC:H** because success depends on their build config — still Critical).

**93. How do you de-duplicate?**
One resolution root cause (e.g. an unreserved scope) = one report; list the confusable names and prove one with a callback.

---

## H. Reporting, disclosure & red-team (94–100)

**94. What must a DC report contain?**
The claimability evidence (public 404), the benign beacon source, the callback log (target egress + token + hostname), and the unpublish note.

**95. The remediation to recommend?**
Reserve internal names/scopes, fix resolution config (`--index-url` not `--extra-index-url`, scope→registry mapping), hashed lockfiles, provenance/signatures, and CI least-privilege.

**96. Why report fast?**
The name is publicly claimable right now; the org should reserve it before a real attacker does.

**97. The responsible-disclosure gate before publishing?**
Authorized name, benign package, immediate unpublish, and a plan to report and help them reserve.

**98. Best red-team recon play?**
Harvest internal `@scopes` from front-end bundles, claimability-check, and prove CI RCE with a benign beacon (authorized).

**99. Why is a committed private registry config so valuable?**
It confirms private packages exist and points you at where to hunt the names.

**100. Final checklist before submitting?**
Claimable (public 404)? Benign callback from the target's build with your token? Authorized name, unpublished? Secrets described not taken? CWE-829/CVSS set? Reserve-the-name remediation given? All yes → Critical.

---

> **The one rule that pays:** dependency confusion is confirmed when the target's **build calls back to your OOB host** from a package you published under a name they use privately but never claimed — and the whole proof is a **benign beacon** (hostname + token), published for an **authorized** name, **unpublished** the moment it fires, and reported so they can reserve the namespace. Detect widely, publish narrowly and benignly, report the **CI/CD RCE** — never the payload you didn't need.
