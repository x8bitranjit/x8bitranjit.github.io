# LDAP Injection — PoC Scripts

Runnable, **benign-by-default** tooling that backs the LDAP kit. The finding is **altered filter logic with impact**
(auth bypass / directory disclosure / blind extraction) — *not* a reflected `*` or a lone 500. **Click a script to
open it on its own page.** *Authorized testing only:* use your own test accounts, read a **bounded** sample, never
mass-dump the directory, and clean up.

| Script | What it does |
|---|---|
| [`ldap_fuzz.py`](#/ldap/poc/ldap_fuzz) | Probe a `FUZZ` point with special chars + AND/OR breakouts + auth-bypass payloads. Detects **error-based** (LDAP error strings), **result-count deltas** (`*` widens the filter), and the **AND/OR context**. |
| [`ldap_blind.py`](#/ldap/poc/ldap_blind) | **Blind boolean extractor** — read an attribute character-by-character through a true/false response oracle (status / length / marker). Bounded by `--maxlen`; paced by `--delay`. |
| [`ldapsearch_cheat.md`](#/ldap/poc/ldapsearch_cheat) | Direct-query cheat-sheet (`ldapsearch`, RootDSE base-DN discovery, AD high-value filters: Kerberoast / AS-REP / `adminCount`) for confirming what an injected filter returns once you hold any bind. |

## Typical flow
1. **Fuzz** the search/login injection point → AND/OR context + error-based signal + result-count delta (`ldap_fuzz.py`).
2. **Auth-bypass payload fired?** Log in with *your* test account and note **which** account you land on — the first OU entry is often admin (Critical). **Wildcard widened results?** Quantify it and match hidden attributes: `q=*)(memberOf=*)`.
3. **Blind?** Build the oracle and extract a **few benign** characters of *your* test user's attribute (`ldap_blind.py`) — enough to prove arbitrary read, never the whole tree.
4. **Confirm directly** once you hold any bind — `ldapsearch` runs the same logic for a clean, quotable PoC (`ldapsearch_cheat.md`).

> Prove **altered logic** (more/other rows · a flipped auth/authz decision · a stable true/false oracle), not a
> reflected character. `${jndi:ldap://…}` is **Log4Shell/JNDI** — a different, RCE bug — *not* LDAP filter injection;
> report it separately. Read the **Testing Guide** for the full attack order and the **Zero to Expert (Q&A)** for the *why*.
