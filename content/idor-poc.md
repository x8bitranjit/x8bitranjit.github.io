# IDOR / BOLA — PoC Scripts

Runnable, **benign-by-default** proof-of-concept scripts that back the IDOR kit — one per proof pattern. **Click a script
to open it on its own page.** *Authorized testing only:* use your own test accounts, prove the pattern with a handful of
your own/second-account objects, throttle to avoid noise, and never mass-exfiltrate real PII.

| Script | What it does |
|---|---|
| [`idor_replay_diff.py`](#/idor/poc/idor_replay_diff) | The **two-account oracle**: replays account A's request with account B's reference and diffs against B's own view — confirms "A sees B's object" with low false-positives. The validity proof for any IDOR finding. |
| [`id_enumerator.py`](#/idor/poc/id_enumerator) | A **polite, rate-limited** sequential/encoded id prober that stops after a small proof set and reports the 403-vs-404 oracle — proves the pattern without mass-scraping. |
| [`graphql_node_sweep.py`](#/idor/poc/graphql_node_sweep) | Decodes, iterates, and re-encodes GraphQL **global node ids** to demonstrate `node(id:)` / `*ById` BOLA over a small, bounded range. |

## How they fit together

1. **Two-account oracle first** — `idor_replay_diff.py` is the core proof: A's token + B's id → B's data. That's the finding.
2. **If the id is enumerable**, prove the *pattern* with a tiny throttled range using `id_enumerator.py`. Cite the population size from server metadata (`X-Total-Count`, max-id) rather than dumping real data.
3. **GraphQL BOLA** — if the target is a GraphQL API, `graphql_node_sweep.py` tests the `node(id:)` interface over a small range of your own ids + one second-account id.

> Each script defaults to safe, bounded behaviour. Read the **Testing Guide** for the full attack order and the
> **Zero to Expert (Q&A)** for the *why* behind each technique.
