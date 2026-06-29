# GraphQL — PoC Scripts

Runnable, **benign-by-default** proof-of-concept helpers that back the GraphQL kit — one per core attack class. **Click a script
to open it on its own page.** *Authorized testing only:* use your own test accounts, your own OOB/interactsh host,
and measure without flooding.

| Script | What it does |
|---|---|
| [`introspect.py`](#/graphql/poc/introspect) | Dumps the schema (or notes it's disabled) and prints the **sink list**: queries, mutations, `*ById`/`node` fields, input objects, and arguments that take urls/file references — the recon foundation for all other tests. |
| [`node_enumerator.py`](#/graphql/poc/node_enumerator) | Encodes, iterates, and decodes **GraphQL global node ids** (and `*ById` fields) to demonstrate BOLA over a small bounded range — proves A's token returns your second account's objects. |
| [`batch_ratelimit_test.py`](#/graphql/poc/batch_ratelimit_test) | Sends an alias-batched query (N operations in **one** request) and reports how many were processed vs a per-request limit — proves a rate-limit / OTP bypass via batching. |

## How they fit together

1. **Recon first** — `introspect.py` maps every query, mutation, and sensitive argument so you know what to attack.
2. **BOLA via node ids** — `node_enumerator.py` proves the `node(id:)` / `*ById` interface doesn't enforce authorization; one second-account object is the finding.
3. **Batching bypass** — `batch_ratelimit_test.py` sends N aliases in one request and measures how many get processed; if N > the documented per-request limit, the rate gate is bypassable (→ OTP brute, scraping at scale).

> Read the **Testing Guide §5 (introspection), §7 (BOLA), §9 (batching)** for the full test order, and the
> **Zero to Expert (Q&A) Beginner Primer (P1–P8)** if you are new to GraphQL.
