# Path / Directory Traversal — PoC Scripts

Runnable helpers that back the Path Traversal kit. **Click a script to open it on its own page.** *Authorized testing
only.* The finding is **escaping the base dir + impact**: a secret / source / cross-user **read**, or a benign
**out-of-dir write** (→ webshell / overwrite → RCE). `/etc/passwd` alone is Medium. Use **benign markers** and **never
overwrite real files**. If the sink **includes / executes** the file, that's the **LFI** kit (wrapper / log-poison RCE).

| Script | What it does |
|---|---|
| [`pt_read_fuzz.py`](#/pathtraversal/poc/pt_read_fuzz) | **Control-baselined READ fuzzer**: sprays the traversal + encoding + server-normalization matrix at a `FUZZ` param **or** path, matches a content marker unique to the target file, and baselines the normal response for low false-positives. Path-context injections are sent over a **raw socket** (`--path-as-is` behavior) so literal `../` / `..;/` transmit un-collapsed. |
| [`zipslip_build.py`](#/pathtraversal/poc/zipslip_build) | **Benign Zip-Slip builder**: makes a zip / tar whose entry name traverses out of the extraction directory, with harmless marker content. Refuses executable payloads by design — you prove the *escape*, then describe the webshell escalation. |
| [`write_probe.py`](#/pathtraversal/poc/write_probe) | **Benign write prober**: submits a marker to an upload / save endpoint with a traversing filename / dest, then tells you exactly what to verify (did the marker land outside the intended dir?). Never drops a shell. |

## How they fit together

1. **Read** — `pt_read_fuzz.py` confirms a read/serve traversal and reaches a secret; climb from `/etc/passwd` to `.env` / config / keys / cloud-creds / source, or to other users' files.
2. **Write (Zip-Slip)** — `zipslip_build.py` makes a benign archive that escapes a naive extractor; upload it to an import / restore / theme-install feature and check whether the marker landed outside the extraction dir.
3. **Write (upload/save)** — `write_probe.py` tests an upload filename / dest-path for out-of-dir write; a marker in the webroot (or over a key/cron path) proves the primitive → webshell / overwrite → RCE.

> Read the **Testing Guide** for the direction taxonomy (read vs write vs include), the server-normalization bypasses
> (nginx `alias` off-by-slash, Tomcat `..;/`, IIS `::$DATA`) and the Python/.NET/Java `os.path.join` / `Path.Combine`
> absolute-path foot-gun, and the **Checklist** for the per-sink order. Send `../` raw (`curl --path-as-is` / Burp) —
> a normal HTTP client collapses it client-side.
