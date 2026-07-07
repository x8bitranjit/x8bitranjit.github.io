#!/usr/bin/env python3
"""
desync_timing.py — SAFE, timing-based HTTP request-smuggling detector (REQUEST_SMUGGLING_TESTING_GUIDE.md §4).

It uses the canonical timing technique (PortSwigger): craft a request where, IF the back-end honors the
"wrong" length header, it WAITS for bytes that never arrive -> a measurable delay; otherwise it returns fast.
This does NOT leave a dangling prefix on the connection (no socket poisoning), so it won't corrupt other
users' requests. It is a DETECTION aid only — confirm deterministically and exploit safely before reporting.

Requires raw socket control; uses a fresh TCP/TLS connection per probe (no keep-alive reuse across users).

Usage:
  python3 desync_timing.py -u https://target/
  python3 desync_timing.py -u https://target/ --path /api --trials 5
"""
import argparse, socket, ssl, statistics, sys, time, urllib.parse as up

def send_raw(host, port, use_tls, raw, read_timeout):
    s = socket.create_connection((host, port), timeout=read_timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        t = time.time()
        s.sendall(raw)
        s.settimeout(read_timeout)
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
        except socket.timeout:
            pass
        return time.time() - t
    finally:
        try:
            s.close()
        except Exception:
            pass

def baseline_req(host, path):
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()

def clte_probe(host, path):
    # back-end honoring TE will wait for more chunk data -> delay
    body = "1\r\nA\r\nX"
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Transfer-Encoding: chunked\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n{body}").encode()

def tecl_probe(host, path):
    body = "0\r\n\r\nX"
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Transfer-Encoding: chunked\r\nContent-Length: 6\r\n"
            f"Connection: close\r\n\r\n{body}").encode()

def median_time(host, port, tls, raw, trials, read_timeout):
    times = []
    for _ in range(trials):
        try:
            times.append(send_raw(host, port, tls, raw, read_timeout))
        except Exception:
            pass
        time.sleep(0.3)
    return statistics.median(times) if times else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--path")
    ap.add_argument("--trials", type=int, default=4)
    ap.add_argument("--read-timeout", type=float, default=12)
    a = ap.parse_args()

    u = up.urlparse(a.url)
    host = u.hostname
    tls = (u.scheme == "https")
    port = u.port or (443 if tls else 80)
    path = a.path or (u.path or "/")

    print(f"[*] timing desync detection on {host}:{port}{path}  (SAFE: fresh connection per probe, no poisoning)\n")
    base = median_time(host, port, tls, baseline_req(host, path), a.trials, a.read_timeout)
    if base is None:
        sys.exit("[!] could not reach host")
    print(f"    baseline       ~{base:.2f}s")

    clte = median_time(host, port, tls, clte_probe(host, path), a.trials, a.read_timeout)
    tecl = median_time(host, port, tls, tecl_probe(host, path), a.trials, a.read_timeout)
    print(f"    CL.TE probe    ~{clte:.2f}s" if clte is not None else "    CL.TE probe    (no data)")
    print(f"    TE.CL probe    ~{tecl:.2f}s" if tecl is not None else "    TE.CL probe    (no data)")

    flagged = []
    if clte is not None and clte > base + 5:
        flagged.append(("CL.TE", clte))
    if tecl is not None and tecl > base + 5:
        flagged.append(("TE.CL", tecl))

    print()
    if flagged:
        for name, t in flagged:
            print(f"[SIGNAL] {name}: ~{t:.1f}s vs baseline ~{base:.1f}s -> possible desync.")
        print("\n[next] CONFIRM deterministically (a smuggled prefix changes YOUR follow-up) with build_smuggle.py +")
        print("       Burp/Turbo Intruder (§8), THEN build a concrete, do-no-harm exploit (§9-§13). Don't report a blip.")
    else:
        print("[*] No timing signal. Try TE.TE obfuscations (§6) and, if HTTP/2 at the edge, H2 downgrade vectors (§7).")
        print("    (Timing can miss some desyncs; Burp 'HTTP Request Smuggler' covers more classes — use carefully.)")

if __name__ == "__main__":
    main()
