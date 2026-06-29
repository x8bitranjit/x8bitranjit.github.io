#!/usr/bin/env python3
"""
sourcemap_unpack.py — reconstruct the original source tree from a JS source map (.map) using
"sourcesContent". Works on a URL or a local file. (JS_FILES_TESTING_GUIDE.md §9.)

Usage:
  python3 sourcemap_unpack.py -u https://target.com/static/js/main.abc123.js.map -o out/src
  python3 sourcemap_unpack.py -f main.js.map -o out/src
"""
import argparse, json, os, sys, urllib.request

def load(url=None, file=None):
    if file:
        return open(file, encoding="utf-8", errors="ignore").read()
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read().decode("utf-8", "ignore")

def safe_path(base, name):
    # strip webpack:// and protocol prefixes, neutralise traversal
    name = name.replace("webpack://", "").replace("webpack:///", "")
    name = name.split("://", 1)[-1]
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return os.path.join(base, *parts) if parts else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url")
    ap.add_argument("-f", "--file")
    ap.add_argument("-o", "--out", default="out/src")
    a = ap.parse_args()
    if not (a.url or a.file):
        ap.error("need -u or -f")

    try:
        raw = load(a.url, a.file)
    except Exception as e:
        sys.exit(f"[!] could not fetch map: {e}")
    try:
        sm = json.loads(raw)
    except Exception as e:
        sys.exit(f"[!] not valid source-map JSON: {e}")

    sources = sm.get("sources", [])
    contents = sm.get("sourcesContent")
    if not contents:
        sys.exit("[!] map has no 'sourcesContent' — original source not embedded. "
                 "Try DevTools, or check for a separate sources host.")

    n = 0
    for name, content in zip(sources, contents):
        if content is None:
            continue
        dest = safe_path(a.out, name)
        if not dest:
            continue
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(content)
        n += 1
        print(f"  + {dest}")

    print(f"\n[done] reconstructed {n} source files into {a.out}")
    print("[next] grep recovered source for secrets/endpoints/comments:")
    print(f"   grep -RiE '(password|secret|token|api[_-]?key|internal|admin|TODO|FIXME)' {a.out}")

if __name__ == "__main__":
    main()
