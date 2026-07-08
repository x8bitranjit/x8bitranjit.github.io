#!/usr/bin/env python3
"""
manifest_scan.py - extract dependency names from a package manifest (authorized recon; read-only).

Parses package.json / package-lock.json / requirements.txt / Pipfile / composer.json / Gemfile / pom.xml / *.csproj and
lists the dependency names (scoped vs unscoped) so you can claimability-check them (claimable_check.py). Pure local parse -
no network. (DEPENDENCY_CONFUSION_TESTING_GUIDE.md §2.)

Usage:
  python3 manifest_scan.py -f package.json
  python3 manifest_scan.py -f requirements.txt
  cat composer.json | python3 manifest_scan.py --type composer
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, json, os, re

SCOPED = re.compile(r"^@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")


def from_pkgjson(text):
    d = json.loads(text)
    names = set()
    for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundledDependencies"):
        v = d.get(k)
        if isinstance(v, dict):
            names.update(v.keys())
        elif isinstance(v, list):
            names.update(v)
    # package-lock v2/v3 "packages": {"node_modules/x": {...}}
    for path in (d.get("packages") or {}):
        if path.startswith("node_modules/"):
            names.add(path.split("node_modules/")[-1])
    return names


def from_composer(text):
    d = json.loads(text)
    names = set()
    for k in ("require", "require-dev"):
        v = d.get(k)
        if isinstance(v, dict):
            names.update(n for n in v if n.lower() not in ("php",) and not n.startswith("ext-"))
    return names


def from_requirements(text):
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:[<>=!~;\[].*)?$", line)
        if m:
            names.add(m.group(1))
    return names


def from_pipfile(text):
    names, section = set(), None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s.strip("[]"); continue
        if section in ("packages", "dev-packages") and "=" in s:
            names.add(s.split("=", 1)[0].strip().strip('"'))
    return names


def from_gemfile(text):
    return set(re.findall(r"""gem\s+['"]([A-Za-z0-9._-]+)['"]""", text))


def from_pom(text):
    return set(re.findall(r"<artifactId>\s*([A-Za-z0-9._-]+)\s*</artifactId>", text))


def from_csproj(text):
    return set(re.findall(r'PackageReference\s+Include="([^"]+)"', text))


PARSERS = {
    "pkgjson": from_pkgjson, "composer": from_composer, "requirements": from_requirements,
    "pipfile": from_pipfile, "gemfile": from_gemfile, "pom": from_pom, "csproj": from_csproj,
}


def detect(fname, text):
    base = os.path.basename(fname).lower() if fname else ""
    if base in ("package.json", "package-lock.json") or base.endswith(".lock") and "node_modules" in text:
        return "pkgjson"
    if base == "composer.json":
        return "composer"
    if base.startswith("requirements") and base.endswith(".txt"):
        return "requirements"
    if base == "pipfile":
        return "pipfile"
    if base.startswith("gemfile"):
        return "gemfile"
    if base.endswith(".csproj"):
        return "csproj"
    if base == "pom.xml":
        return "pom"
    # content sniff
    t = text.lstrip()
    if t.startswith("{"):
        return "composer" if '"require"' in text else "pkgjson"
    if "<artifactId>" in text:
        return "pom"
    if "PackageReference" in text:
        return "csproj"
    if re.search(r"gem\s+['\"]", text):
        return "gemfile"
    if "[packages]" in text:
        return "pipfile"
    return "requirements"


def main():
    ap = argparse.ArgumentParser(description="Extract dependency names from a manifest (authorized recon).")
    ap.add_argument("-f", "--file", help="manifest file (default: stdin)")
    ap.add_argument("--type", choices=list(PARSERS), help="force the manifest type")
    a = ap.parse_args()
    text = open(a.file, encoding="utf-8", errors="replace").read() if a.file else sys.stdin.read()
    if not text.strip():
        sys.exit("[!] empty input")
    kind = a.type or detect(a.file or "", text)
    try:
        names = PARSERS[kind](text)
    except Exception as e:
        sys.exit(f"[!] parse failed as '{kind}': {e}")

    names = sorted(n for n in names if n)
    scoped = [n for n in names if SCOPED.match(n)]
    unscoped = [n for n in names if not SCOPED.match(n)]

    print(f"== manifest scan ==  (type: {kind})")
    print(f"[i] {len(names)} dependency name(s): {len(scoped)} scoped, {len(unscoped)} unscoped")
    if scoped:
        print("\n[scoped] (an UNRESERVED scope makes ALL of these confusable - check the scope):")
        for n in scoped:
            print(f"  {n}")
    if unscoped:
        print("\n[unscoped]:")
        for n in unscoped:
            print(f"  {n}")
    print("\n[next] claimable_check.py on these names (public-registry 404 = claimable candidate). Exclude well-known public pkgs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
