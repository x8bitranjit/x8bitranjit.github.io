# `ldapsearch` cheat-sheet — confirm what an injected filter returns (authorized)

Once you have **any** bind (anonymous, or creds you legitimately hold / obtained in-scope), query the directory
directly to confirm what a given filter would return — and to enumerate high-value targets. This is the same logic
your injected filter executes; it makes a clean, quotable PoC. See `../LDAP_INJECTION_TESTING_GUIDE.md` §1/§15.

> Authorized testing only. **Bounded** reads, benign, your own/in-scope identities. Don't mass-dump the directory.

## Install
```bash
# Kali/WSL
sudo apt install ldap-utils          # provides ldapsearch
```

## Bind modes
```bash
# anonymous (many directories allow read of some attributes anonymously):
ldapsearch -x -H ldap://dc.target.local -b "dc=corp,dc=local" "(objectClass=*)"

# simple bind with credentials:
ldapsearch -x -H ldap://dc.target.local \
  -D "uid=svc,ou=people,dc=corp,dc=local" -w 'PASSWORD' \
  -b "dc=corp,dc=local" "(uid=*)" mail memberOf

# LDAPS (TLS) — appliances often require it:
ldapsearch -x -H ldaps://dc.target.local:636 -b "dc=corp,dc=local" "(cn=*)"

# Active Directory simple bind (UPN works as the bind DN):
ldapsearch -x -H ldap://dc.corp.local -D "user@corp.local" -w 'PASSWORD' \
  -b "DC=corp,DC=local" "(sAMAccountName=*)" sAMAccountName mail memberOf
```

## Find the base DN / what you're allowed to read (RootDSE)
```bash
ldapsearch -x -H ldap://dc.target.local -s base -b "" "(objectClass=*)" \
  namingContexts defaultNamingContext supportedLDAPVersion
# namingContexts / defaultNamingContext = the base DN(s) to use with -b
```

## The queries that map to injection impact
```bash
# directory disclosure (what  q=*)(objectClass=*)  would dump):
ldapsearch ... -b "dc=corp,dc=local" "(objectClass=person)" cn mail telephoneNumber

# auth-relevant: does a user exist? (username enumeration / what  )(uid=NAME)  tests)
ldapsearch ... "(uid=admin)" dn

# authorization: who is in a privileged group? (what  )(memberOf=...)  tests)
ldapsearch ... "(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)" sAMAccountName
```

## Active Directory — high-value enumeration (red-team, §15)
```bash
# Kerberoast targets (service accounts with SPNs):
ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# AS-REP roastable (DONT_REQ_PREAUTH bit, userAccountControl & 0x400000):
ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName

# privileged / protected accounts:
ldapsearch ... "(adminCount=1)" sAMAccountName memberOf

# disabled accounts (UAC & 0x2), never-expire (UAC & 0x10000), etc. — bitwise matching rule 1.2.840.113556.1.4.803
```

## Higher-level AD tooling (once you can query)
```
windapsearch    --dc-ip <ip> -u <user> -p <pass> --users --groups --da    # quick AD enum
ldapdomaindump  ldap://<dc-ip> -u 'CORP\user' -p 'pass' -o out/           # HTML/JSON dump of users/groups/computers
bloodhound-python -d corp.local -u user -p pass -c All -ns <dc-ip>        # the privilege graph (feeds BloodHound)
```
> Bug bounty: an **enumerated privileged username / SPN** is enough proof. Run offline cracking (AS-REP/Kerberoast)
> only inside an authorized **red-team** scope. Pace queries — bind storms trip lockout/SIEM (§22).
