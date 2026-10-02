# Defense — detections for every step of the chain

This is the deliverable for a detection / SOC role. For each attack in
[attacks/walkthrough.md](../attacks/walkthrough.md): the log source, the
signal, the false positives, and an interview-ready sentence.

## 1. AS-REP roasting

- **Log**: Windows Security **4768** (Kerberos AS-REQ) on the DC.
- **Signal**: AS-REQ for an account with pre-auth not required, encryption type
  RC4 (`0x17`). A burst of 4768s for many accounts = roasting.
- **Prevent**: do not disable Kerberos pre-auth; it is almost never needed.
- **False positives**: some legacy apps legitimately disable pre-auth — baseline
  which accounts do, alert on new ones and on bulk requests.
- **Say**: "AS-REP roasting shows up as 4768 for pre-auth-disabled accounts. I'd
  alert on any account that newly gets that flag, since it's rarely legitimate."

## 2. Kerberoasting

- **Log**: Windows Security **4769** (TGS-REP) on the DC.
- **Signal**: one account requesting TGS for many SPNs in a short window,
  especially RC4 (`0x17`) when the domain otherwise uses AES.
- **Prevent**: gMSA for service accounts (uncrackable), AES-only, long passwords.
- **False positives**: vuln scanners and some apps request many SPNs — allowlist
  known scanners; the RC4-downgrade is the higher-fidelity signal.
- **Say**: "Kerberoasting is 4769 at volume with RC4 encryption. The highest-
  fidelity version is an RC4 request in an AES domain — that's a downgrade."

## 3. BloodHound / SharpHound collection

- **Log**: heavy LDAP queries (Event 1644 if LDAP diagnostics on), SMB sessions
  to many hosts, net session enumeration.
- **Signal**: one host enumerating every user, group, session, and ACL in minutes.
- **Prevent**: can't block enumeration entirely; limit who can read sensitive ACLs.
- **Say**: "SharpHound is a burst of LDAP and SMB enumeration from one host. It's
  noisy if you're watching for one box reading the whole directory fast."

## 4. ACL abuse (GenericAll -> group change)

- **Log**: Windows Security **4728/4732** (member added to a security/privileged
  group), **5136** (directory object modified).
- **Signal**: a non-admin principal adding a member to Domain Admins; any change
  to Domain Admins membership at all.
- **Prevent**: audit and remove dangerous ACLs (BloodHound finds them); protected
  groups / AdminSDHolder.
- **Say**: "Adding a member to Domain Admins is 4728. That group should change
  almost never, so any membership change is a page-worthy alert."

## 5. secretsdump / DCSync

- **Log**: Windows Security **4662** (operation on an object).
- **Signal**: a **non-DC** account requesting directory replication — the
  DS-Replication-Get-Changes / -All control access right GUIDs
  (`1131f6aa-...` / `1131f6ad-...`).
- **Prevent**: restrict replication rights to actual DCs; tier-0 isolation.
- **False positives**: Azure AD Connect and real DCs replicate — allowlist those
  specific accounts/hosts, alert on everything else.
- **Say**: "DCSync is a 4662 with the replication GUIDs from something that isn't
  a domain controller. Legit replication is a short allowlist, so the alert is
  clean."

## 6. LSASS dump (local credential theft)

- **Log**: **Sysmon Event ID 10** (ProcessAccess) targeting `lsass.exe`.
- **Signal**: a non-system process opening LSASS with `GrantedAccess` 0x1010 or
  0x1410 (read memory). Also Sysmon 1 for `comsvcs.dll MiniDump`, `procdump`.
- **Prevent**: Credential Guard, LSASS as a protected process (RunAsPPL).
- **Say**: "Mimikatz-style LSASS access is Sysmon 10 with a telltale
  GrantedAccess mask. Credential Guard plus that detection covers most of it."

## Why this maps to the cracking repo

Steps 1, 2, 5, and 6 all *produce* the hashes that get cracked in
[gpu-hash-cracking](../../gpu-hash-cracking). You cannot detect the offline
crack — so the whole defensive game is catching these theft events before the
attacker ever reaches their 4090.
