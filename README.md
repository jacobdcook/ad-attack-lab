# AD Attack Lab (KVM / libvirt)

A deliberately vulnerable Active Directory domain (`CORP.LOCAL`) you attack end
to end: map it with BloodHound, extract credentials, and crack them in the
companion [`gpu-hash-cracking`](../gpu-hash-cracking) repo — then write the
detection for every step.

Built on **KVM/libvirt**, the native Linux hypervisor (not VMware — on a
Secure Boot host, libvirt avoids the kernel-module signing dance for zero
loss of capability).

## The attack chain this lab teaches

```
  recon            credential access        escalation          goal
  -----            -----------------        ----------          ----
  SharpHound  -->  AS-REP roast        -->  crack (4090)   -->  domain
  BloodHound       Kerberoast               BloodHound path     admin
  netexec          secretsdump/DCSync       ACL abuse
```

Each arrow has a **detection** in [docs/defense.md](docs/defense.md), which is
the real deliverable for a SOC / detection-engineering role.

## Topology (minimal, fits 62 GB RAM)

| VM | Role | RAM | Notes |
|---|---|---|---|
| DC01 | Domain Controller, `CORP.LOCAL` | 4 GB | Windows Server 2022 eval (free 180 days) |
| WS01 | Domain-joined workstation | 4 GB | Windows 10/11 eval; where you run SharpHound |
| (host) | Attacker | — | Linux + impacket + netexec + BloodHound-CE in Docker |

You can run the whole credential-access half from the Linux host against DC01
alone; WS01 is for realistic SharpHound collection and lateral movement.

## Quick start

```bash
# 1. host prerequisites (libvirt, virt-manager, tools)
bash scripts/host-setup.sh          # see docs/01-host-setup.md

# 2. bring up BloodHound Community Edition (Docker)
docker compose -f bloodhound/docker-compose.yml up -d
docker compose -f bloodhound/docker-compose.yml logs bloodhound | grep -i "Initial"

# 3. build the Windows VMs (see docs/01-host-setup.md for ISO + virt-install)
#    then on DC01, from an elevated PowerShell:
#      .\setup-domain.ps1            # promotes DC, creates vulnerable CORP.LOCAL
```

## What makes it vulnerable (on purpose)

`provision/setup-domain.ps1` builds the same user set as the hash-cracking lab
and plants the classic misconfigurations:

- **Kerberoastable** service accounts (`svc_sql`, `svc_backup`) with SPNs and
  weak passwords.
- **AS-REP roastable** user (`jsmith`) with Kerberos pre-auth disabled.
- **Dangerous ACL**: a low-priv user granted `GenericAll` over a privileged
  group — the kind of edge BloodHound lights up.
- Passwords that span the strength spectrum so cracking is realistic.

## Tools used

- `impacket` (GetUserSPNs, GetNPUsers, secretsdump) — installed via pipx
- `netexec` (nxc) — SMB/LDAP enumeration and spraying
- `bloodhound-ce` + SharpHound collector — attack-path graphing
- `hashcat` on the RTX 4090 — the cracking half (other repo)

## Ethics

A self-contained lab on hardware the author owns, isolated on a host-only
libvirt network. Every technique here is run only against `CORP.LOCAL`. Do not
point these tools at anything you are not authorized to test.
