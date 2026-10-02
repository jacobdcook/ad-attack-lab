# HANDOFF — ad-attack-lab

## State (2026-10-01)
Scaffolding + all docs/scripts written. VMs NOT yet built (need Windows eval ISOs + interactive install).
- README.md: full attack chain + topology.
- scripts/host-setup.sh: libvirt/KVM install + isolated adlab network (needs sudo).
- provision/setup-domain.ps1: builds vulnerable CORP.LOCAL (users match hash-lab, SPNs, AS-REP, GenericAll ACL).
- bloodhound/docker-compose.yml: BloodHound-CE stack (docker present; `up -d` to launch).
- attacks/walkthrough.md: AS-REP -> Kerberoast -> BloodHound -> ACL abuse -> DCSync.
- docs/defense.md: detection per attack step (the SOC deliverable).

## Next (interactive, needs you)
1. apt install libvirt/virt-manager (host-setup.sh) + log out/in.
2. docker compose -f bloodhound/docker-compose.yml up -d  (works now, pulls images).
3. Download Win Server 2022 + Win10 eval ISOs -> ~/isos/.
4. virt-install DC01 (see docs/01-host-setup.md), run setup-domain.ps1 twice.
5. Run walkthrough.md, feed dumped hashes into ../gpu-hash-cracking.

## Design decision
KVM/libvirt chosen over VMware: Secure Boot on kernel 7.0 makes VMware modules a signing hassle; KVM is in-kernel and already active.
