# Host setup — KVM/libvirt + Windows VMs

## Why KVM, not VMware

This host runs Linux Mint on kernel 7.0 with **Secure Boot enabled**. VMware
Workstation's `vmmon`/`vmnet` modules are out-of-tree and must be re-signed by
hand on every kernel update under Secure Boot — a recurring failure point for
no added capability. **KVM/libvirt is in-kernel, signed, and already active**
(`/dev/kvm` present), and is the hypervisor real Linux infra teams use. We use it.

## 1. Host prerequisites

```bash
bash scripts/host-setup.sh
# log out/in afterward so libvirt/kvm group membership applies
```

This installs `qemu-kvm`, `libvirt`, `virt-manager`, `virtinst`, plus `hashcat`
and `seclists`, and creates an isolated host-only network `adlab` (10.0.0.0/24).
Keeping the lab off your main LAN is the whole point — attack traffic stays
contained.

## 2. Get the Windows eval ISOs (free, time-limited)

- **Windows Server 2022** evaluation (180 days): Microsoft Evaluation Center.
- **Windows 10/11 Enterprise** evaluation (90 days): same source, for WS01.

Drop them in `~/isos/`.

## 3. Create the Domain Controller VM

```bash
virt-install \
  --name DC01 --memory 4096 --vcpus 2 \
  --disk size=40,format=qcow2 \
  --cdrom ~/isos/windows_server_2022_eval.iso \
  --network network=adlab \
  --os-variant win2k22 \
  --graphics spice
```

Finish the Windows install in `virt-manager`, set a static IP `10.0.0.10`, then
from an elevated PowerShell run the provisioning script twice (it reboots in
between — first run installs/promotes the DC, second run builds the domain):

```powershell
.\setup-domain.ps1    # run 1: promote to DC, reboots
.\setup-domain.ps1    # run 2 (after reboot): create vulnerable CORP.LOCAL
```

## 4. Create the workstation VM (optional but realistic)

```bash
virt-install \
  --name WS01 --memory 4096 --vcpus 2 \
  --disk size=40,format=qcow2 \
  --cdrom ~/isos/windows_10_eval.iso \
  --network network=adlab \
  --os-variant win10 --graphics spice
```

Set DNS to `10.0.0.10` and join it to `corp.local`. Run `SharpHound.exe` here
for realistic collection, or use the Python collector from the host (see the
walkthrough).

## 5. Verify

```bash
virsh list --all            # DC01, WS01 present
nxc smb 10.0.0.10           # DC answers SMB
```

Then follow [attacks/walkthrough.md](../attacks/walkthrough.md).

## Snapshots

Take a libvirt snapshot of DC01 right after `setup-domain.ps1` so you can reset
to a clean-but-vulnerable state after each attack run:

```bash
virsh snapshot-create-as DC01 clean-vuln "fresh CORP.LOCAL"
virsh snapshot-revert DC01 clean-vuln
```
