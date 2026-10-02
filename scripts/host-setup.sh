#!/usr/bin/env bash
# Linux host prerequisites for the AD attack lab (KVM/libvirt).
# Debian/Ubuntu/Mint. Run once.
set -euo pipefail
echo "[*] Installing libvirt/KVM + attack tooling..."
sudo apt update
sudo apt install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients virtinst virt-manager \
    bridge-utils hashcat seclists
sudo usermod -aG libvirt,kvm "$USER"
sudo systemctl enable --now libvirtd

echo "[*] Creating isolated lab network (host-only, 10.0.0.0/24)..."
cat > /tmp/lab-net.xml <<XML
<network>
  <name>adlab</name>
  <bridge name="virbr-adlab"/>
  <ip address="10.0.0.1" netmask="255.255.255.0">
    <dhcp><range start="10.0.0.50" end="10.0.0.99"/></dhcp>
  </ip>
</network>
XML
sudo virsh net-define /tmp/lab-net.xml 2>/dev/null || true
sudo virsh net-start adlab 2>/dev/null || true
sudo virsh net-autostart adlab 2>/dev/null || true

echo "[*] pipx tools (impacket, netexec)..."
pipx install impacket 2>/dev/null || pipx upgrade impacket || true
pipx install git+https://github.com/Pennyw0rth/NetExec 2>/dev/null || true

echo "[+] Done. Log out/in for group membership. Next: docs/01-host-setup.md for the Windows VMs."
