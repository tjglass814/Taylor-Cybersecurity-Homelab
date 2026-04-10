Proxmox VE Installation — Dell OptiPlex 7060 Micro
Overview
Deployed Proxmox Virtual Environment 8.x directly onto a Dell OptiPlex 7060 Micro as the foundation of a dedicated cybersecurity homelab. This bare-metal hypervisor installation replaced the stock Windows 11 Pro environment, converting the machine into a Type 1 hypervisor capable of running multiple isolated virtual machines simultaneously for security research, attack simulation, and detection engineering.

Environment
ComponentDetailsHardwareDell OptiPlex 7060 MicroCPUIntel Core i5-8500T 6-CoreRAM32GB DDR4Storage512GB NVMe SSDHypervisorProxmox VE 8.xNetworkStatic IP — 192.168.1.50Management AccessBrowser-based Web UI via https://192.168.1.50:8006

<img width="754" height="595" alt="OptiPlex Hardware Specs" src="https://github.com/user-attachments/assets/215f0520-e022-47bf-9098-602f84cb7b66" />
<img width="3326" height="1276" alt="Optiplexe System Summary" src="https://github.com/user-attachments/assets/99e72bb1-7f85-48ce-995b-96e68758a243" />


Why Proxmox
Proxmox VE was selected over Type 2 hypervisors like VirtualBox for several reasons relevant to building a professional lab environment:

Bare metal performance — direct hardware access with minimal overhead means VMs receive maximum available resources
Browser-based management — the entire lab is managed remotely from any device on the network, mirroring enterprise virtualization workflows
Enterprise relevance — Proxmox VE operates on the same architectural principles as VMware ESXi and Microsoft Hyper-V, both widely deployed in enterprise SOC environments
Snapshot and cloning capabilities — professional-grade VM lifecycle management essential for maintaining clean lab states between exercises


Installation Process
Step 1 — Pre-Installation Preparation
Downloaded the Proxmox VE 8.x ISO directly from proxmox.com and flashed it to a 16GB USB drive using Balena Etcher. The bootable USB was created on the Dell itself running Windows 11 Pro, eliminating the need for a separate machine.

<img width="1686" height="1253" alt="Proxmox Download" src="https://github.com/user-attachments/assets/574d667f-6408-45fb-a6bf-b4d45cdc7217" />


Step 2 — BIOS Configuration
Accessed the Dell BIOS via F2 on boot and made two critical configuration changes required for successful Proxmox installation:

Disabled Secure Boot — Proxmox's bootloader is not signed for Secure Boot and will not load without this disabled
Verified SATA mode set to AHCI — required for the NVMe drive to be recognized correctly by the Proxmox installer

Step 3 — Booting the Installer
Accessed the Dell boot menu via F12 and selected the Proxmox USB installer which appeared as UEFI: General Udisk 5.00 — standard nomenclature for generic USB storage devices in Dell UEFI environments.

Step 4 — Target Drive Selection
Selected the 512GB NVMe SSD as the installation target. Proxmox formats and partitions the drive automatically during installation, allocating storage for the hypervisor OS and the local-lvm storage pool used for VM disks.

Step 5 — Network Configuration
Configured a static IP address to ensure consistent remote management access. Dynamic IPs assigned by DHCP would break browser access after any router restart.
SettingValueInterfaceeno1 (onboard ethernet)IP Address192.168.1.50/24Gateway192.168.1.1DNS8.8.8.8Hostnamepve.homelab

Step 6 — Installation Complete
Installation completed successfully in approximately 8 minutes. Removed USB drive post-installation and allowed the system to reboot into Proxmox VE.

<img width="1506" height="824" alt="Screenshot 2026-04-07 at 11 13 11 PM" src="https://github.com/user-attachments/assets/db85cd2c-a6b7-4a9c-9056-50bcb4d6933a" />

Challenges and Solutions

Secure Boot Blocking Installation
Challenge: Proxmox installer failed to load on first boot attempt due to Secure Boot being enabled by default in Dell BIOS.
Resolution: Accessed BIOS setup, navigated to the Security section, and disabled Secure Boot. Rebooted and Proxmox installer loaded successfully. This is a known requirement for open-source hypervisors and Linux-based systems on modern Dell hardware.

Post-Installation Verification
After installation confirmed the following:

Proxmox web interface accessible at https://192.168.1.50:8006 from MacBook browser on the same network
Node pve showing correctly in the web UI left panel
CPU, memory, and storage resources displaying accurately in the dashboard


<img width="1478" height="489" alt="Screenshot 2026-04-10 at 2 15 41 PM" src="https://github.com/user-attachments/assets/b5f02bcf-c332-4aa1-bfc1-5f81f6781358" />



Result
A fully operational Type 1 hypervisor running on dedicated hardware, remotely accessible from any device on the local network. This forms the foundation of the homelab environment — all subsequent virtual machines, network segments, and security tooling are deployed and managed through this Proxmox instance.
