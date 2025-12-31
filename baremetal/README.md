# Ubuntu Enterprise Hardening Script (CIS Level 1 + Healthcare Tweaks)

Opinionated hardening script for Ubuntu hosts used in enterprise environments, aligned to **CIS Ubuntu Linux Benchmark Level 1**-style controls and augmented with healthcare-focused operational safeguards (e.g., stronger auditing, endpoint malware scanning, stricter defaults).

This script is intended for bare metal or VM deployments where you control the baseline image and can validate operational impact (SSH access, application behavior, logging pipeline, etc.) before rolling out broadly.

## What this does

The script applies a set of security hardening controls across common areas:

- Installs and enables core security services (UFW, Auditd, AppArmor, Fail2Ban, AIDE, Unattended Upgrades, Rsyslog, ClamAV)
- SSH hardening (key-only access, root login restrictions, idle behavior)
- Firewall baseline (deny inbound by default; allow SSH and web ports; internal network allowlist example)
- Kernel hardening via `sysctl` (anti-spoofing, redirect handling, memory protections, logging)
- Optional Apache hardening (headers, tokens/signature, directory options, redirect to HTTPS)
- Centralized logging preparation (Rsyslog + persistent journald)
- Session idle timeout + restrictive default `umask`
- Legal access banners (`/etc/issue`, `/etc/issue.net`, `/etc/motd`) and SSH banner hook
- Password quality policies and hashing configuration
- Patch management via unattended upgrades
- Audit rules emphasizing identity, SSH config, process execution, and auth/sudo-related logging
- Disables commonly unnecessary services in server environments (avahi, cups, bluetooth, etc.)
- GRUB hardening (permissions + AppArmor kernel parameters)

## Important notes (read before running)

- This script makes **breaking changes** on purpose (notably SSH password login disabling). Ensure you have SSH keys deployed and console access available.
- “HIPAA adjusted” here means “healthcare-oriented hardening choices.” It does **not** make a system HIPAA compliant on its own. Compliance also requires administrative, physical, and procedural controls.
- Test on a staging host that mirrors production. Validate:
  - SSH access paths (keys, bastion, break-glass)
  - Firewall rules for app dependencies (DNS/NTP/web egress)
  - Apache behavior (if you actually run Apache)
  - Audit log volume and forwarding
  - Any agents (EDR/SIEM) that require additional outbound access

## Compatibility

Designed for Ubuntu Server environments using `apt` and `systemd`.

- Best effort compatibility: Ubuntu 20.04/22.04/24.04 (validate in your environment)
- Requires `sudo` privileges
- Assumes `systemctl` is available

## Conclusion

This script provides a strong foundation for securing Ubuntu systems in enterprise and healthcare environments. Regular review, testing, and adaptation to evolving threat landscapes and compliance requirements are crucial for maintaining a robust security posture.

