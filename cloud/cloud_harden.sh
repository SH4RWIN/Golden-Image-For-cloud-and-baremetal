#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "Starting AWS-safe base AMI hardening..."

# --------------------------------------------------
# CORE PACKAGES 
# --------------------------------------------------
apt-get update -yqq
apt-get install -yqq \
  openssh-server \
  ufw \
  auditd \
  audispd-plugins \
  unattended-upgrades \
  rsyslog \
  apparmor \
  apparmor-utils \
  fail2ban

apt-get autoremove -yqq
apt-get autoclean -yqq

systemctl enable ssh rsyslog auditd apparmor fail2ban unattended-upgrades

# --------------------------------------------------
# 1. SSH HARDENING
# --------------------------------------------------
echo "Hardening SSH..."
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?UseDNS.*/UseDNS no/' /etc/ssh/sshd_config
sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config

# --------------------------------------------------
# 2. FIREWALL
# --------------------------------------------------
echo "Configuring UFW..."
ufw default deny incoming
ufw default allow outgoing

# Required for AWS
ufw allow OpenSSH
ufw allow out 443/tcp
ufw allow out to 169.254.169.254

ufw --force enable  

# --------------------------------------------------
# 4. KERNEL HARDENING
# --------------------------------------------------
echo "Applying sysctl hardening..."
cat >/etc/sysctl.d/99-hardening.conf <<EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
EOF

sysctl --system

# --------------------------------------------------
# 5. AUDITD
# --------------------------------------------------
echo "Configuring auditd..."
cat >/etc/audit/rules.d/base.rules <<'EOF'
# Delete all existing rules
-D

# Buffer Size - increase if you get audit queue overflow errors
-b 8192

# Failure mode (0=silent 1=printk 2=panic)
-f 1

## 1. Identity Changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## 2. Sudo and Privilege Escalation
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-a always,exit -F path=/usr/bin/sudo -F perm=x -k sudo_execution
-a always,exit -F path=/usr/bin/su -F perm=x -k priv_escalation

## 3. SSH Configuration
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/sshd_config.d/ -p wa -k ssh_config

## 4. Authentication/Login Events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

## 5. System Calls - Program Execution
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

## 6. File Deletion Auditing
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k delete

## 7. Permission/Ownership Changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod

## 8. Kernel Module Loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

## 9. System Time Changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

## 10. Make configuration immutable (must be last)
-e 2
EOF

augenrules --load
systemctl restart auditd

# --------------------------------------------------
# 6. APPARMOR
# --------------------------------------------------
echo "Enforcing AppArmor..."
if command -v aa-enforce &> /dev/null; then
    aa-enforce /etc/apparmor.d/usr.sbin.sshd || true
else
    echo "AppArmor utilities not installed, skipping profile enforcement"
fi
systemctl restart apparmor

# --------------------------------------------------
# 7. LOGGING
# --------------------------------------------------
echo "[+] Hardening journald..."
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-hardening.conf <<EOF
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
EOF

systemctl restart systemd-journald

# --------------------------------------------------
# 9. DISABLE NOISY SERVICES
# --------------------------------------------------
echo "Disabling unnecessary services... if they exist"
systemctl disable --now cups bluetooth ModemManager whoopsie || true

# --------------------------------------------------
# 10. FINAL
# --------------------------------------------------
systemctl restart ssh rsyslog auditd apparmor fail2ban
echo "AWS-safe hardened AMI build complete"
