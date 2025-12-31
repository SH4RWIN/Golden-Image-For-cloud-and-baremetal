#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "[*] Starting Enhanced Bare Metal Hardening (CIS Level 1 + Hospital/HIPAA Tweaks)..."

# --------------------------------------------------
# 0. ENSURE CORE SERVICES (Add ClamAV for hospital AV)
# --------------------------------------------------
sudo apt-get update -yqq
sudo apt-get install -yqq \
  openssh-server \
  apache2 \
  ufw \
  auditd \
  audispd-plugins \
  unattended-upgrades \
  rsyslog \
  apparmor \
  fail2ban \
  libpam-faillock \
  aide \
  libapache2-mod-security2 \
  clamav \
  clamav-daemon \
  cryptsetup \
  apparmor-utils \
  libpam-pwquality \
  clamav-freshclam \
  cron 
sudo apt-get autoremove -yqq && sudo apt-get autoclean -yqq

sudo systemctl enable ssh auditd rsyslog apparmor fail2ban unattended-upgrades clamav-freshclam clamav-daemon
sudo systemctl enable apache2  # Uncomment if needed

# AIDE init
echo "[+] Initializing AIDE..."
sudo aideinit > /var/log/aide-init.log 2>&1
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
sudo aide --check | tee /var/log/aide-check.log

# ClamAV setup
echo "[+] Setting up ClamAV..."
sudo freshclam --quiet
echo "0 2 * * * /usr/bin/freshclam --quiet" | sudo crontab -

# LUKS note (manual: Run on install media for full-disk)
echo "[+] LUKS Encryption Prep: For production, enable on /dev/sdX via 'cryptsetup luksFormat' pre-OS install."

# --------------------------------------------------
# 1. SSH HARDENING
# --------------------------------------------------
echo "[+] Enforcing SSH key-only authentication..."
sudo sed -i 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sudo sed -i 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#?UseDNS.*/UseDNS no/' /etc/ssh/sshd_config
sudo sed -i 's/^#?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sudo sed -i 's/^#?ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config

# PAM faillock
echo "auth required pam_faillock.so preauth audit silent deny=3 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth
echo "auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth

# --------------------------------------------------
# 2. FIREWALL (UFW: Internal Hospital Network)
# --------------------------------------------------
echo "[+] Configuring UFW for internal network..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow out 53 proto udp to any
sudo ufw allow out 53 proto tcp to any
sudo ufw allow out 123 proto udp
# No external web outbound (air-gapped friendly)
sudo ufw allow out 80 proto tcp  # Uncomment if needed
# sudo ufw allow out 443 proto tcp
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp  # For web
# sudo ufw allow 443/tcp
sudo ufw allow in on lo
sudo ufw insert 1 deny in from 127.0.0.0/8
# Internal VLAN (e.g., 10.0.0.0/16 for hospital)
sudo ufw allow from 10.0.0.0/16 to any port 22 proto tcp
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee /etc/sysctl.d/99-disable-ipv6.conf
sudo ufw --force enable
sudo ufw reload

# --------------------------------------------------
# 3. KERNEL HARDENING
# --------------------------------------------------
echo "[+] Applying kernel sysctl hardening..."
sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null <<EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.printk = 4 4 1 7
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
vm.mmap_min_addr = 65536
EOF
sudo sysctl --system

# --------------------------------------------------
# 4. APACHE HARDENING (DISABLED BY DEFAULT)
# --------------------------------------------------
echo "[+] Hardening Apache2..."
sudo a2enmod headers ssl
sudo a2disconf other-vhosts-access-log
sudo sed -i "s/^ServerTokens .*/ServerTokens Prod/" /etc/apache2/apache2.conf
sudo sed -i "s/^ServerSignature .*/ServerSignature Off/" /etc/apache2/apache2.conf
sudo tee -a /etc/apache2/apache2.conf > /dev/null <<EOF

<Directory /var/www/>
    Options -Indexes
    AllowOverride None
</Directory>

User www-data
Group www-data

<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
EOF

sudo tee /etc/apache2/sites-available/000-default.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options -Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>
EOF
sudo a2ensite 000-default
sudo systemctl restart apache2

# --------------------------------------------------
# 5. CENTRALIZED LOGGING
# --------------------------------------------------
echo "[+] Preparing centralized logging..."
sudo tee /etc/rsyslog.d/90-central-logging.conf > /dev/null <<EOF
# *.* @@log-server.example.com:514
\$FileCreateMode 0640
\$DirCreateMode 0750
EOF
sudo systemctl restart rsyslog

sudo tee /etc/systemd/journald.conf.d/99-hardening.conf > /dev/null <<EOF
[Journal]
Storage=persistent
Compress=yes
RuntimeMaxUse=100M
SystemMaxUse=500M
EOF
sudo systemctl restart systemd-journald

# --------------------------------------------------
# 6. AUTOMATIC SESSION LOCK
# --------------------------------------------------
echo "[+] Enforcing session idle timeout..."
sudo tee /etc/profile.d/idle-timeout.sh > /dev/null <<EOF
TMOUT=900
readonly TMOUT
export TMOUT
umask 077
EOF

# --------------------------------------------------
# 7. COMPLIANCE: LEGAL BANNERS (HIPAA-Tweaked)
# --------------------------------------------------
sudo tee /etc/issue.net > /dev/null <<EOF
WARNING: Authorized Access Only.
All actions are logged and monitored.
Unauthorized access will be prosecuted under HIPAA.
EOF
sudo tee /etc/issue > /dev/null <<EOF
$(cat /etc/issue.net)
EOF
sudo tee /etc/motd > /dev/null <<EOF
$(cat /etc/issue.net)
EOF
sudo chown root:root /etc/issue /etc/issue.net /etc/motd
sudo chmod 644 /etc/issue /etc/issue.net /etc/motd
grep -q "^Banner /etc/issue.net" /etc/ssh/sshd_config || echo "Banner /etc/issue.net" | sudo tee -a /etc/ssh/sshd_config > /dev/null

# --------------------------------------------------
# 8. PASSWORD POLICIES
# --------------------------------------------------
echo "[+] Configuring password policies..."
sudo tee /etc/security/pwquality.conf > /dev/null <<EOF
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 4
EOF
sudo sed -i '/pam_pwquality.so/s/$/ retry=3/' /etc/pam.d/common-password
echo "password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5" | sudo tee -a /etc/pam.d/common-password > /dev/null
sudo sed -i 's/^#?ENCRYPT_METHOD.*/ENCRYPT_METHOD yescrypt/' /etc/login.defs
sudo chage -m 1 -M 365 ubuntu
echo "INACTIVE=30" | sudo tee -a /etc/default/useradd

# --------------------------------------------------
# 9. PATCH MANAGEMENT
# --------------------------------------------------
sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Unattended-Upgrade-Include "1-1";
EOF
sudo dpkg-reconfigure -f noninteractive unattended-upgrades

# --------------------------------------------------
# 10. AUDITD CONFIG (Add sudo for HIPAA)
# --------------------------------------------------
echo "[+] Configuring auditd..."
sudo tee /etc/audit/rules.d/hardening.rules > /dev/null <<EOF
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k ssh_config
# -w /etc/apache2/ -p wa -k apache_config  # If Apache enabled
-a always,exit -F arch=b64 -S execve -k process_exec
-w /var/log/auth.log -p wa -k sudo_log  # HIPAA: Track sudo
EOF
sudo augenrules --load
sudo systemctl restart auditd

# --------------------------------------------------
# 11. FAIL2BAN
# --------------------------------------------------
echo "[+] Configuring Fail2Ban..."
sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log

# [apache-auth]  # If Apache enabled
# enabled = true
# port = http,https
# logpath = /var/log/apache2/*error.log
EOF
sudo systemctl restart fail2ban

# --------------------------------------------------
# 12. APPARMOR ENFORCEMENT
# --------------------------------------------------
echo "[+] Enforcing AppArmor..."
sudo aa-enforce /etc/apparmor.d/usr.sbin.sshd
# sudo aa-enforce /etc/apparmor.d/usr.sbin.apache2  # If Apache
sudo systemctl restart apparmor

# --------------------------------------------------
# 13. GRUB HARDENING
# --------------------------------------------------
echo "[+] Hardening GRUB..."
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor"/' /etc/default/grub
sudo update-grub
sudo chown root:root /boot/grub/grub.cfg
sudo chmod 600 /boot/grub/grub.cfg

# --------------------------------------------------
# 14. DISABLE UNNECESSARY SERVICES
# --------------------------------------------------
echo "[+] Disabling unnecessary services..."
sudo systemctl disable --now avahi-daemon cups bluetooth ModemManager whoopsie
# sudo a2dismod status  # If Apache
sudo modprobe -r ipv6

# --------------------------------------------------
# 15. FINALIZE
# --------------------------------------------------
sudo systemctl restart ssh rsyslog auditd apparmor fail2ban
echo "[✓] Bare metal hardening complete. Reboot recommended."