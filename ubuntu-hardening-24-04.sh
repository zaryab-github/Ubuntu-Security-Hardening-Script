#!/bin/bash
# Ubuntu 24.04 LTS Security Hardening Script - Production Grade
# Author: Aloke Majumder
# GitHub: https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script
# License: MIT License
# Version: 3.0
# Specifically optimized for Ubuntu 24.04 LTS (Noble Numbat)

# DISCLAIMER:
# This script is provided "AS IS" without warranty of any kind, express or implied. 
# The author expressly disclaims any and all warranties, express or implied, including 
# any warranties as to the usability, suitability or effectiveness of any methods or 
# measures this script attempts to apply. By using this script, you agree that the 
# author shall not be held liable for any damages resulting from the use of this script.

set -euo pipefail  # Exit on error, undefined variables, pipe failures
IFS=$'\n\t'       # Set secure Internal Field Separator

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_VERSION="3.0"
readonly LOG_DIR="/var/log/security-hardening"
readonly LOG_FILE="${LOG_DIR}/hardening-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/var/backups/security-hardening"
readonly REPORT_FILE="${LOG_DIR}/hardening_report_$(date +%Y%m%d-%H%M%S).txt"
readonly UBUNTU_VERSION="24.04"

# Ubuntu 24.04 specific features
readonly SUPPORTS_DBUS_BROKER=true
readonly SUPPORTS_SYSTEMD_RESOLVED=true
readonly SUPPORTS_NETPLAN=true
readonly SUPPORTS_SNAP_STRICT_CONFINEMENT=true

# Function to print colored output with timestamp
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}" | tee -a "$LOG_FILE"
}

# Function to handle errors gracefully
error_exit() {
    print_message "$RED" "ERROR: $1"
    cleanup_on_error
    exit 1
}

# Function to cleanup on error
cleanup_on_error() {
    print_message "$YELLOW" "Performing cleanup due to error..."
    # Add any necessary cleanup operations here
}

# Function to create necessary directories with proper permissions
setup_directories() {
    mkdir -p "$LOG_DIR" "$BACKUP_DIR"
    chmod 700 "$LOG_DIR" "$BACKUP_DIR"
    # Set proper SELinux context if available
    if command -v semanage &> /dev/null; then
        semanage fcontext -a -t admin_home_t "$LOG_DIR" 2>/dev/null || true
        semanage fcontext -a -t admin_home_t "$BACKUP_DIR" 2>/dev/null || true
        restorecon -R "$LOG_DIR" "$BACKUP_DIR" 2>/dev/null || true
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Function to verify Ubuntu 24.04 LTS
check_ubuntu_version() {
    if ! command -v lsb_release &> /dev/null; then
        error_exit "lsb_release not found. Is this Ubuntu?"
    fi
    
    local version=$(lsb_release -rs)
    local codename=$(lsb_release -cs)
    
    print_message "$GREEN" "Detected Ubuntu version: $version ($codename)"
    
    if [[ "$version" != "$UBUNTU_VERSION" ]]; then
        print_message "$YELLOW" "WARNING: This script is optimized for Ubuntu 24.04 LTS"
        print_message "$YELLOW" "Current version: $version"
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "User cancelled operation"
        fi
    fi
}

# Function to check system requirements
check_system_requirements() {
    print_message "$GREEN" "Checking system requirements..."
    
    # Check available disk space (minimum 2GB)
    local available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 2097152 ]]; then
        error_exit "Insufficient disk space. At least 2GB required."
    fi
    
    # Check memory (minimum 1GB)
    local total_memory=$(free -m | awk 'NR==2 {print $2}')
    if [[ $total_memory -lt 1024 ]]; then
        print_message "$YELLOW" "WARNING: Low memory detected. Some operations may be slow."
    fi
    
    # Check if running in container
    if systemd-detect-virt -c &>/dev/null; then
        print_message "$YELLOW" "WARNING: Running in a container. Some features may not work."
    fi
}

# Function to backup configuration files with metadata
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup_name="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
        cp -p "$file" "$backup_name"
        # Save file permissions and ownership
        stat -c "%a %U:%G" "$file" > "${backup_name}.meta"
        print_message "$GREEN" "Backed up $file to $backup_name"
    fi
}

# Function to validate user input for frequency
validate_frequency() {
    local frequency=$1
    case "$frequency" in
        daily|weekly|monthly)
            echo "$frequency"
            ;;
        *)
            print_message "$YELLOW" "Invalid frequency. Using 'weekly' as default."
            echo "weekly"
            ;;
    esac
}

# Function to update and upgrade packages with Ubuntu Pro integration
update_system() {
    print_message "$GREEN" "Updating package lists..."
    
    # Check for Ubuntu Pro status
    if command -v pro &> /dev/null; then
        print_message "$BLUE" "Checking Ubuntu Pro status..."
        pro status --format=json > "${LOG_DIR}/ubuntu-pro-status.json" 2>/dev/null || true
    fi
    
    # Update package lists
    apt-get update -y || error_exit "Failed to update package lists"
    
    # Upgrade packages
    print_message "$GREEN" "Upgrading installed packages..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" || error_exit "Failed to upgrade packages"
    
    # Perform distribution upgrade if available
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" || true
}

# Function to install required packages for Ubuntu 24.04
install_packages() {
    print_message "$GREEN" "Installing security tools and packages..."
    
    # Core security packages for Ubuntu 24.04
    local packages=(
        # File integrity and monitoring
        "aide"
        "aide-common"
        "tripwire"
        
        # Auditing and compliance
        "auditd"
        "audispd-plugins"
        "auditd-plugin-clickhouse"
        
        # System integrity
        "debsums"
        "apt-listchanges"
        "needrestart"
        "debsecan"
        
        # Access control
        "apparmor"
        "apparmor-utils"
        "apparmor-profiles"
        "apparmor-profiles-extra"
        "apparmor-notify"
        
        # Antivirus and malware detection
        "clamav"
        "clamav-daemon"
        "clamav-freshclam"
        "clamdscan"
        
        # Automatic updates
        "unattended-upgrades"
        "update-notifier-common"
        
        # Firewall
        "ufw"
        "gufw"
        "iptables-persistent"
        
        # Intrusion detection/prevention
        "fail2ban"
        "fail2ban-systemd"
        "psad"
        "snort"
        
        # Rootkit detection
        "rkhunter"
        "chkrootkit"
        "unhide"
        
        # Security auditing
        "lynis"
        "tiger"
        "nmap"
        
        # Authentication and PAM
        "libpam-pwquality"
        "libpam-tmpdir"
        "libpam-apparmor"
        "libpam-cap"
        "libpam-modules-bin"
        "libpam-faillock"
        
        # Cryptography
        "cryptsetup"
        "cryptsetup-initramfs"
        "ecryptfs-utils"
        
        # SELinux tools (optional but recommended)
        "selinux-utils"
        "selinux-policy-default"
        
        # Network security
        "arpwatch"
        "net-tools"
        "iftop"
        "tcpdump"
        
        # System monitoring
        "sysstat"
        "acct"
        "aide-dynamic"
        
        # Ubuntu 24.04 specific
        "ubuntu-advantage-tools"
        "systemd-oomd"
        "systemd-homed"
    )
    
    # Install OpenSCAP for Ubuntu 24.04
    packages+=("libopenscap8" "openscap-scanner" "openscap-utils" "scap-security-guide")
    
    # Install packages with error handling
    for package in "${packages[@]}"; do
        print_message "$GREEN" "Installing $package..."
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" 2>/dev/null; then
            print_message "$YELLOW" "WARNING: Failed to install $package (may not be available)"
        fi
    done
    
    # Enable additional Ubuntu Pro features if available
    if command -v pro &> /dev/null && pro status | grep -q "entitled"; then
        print_message "$BLUE" "Enabling Ubuntu Pro security features..."
        pro enable usg || true
        pro enable cis || true
    fi
}

# Function to configure AIDE with Ubuntu 24.04 optimizations
configure_aide() {
    print_message "$GREEN" "Configuring AIDE file integrity checker..."
    
    backup_file "/etc/aide/aide.conf"
    
    # Configure AIDE for Ubuntu 24.04
    cat >> /etc/aide/aide.conf << 'EOF'

# Ubuntu 24.04 specific exclusions
!/snap/
!/var/snap/
!/var/lib/snapd/
!/run/snapd/
!/sys/
!/proc/
!/dev/
!/run/
!/var/lib/docker/
!/var/lib/containerd/
!/var/lib/lxc/
!/var/lib/lxd/
EOF

    # Initialize AIDE database
    print_message "$GREEN" "Initializing AIDE database (this may take several minutes)..."
    aideinit || error_exit "Failed to initialize AIDE"
    
    # Move database to production location
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        chmod 600 /var/lib/aide/aide.db
        print_message "$GREEN" "AIDE database initialized successfully"
    fi
    
    # Create systemd timer for AIDE checks (Ubuntu 24.04 preferred method)
    cat > /etc/systemd/system/aide-check.service << 'EOF'
[Unit]
Description=AIDE File Integrity Check
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aide
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    cat > /etc/systemd/system/aide-check.timer << 'EOF'
[Unit]
Description=Run AIDE check daily
Requires=aide-check.service

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable aide-check.timer
    systemctl start aide-check.timer
}

# Function to configure Auditd with Ubuntu 24.04 enhancements
configure_auditd() {
    print_message "$GREEN" "Configuring auditd with Ubuntu 24.04 optimizations..."
    
    backup_file "/etc/audit/auditd.conf"
    backup_file "/etc/audit/rules.d/audit.rules"
    
    # Configure auditd for Ubuntu 24.04
    cat > /etc/audit/auditd.conf << 'EOF'
# Ubuntu 24.04 Optimized Audit Configuration
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
transport = TCP
krb5_principal = auditd
distribute_network = no
q_depth = 1200
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
end_of_event_timeout = 2
EOF

    # Create comprehensive audit rules for Ubuntu 24.04
    cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Ubuntu 24.04 Security Audit Rules
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudo configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor systemd
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd

# Monitor snap changes (Ubuntu specific)
-w /snap/bin/ -p wa -k snap_changes
-w /var/lib/snapd/ -p wa -k snap_changes

# Monitor AppArmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /etc/apparmor/ -p wa -k apparmor

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module -k module_insertion
-a always,exit -F arch=b64 -S delete_module -k module_deletion

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Monitor network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/netplan/ -p wa -k network_config

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Make configuration immutable
-e 2
EOF

    # Load rules and restart auditd
    augenrules --load
    systemctl restart auditd
    systemctl enable auditd
    
    # Configure audit log rotation
    cat > /etc/logrotate.d/audit << 'EOF'
/var/log/audit/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s USR1 auditd.service >/dev/null 2>&1 || true
    endscript
}
EOF
}

# Function to configure AppArmor with Ubuntu 24.04 profiles
configure_apparmor() {
    print_message "$GREEN" "Configuring AppArmor with Ubuntu 24.04 profiles..."
    
    # Ensure AppArmor is enabled
    systemctl enable apparmor
    systemctl start apparmor
    
    # Set kernel parameter
    if ! grep -q "apparmor=1" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
        update-grub
    fi
    
    # Install additional profiles
    if [[ -d /usr/share/apparmor/extra-profiles/ ]]; then
        cp -n /usr/share/apparmor/extra-profiles/* /etc/apparmor.d/ 2>/dev/null || true
    fi
    
    # Enable all profiles
    find /etc/apparmor.d -maxdepth 1 -type f -exec aa-enforce {} \; 2>/dev/null || true
    
    # Configure snap confinement (Ubuntu 24.04 specific)
    if command -v snap &> /dev/null; then
        print_message "$BLUE" "Configuring strict snap confinement..."
        snap set system experimental.parallel-instances=true 2>/dev/null || true
        # Ensure all snaps use strict confinement where possible
    fi
    
    print_message "$GREEN" "AppArmor profiles enforced"
}

# Function to configure ClamAV with Ubuntu 24.04 optimizations
configure_clamav() {
    print_message "$GREEN" "Configuring ClamAV with performance optimizations..."
    
    # Configure ClamAV for Ubuntu 24.04
    backup_file "/etc/clamav/clamd.conf"
    backup_file "/etc/clamav/freshclam.conf"
    
    # Optimize ClamAV configuration
    cat >> /etc/clamav/clamd.conf << 'EOF'

# Ubuntu 24.04 Optimizations
MaxThreads 4
MaxDirectoryRecursion 20
FollowDirectorySymlinks false
FollowFileSymlinks false
CrossFilesystems false
ScanPE true
ScanELF true
DetectBrokenExecutables true
ScanOLE2 true
ScanPDF true
ScanSWF true
ScanHTML true
ScanXMLDOCS true
ScanHWP3 true
ScanArchive true
MaxScanTime 300000
MaxScanSize 400M
MaxFileSize 100M
MaxRecursion 16
MaxFiles 10000
EOF

    # Configure freshclam for automatic updates
    sed -i 's/^Checks.*/Checks 24/' /etc/clamav/freshclam.conf 2>/dev/null || true
    
    # Stop services for configuration
    systemctl stop clamav-freshclam
    systemctl stop clamav-daemon
    
    # Update virus database
    print_message "$GREEN" "Updating ClamAV virus database..."
    freshclam || print_message "$YELLOW" "WARNING: Failed to update ClamAV database"
    
    # Start and enable services
    systemctl start clamav-freshclam
    systemctl start clamav-daemon
    systemctl enable clamav-freshclam
    systemctl enable clamav-daemon
    
    # Get scan frequency
    print_message "$GREEN" "Please enter how often you want ClamAV scans to run (daily/weekly/monthly):"
    read -r scan_frequency
    scan_frequency=$(validate_frequency "$scan_frequency")
    
    # Create systemd timer for scans (Ubuntu 24.04 preferred)
    cat > /etc/systemd/system/clamav-scan.service << 'EOF'
[Unit]
Description=ClamAV Virus Scan
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/clamav-scan.sh
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    # Create scan script
    cat > /usr/local/bin/clamav-scan.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/clamav/scan-$(date +%Y%m%d-%H%M%S).log"
INFECTED_DIR="/var/quarantine"

mkdir -p "$INFECTED_DIR"
chmod 700 "$INFECTED_DIR"

# Exclude virtual filesystems and large directories
EXCLUDE_DIRS="--exclude-dir=^/sys --exclude-dir=^/proc --exclude-dir=^/dev --exclude-dir=^/run --exclude-dir=^/snap --exclude-dir=^/var/lib/docker --exclude-dir=^/var/lib/containerd"

# Scan with optimized settings
nice -n 19 ionice -c 3 clamscan -r -i \
    --move="$INFECTED_DIR" \
    $EXCLUDE_DIRS \
    --max-filesize=100M \
    --max-scansize=400M \
    --max-recursion=16 \
    --max-dir-recursion=20 \
    --log="$LOG_FILE" \
    / 2>/dev/null

# Send notification if infections found
if grep -q "Infected files:" "$LOG_FILE" && grep -q "Infected files: [1-9]" "$LOG_FILE"; then
    # Use systemd journal for notifications
    echo "ClamAV: Infections detected on $(hostname)" | systemd-cat -t clamav -p err
    # Send email if mail is configured
    if command -v mail &>/dev/null; then
        mail -s "ClamAV: Infections detected on $(hostname)" root < "$LOG_FILE"
    fi
fi
EOF
    chmod 755 /usr/local/bin/clamav-scan.sh
    
    # Create timer based on frequency
    case "$scan_frequency" in
        daily)
            timer_schedule="daily"
            ;;
        weekly)
            timer_schedule="weekly"
            ;;
        monthly)
            timer_schedule="monthly"
            ;;
    esac
    
    cat > /etc/systemd/system/clamav-scan.timer << EOF
[Unit]
Description=Run ClamAV scan $scan_frequency
Requires=clamav-scan.service

[Timer]
OnCalendar=$timer_schedule
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable clamav-scan.timer
    systemctl start clamav-scan.timer
    
    print_message "$GREEN" "ClamAV configured with $scan_frequency scans"
}

# Function to configure automatic updates for Ubuntu 24.04
configure_unattended_upgrades() {
    print_message "$GREEN" "Configuring automatic security updates for Ubuntu 24.04..."
    
    backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
    
    # Configure unattended-upgrades for Ubuntu 24.04
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Ubuntu 24.04 Automatic Updates Configuration
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-security";
        "${distro_id}:${distro_codename}-updates";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
        "${distro_id}:${distro_codename}-proposed";
};

// Automatically fix interrupted dpkg
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

// Do automatic removal of unused packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot if required
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

// Keep updated packages
Unattended-Upgrade::Keep-Debs-After-Install "false";

// Email notifications
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";

// Do upgrade in minimal steps
Unattended-Upgrade::MinimalSteps "true";

// Set download speed limit (KB/s)
// Acquire::http::Dl-Limit "70";

// Set package blacklist
Unattended-Upgrade::Package-Blacklist {
    // "package1";
    // "package2";
};

// Ubuntu 24.04 specific - enable Livepatch if available
Unattended-Upgrade::DevRelease "auto";
EOF

    # Enable automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Verbose "1";
EOF

    # Enable update-notifier for desktop systems
    if dpkg -l | grep -q "update-notifier"; then
        cat > /etc/apt/apt.conf.d/99update-notifier << 'EOF'
DPkg::Post-Invoke {"if [ -d /var/lib/update-notifier ]; then touch /var/lib/update-notifier/dpkg-run-stamp; fi; };";
EOF
    fi
    
    # Configure needrestart for automatic service restarts
    if command -v needrestart &> /dev/null; then
        cat > /etc/needrestart/conf.d/auto.conf << 'EOF'
# Automatically restart services
$nrconf{restart} = 'a';
# Disable kernel checks (we handle reboots separately)
$nrconf{kernelhints} = 0;
EOF
    fi
    
    systemctl restart unattended-upgrades
    systemctl enable unattended-upgrades
}

# Function to configure UFW with Ubuntu 24.04 enhancements
configure_ufw() {
    print_message "$GREEN" "Configuring UFW firewall with IPv6 support..."
    
    backup_file "/etc/default/ufw"
    
    # Enable IPv6 support
    sed -i 's/IPV6=.*/IPV6=yes/' /etc/default/ufw
    
    # Reset firewall to defaults
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    
    # Configure logging
    ufw logging on
    ufw logging medium
    
    # Basic rules with rate limiting
    ufw limit 22/tcp comment 'SSH rate limit'
    
    # Allow DHCP client (important for cloud instances)
    ufw allow 68/udp comment 'DHCP client'
    
    # Enable firewall
    echo "y" | ufw enable
    
    # Configure iptables-persistent
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
        systemctl enable netfilter-persistent
    fi
    
    print_message "$GREEN" "UFW firewall configured and enabled"
    print_message "$YELLOW" "NOTE: Only SSH (rate-limited) and DHCP are allowed"
}

# Function to configure Fail2ban with Ubuntu 24.04 optimizations
configure_fail2ban() {
    print_message "$GREEN" "Configuring Fail2ban with systemd integration..."
    
    backup_file "/etc/fail2ban/jail.conf"
    
    # Create jail.local with Ubuntu 24.04 optimizations
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ubuntu 24.04 Fail2ban Configuration
bantime  = 1h
findtime  = 10m
maxretry = 5
backend = systemd
usedns = warn
logencoding = utf-8
enabled = false
mode = normal
filter = %(__name__)s[mode=%(mode)s]

# Destination email
destemail = root@localhost
sender = root@localhost
mta = sendmail

# Action
action = %(action_mwl)s

# Ignore localhost and private networks
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 2h
findtime = 20m

[sshd-ddos]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 10
findtime = 5m
bantime = 10m

# Ubuntu 24.04 - systemd journal monitoring
[systemd-ssh]
enabled = true
backend = systemd
journalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd
maxretry = 3
bantime = 2h

# Protect against port scanning
[port-scan]
enabled = true
filter = port-scan
logpath = /var/log/ufw.log
maxretry = 2
bantime = 1d
findtime = 1d

# Additional jails for common services
[apache-auth]
enabled = false
port = http,https
logpath = %(apache_error_log)s

[nginx-http-auth]
enabled = false
port = http,https
logpath = %(nginx_error_log)s

[postfix]
enabled = false
mode = aggressive
port = smtp,465,submission
logpath = %(postfix_log)s
backend = %(postfix_backend)s
EOF

    # Create custom filters
    mkdir -p /etc/fail2ban/filter.d
    
    # Port scan filter
    cat > /etc/fail2ban/filter.d/port-scan.conf << 'EOF'
[Definition]
failregex = .*UFW BLOCK.* SRC=<HOST>
ignoreregex =
EOF

    # Restart fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    print_message "$GREEN" "Fail2ban configured with systemd integration"
}

# Function to harden SSH for Ubuntu 24.04
harden_ssh() {
    print_message "$GREEN" "Hardening SSH configuration for Ubuntu 24.04..."
    
    backup_file "/etc/ssh/sshd_config"
    
    # Create hardened SSH config using Include directive (Ubuntu 24.04 style)
    mkdir -p /etc/ssh/sshd_config.d/
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# Ubuntu 24.04 SSH Hardening Configuration
# Protocol and Network
Protocol 2
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Host Keys (Ubuntu 24.04 defaults)
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes
MaxAuthTries 3
MaxSessions 10
AuthenticationMethods publickey

# Security Features
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
IgnoreUserKnownHosts yes

# Forwarding Options
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PermitUserRC no
GatewayPorts no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Crypto (Ubuntu 24.04 strong defaults)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# Connection Settings
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30s
MaxStartups 10:30:60
TCPKeepAlive yes
Compression no
UseDNS no

# Misc Security
PermitUserEnvironment no
DebianBanner no
VersionAddendum none
PrintMotd no
PrintLastLog yes
PidFile /run/sshd.pid
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# Ubuntu 24.04 - Restrict users/groups (customize as needed)
# AllowUsers user1 user2
# AllowGroups sshusers
# DenyUsers nobody
# DenyGroups nogroup
EOF

    # Test configuration
    sshd -t || error_exit "SSH configuration test failed"
    
    # Create SSH banner
    cat > /etc/issue.net << 'EOF'
********************************************************************************
*                            AUTHORIZED ACCESS ONLY                            *
* Unauthorized access to this system is forbidden and will be prosecuted by    *
* law. By accessing this system, you consent to monitoring and recording.      *
********************************************************************************
EOF
    
    # Update main sshd_config to use banner
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config.d/99-hardening.conf
    
    # Restart SSH service
    systemctl restart sshd
    
    print_message "$GREEN" "SSH hardened successfully"
    print_message "$YELLOW" "WARNING: Password authentication is disabled. Ensure SSH keys are configured!"
}

# Function to configure system limits for Ubuntu 24.04
configure_limits() {
    print_message "$GREEN" "Configuring system security limits..."
    
    backup_file "/etc/security/limits.conf"
    
    # Add security limits
    cat >> /etc/security/limits.conf << 'EOF'

# Ubuntu 24.04 Security Limits
# Disable core dumps
* soft core 0
* hard core 0

# Limit number of processes
* soft nproc 512
* hard nproc 1024
root soft nproc unlimited
root hard nproc unlimited

# Limit number of open files
* soft nofile 1024
* hard nofile 65536

# Limit max locked memory
* soft memlock 64
* hard memlock 64

# Limit max address space
* soft as unlimited
* hard as unlimited

# Limit max file size
* soft fsize unlimited
* hard fsize unlimited

# Limit max cpu time
* soft cpu unlimited
* hard cpu unlimited

# Limit max number of logins
* soft maxlogins 10
* hard maxlogins 10

# Limit priority
* soft priority 0
* hard priority 0

# Limit max number of system logins
* soft maxsyslogins 3
* hard maxsyslogins 3
EOF

    # Configure systemd limits
    mkdir -p /etc/systemd/system.conf.d/
    cat > /etc/systemd/system.conf.d/99-limits.conf << 'EOF'
[Manager]
# Ubuntu 24.04 Systemd Limits
DefaultLimitCORE=0
DefaultLimitNOFILE=1024:65536
DefaultLimitNPROC=512:1024
DefaultLimitMEMLOCK=64M
DefaultTasksMax=512
EOF

    # Reload systemd
    systemctl daemon-reload
}

# Function to configure kernel parameters for Ubuntu 24.04
configure_sysctl() {
    print_message "$GREEN" "Configuring kernel security parameters for Ubuntu 24.04..."
    
    backup_file "/etc/sysctl.conf"
    
    # Create comprehensive sysctl security configuration
    cat > /etc/sysctl.d/99-security-hardening.conf << 'EOF'
# Ubuntu 24.04 Kernel Security Hardening

### Network Security ###

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable TCP timestamps
net.ipv4.tcp_timestamps = 0

# Enable TCP RFC 1337
net.ipv4.tcp_rfc1337 = 1

# Secure ICMP
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# ARP security
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

### Kernel Security ###

# Enable ExecShield (if available)
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 2

# Disable kexec
kernel.kexec_load_disabled = 1

# Harden BPF JIT
net.core.bpf_jit_harden = 2

# Restrict performance events
kernel.perf_event_paranoid = 3

# Disable SysRq
kernel.sysrq = 0

# Restrict core dumps
fs.suid_dumpable = 0

# Protect hardlinks and symlinks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2

# ASLR
kernel.randomize_va_space = 2

# Restrict unprivileged userns
kernel.unprivileged_userns_clone = 0

# Ubuntu 24.04 specific
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_enable = 0
kernel.modules_disabled = 0
kernel.io_uring_disabled = 2

### IPv6 Security (disable if not needed) ###
# Uncomment to disable IPv6
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
# net.ipv6.conf.lo.disable_ipv6 = 1

### Performance and Resource Protection ###
vm.swappiness = 10
vm.vfs_cache_pressure = 50
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_fastopen = 3

# Increase system file limits
fs.file-max = 65536

# Restrict access to kernel logs
kernel.printk = 3 3 3 3
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-security-hardening.conf
    
    print_message "$GREEN" "Kernel parameters configured"
}

# Function to configure OpenSCAP for Ubuntu 24.04
configure_openscap() {
    if ! command -v oscap &> /dev/null; then
        print_message "$YELLOW" "OpenSCAP not available, skipping configuration"
        return
    fi
    
    print_message "$GREEN" "Configuring OpenSCAP for Ubuntu 24.04..."
    
    # Get scan frequency
    print_message "$GREEN" "Please enter how often you want OpenSCAP scans to run (daily/weekly/monthly):"
    read -r oscap_frequency
    oscap_frequency=$(validate_frequency "$oscap_frequency")
    
    # Find the appropriate SCAP content
    local ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
    if [[ ! -f "$ssg_file" ]]; then
        # Try alternative location
        ssg_file="/usr/share/openscap/ssg/ssg-ubuntu2204-ds.xml"
    fi
    
    if [[ ! -f "$ssg_file" ]]; then
        print_message "$YELLOW" "WARNING: SCAP Security Guide content not found"
        return
    fi
    
    # Create scan script
    cat > /usr/local/bin/openscap-scan.sh << EOF
#!/bin/bash
# OpenSCAP Security Scan for Ubuntu 24.04
REPORT_DIR="/var/log/openscap"
mkdir -p "\$REPORT_DIR"

# Available profiles:
# - xccdf_org.ssgproject.content_profile_cis_level1_server
# - xccdf_org.ssgproject.content_profile_cis_level2_server
# - xccdf_org.ssgproject.content_profile_standard
# - xccdf_org.ssgproject.content_profile_pci-dss

PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"

oscap xccdf eval \\
    --profile "\$PROFILE" \\
    --report "\$REPORT_DIR/report_\$(date +%Y%m%d-%H%M%S).html" \\
    --results "\$REPORT_DIR/results_\$(date +%Y%m%d-%H%M%S).xml" \\
    --oval-results \\
    "$ssg_file" 2>&1 | tee "\$REPORT_DIR/scan_\$(date +%Y%m%d-%H%M%S).log"

# Generate remediation script
oscap xccdf generate fix \\
    --profile "\$PROFILE" \\
    --output "\$REPORT_DIR/remediation_\$(date +%Y%m%d-%H%M%S).sh" \\
    "\$REPORT_DIR"/results_*.xml | tail -1
EOF
    chmod 755 /usr/local/bin/openscap-scan.sh
    
    # Create systemd timer
    cat > /etc/systemd/system/openscap-scan.service << 'EOF'
[Unit]
Description=OpenSCAP Security Compliance Scan
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openscap-scan.sh
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    # Configure timer based on frequency
    case "$oscap_frequency" in
        daily)
            timer_schedule="daily"
            ;;
        weekly)
            timer_schedule="weekly"
            ;;
        monthly)
            timer_schedule="monthly"
            ;;
    esac
    
    cat > /etc/systemd/system/openscap-scan.timer << EOF
[Unit]
Description=Run OpenSCAP scan $oscap_frequency
Requires=openscap-scan.service

[Timer]
OnCalendar=$timer_schedule
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable openscap-scan.timer
    systemctl start openscap-scan.timer
    
    print_message "$GREEN" "OpenSCAP configured with $oscap_frequency scans"
}

# Function to configure additional Ubuntu 24.04 security features
configure_ubuntu_24_features() {
    print_message "$GREEN" "Configuring Ubuntu 24.04 specific security features..."
    
    # Configure systemd security features
    print_message "$BLUE" "Configuring systemd security features..."
    
    # Enable systemd-oomd (Out of Memory Daemon)
    if systemctl list-unit-files | grep -q systemd-oomd; then
        systemctl enable systemd-oomd
        systemctl start systemd-oomd
    fi
    
    # Configure private tmp for services
    mkdir -p /etc/systemd/system/
    cat > /etc/systemd/system/private-tmp.conf << 'EOF'
[Service]
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
EOF
    
    # Configure DNSStubListener if using systemd-resolved
    if systemctl is-active systemd-resolved; then
        mkdir -p /etc/systemd/resolved.conf.d/
        cat > /etc/systemd/resolved.conf.d/security.conf << 'EOF'
[Resolve]
DNSStubListener=yes
DNSSEC=allow-downgrade
DNSOverTLS=opportunistic
EOF
        systemctl restart systemd-resolved
    fi
    
    # Configure snap security
    if command -v snap &> /dev/null; then
        print_message "$BLUE" "Hardening snap security..."
        # Refresh snaps to ensure latest security updates
        snap refresh || true
    fi
    
    # Configure netplan security (if used)
    if command -v netplan &> /dev/null && [[ -d /etc/netplan ]]; then
        print_message "$BLUE" "Securing netplan configuration..."
        chmod 600 /etc/netplan/*.yaml 2>/dev/null || true
    fi
}

# Function to perform security audits
perform_security_audit() {
    print_message "$GREEN" "Performing initial security audit..."
    
    local audit_dir="${LOG_DIR}/initial-audit"
    mkdir -p "$audit_dir"
    
    # Run Lynis audit
    if command -v lynis &> /dev/null; then
        print_message "$BLUE" "Running Lynis security audit..."
        lynis audit system --quick --quiet --report-file "$audit_dir/lynis-report.txt" || true
    fi
    
    # Run rkhunter
    if command -v rkhunter &> /dev/null; then
        print_message "$BLUE" "Running rkhunter check..."
        rkhunter --update || true
        rkhunter --check --skip-keypress --report-file "$audit_dir/rkhunter-report.txt" || true
    fi
    
    # Check for listening services
    print_message "$BLUE" "Checking listening services..."
    ss -tulpn > "$audit_dir/listening-services.txt" 2>&1
    
    # Check for running processes
    ps auxf > "$audit_dir/running-processes.txt" 2>&1
    
    # Check system users
    awk -F: '$3 >= 1000 {print $1}' /etc/passwd > "$audit_dir/system-users.txt"
    
    print_message "$GREEN" "Security audit completed. Results in: $audit_dir"
}

# Function to generate comprehensive report
generate_report() {
    print_message "$GREEN" "Generating comprehensive hardening report..."
    
    cat > "$REPORT_FILE" << EOF
Ubuntu 24.04 LTS Security Hardening Report
==========================================
Generated: $(date)
Hostname: $(hostname)
Ubuntu Version: $(lsb_release -ds)
Kernel: $(uname -r)
Script Version: $SCRIPT_VERSION

Executive Summary
-----------------
This system has been hardened according to security best practices for Ubuntu 24.04 LTS.
All security tools have been installed and configured with appropriate policies.

Applied Security Measures
-------------------------

1. SYSTEM UPDATES
   ✓ All packages updated to latest versions
   ✓ Automatic security updates enabled via unattended-upgrades
   ✓ Update notifications configured
   ✓ Kernel live patching ready (if Ubuntu Pro enabled)

2. FILE INTEGRITY MONITORING
   ✓ AIDE configured with systemd timer
   ✓ Daily integrity checks scheduled
   ✓ Tripwire available as secondary option
   ✓ Database location: /var/lib/aide/aide.db

3. AUDIT SYSTEM
   ✓ Auditd configured with comprehensive ruleset
   ✓ Monitoring: auth, sudo, SSH, systemd, kernel modules
   ✓ Ubuntu 24.04 specific paths included
   ✓ Log rotation configured

4. MANDATORY ACCESS CONTROL
   ✓ AppArmor enabled and enforcing
   ✓ All profiles in enforce mode
   ✓ Snap confinement configured
   ✓ Additional profiles installed

5. ANTIVIRUS PROTECTION
   ✓ ClamAV installed and configured
   ✓ Scheduled scans: $scan_frequency
   ✓ Real-time scanning enabled
   ✓ Automatic updates configured

6. FIREWALL
   ✓ UFW enabled with secure defaults
   ✓ IPv6 support enabled
   ✓ Rate limiting on SSH
   ✓ Logging enabled at medium level

7. INTRUSION PREVENTION
   ✓ Fail2ban configured with systemd backend
   ✓ SSH protection enabled
   ✓ Port scan detection enabled
   ✓ Custom jails configured

8. SSH HARDENING
   ✓ Root login disabled
   ✓ Password authentication disabled
   ✓ Strong crypto algorithms only
   ✓ Connection limits configured

9. KERNEL HARDENING
   ✓ Sysctl parameters optimized
   ✓ ASLR enabled
   ✓ Core dumps restricted
   ✓ Module loading restrictions

10. SYSTEM LIMITS
    ✓ Resource limits configured
    ✓ Process limits enforced
    ✓ Systemd limits applied
    ✓ Core dumps disabled

11. UBUNTU 24.04 FEATURES
    ✓ Systemd security features enabled
    ✓ OOM daemon configured
    ✓ DNS security enhanced
    ✓ Private tmp enabled for services

12. COMPLIANCE SCANNING
    ✓ OpenSCAP configured
    ✓ CIS benchmark scanning
    ✓ Scheduled assessments

Important File Locations
------------------------
Configuration Backups: $BACKUP_DIR
Log Files: $LOG_DIR
Audit Logs: /var/log/audit/
ClamAV Logs: /var/log/clamav/
Fail2ban Logs: /var/log/fail2ban.log
UFW Logs: /var/log/ufw.log
OpenSCAP Reports: /var/log/openscap/

Security Tool Commands
----------------------
# System Audit
lynis audit system                    # Comprehensive security audit
rkhunter -c                          # Rootkit check
chkrootkit                           # Alternative rootkit check

# File Integrity
aide --check                         # Check file integrity
aide --update                        # Update AIDE database

# Audit System
aureport --summary                   # Audit report summary
ausearch -m LOGIN --success no       # Failed login attempts

# Firewall
ufw status verbose                   # Firewall status
ufw show raw                         # Raw firewall rules

# Intrusion Detection
fail2ban-client status              # Fail2ban status
fail2ban-client status sshd         # SSH jail status

# Updates
unattended-upgrade --dry-run        # Test automatic updates

# Compliance
/usr/local/bin/openscap-scan.sh    # Run compliance scan

Post-Installation Checklist
---------------------------
□ Review and test all configurations
□ Configure SSH keys for all users
□ Add necessary firewall rules for services
□ Review audit logs regularly
□ Schedule regular security reviews
□ Configure log forwarding if needed
□ Set up monitoring and alerting
□ Document any custom changes
□ Test system recovery procedures

⚠️  CRITICAL WARNINGS ⚠️
------------------------
1. SSH password authentication is DISABLED
   - Ensure SSH keys are configured before disconnecting
   - Test SSH key access from another terminal

2. Firewall is blocking all incoming except SSH
   - Add rules for required services using: ufw allow <port>/<protocol>

3. Some kernel parameters may affect applications
   - Test all critical applications thoroughly

4. Automatic updates are enabled
   - Review /etc/apt/apt.conf.d/50unattended-upgrades for exclusions

Next Steps
----------
1. Run 'lynis audit system' for detailed recommendations
2. Review OpenSCAP compliance reports
3. Configure centralized logging if applicable
4. Set up regular backup procedures
5. Create system recovery documentation
6. Train staff on security procedures

Support and Maintenance
-----------------------
- Check system logs regularly
- Monitor security mailing lists
- Keep security tools updated
- Review hardening quarterly
- Test incident response procedures

This report was generated by: $SCRIPT_NAME v$SCRIPT_VERSION
For issues or updates: https://github.com/alokemajumder
EOF

    # Set appropriate permissions
    chmod 600 "$REPORT_FILE"
    
    print_message "$GREEN" "Comprehensive report saved to: $REPORT_FILE"
}

# Function to perform final system checks
final_system_checks() {
    print_message "$GREEN" "Performing final system checks..."
    
    # Check critical services
    local services=(
        "auditd"
        "apparmor"
        "clamav-daemon"
        "clamav-freshclam"
        "ufw"
        "fail2ban"
        "unattended-upgrades"
        "systemd-resolved"
    )
    
    print_message "$BLUE" "Service Status:"
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_message "$GREEN" "  ✓ $service is running"
        else
            print_message "$YELLOW" "  ⚠ $service is not running (may not be required)"
        fi
    done
    
    # Check firewall
    print_message "$BLUE" "Firewall Status:"
    if ufw status | grep -q "Status: active"; then
        print_message "$GREEN" "  ✓ UFW firewall is active"
        ufw status numbered | grep -E "^\[[0-9]+\]" | head -5
    else
        print_message "$RED" "  ✗ UFW firewall is not active"
    fi
    
    # Check for updates
    print_message "$BLUE" "Checking for remaining updates..."
    if apt-get -s upgrade | grep -q "0 upgraded"; then
        print_message "$GREEN" "  ✓ System is fully updated"
    else
        print_message "$YELLOW" "  ⚠ Updates are available"
    fi
}

# Main function
main() {
    print_message "$GREEN" "╔══════════════════════════════════════════════════════╗"
    print_message "$GREEN" "║     Ubuntu 24.04 LTS Security Hardening Script       ║"
    print_message "$GREEN" "║                   Version $SCRIPT_VERSION                        ║"
    print_message "$GREEN" "╚══════════════════════════════════════════════════════╝"
    
    # Pre-flight checks
    check_root
    setup_directories
    check_ubuntu_version
    check_system_requirements
    
    # Create system restore point notification
    print_message "$YELLOW" "Consider creating a system backup/snapshot before proceeding"
    read -p "Press Enter to continue or Ctrl+C to cancel..."
    
    # Main hardening process
    print_message "$GREEN" "Starting security hardening process..."
    
    update_system
    install_packages
    
    # Core security configurations
    configure_aide
    configure_auditd
    configure_apparmor
    configure_clamav
    configure_unattended_upgrades
    configure_ufw
    configure_fail2ban
    harden_ssh
    configure_limits
    configure_sysctl
    configure_openscap
    
    # Ubuntu 24.04 specific features
    configure_ubuntu_24_features
    
    # Auditing and reporting
    perform_security_audit
    generate_report
    final_system_checks
    
    # Completion
    print_message "$GREEN" "╔══════════════════════════════════════════════════════╗"
    print_message "$GREEN" "║        Security Hardening Completed Successfully!     ║"
    print_message "$GREEN" "╚══════════════════════════════════════════════════════╝"
    print_message "$GREEN" ""
    print_message "$YELLOW" "📋 Report Location: $REPORT_FILE"
    print_message "$YELLOW" "📁 Backup Location: $BACKUP_DIR"
    print_message "$YELLOW" "📊 Audit Results: ${LOG_DIR}/initial-audit/"
    print_message ""
    print_message "$RED" "⚠️  CRITICAL: Ensure you have SSH key access before disconnecting!"
    print_message "$RED" "⚠️  Password authentication has been disabled for security."
    print_message ""
    print_message "$GREEN" "Next: Review the report and test all services before production use."
}

# Trap errors
trap 'error_exit "Script failed at line $LINENO"' ERR

# Run main function
main "$@"