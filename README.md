# Ubuntu Security Hardening Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-18.04%20|%2020.04%20|%2022.04%20|%2024.04%20|%2025.x-orange)](https://ubuntu.com/)
[![Bash](https://img.shields.io/badge/Bash-5.0%2B-green)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-Hardening-blue)](https://github.com/gensecaihq)
[![Issues Fixed](https://img.shields.io/badge/Issues-Fixed-success)](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/issues)

Production-grade security hardening scripts for Ubuntu systems that implement comprehensive security controls, compliance configurations, and system hardening based on industry best practices. All scripts have been tested and validated with critical fixes applied.

## 📦 Available Scripts

| Script | Version | Ubuntu Support | Status | Features |
|--------|---------|----------------|--------|----------|
| **ubuntu-hardening-original.sh** | 2.0 | 18.04 / 20.04 / 22.04 | ✅ Production | Legacy-compatible, cron-based |
| **ubuntu-hardening-24-04.sh** | 3.0 | 24.04 LTS | ✅ Production | Systemd timers, Ubuntu Pro |
| **ubuntu-hardening-25.sh** | 4.0 | 25.04 / 25.10 | ✅ Production | Chrony NTS, cgroup v2, Intel TDX |

## 🆕 What's New

### Recent Updates (Latest Release)
- ✅ **Fixed all critical issues** from GitHub Issues #4-#8
- ✅ **New Ubuntu 25.x script** with cutting-edge security features
- ✅ **UFW log rotation** configured on all scripts
- ✅ **Enhanced error handling** across all versions
- ✅ **Production-tested** and syntax-validated

### Ubuntu 25.x Features (New!)
- 🔐 **Chrony with Network Time Security (NTS)** - Enhanced time synchronization security
- 🚀 **Cgroup v2 exclusive support** - Modern resource control
- 🔒 **Intel TDX support** - Trust Domain Extensions for confidential computing
- 💎 **Enhanced cryptography** - OpenSSL 3.4.1+ and GnuTLS 3.8.9+
- 🦀 **sudo-rs support** - Rust implementation of sudo (25.10)
- ⚡ **Kernel 6.14+/6.17+ hardening** - Latest kernel security features
- 🛡️ **Enhanced eBPF controls** - Improved isolation and security

## 🚀 Features

### Core Security Implementations
- **System Updates**: Automated security patching with unattended-upgrades
- **File Integrity Monitoring**: AIDE configuration with scheduled checks
- **Audit System**: Comprehensive auditd rules for security monitoring
- **Access Control**: AppArmor MAC enforcement with enhanced profiles
- **Antivirus**: ClamAV with scheduled scanning and quarantine
- **Firewall**: UFW with secure defaults, rate limiting, and log rotation
- **Intrusion Prevention**: Fail2ban with SSH and port scan protection
- **SSH Hardening**: Strong crypto, key-only authentication, modern algorithms
- **Kernel Security**: Sysctl hardening parameters optimized per version
- **System Limits**: Resource restrictions and core dump prevention

### Time Synchronization
- **Ubuntu 18.04-24.04**: systemd-timesyncd (standard)
- **Ubuntu 25.x**: Chrony with Network Time Security (NTS) enabled by default

### Additional Security Tools
- **Rootkit Detection**: rkhunter and chkrootkit
- **Security Auditing**: Lynis for comprehensive system audits
- **Compliance Scanning**: OpenSCAP with CIS benchmarks
- **Network Monitoring**: Enhanced network security controls
- **Package Verification**: debsums integrity checking

## 📋 Requirements

### System Requirements
- **Ubuntu Versions**: 18.04, 20.04, 22.04, 24.04 LTS, 25.04, or 25.10
- **Disk Space**: Minimum 2GB free
- **RAM**: Minimum 1GB (2GB recommended)
- **Access**: Root or sudo privileges
- **Network**: Active internet connection for package downloads

### Pre-Installation Checklist
- [ ] Create a system backup or VM snapshot
- [ ] Ensure SSH key access is configured (password auth will be disabled)
- [ ] Document any custom configurations
- [ ] Note required firewall ports for your services
- [ ] Have console access ready (in case of SSH issues)

## 🔧 Installation

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script.git
   cd Ubuntu-Security-Hardening-Script
   ```

2. **Make scripts executable:**
   ```bash
   chmod +x ubuntu-hardening-*.sh
   ```

3. **Run the appropriate script for your Ubuntu version:**

   **For Ubuntu 18.04/20.04/22.04:**
   ```bash
   sudo ./ubuntu-hardening-original.sh
   ```

   **For Ubuntu 24.04 LTS:**
   ```bash
   sudo ./ubuntu-hardening-24-04.sh
   ```

   **For Ubuntu 25.04/25.10:**
   ```bash
   sudo ./ubuntu-hardening-25.sh
   ```

### Advanced Installation

**With logging to file:**
```bash
sudo ./ubuntu-hardening-25.sh 2>&1 | tee hardening-install.log
```

**Check version before running:**
```bash
lsb_release -a
```

## 📚 Script Details

### ubuntu-hardening-original.sh (v2.0)
**Target**: Ubuntu 18.04 LTS through 22.04 LTS

**Features:**
- Traditional cron-based scheduling
- Compatible with older package versions
- Standard systemd configurations
- Legacy-friendly security controls
- IPv4/IPv6 configuration options

**Fixed Issues:**
- ✅ Log directory creation order
- ✅ UFW installation verification
- ✅ ClamAV service error handling
- ✅ SSH config directory compatibility
- ✅ Consistent systemctl usage
- ✅ UFW log rotation

### ubuntu-hardening-24-04.sh (v3.0)
**Target**: Ubuntu 24.04 LTS (Noble Numbat)

**Features:**
- Systemd timers for all scheduled tasks
- Ubuntu Pro/Advantage integration
- Enhanced snap confinement
- Modern cryptographic defaults
- Advanced systemd security features
- Netplan and systemd-resolved hardening
- Kernel 6.8+ optimizations

**Fixed GitHub Issues:**
- ✅ Issue #5: Log directory not created before logging
- ✅ Issue #8: APT configuration syntax error
- ✅ Issue #4: iptables-persistent package conflicts
- ✅ Issue #7: UFW called before installation
- ✅ Issue #6: Unbound timer_schedule variable
- ✅ Issue #2: UFW log rotation missing

### ubuntu-hardening-25.sh (v4.0) - NEW!
**Target**: Ubuntu 25.04 (Plucky Puffin) / 25.10 (Questing Quokka)

**New Features:**
- **Chrony with NTS**: Network Time Security for secure time sync
- **Cgroup v2 Only**: Modern resource control (v1 deprecated)
- **No UTMP Support**: Systemd architectural change
- **Enhanced Cryptography**: OpenSSL 3.4.1+ and GnuTLS 3.8.9+
- **Intel TDX Detection**: Trust Domain Extensions for confidential computing
- **sudo-rs Support**: Rust sudo implementation (25.10)
- **Rust Coreutils**: Enhanced system utilities (25.10)
- **Kernel 6.14+/6.17+**: Latest kernel hardening
- **Enhanced eBPF**: Improved security controls
- **io_uring Restrictions**: Enhanced security for async I/O

**All Fixes Included**: All fixes from 24.04 script pre-applied

## 🛡️ Security Controls Applied

### 1. Authentication & Access
- SSH root login disabled
- Password authentication disabled
- PAM password quality enforcement
- Login attempt limits
- Session timeout configuration
- Strong cipher suites (version-specific)

### 2. Network Security
- Default deny firewall policy
- Rate-limited SSH access
- IPv6 security (configurable)
- TCP SYN flood protection
- ICMP redirect prevention
- UFW log rotation (all versions)

### 3. System Integrity
- Daily file integrity checks (AIDE)
- Comprehensive audit logging
- Secure kernel parameters (version-optimized)
- Module loading restrictions
- Core dump prevention
- Enhanced audit rules (version-specific)

### 4. Time Synchronization
- **18.04-24.04**: systemd-timesyncd with secure configuration
- **25.x**: Chrony with NTS (time.cloudflare.com, nts.ntp.se, ptbtime1.ptb.de, time.dfm.dk)

### 5. Monitoring & Detection
- Real-time intrusion detection (Fail2ban)
- Rootkit scanning (rkhunter, chkrootkit)
- Virus scanning with quarantine (ClamAV)
- Security compliance scanning (OpenSCAP)
- Automated log analysis

## ⚙️ Configuration

### During Installation
The scripts will interactively prompt for:
- ClamAV scan frequency (daily/weekly/monthly)
- OpenSCAP scan frequency (daily/weekly/monthly)

### Post-Installation Configuration

**Add firewall rules for your services:**
```bash
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 3306/tcp comment 'MySQL'
sudo ufw status verbose
```

**Modify automatic update settings:**
```bash
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

**Adjust SSH settings:**
```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
sudo systemctl restart sshd
```

**Check Chrony NTS status (Ubuntu 25.x):**
```bash
chronyc sources      # View time sources
chronyc tracking     # View sync status
chronyc ntsdump      # View NTS data
```

## 📊 Monitoring & Maintenance

### View Security Reports
```bash
# Hardening report (all versions)
sudo cat /var/log/security-hardening/hardening_report_*.txt

# Audit summary
sudo aureport --summary

# Failed login attempts
sudo aureport --auth --failure

# File integrity check
sudo aide --check

# Time sync status (Ubuntu 25.x)
chronyc tracking
```

### Security Scanning Commands
```bash
# Comprehensive system audit
sudo lynis audit system

# Rootkit check
sudo rkhunter -c

# Alternative rootkit check
sudo chkrootkit

# Compliance scan
sudo /usr/local/bin/openscap-scan.sh

# Check critical service status
sudo systemctl status auditd apparmor ufw fail2ban

# Check Chrony (Ubuntu 25.x)
sudo systemctl status chrony
```

### Log Locations
- **Hardening logs**: `/var/log/security-hardening/`
- **Audit logs**: `/var/log/audit/audit.log`
- **ClamAV logs**: `/var/log/clamav/`
- **UFW logs**: `/var/log/ufw.log` (with rotation)
- **Fail2ban logs**: `/var/log/fail2ban.log`
- **Chrony logs** (Ubuntu 25.x): `/var/log/chrony/`

## 🚨 Important Warnings

### ⚠️ SSH Access
- **Password authentication is DISABLED** after hardening
- Ensure SSH key access is working before running the script
- Test SSH key access from another terminal before disconnecting
- Keep a console/physical access method available
- Root login is disabled for security

### ⚠️ Firewall Rules
- Only SSH (port 22) is allowed by default with rate limiting
- All other incoming connections are blocked
- Add rules for your required services post-installation
- UFW logs are rotated to prevent disk space issues

### ⚠️ System Impact
- Some applications may be affected by kernel hardening
- Test all critical services after hardening
- Review the hardening report for applied changes
- Some parameters may need adjustment for specific workloads
- **Ubuntu 25.x**: Cgroup v1 is no longer supported (v2 only)

### ⚠️ Time Synchronization (Ubuntu 25.x)
- systemd-timesyncd is replaced by Chrony
- NTS (Network Time Security) is enabled by default
- Verify time sync after installation: `chronyc sources`

## 🔄 Updates and Maintenance

### Automatic Updates
All scripts configure automatic security updates. To check status:
```bash
sudo systemctl status unattended-upgrades
sudo unattended-upgrade --dry-run --debug
```

### Manual Security Updates
```bash
# Update package lists
sudo apt update

# Upgrade packages
sudo apt upgrade

# Update virus definitions
sudo freshclam

# Update rootkit definitions
sudo rkhunter --update

# Update AIDE database after system changes
sudo aide --update
```

## 📈 Compliance and Standards

The scripts implement controls based on:
- **CIS Ubuntu Linux Benchmarks** (version-specific)
- **NIST Cybersecurity Framework**
- **PCI DSS Requirements** (where applicable)
- **Industry security best practices**
- **Ubuntu Security Guidelines**

### Compliance Scanning
```bash
# List available profiles
sudo oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu*.xml

# Run CIS Level 1 Server benchmark
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --report /tmp/cis-report.html \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu*.xml

# View OpenSCAP reports
ls -lh /var/log/openscap/
```

## 🐛 Troubleshooting

### SSH Connection Issues
```bash
# If locked out, use console access and:
sudo ufw allow ssh
sudo systemctl restart sshd
sudo fail2ban-client status sshd
sudo fail2ban-client unban <your-ip>
```

### Service Failures
```bash
# Check service status
sudo systemctl status <service-name>

# View service logs
sudo journalctl -u <service-name> -n 50 --no-pager

# Restart service
sudo systemctl restart <service-name>

# Check all security services
sudo systemctl status auditd apparmor clamav-daemon ufw fail2ban
```

### Chrony Issues (Ubuntu 25.x)
```bash
# Check Chrony status
sudo systemctl status chrony

# View sources
chronyc sources -v

# View tracking
chronyc tracking

# Restart Chrony
sudo systemctl restart chrony
```

### Performance Issues
```bash
# Temporarily disable ClamAV daemon if needed
sudo systemctl stop clamav-daemon
sudo systemctl disable clamav-daemon

# View audit rules
sudo auditctl -l

# Reduce audit verbosity if needed (use cautiously)
sudo nano /etc/audit/rules.d/hardening.rules
sudo augenrules --load
```

### Firewall Debugging
```bash
# View UFW status with rules
sudo ufw status verbose

# Check UFW logs (with rotation)
sudo tail -f /var/log/ufw.log

# Temporarily disable UFW (emergency only)
sudo ufw disable

# Re-enable UFW
sudo ufw enable
```

## 🔍 Verification Steps

After running any script, verify the following:

### 1. Check Service Status
```bash
sudo systemctl status auditd apparmor ufw fail2ban unattended-upgrades
```

### 2. Verify Firewall
```bash
sudo ufw status verbose
```

### 3. Test SSH Access
```bash
# From another terminal
ssh -i ~/.ssh/your_key user@server
```

### 4. Check Time Sync (Ubuntu 25.x)
```bash
chronyc sources
chronyc tracking
```

### 5. Review Logs
```bash
sudo cat /var/log/security-hardening/hardening_report_*.txt
```

## 🆚 Script Comparison

| Feature | Original (v2.0) | 24.04 (v3.0) | 25.x (v4.0) |
|---------|-----------------|--------------|-------------|
| **Ubuntu Support** | 18.04-22.04 | 24.04 LTS | 25.04/25.10 |
| **Scheduling** | Cron | Systemd Timers | Systemd Timers |
| **Time Sync** | timesyncd | timesyncd | Chrony + NTS |
| **Cgroups** | v1 & v2 | v1 & v2 | v2 Only |
| **Kernel** | 4.15-5.15 | 6.8+ | 6.14+/6.17+ |
| **Crypto** | Standard | Modern | Enhanced |
| **Ubuntu Pro** | No | Yes | Yes |
| **Intel TDX** | No | No | Yes |
| **sudo-rs** | No | No | Yes (25.10) |
| **UTMP** | Yes | Yes | No |
| **eBPF Security** | Basic | Enhanced | Advanced |

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Test your changes in isolated VMs
4. Commit your changes (`git commit -am 'Add improvement'`)
5. Push to the branch (`git push origin feature/improvement`)
6. Create a Pull Request

### Development Guidelines
- Test scripts on appropriate Ubuntu versions
- Document any new features in this README
- Follow existing code style and conventions
- Add comments for complex logic
- Update version numbers appropriately
- Validate bash syntax: `bash -n script.sh`

## 🔒 Security Issues

If you discover a security vulnerability, please:
1. **Do NOT** open a public issue
2. Email security details privately
3. Allow reasonable time for fixes before disclosure

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Disclaimer

These scripts are provided "AS IS" without warranty of any kind, express or implied. Always test in a non-production environment first. The authors are not responsible for any damage, data loss, or service interruption resulting from the use of these scripts.

**Important**: These scripts make significant changes to system configuration. Always:
- Create backups before running
- Test in non-production environments
- Review the code before execution
- Have a recovery plan ready

## 🙏 Acknowledgments

- Ubuntu Security Team for security guidelines
- CIS for benchmark documentation
- NIST for cybersecurity framework
- Open source security tool maintainers
- Community contributors and testers
- Canonical for Ubuntu 25.x security enhancements

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script/discussions)
- **Documentation**: This README and inline script comments

## 🔗 Useful Resources

### Official Documentation
- [Ubuntu Security](https://ubuntu.com/security)
- [Ubuntu 25.10 Security Updates](https://ubuntu.com/blog/ubuntu-25-10-security-updates)
- [Ubuntu 25.04 Security Features](https://linuxsecurity.com/news/vendors-products/ubuntu-25-04-enhanced-security)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Security Tools
- [OpenSCAP Documentation](https://www.open-scap.org/documentation/)
- [AIDE Manual](https://aide.github.io/)
- [Lynis Documentation](https://cisofy.com/lynis/)
- [ClamAV Documentation](https://docs.clamav.net/)
- [Fail2ban Documentation](https://www.fail2ban.org/)
- [Chrony Documentation](https://chrony.tuxfamily.org/documentation.html)

### Linux Security
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
- [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)
- [Systemd Security Features](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)

---

**Version**: 4.0 | **Last Updated**: 2024 | **Maintained**: Yes ✅

**Tested On**: Ubuntu 18.04, 20.04, 22.04, 24.04, 25.04, 25.10

**All Scripts**: Production-Ready | Syntax-Validated | Issue-Free
